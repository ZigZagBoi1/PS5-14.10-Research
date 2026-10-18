; Handler 663; REA/Ghidra function-aware assembly with supplemental original-byte disassembly.
; RVAs, not rebased absolute VAs. Static analysis only.
; COMPLETE ORIGINAL INPUT WINDOW: handler_663.bin, 4096 bytes
; SHA256 60731b114b4e7245cb2ae36af79cfce0c6cadb0443693c34f6a74f98714e2bda; file offset zero = kernel RVA 0x265720.
; REA 6.7.0 / Ghidra 12.1.4 procedure_assembly disassembled every JMP below.
; Each function range is its five-byte tail-JMP; three CC padding bytes follow.
; INT3 padding is decoded from verified original bytes; GNU full-byte listing is supplied separately.
; Evidence source: byte-identical slice of raw_union.bin; evidence IDs per procedure.

; FUNCTION thunk_265720 [0x265720, 0x265724] | file +0x0 | ev_663b0a68a7b3c2be7c9493c0aead17e89f76910d56519503799ba2ffda9209d0
thunk_265720:
0x265720: JMP 0x003b01f0
; END FUNCTION thunk_265720
0x265725: INT3 ; original byte CC, padding
0x265726: INT3 ; original byte CC, padding
0x265727: INT3 ; original byte CC, padding

; FUNCTION thunk_265728 [0x265728, 0x26572c] | file +0x8 | ev_d69bbc7a859c476d6141155d3b2d923da60bf9e3f5f4355d77f3bcedce013985
thunk_265728:
0x265728: JMP 0x003b0fb0
; END FUNCTION thunk_265728
0x26572d: INT3 ; original byte CC, padding
0x26572e: INT3 ; original byte CC, padding
0x26572f: INT3 ; original byte CC, padding

; FUNCTION thunk_265730 [0x265730, 0x265734] | file +0x10 | ev_cf4a0758f2319cf7845c9debebe9582bfd69286eb3a26b66f296653aa9038eb8
thunk_265730:
0x265730: JMP 0x003b1670
; END FUNCTION thunk_265730
0x265735: INT3 ; original byte CC, padding
0x265736: INT3 ; original byte CC, padding
0x265737: INT3 ; original byte CC, padding

; FUNCTION thunk_265738 [0x265738, 0x26573c] | file +0x18 | ev_92ce22eed051fe8e75b8bc76827733d13e499e4d8d596bf46af0d7d5c1429ef3
thunk_265738:
0x265738: JMP 0x003b1680
; END FUNCTION thunk_265738
0x26573d: INT3 ; original byte CC, padding
0x26573e: INT3 ; original byte CC, padding
0x26573f: INT3 ; original byte CC, padding

; FUNCTION thunk_265740 [0x265740, 0x265744] | file +0x20 | ev_33530924e7685bff9fddd82f68a628a756c5337ce46b62cbd6d38d80f5fa6096
thunk_265740:
0x265740: JMP 0x003b2060
; END FUNCTION thunk_265740
0x265745: INT3 ; original byte CC, padding
0x265746: INT3 ; original byte CC, padding
0x265747: INT3 ; original byte CC, padding

; FUNCTION thunk_265748 [0x265748, 0x26574c] | file +0x28 | ev_de67cf534443a31bebab6a25bf45f5fd82945002817eb37fa40aaff619e6d23a
thunk_265748:
0x265748: JMP 0x003b28d0
; END FUNCTION thunk_265748
0x26574d: INT3 ; original byte CC, padding
0x26574e: INT3 ; original byte CC, padding
0x26574f: INT3 ; original byte CC, padding

; FUNCTION thunk_265750 [0x265750, 0x265754] | file +0x30 | ev_132234fcaf537fa6a42b874d00a2e1aad642c7a28a779da7ebbeaa20c0874aaa
thunk_265750:
0x265750: JMP 0x003b2d50
; END FUNCTION thunk_265750
0x265755: INT3 ; original byte CC, padding
0x265756: INT3 ; original byte CC, padding
0x265757: INT3 ; original byte CC, padding

; FUNCTION thunk_265758 [0x265758, 0x26575c] | file +0x38 | ev_068558a7684bdcceb36c61662c628b8e88ef07ac65492f923014b5c82b93fade
thunk_265758:
0x265758: JMP 0x003b3090
; END FUNCTION thunk_265758
0x26575d: INT3 ; original byte CC, padding
0x26575e: INT3 ; original byte CC, padding
0x26575f: INT3 ; original byte CC, padding

; FUNCTION thunk_265760 [0x265760, 0x265764] | file +0x40 | ev_bd63dc1cd6837db427a1056eb97158fe259206066faca40c28dcf7934f20ba4d
thunk_265760:
0x265760: JMP 0x005620e0
; END FUNCTION thunk_265760
0x265765: INT3 ; original byte CC, padding
0x265766: INT3 ; original byte CC, padding
0x265767: INT3 ; original byte CC, padding

; FUNCTION thunk_265768 [0x265768, 0x26576c] | file +0x48 | ev_1d901a1b7fdb0a3a9f237abaa418c80c2b2fea99395acd4e1fbac26e3445716b
thunk_265768:
0x265768: JMP 0x003b6020
; END FUNCTION thunk_265768
0x26576d: INT3 ; original byte CC, padding
0x26576e: INT3 ; original byte CC, padding
0x26576f: INT3 ; original byte CC, padding

; FUNCTION thunk_265770 [0x265770, 0x265774] | file +0x50 | ev_b6804c0eb21d9151919aae4a42f9c0cfc063fb2f53e6396e6dc77cbac8e2a1ba
thunk_265770:
0x265770: JMP 0x003b6240
; END FUNCTION thunk_265770
0x265775: INT3 ; original byte CC, padding
0x265776: INT3 ; original byte CC, padding
0x265777: INT3 ; original byte CC, padding

; FUNCTION thunk_265778 [0x265778, 0x26577c] | file +0x58 | ev_34f74d2743a15a04b1f71fa6f65bd4bd17e95b886cba7359e78b5faeff6c856d
thunk_265778:
0x265778: JMP 0x003c1e10
; END FUNCTION thunk_265778
0x26577d: INT3 ; original byte CC, padding
0x26577e: INT3 ; original byte CC, padding
0x26577f: INT3 ; original byte CC, padding

; FUNCTION thunk_265780 [0x265780, 0x265784] | file +0x60 | ev_10c0daa579f734a4a7decbb86d19d366ccc650fa23eb00375ad24032a5e6e0b8
thunk_265780:
0x265780: JMP 0x003c2240
; END FUNCTION thunk_265780
0x265785: INT3 ; original byte CC, padding
0x265786: INT3 ; original byte CC, padding
0x265787: INT3 ; original byte CC, padding

; FUNCTION thunk_265788 [0x265788, 0x26578c] | file +0x68 | ev_f3de7310226151c0183fe0d6a12e4162a8775d55c90b0d1ecb962e5e74c27fbf
thunk_265788:
0x265788: JMP 0x0012f7e0
; END FUNCTION thunk_265788
0x26578d: INT3 ; original byte CC, padding
0x26578e: INT3 ; original byte CC, padding
0x26578f: INT3 ; original byte CC, padding

; FUNCTION thunk_265790 [0x265790, 0x265794] | file +0x70 | ev_ce96bb8ef60d99823c5763a8166e15725e79734fa2c841d7a584703f32adc295
thunk_265790:
0x265790: JMP 0x003ce150
; END FUNCTION thunk_265790
0x265795: INT3 ; original byte CC, padding
0x265796: INT3 ; original byte CC, padding
0x265797: INT3 ; original byte CC, padding

; FUNCTION thunk_265798 [0x265798, 0x26579c] | file +0x78 | ev_0f8dc4e185eda329d0f5b8a0e374280c6e3304d1ed60a8d7d32f05850edf66e6
thunk_265798:
0x265798: JMP 0x003d52b0
; END FUNCTION thunk_265798
0x26579d: INT3 ; original byte CC, padding
0x26579e: INT3 ; original byte CC, padding
0x26579f: INT3 ; original byte CC, padding

; FUNCTION thunk_2657a0 [0x2657a0, 0x2657a4] | file +0x80 | ev_e2f761a65fdd84dab59b1b13e22a3b855068bf5d9a5be19d82c77854c4429308
thunk_2657a0:
0x2657a0: JMP 0x003e5aa0
; END FUNCTION thunk_2657a0
0x2657a5: INT3 ; original byte CC, padding
0x2657a6: INT3 ; original byte CC, padding
0x2657a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657a8 [0x2657a8, 0x2657ac] | file +0x88 | ev_6697810b038fc1b12c4d4c9a9b0dd049ff025f425f50042e871cec4631353f94
thunk_2657a8:
0x2657a8: JMP 0x003e5ad0
; END FUNCTION thunk_2657a8
0x2657ad: INT3 ; original byte CC, padding
0x2657ae: INT3 ; original byte CC, padding
0x2657af: INT3 ; original byte CC, padding

; FUNCTION thunk_2657b0 [0x2657b0, 0x2657b4] | file +0x90 | ev_ebf7b57120fb86445774a5dca464139125d8f4d01fa8fb9287d3638ebaef2c34
thunk_2657b0:
0x2657b0: JMP 0x003e5af0
; END FUNCTION thunk_2657b0
0x2657b5: INT3 ; original byte CC, padding
0x2657b6: INT3 ; original byte CC, padding
0x2657b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657b8 [0x2657b8, 0x2657bc] | file +0x98 | ev_f18742952a9bc02a461e135a15fb6ef707ecbaf16ba12b4da18dbdae79073308
thunk_2657b8:
0x2657b8: JMP 0x003ec340
; END FUNCTION thunk_2657b8
0x2657bd: INT3 ; original byte CC, padding
0x2657be: INT3 ; original byte CC, padding
0x2657bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2657c0 [0x2657c0, 0x2657c4] | file +0xa0 | ev_91f732a1a4e63f6a6eb155545811fa0e43b164dacb291025c69d8da804414ace
thunk_2657c0:
0x2657c0: JMP 0x003f05c0
; END FUNCTION thunk_2657c0
0x2657c5: INT3 ; original byte CC, padding
0x2657c6: INT3 ; original byte CC, padding
0x2657c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657c8 [0x2657c8, 0x2657cc] | file +0xa8 | ev_c7b98d7ba8ab37f6d1800ccac069f4d56bde69cdec76707b570744d7e7dc1d69
thunk_2657c8:
0x2657c8: JMP 0x003f2810
; END FUNCTION thunk_2657c8
0x2657cd: INT3 ; original byte CC, padding
0x2657ce: INT3 ; original byte CC, padding
0x2657cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2657d0 [0x2657d0, 0x2657d4] | file +0xb0 | ev_4f51d5c363cf402cd2db4e9f992362fbab4776f0ecbd528c24eb13344bbd3dca
thunk_2657d0:
0x2657d0: JMP 0x003f2b60
; END FUNCTION thunk_2657d0
0x2657d5: INT3 ; original byte CC, padding
0x2657d6: INT3 ; original byte CC, padding
0x2657d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657d8 [0x2657d8, 0x2657dc] | file +0xb8 | ev_1fa68ba64ca0d7c70f430e815cb0b0f22e75fe57ded1c269a505586d5c58f4d2
thunk_2657d8:
0x2657d8: JMP 0x0050ce20
; END FUNCTION thunk_2657d8
0x2657dd: INT3 ; original byte CC, padding
0x2657de: INT3 ; original byte CC, padding
0x2657df: INT3 ; original byte CC, padding

; FUNCTION thunk_2657e0 [0x2657e0, 0x2657e4] | file +0xc0 | ev_cdf4533c696eba4277540c786b459e9ea015d47fce9d5d76f4a652cb6ac58172
thunk_2657e0:
0x2657e0: JMP 0x003f3f90
; END FUNCTION thunk_2657e0
0x2657e5: INT3 ; original byte CC, padding
0x2657e6: INT3 ; original byte CC, padding
0x2657e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657e8 [0x2657e8, 0x2657ec] | file +0xc8 | ev_374afdf2cce64a46acab5a174134a7f968029c9c59d14d6742cd560ce5213f23
thunk_2657e8:
0x2657e8: JMP 0x00409790
; END FUNCTION thunk_2657e8
0x2657ed: INT3 ; original byte CC, padding
0x2657ee: INT3 ; original byte CC, padding
0x2657ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2657f0 [0x2657f0, 0x2657f4] | file +0xd0 | ev_58e9f1700ab212c7bbdd085f1ce9a5bdbaedb7fab614a122c69f2a9c6762e1bd
thunk_2657f0:
0x2657f0: JMP 0x00be7240
; END FUNCTION thunk_2657f0
0x2657f5: INT3 ; original byte CC, padding
0x2657f6: INT3 ; original byte CC, padding
0x2657f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657f8 [0x2657f8, 0x2657fc] | file +0xd8 | ev_f6bc973f7dcabf9e89f903c9e2bf5dbf21259650a2b611915c1164b66fa72741
thunk_2657f8:
0x2657f8: JMP 0x00cb1390
; END FUNCTION thunk_2657f8
0x2657fd: INT3 ; original byte CC, padding
0x2657fe: INT3 ; original byte CC, padding
0x2657ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265800 [0x265800, 0x265804] | file +0xe0 | ev_21b84e85838248825fd2de74126e431447c58868f9b80275e73f098e74c945cf
thunk_265800:
0x265800: JMP 0x004ec000
; END FUNCTION thunk_265800
0x265805: INT3 ; original byte CC, padding
0x265806: INT3 ; original byte CC, padding
0x265807: INT3 ; original byte CC, padding

; FUNCTION thunk_265808 [0x265808, 0x26580c] | file +0xe8 | ev_ed36ff2d496580222b1f83b896dfddfaf483e38fce8c3c285a7c9581d5ef186f
thunk_265808:
0x265808: JMP 0x004ec560
; END FUNCTION thunk_265808
0x26580d: INT3 ; original byte CC, padding
0x26580e: INT3 ; original byte CC, padding
0x26580f: INT3 ; original byte CC, padding

; FUNCTION thunk_265810 [0x265810, 0x265814] | file +0xf0 | ev_89727ec834a0cfe20eb32510eb9c2eae50ce027f3e6a558042ad62d7e27d8e1b
thunk_265810:
0x265810: JMP 0x008f6e00
; END FUNCTION thunk_265810
0x265815: INT3 ; original byte CC, padding
0x265816: INT3 ; original byte CC, padding
0x265817: INT3 ; original byte CC, padding

; FUNCTION thunk_265818 [0x265818, 0x26581c] | file +0xf8 | ev_eefb66ff0c291781258b8a7b7ae899d7e3dcf66c5c651f06811347f6134cff7e
thunk_265818:
0x265818: JMP 0x0072bf00
; END FUNCTION thunk_265818
0x26581d: INT3 ; original byte CC, padding
0x26581e: INT3 ; original byte CC, padding
0x26581f: INT3 ; original byte CC, padding

; FUNCTION thunk_265820 [0x265820, 0x265824] | file +0x100 | ev_b01c8ded1e53f1229648a8fc823292f76ba1e191912f08da40a003017916d032
thunk_265820:
0x265820: JMP 0x00be8290
; END FUNCTION thunk_265820
0x265825: INT3 ; original byte CC, padding
0x265826: INT3 ; original byte CC, padding
0x265827: INT3 ; original byte CC, padding

; FUNCTION thunk_265828 [0x265828, 0x26582c] | file +0x108 | ev_e877aa9a22237e98d7eb06a87171e8dc74a5766852423ce01502627d2dfb95bb
thunk_265828:
0x265828: JMP 0x008f8550
; END FUNCTION thunk_265828
0x26582d: INT3 ; original byte CC, padding
0x26582e: INT3 ; original byte CC, padding
0x26582f: INT3 ; original byte CC, padding

; FUNCTION thunk_265830 [0x265830, 0x265834] | file +0x110 | ev_ba7051f63021a6fd1c6284d1f82b4898b77f53988089d8426c18b784cb611820
thunk_265830:
0x265830: JMP 0x008f6b20
; END FUNCTION thunk_265830
0x265835: INT3 ; original byte CC, padding
0x265836: INT3 ; original byte CC, padding
0x265837: INT3 ; original byte CC, padding

; FUNCTION thunk_265838 [0x265838, 0x26583c] | file +0x118 | ev_29e270b89c7ed4c79f5d94bb4bd94f9805dda1cdee86aa988991baafe5cab9bf
thunk_265838:
0x265838: JMP 0x008f9b40
; END FUNCTION thunk_265838
0x26583d: INT3 ; original byte CC, padding
0x26583e: INT3 ; original byte CC, padding
0x26583f: INT3 ; original byte CC, padding

; FUNCTION thunk_265840 [0x265840, 0x265844] | file +0x120 | ev_2286b3dda1e7e72b42d6a92a0a0aefa2f61011e9c731cefc24e2698890829772
thunk_265840:
0x265840: JMP 0x005329e0
; END FUNCTION thunk_265840
0x265845: INT3 ; original byte CC, padding
0x265846: INT3 ; original byte CC, padding
0x265847: INT3 ; original byte CC, padding

; FUNCTION thunk_265848 [0x265848, 0x26584c] | file +0x128 | ev_01217ef4807cb3458c4e52bd4cc87292cea659508dadb94fb69d13110186d725
thunk_265848:
0x265848: JMP 0x005321e0
; END FUNCTION thunk_265848
0x26584d: INT3 ; original byte CC, padding
0x26584e: INT3 ; original byte CC, padding
0x26584f: INT3 ; original byte CC, padding

; FUNCTION thunk_265850 [0x265850, 0x265854] | file +0x130 | ev_6d5fd951eb8cbb265a712cc176037c10716ffd34adb58ee287e6ce7605307018
thunk_265850:
0x265850: JMP 0x005328d0
; END FUNCTION thunk_265850
0x265855: INT3 ; original byte CC, padding
0x265856: INT3 ; original byte CC, padding
0x265857: INT3 ; original byte CC, padding

; FUNCTION thunk_265858 [0x265858, 0x26585c] | file +0x138 | ev_5090551b84c0f978635bfd1de6823dd5bef2c93d319a2411da7d400cedf97693
thunk_265858:
0x265858: JMP 0x00531080
; END FUNCTION thunk_265858
0x26585d: INT3 ; original byte CC, padding
0x26585e: INT3 ; original byte CC, padding
0x26585f: INT3 ; original byte CC, padding

; FUNCTION thunk_265860 [0x265860, 0x265864] | file +0x140 | ev_01c5c090c8cdb41592a81f1781d3f81583f8dd4d4fe769363a8450c7d1f7a771
thunk_265860:
0x265860: JMP 0x00533310
; END FUNCTION thunk_265860
0x265865: INT3 ; original byte CC, padding
0x265866: INT3 ; original byte CC, padding
0x265867: INT3 ; original byte CC, padding

; FUNCTION thunk_265868 [0x265868, 0x26586c] | file +0x148 | ev_c24a1e048aeb103df20b0435af6b29a74f5df513f9f5c72aaa03666f01eb6fdc
thunk_265868:
0x265868: JMP 0x00533030
; END FUNCTION thunk_265868
0x26586d: INT3 ; original byte CC, padding
0x26586e: INT3 ; original byte CC, padding
0x26586f: INT3 ; original byte CC, padding

; FUNCTION thunk_265870 [0x265870, 0x265874] | file +0x150 | ev_76ba314b67213efa76858206a61bcd4163406a9f26e42af0d8698645842db016
thunk_265870:
0x265870: JMP 0x008f8be0
; END FUNCTION thunk_265870
0x265875: INT3 ; original byte CC, padding
0x265876: INT3 ; original byte CC, padding
0x265877: INT3 ; original byte CC, padding

; FUNCTION thunk_265878 [0x265878, 0x26587c] | file +0x158 | ev_896c34d770fdd0c212052502dd983d487250108abf025f4f05b524748fb80c86
thunk_265878:
0x265878: JMP 0x008f95b0
; END FUNCTION thunk_265878
0x26587d: INT3 ; original byte CC, padding
0x26587e: INT3 ; original byte CC, padding
0x26587f: INT3 ; original byte CC, padding

; FUNCTION thunk_265880 [0x265880, 0x265884] | file +0x160 | ev_f8863d096867a30cdba9addd987914e5d320e078b4aade3ac9e818e1f98319d5
thunk_265880:
0x265880: JMP 0x008f9760
; END FUNCTION thunk_265880
0x265885: INT3 ; original byte CC, padding
0x265886: INT3 ; original byte CC, padding
0x265887: INT3 ; original byte CC, padding

; FUNCTION thunk_265888 [0x265888, 0x26588c] | file +0x168 | ev_85141131e97cdc037a66618a2dab05c4883afdef7550bb962d7c3b1108406661
thunk_265888:
0x265888: JMP 0x008f5d20
; END FUNCTION thunk_265888
0x26588d: INT3 ; original byte CC, padding
0x26588e: INT3 ; original byte CC, padding
0x26588f: INT3 ; original byte CC, padding

; FUNCTION thunk_265890 [0x265890, 0x265894] | file +0x170 | ev_5ede924fc5154e62e37e7bf8c3f811e88e9b2faec58b249284bb80f0fb48025b
thunk_265890:
0x265890: JMP 0x0055f5b0
; END FUNCTION thunk_265890
0x265895: INT3 ; original byte CC, padding
0x265896: INT3 ; original byte CC, padding
0x265897: INT3 ; original byte CC, padding

; FUNCTION thunk_265898 [0x265898, 0x26589c] | file +0x178 | ev_a23d17f391f4d36d97e50a18a5186539d45e2bed5fc87ffe4a0dcc4d6db07939
thunk_265898:
0x265898: JMP 0x00729d80
; END FUNCTION thunk_265898
0x26589d: INT3 ; original byte CC, padding
0x26589e: INT3 ; original byte CC, padding
0x26589f: INT3 ; original byte CC, padding

; FUNCTION thunk_2658a0 [0x2658a0, 0x2658a4] | file +0x180 | ev_b7a1dccb9d6a6d2325e92a7739fa6f321de83fb32cf43179dc7d2b1beed1ac61
thunk_2658a0:
0x2658a0: JMP 0x00802d90
; END FUNCTION thunk_2658a0
0x2658a5: INT3 ; original byte CC, padding
0x2658a6: INT3 ; original byte CC, padding
0x2658a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658a8 [0x2658a8, 0x2658ac] | file +0x188 | ev_b19515a52787f810c0fc8a150c253edf5a09f1ecb6685c5ddb19a7fcbd31e7f0
thunk_2658a8:
0x2658a8: JMP 0x0045e4d0
; END FUNCTION thunk_2658a8
0x2658ad: INT3 ; original byte CC, padding
0x2658ae: INT3 ; original byte CC, padding
0x2658af: INT3 ; original byte CC, padding

; FUNCTION thunk_2658b0 [0x2658b0, 0x2658b4] | file +0x190 | ev_5b2cef43eb0f5d13ddd9c2fd9b7fa4dd2b081756fab4a5992d820a192c878767
thunk_2658b0:
0x2658b0: JMP 0x0055f400
; END FUNCTION thunk_2658b0
0x2658b5: INT3 ; original byte CC, padding
0x2658b6: INT3 ; original byte CC, padding
0x2658b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658b8 [0x2658b8, 0x2658bc] | file +0x198 | ev_17fe6fbebe1335a99ecaeac06f571ba24b9ad7de60e42acf82b9b228106d6104
thunk_2658b8:
0x2658b8: JMP 0x004ecf40
; END FUNCTION thunk_2658b8
0x2658bd: INT3 ; original byte CC, padding
0x2658be: INT3 ; original byte CC, padding
0x2658bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2658c0 [0x2658c0, 0x2658c4] | file +0x1a0 | ev_eee7a1b6ecdce4e0b77d92dfc20a43dc2782e75827d3f98726902e4b96738d77
thunk_2658c0:
0x2658c0: JMP 0x007e4810
; END FUNCTION thunk_2658c0
0x2658c5: INT3 ; original byte CC, padding
0x2658c6: INT3 ; original byte CC, padding
0x2658c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658c8 [0x2658c8, 0x2658cc] | file +0x1a8 | ev_845ed6badef4ae9ef77ba2e779a2375a56564fca34ec6fbcd0911725b268c459
thunk_2658c8:
0x2658c8: JMP 0x008fc490
; END FUNCTION thunk_2658c8
0x2658cd: INT3 ; original byte CC, padding
0x2658ce: INT3 ; original byte CC, padding
0x2658cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2658d0 [0x2658d0, 0x2658d4] | file +0x1b0 | ev_d1b9e0d38d6434e6a73c7cd5580db593062890703035603def4048e5f0f70516
thunk_2658d0:
0x2658d0: JMP 0x006e2dc0
; END FUNCTION thunk_2658d0
0x2658d5: INT3 ; original byte CC, padding
0x2658d6: INT3 ; original byte CC, padding
0x2658d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658d8 [0x2658d8, 0x2658dc] | file +0x1b8 | ev_ef22b085ea6deaa05e80e7ecc0348d6d86c49968e69baffefc4836914656a99f
thunk_2658d8:
0x2658d8: JMP 0x00ab8af0
; END FUNCTION thunk_2658d8
0x2658dd: INT3 ; original byte CC, padding
0x2658de: INT3 ; original byte CC, padding
0x2658df: INT3 ; original byte CC, padding

; FUNCTION thunk_2658e0 [0x2658e0, 0x2658e4] | file +0x1c0 | ev_4f526ca80fe3367a5a614419397741f41bb8b497bda0c49a4d7663d093a8a633
thunk_2658e0:
0x2658e0: JMP 0x00ab8bb0
; END FUNCTION thunk_2658e0
0x2658e5: INT3 ; original byte CC, padding
0x2658e6: INT3 ; original byte CC, padding
0x2658e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658e8 [0x2658e8, 0x2658ec] | file +0x1c8 | ev_6df4f33e4cce4fbceedd1cb5393b063a0eedd64e4998eb6e45e4de8a5ac03640
thunk_2658e8:
0x2658e8: JMP 0x00ab8d20
; END FUNCTION thunk_2658e8
0x2658ed: INT3 ; original byte CC, padding
0x2658ee: INT3 ; original byte CC, padding
0x2658ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2658f0 [0x2658f0, 0x2658f4] | file +0x1d0 | ev_890257df8433a0b7603458bc3bad772ae2bbe8da754402853cc8349d35c35c69
thunk_2658f0:
0x2658f0: JMP 0x00ab8e00
; END FUNCTION thunk_2658f0
0x2658f5: INT3 ; original byte CC, padding
0x2658f6: INT3 ; original byte CC, padding
0x2658f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658f8 [0x2658f8, 0x2658fc] | file +0x1d8 | ev_fccee6840eafe44da8599577bb9231c256a751d24cfad1a211d736e7cc16a240
thunk_2658f8:
0x2658f8: JMP 0x00ab8ec0
; END FUNCTION thunk_2658f8
0x2658fd: INT3 ; original byte CC, padding
0x2658fe: INT3 ; original byte CC, padding
0x2658ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265900 [0x265900, 0x265904] | file +0x1e0 | ev_c4d18df255e8b78afdffc056ebfd253100811ec71a1ccc354048d17e93f0b70a
thunk_265900:
0x265900: JMP 0x006bccc0
; END FUNCTION thunk_265900
0x265905: INT3 ; original byte CC, padding
0x265906: INT3 ; original byte CC, padding
0x265907: INT3 ; original byte CC, padding

; FUNCTION thunk_265908 [0x265908, 0x26590c] | file +0x1e8 | ev_1d8c648b8c949bddfa542a680881a2b6d34989bc252b7c050d7498240ee980e3
thunk_265908:
0x265908: JMP 0x006bca20
; END FUNCTION thunk_265908
0x26590d: INT3 ; original byte CC, padding
0x26590e: INT3 ; original byte CC, padding
0x26590f: INT3 ; original byte CC, padding

; FUNCTION thunk_265910 [0x265910, 0x265914] | file +0x1f0 | ev_2fbce8ef0f6b1d956a901b81cb57c9f16ae0b93127324c46ac5e0c8dc797f3fb
thunk_265910:
0x265910: JMP 0x007299f0
; END FUNCTION thunk_265910
0x265915: INT3 ; original byte CC, padding
0x265916: INT3 ; original byte CC, padding
0x265917: INT3 ; original byte CC, padding

; FUNCTION thunk_265918 [0x265918, 0x26591c] | file +0x1f8 | ev_51a7fedd9d37821417b557dbf67683f2594f508d9320da3f13e506d0066051e8
thunk_265918:
0x265918: JMP 0x00729a40
; END FUNCTION thunk_265918
0x26591d: INT3 ; original byte CC, padding
0x26591e: INT3 ; original byte CC, padding
0x26591f: INT3 ; original byte CC, padding

; FUNCTION thunk_265920 [0x265920, 0x265924] | file +0x200 | ev_c39c0d1fff985a45fbc3bd1198cf1b0ecd31692fb4a457f2d3a91762a9715145
thunk_265920:
0x265920: JMP 0x00729dc0
; END FUNCTION thunk_265920
0x265925: INT3 ; original byte CC, padding
0x265926: INT3 ; original byte CC, padding
0x265927: INT3 ; original byte CC, padding

; FUNCTION thunk_265928 [0x265928, 0x26592c] | file +0x208 | ev_6ed115f20180546ca451c6a4143e4cbcf49238cec1d7281f9c760435a3f48a16
thunk_265928:
0x265928: JMP 0x004ee4b0
; END FUNCTION thunk_265928
0x26592d: INT3 ; original byte CC, padding
0x26592e: INT3 ; original byte CC, padding
0x26592f: INT3 ; original byte CC, padding

; FUNCTION thunk_265930 [0x265930, 0x265934] | file +0x210 | ev_168128ab332fee133851c8c2c0dfed0372d386808a7ee24636fca3e8f350e72b
thunk_265930:
0x265930: JMP 0x008fb430
; END FUNCTION thunk_265930
0x265935: INT3 ; original byte CC, padding
0x265936: INT3 ; original byte CC, padding
0x265937: INT3 ; original byte CC, padding

; FUNCTION thunk_265938 [0x265938, 0x26593c] | file +0x218 | ev_c519c25eba1520b948eb17ada921ff130548b371bb9e749cd1a8197150ae7c7e
thunk_265938:
0x265938: JMP 0x0049ff80
; END FUNCTION thunk_265938
0x26593d: INT3 ; original byte CC, padding
0x26593e: INT3 ; original byte CC, padding
0x26593f: INT3 ; original byte CC, padding

; FUNCTION thunk_265940 [0x265940, 0x265944] | file +0x220 | ev_b31257a300ab503ae550e8b75e4beed9089c4d8aeff2ef13c06811b5f847cdcf
thunk_265940:
0x265940: JMP 0x0052f8f0
; END FUNCTION thunk_265940
0x265945: INT3 ; original byte CC, padding
0x265946: INT3 ; original byte CC, padding
0x265947: INT3 ; original byte CC, padding

; FUNCTION thunk_265948 [0x265948, 0x26594c] | file +0x228 | ev_6a0bec579f7db081777d62e5e84debe5bdb67589729a3712805f516afce5c16d
thunk_265948:
0x265948: JMP 0x00531260
; END FUNCTION thunk_265948
0x26594d: INT3 ; original byte CC, padding
0x26594e: INT3 ; original byte CC, padding
0x26594f: INT3 ; original byte CC, padding

; FUNCTION thunk_265950 [0x265950, 0x265954] | file +0x230 | ev_4ce2255d03764bdadf7c883b0fef92a89073cd0f77961ad7c78a4b7f395b1148
thunk_265950:
0x265950: JMP 0x0052fce0
; END FUNCTION thunk_265950
0x265955: INT3 ; original byte CC, padding
0x265956: INT3 ; original byte CC, padding
0x265957: INT3 ; original byte CC, padding

; FUNCTION thunk_265958 [0x265958, 0x26595c] | file +0x238 | ev_46ac121cd15ec4f1eef7e953216a00693eb003f1b8f3a51d54159f9c8db904ba
thunk_265958:
0x265958: JMP 0x0049fcf0
; END FUNCTION thunk_265958
0x26595d: INT3 ; original byte CC, padding
0x26595e: INT3 ; original byte CC, padding
0x26595f: INT3 ; original byte CC, padding

; FUNCTION thunk_265960 [0x265960, 0x265964] | file +0x240 | ev_58f2dc23be3ba21d60623d9e300f14eff0866f1b9d61326b6f93f17a5fe0e31d
thunk_265960:
0x265960: JMP 0x0052fd00
; END FUNCTION thunk_265960
0x265965: INT3 ; original byte CC, padding
0x265966: INT3 ; original byte CC, padding
0x265967: INT3 ; original byte CC, padding

; FUNCTION thunk_265968 [0x265968, 0x26596c] | file +0x248 | ev_7edf4937f75b34607d7282f661231292fd6b0e1043adabcdb3cec2032a84ae52
thunk_265968:
0x265968: JMP 0x0052fe00
; END FUNCTION thunk_265968
0x26596d: INT3 ; original byte CC, padding
0x26596e: INT3 ; original byte CC, padding
0x26596f: INT3 ; original byte CC, padding

; FUNCTION thunk_265970 [0x265970, 0x265974] | file +0x250 | ev_a61179069aea9d46cde19c9c505ec477bfafb1f1307b2ecb9a5dd4481f9599b0
thunk_265970:
0x265970: JMP 0x00530480
; END FUNCTION thunk_265970
0x265975: INT3 ; original byte CC, padding
0x265976: INT3 ; original byte CC, padding
0x265977: INT3 ; original byte CC, padding

; FUNCTION thunk_265978 [0x265978, 0x26597c] | file +0x258 | ev_8f68cf96d5c5641edab50be0cecfebf44ffa93a70f88e3e350a9ed6c39d0444f
thunk_265978:
0x265978: JMP 0x00532bc0
; END FUNCTION thunk_265978
0x26597d: INT3 ; original byte CC, padding
0x26597e: INT3 ; original byte CC, padding
0x26597f: INT3 ; original byte CC, padding

; FUNCTION thunk_265980 [0x265980, 0x265984] | file +0x260 | ev_96bd70da6010511498989cf153467883d54c72197753f7d56914e6848963c666
thunk_265980:
0x265980: JMP 0x005307d0
; END FUNCTION thunk_265980
0x265985: INT3 ; original byte CC, padding
0x265986: INT3 ; original byte CC, padding
0x265987: INT3 ; original byte CC, padding

; FUNCTION thunk_265988 [0x265988, 0x26598c] | file +0x268 | ev_ad263442a4957628c3651d02ff31caf3ff123d91ac6e612316130ef55a06fc41
thunk_265988:
0x265988: JMP 0x0052fae0
; END FUNCTION thunk_265988
0x26598d: INT3 ; original byte CC, padding
0x26598e: INT3 ; original byte CC, padding
0x26598f: INT3 ; original byte CC, padding

; FUNCTION thunk_265990 [0x265990, 0x265994] | file +0x270 | ev_6ddca225a8844f0a956e72eb36adca2fe53bd90a89eff3a53ef68aef49eda57d
thunk_265990:
0x265990: JMP 0x0072c140
; END FUNCTION thunk_265990
0x265995: INT3 ; original byte CC, padding
0x265996: INT3 ; original byte CC, padding
0x265997: INT3 ; original byte CC, padding

; FUNCTION thunk_265998 [0x265998, 0x26599c] | file +0x278 | ev_65c2b3b478763fa59180871059f420c13f43e74bbb5db32ea6e8a3ba14aed9c9
thunk_265998:
0x265998: JMP 0x006bc800
; END FUNCTION thunk_265998
0x26599d: INT3 ; original byte CC, padding
0x26599e: INT3 ; original byte CC, padding
0x26599f: INT3 ; original byte CC, padding

; FUNCTION thunk_2659a0 [0x2659a0, 0x2659a4] | file +0x280 | ev_3737c135be6511a09efc868cc07a5c07499ffae8ae300ed846470a34637263b2
thunk_2659a0:
0x2659a0: JMP 0x004a1ba0
; END FUNCTION thunk_2659a0
0x2659a5: INT3 ; original byte CC, padding
0x2659a6: INT3 ; original byte CC, padding
0x2659a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659a8 [0x2659a8, 0x2659ac] | file +0x288 | ev_1c8053eb5bc3aa09b01e0bc4d2c28858562f68c983c137ac0e898b243011a3f4
thunk_2659a8:
0x2659a8: JMP 0x00532cd0
; END FUNCTION thunk_2659a8
0x2659ad: INT3 ; original byte CC, padding
0x2659ae: INT3 ; original byte CC, padding
0x2659af: INT3 ; original byte CC, padding

; FUNCTION thunk_2659b0 [0x2659b0, 0x2659b4] | file +0x290 | ev_1a5b353552123c0d975b18fde8275291d3bc26fef98318c05a592f13ef508e30
thunk_2659b0:
0x2659b0: JMP 0x004ec2c0
; END FUNCTION thunk_2659b0
0x2659b5: INT3 ; original byte CC, padding
0x2659b6: INT3 ; original byte CC, padding
0x2659b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659b8 [0x2659b8, 0x2659bc] | file +0x298 | ev_ed5e8fd16ab4df76ed7f71c3c304a25e832678c51f3912fc41e30f28750c643e
thunk_2659b8:
0x2659b8: JMP 0x004ec8e0
; END FUNCTION thunk_2659b8
0x2659bd: INT3 ; original byte CC, padding
0x2659be: INT3 ; original byte CC, padding
0x2659bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2659c0 [0x2659c0, 0x2659c4] | file +0x2a0 | ev_42388928d43dbee314a6c1ce3245c8d49c8390da3c4bc594fb5aaddafc070ab7
thunk_2659c0:
0x2659c0: JMP 0x006bc8d0
; END FUNCTION thunk_2659c0
0x2659c5: INT3 ; original byte CC, padding
0x2659c6: INT3 ; original byte CC, padding
0x2659c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659c8 [0x2659c8, 0x2659cc] | file +0x2a8 | ev_aa1de99500333816fe82e6a0e9e23204b7b21bb793b90cf9923a4574ffd80d7c
thunk_2659c8:
0x2659c8: JMP 0x008f9d40
; END FUNCTION thunk_2659c8
0x2659cd: INT3 ; original byte CC, padding
0x2659ce: INT3 ; original byte CC, padding
0x2659cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2659d0 [0x2659d0, 0x2659d4] | file +0x2b0 | ev_d7c4da6f51e0244008bec03e69af471e068616e27e56eaaba7cd17e57aee7856
thunk_2659d0:
0x2659d0: JMP 0x0052fe70
; END FUNCTION thunk_2659d0
0x2659d5: INT3 ; original byte CC, padding
0x2659d6: INT3 ; original byte CC, padding
0x2659d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659d8 [0x2659d8, 0x2659dc] | file +0x2b8 | ev_d812c2321b5e8acb07f8f189c4f83d49099c0d10ab687c950cf9040645c78369
thunk_2659d8:
0x2659d8: JMP 0x008fb450
; END FUNCTION thunk_2659d8
0x2659dd: INT3 ; original byte CC, padding
0x2659de: INT3 ; original byte CC, padding
0x2659df: INT3 ; original byte CC, padding

; FUNCTION thunk_2659e0 [0x2659e0, 0x2659e4] | file +0x2c0 | ev_eeaf3a8beaaed8e90f29f246e32ffa9b14bf76351f9c7cdd7b75a5907064074e
thunk_2659e0:
0x2659e0: JMP 0x0072e590
; END FUNCTION thunk_2659e0
0x2659e5: INT3 ; original byte CC, padding
0x2659e6: INT3 ; original byte CC, padding
0x2659e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659e8 [0x2659e8, 0x2659ec] | file +0x2c8 | ev_93e5bf490834f1047815cb55d92a50b3522304ffe4de081ae3e2a6297c559350
thunk_2659e8:
0x2659e8: JMP 0x00531b30
; END FUNCTION thunk_2659e8
0x2659ed: INT3 ; original byte CC, padding
0x2659ee: INT3 ; original byte CC, padding
0x2659ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2659f0 [0x2659f0, 0x2659f4] | file +0x2d0 | ev_57eee56aad063f12744228690ca7ce45177d557dbda4f1cfc4949d59a3dd76f2
thunk_2659f0:
0x2659f0: JMP 0x00532af0
; END FUNCTION thunk_2659f0
0x2659f5: INT3 ; original byte CC, padding
0x2659f6: INT3 ; original byte CC, padding
0x2659f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659f8 [0x2659f8, 0x2659fc] | file +0x2d8 | ev_db6ed9d2e0cae311a8d595ad0e20575d70be3c6634b7afa4daa42c7afdd41d1c
thunk_2659f8:
0x2659f8: JMP 0x00531720
; END FUNCTION thunk_2659f8
0x2659fd: INT3 ; original byte CC, padding
0x2659fe: INT3 ; original byte CC, padding
0x2659ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265a00 [0x265a00, 0x265a04] | file +0x2e0 | ev_b9362fe323a442adbbe22eddd8cb779a87e9f35aa42d1392c2f78475a282a46c
thunk_265a00:
0x265a00: JMP 0x008fb8e0
; END FUNCTION thunk_265a00
0x265a05: INT3 ; original byte CC, padding
0x265a06: INT3 ; original byte CC, padding
0x265a07: INT3 ; original byte CC, padding

; FUNCTION thunk_265a08 [0x265a08, 0x265a0c] | file +0x2e8 | ev_e101e165d55e3c023ea9702dfff16f6e79246d887abaaf2a48215537ac448782
thunk_265a08:
0x265a08: JMP 0x008fbbc0
; END FUNCTION thunk_265a08
0x265a0d: INT3 ; original byte CC, padding
0x265a0e: INT3 ; original byte CC, padding
0x265a0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a10 [0x265a10, 0x265a14] | file +0x2f0 | ev_ab047a2ffd77c7fb21b69d50e06b794aa9de69186983e5cd51eb5c80a01023a4
thunk_265a10:
0x265a10: JMP 0x008fa310
; END FUNCTION thunk_265a10
0x265a15: INT3 ; original byte CC, padding
0x265a16: INT3 ; original byte CC, padding
0x265a17: INT3 ; original byte CC, padding

; FUNCTION thunk_265a18 [0x265a18, 0x265a1c] | file +0x2f8 | ev_457281366867d82ba2e84e2eeef2531b31b5cda653fa8dea15200204f38ec3dc
thunk_265a18:
0x265a18: JMP 0x0047b030
; END FUNCTION thunk_265a18
0x265a1d: INT3 ; original byte CC, padding
0x265a1e: INT3 ; original byte CC, padding
0x265a1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a20 [0x265a20, 0x265a24] | file +0x300 | ev_4cb9f4b02ac3982206479c7a415db43ef9663b9930a274e8917298018a4f8c09
thunk_265a20:
0x265a20: JMP 0x008f8e20
; END FUNCTION thunk_265a20
0x265a25: INT3 ; original byte CC, padding
0x265a26: INT3 ; original byte CC, padding
0x265a27: INT3 ; original byte CC, padding

; FUNCTION thunk_265a28 [0x265a28, 0x265a2c] | file +0x308 | ev_6aeeb89ab9fdd62d9997b8bb32c9bed71748578a672c0ba09686d984be5a9bdc
thunk_265a28:
0x265a28: JMP 0x0072c150
; END FUNCTION thunk_265a28
0x265a2d: INT3 ; original byte CC, padding
0x265a2e: INT3 ; original byte CC, padding
0x265a2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a30 [0x265a30, 0x265a34] | file +0x310 | ev_be064326b7431503cdcb02908a7217e744357b729e72e1614dc1328bc1ea66b1
thunk_265a30:
0x265a30: JMP 0x008f9260
; END FUNCTION thunk_265a30
0x265a35: INT3 ; original byte CC, padding
0x265a36: INT3 ; original byte CC, padding
0x265a37: INT3 ; original byte CC, padding

; FUNCTION thunk_265a38 [0x265a38, 0x265a3c] | file +0x318 | ev_eb91a911fcc71da70f30352af205783637b459c9f8d67b0eed63722a8d86b1cf
thunk_265a38:
0x265a38: JMP 0x008f9310
; END FUNCTION thunk_265a38
0x265a3d: INT3 ; original byte CC, padding
0x265a3e: INT3 ; original byte CC, padding
0x265a3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a40 [0x265a40, 0x265a44] | file +0x320 | ev_a3a52775b98c6fc5df9d7b69dd708e06229385519208b8f9465b77c8a0e0b83d
thunk_265a40:
0x265a40: JMP 0x0072c3e0
; END FUNCTION thunk_265a40
0x265a45: INT3 ; original byte CC, padding
0x265a46: INT3 ; original byte CC, padding
0x265a47: INT3 ; original byte CC, padding

; FUNCTION thunk_265a48 [0x265a48, 0x265a4c] | file +0x328 | ev_96925a78451c47ba5cdc7f70b51a7168ab595113055ce5d9d6b7261f687e8714
thunk_265a48:
0x265a48: JMP 0x004a13e0
; END FUNCTION thunk_265a48
0x265a4d: INT3 ; original byte CC, padding
0x265a4e: INT3 ; original byte CC, padding
0x265a4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a50 [0x265a50, 0x265a54] | file +0x330 | ev_06598b27113e0dd15bfe1ee2bc7d1d3b941c688d483dbbb8500b929308de0685
thunk_265a50:
0x265a50: JMP 0x004a0c30
; END FUNCTION thunk_265a50
0x265a55: INT3 ; original byte CC, padding
0x265a56: INT3 ; original byte CC, padding
0x265a57: INT3 ; original byte CC, padding

; FUNCTION thunk_265a58 [0x265a58, 0x265a5c] | file +0x338 | ev_ee56e932effb8cd11abcdecf19d018c0439a597586b5af12955784334c9c2e4c
thunk_265a58:
0x265a58: JMP 0x008fbbe0
; END FUNCTION thunk_265a58
0x265a5d: INT3 ; original byte CC, padding
0x265a5e: INT3 ; original byte CC, padding
0x265a5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a60 [0x265a60, 0x265a64] | file +0x340 | ev_c95aaa86727ffe60a4df1d510d7c3093e8db94cd313c902d93a5997623489575
thunk_265a60:
0x265a60: JMP 0x005581e0
; END FUNCTION thunk_265a60
0x265a65: INT3 ; original byte CC, padding
0x265a66: INT3 ; original byte CC, padding
0x265a67: INT3 ; original byte CC, padding

; FUNCTION thunk_265a68 [0x265a68, 0x265a6c] | file +0x348 | ev_a0b1537d4bc5be6705b058b5985864a5157864850b1bd21bf57c9b2325380cf6
thunk_265a68:
0x265a68: JMP 0x00ab9450
; END FUNCTION thunk_265a68
0x265a6d: INT3 ; original byte CC, padding
0x265a6e: INT3 ; original byte CC, padding
0x265a6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a70 [0x265a70, 0x265a74] | file +0x350 | ev_e362c6c038b8a2de4031260263b33b300becdbb2a86e2dc2d06b1a513f67a290
thunk_265a70:
0x265a70: JMP 0x00ab9710
; END FUNCTION thunk_265a70
0x265a75: INT3 ; original byte CC, padding
0x265a76: INT3 ; original byte CC, padding
0x265a77: INT3 ; original byte CC, padding

; FUNCTION thunk_265a78 [0x265a78, 0x265a7c] | file +0x358 | ev_495d3038041b1a058b06ff2e731663ea4085c3483dad60be8c277ec4650ae131
thunk_265a78:
0x265a78: JMP 0x008fa8e0
; END FUNCTION thunk_265a78
0x265a7d: INT3 ; original byte CC, padding
0x265a7e: INT3 ; original byte CC, padding
0x265a7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a80 [0x265a80, 0x265a84] | file +0x360 | ev_01494b260f43259ae66379dfaa4ec3220cf27d283f5fa293cc9016f999ef5a95
thunk_265a80:
0x265a80: JMP 0x004ee550
; END FUNCTION thunk_265a80
0x265a85: INT3 ; original byte CC, padding
0x265a86: INT3 ; original byte CC, padding
0x265a87: INT3 ; original byte CC, padding

; FUNCTION thunk_265a88 [0x265a88, 0x265a8c] | file +0x368 | ev_44497fb3e04c8f7d5d0ac5c7e05dd2da54ffa2c8543f7248613743fa2124e22e
thunk_265a88:
0x265a88: JMP 0x008fc810
; END FUNCTION thunk_265a88
0x265a8d: INT3 ; original byte CC, padding
0x265a8e: INT3 ; original byte CC, padding
0x265a8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a90 [0x265a90, 0x265a94] | file +0x370 | ev_9ae732fc69c6cc412b0330c58f2d0bb51a78ab4d537f32b719ec38209eac178a
thunk_265a90:
0x265a90: JMP 0x008fc820
; END FUNCTION thunk_265a90
0x265a95: INT3 ; original byte CC, padding
0x265a96: INT3 ; original byte CC, padding
0x265a97: INT3 ; original byte CC, padding

; FUNCTION thunk_265a98 [0x265a98, 0x265a9c] | file +0x378 | ev_703f3a9a7f45ff25eec1878f102b43f3b14214814250fb5f5c02f5bb7cae1c1b
thunk_265a98:
0x265a98: JMP 0x006bb670
; END FUNCTION thunk_265a98
0x265a9d: INT3 ; original byte CC, padding
0x265a9e: INT3 ; original byte CC, padding
0x265a9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265aa0 [0x265aa0, 0x265aa4] | file +0x380 | ev_74184725994ed2974629c910264ae0ce707c4aedf51a50f3a0ed2fdb4811bafd
thunk_265aa0:
0x265aa0: JMP 0x006bbd20
; END FUNCTION thunk_265aa0
0x265aa5: INT3 ; original byte CC, padding
0x265aa6: INT3 ; original byte CC, padding
0x265aa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265aa8 [0x265aa8, 0x265aac] | file +0x388 | ev_e9fefd27bc7e8195f87b57be11e34664c183dddbdafa1971b6354208ba73289c
thunk_265aa8:
0x265aa8: JMP 0x006bc030
; END FUNCTION thunk_265aa8
0x265aad: INT3 ; original byte CC, padding
0x265aae: INT3 ; original byte CC, padding
0x265aaf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ab0 [0x265ab0, 0x265ab4] | file +0x390 | ev_d6bb2d3864dfa8653d8b0a1a1a301a0ec61fc622efb8ed1a8c716a6616500d8c
thunk_265ab0:
0x265ab0: JMP 0x006bd570
; END FUNCTION thunk_265ab0
0x265ab5: INT3 ; original byte CC, padding
0x265ab6: INT3 ; original byte CC, padding
0x265ab7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ab8 [0x265ab8, 0x265abc] | file +0x398 | ev_da8086beb71b8289e8a89ced618b14099f0e550d9c8b00b77e86342eb26afc6b
thunk_265ab8:
0x265ab8: JMP 0x006bdfa0
; END FUNCTION thunk_265ab8
0x265abd: INT3 ; original byte CC, padding
0x265abe: INT3 ; original byte CC, padding
0x265abf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ac0 [0x265ac0, 0x265ac4] | file +0x3a0 | ev_a7a4b472e4d5050be1e8b517eb6b54f185b39ba3a423190aeff61c75a894d6a6
thunk_265ac0:
0x265ac0: JMP 0x006bdfb0
; END FUNCTION thunk_265ac0
0x265ac5: INT3 ; original byte CC, padding
0x265ac6: INT3 ; original byte CC, padding
0x265ac7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ac8 [0x265ac8, 0x265acc] | file +0x3a8 | ev_f5662ab849c8da53ecae1ad0eeaddb1df22fad5b85181d96d1a93b3c3137080b
thunk_265ac8:
0x265ac8: JMP 0x006be1d0
; END FUNCTION thunk_265ac8
0x265acd: INT3 ; original byte CC, padding
0x265ace: INT3 ; original byte CC, padding
0x265acf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ad0 [0x265ad0, 0x265ad4] | file +0x3b0 | ev_a83086b17cb41202f8a783e29293a14cf7083aef07c71243350a67baf6a55783
thunk_265ad0:
0x265ad0: JMP 0x006be370
; END FUNCTION thunk_265ad0
0x265ad5: INT3 ; original byte CC, padding
0x265ad6: INT3 ; original byte CC, padding
0x265ad7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ad8 [0x265ad8, 0x265adc] | file +0x3b8 | ev_8b313a4cd4e03d138294806bc1259185344520a276b48d244c4a89477c4c787c
thunk_265ad8:
0x265ad8: JMP 0x006bc4e0
; END FUNCTION thunk_265ad8
0x265add: INT3 ; original byte CC, padding
0x265ade: INT3 ; original byte CC, padding
0x265adf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ae0 [0x265ae0, 0x265ae4] | file +0x3c0 | ev_f30b4d187411d67d73401e1457f57a54727fc2e9e0ff00e7587ba82b85313d03
thunk_265ae0:
0x265ae0: JMP 0x00cb1ab0
; END FUNCTION thunk_265ae0
0x265ae5: INT3 ; original byte CC, padding
0x265ae6: INT3 ; original byte CC, padding
0x265ae7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ae8 [0x265ae8, 0x265aec] | file +0x3c8 | ev_afba907846997d56d0b1e5c1e415974c601de5cf6166c57a19b6f6715465b552
thunk_265ae8:
0x265ae8: JMP 0x008fc390
; END FUNCTION thunk_265ae8
0x265aed: INT3 ; original byte CC, padding
0x265aee: INT3 ; original byte CC, padding
0x265aef: INT3 ; original byte CC, padding

; FUNCTION thunk_265af0 [0x265af0, 0x265af4] | file +0x3d0 | ev_cd81f5026adc4e739b1631c6db8bc6dfcb618f6a8d7556dd3134662e421e165f
thunk_265af0:
0x265af0: JMP 0x004ec4e0
; END FUNCTION thunk_265af0
0x265af5: INT3 ; original byte CC, padding
0x265af6: INT3 ; original byte CC, padding
0x265af7: INT3 ; original byte CC, padding

; FUNCTION thunk_265af8 [0x265af8, 0x265afc] | file +0x3d8 | ev_3a07c8c9cac85f4902d53fd0bdeb88f36620f674b725f543cc5ddc1cfe02744f
thunk_265af8:
0x265af8: JMP 0x004ecc70
; END FUNCTION thunk_265af8
0x265afd: INT3 ; original byte CC, padding
0x265afe: INT3 ; original byte CC, padding
0x265aff: INT3 ; original byte CC, padding

; FUNCTION thunk_265b00 [0x265b00, 0x265b04] | file +0x3e0 | ev_3421d95e17cc4a1925878bcf237c85a181496eb13254fc09214051717e3bf956
thunk_265b00:
0x265b00: JMP 0x00b7e960
; END FUNCTION thunk_265b00
0x265b05: INT3 ; original byte CC, padding
0x265b06: INT3 ; original byte CC, padding
0x265b07: INT3 ; original byte CC, padding

; FUNCTION thunk_265b08 [0x265b08, 0x265b0c] | file +0x3e8 | ev_75fd94589e78a26fe265113c01ec72d5cc7b39e10c9ab4703526f635bb918b90
thunk_265b08:
0x265b08: JMP 0x00ab9580
; END FUNCTION thunk_265b08
0x265b0d: INT3 ; original byte CC, padding
0x265b0e: INT3 ; original byte CC, padding
0x265b0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b10 [0x265b10, 0x265b14] | file +0x3f0 | ev_af1b623e4e48ac4d33130b6c322bad5504b08c7fcfd69f2794de5fdd99e36ba2
thunk_265b10:
0x265b10: JMP 0x00ab9690
; END FUNCTION thunk_265b10
0x265b15: INT3 ; original byte CC, padding
0x265b16: INT3 ; original byte CC, padding
0x265b17: INT3 ; original byte CC, padding

; FUNCTION thunk_265b18 [0x265b18, 0x265b1c] | file +0x3f8 | ev_6f08de602f743b11af2a3ca81a92e66b4599a09ea231bf06d2b2b6b3b5eaaca6
thunk_265b18:
0x265b18: JMP 0x005a3a60
; END FUNCTION thunk_265b18
0x265b1d: INT3 ; original byte CC, padding
0x265b1e: INT3 ; original byte CC, padding
0x265b1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b20 [0x265b20, 0x265b24] | file +0x400 | ev_c564b04ab0134458f3ec21037b36c3c93539d25c908e0ad6ca22354547c06438
thunk_265b20:
0x265b20: JMP 0x005a3b50
; END FUNCTION thunk_265b20
0x265b25: INT3 ; original byte CC, padding
0x265b26: INT3 ; original byte CC, padding
0x265b27: INT3 ; original byte CC, padding

; FUNCTION thunk_265b28 [0x265b28, 0x265b2c] | file +0x408 | ev_5affb35aa9906b7dce9056179ac6876de7facd3be39c71c34d941337286ca5a6
thunk_265b28:
0x265b28: JMP 0x005a3c60
; END FUNCTION thunk_265b28
0x265b2d: INT3 ; original byte CC, padding
0x265b2e: INT3 ; original byte CC, padding
0x265b2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b30 [0x265b30, 0x265b34] | file +0x410 | ev_c7936173b4efa1a6af8d0aa07fef51e96aec939bed94b875ebdf5c5837764184
thunk_265b30:
0x265b30: JMP 0x005a3d80
; END FUNCTION thunk_265b30
0x265b35: INT3 ; original byte CC, padding
0x265b36: INT3 ; original byte CC, padding
0x265b37: INT3 ; original byte CC, padding

; FUNCTION thunk_265b38 [0x265b38, 0x265b3c] | file +0x418 | ev_0e76e0fad593dfb982ea3a62cc569e5ea657347adda0b8922d71b521086b1c2b
thunk_265b38:
0x265b38: JMP 0x005a3e70
; END FUNCTION thunk_265b38
0x265b3d: INT3 ; original byte CC, padding
0x265b3e: INT3 ; original byte CC, padding
0x265b3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b40 [0x265b40, 0x265b44] | file +0x420 | ev_f1fc0fe618834671b18566b6c97f93eb32d77f7ff6bc3a5c418a0488c6417721
thunk_265b40:
0x265b40: JMP 0x005a3e90
; END FUNCTION thunk_265b40
0x265b45: INT3 ; original byte CC, padding
0x265b46: INT3 ; original byte CC, padding
0x265b47: INT3 ; original byte CC, padding

; FUNCTION thunk_265b48 [0x265b48, 0x265b4c] | file +0x428 | ev_297e4ad1506e4fa588be7ffb3cc64d2c156a60c7398949f2861c53f18d5b17d2
thunk_265b48:
0x265b48: JMP 0x005a3ef0
; END FUNCTION thunk_265b48
0x265b4d: INT3 ; original byte CC, padding
0x265b4e: INT3 ; original byte CC, padding
0x265b4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b50 [0x265b50, 0x265b54] | file +0x430 | ev_957aacb527787eb0bbe4be89cd09cb9d646bdb0b0eef73532724401411d3f83f
thunk_265b50:
0x265b50: JMP 0x005a3f50
; END FUNCTION thunk_265b50
0x265b55: INT3 ; original byte CC, padding
0x265b56: INT3 ; original byte CC, padding
0x265b57: INT3 ; original byte CC, padding

; FUNCTION thunk_265b58 [0x265b58, 0x265b5c] | file +0x438 | ev_cdf8cfb3dbfa1c991b88c6fb6c622969311bf5929ddd06d485acb7358d3b157f
thunk_265b58:
0x265b58: JMP 0x0055ddc0
; END FUNCTION thunk_265b58
0x265b5d: INT3 ; original byte CC, padding
0x265b5e: INT3 ; original byte CC, padding
0x265b5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b60 [0x265b60, 0x265b64] | file +0x440 | ev_ff82123b8e6c256e78638c22fe7f10d74d0dfa36b00ec56cab6d9ea3a0aa3319
thunk_265b60:
0x265b60: JMP 0x0055ed70
; END FUNCTION thunk_265b60
0x265b65: INT3 ; original byte CC, padding
0x265b66: INT3 ; original byte CC, padding
0x265b67: INT3 ; original byte CC, padding

; FUNCTION thunk_265b68 [0x265b68, 0x265b6c] | file +0x448 | ev_741b6004488946980cd7fb46c8ac97d67f459efd27fe6f2f52fb1230a023caee
thunk_265b68:
0x265b68: JMP 0x0055ec90
; END FUNCTION thunk_265b68
0x265b6d: INT3 ; original byte CC, padding
0x265b6e: INT3 ; original byte CC, padding
0x265b6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b70 [0x265b70, 0x265b74] | file +0x450 | ev_a80907af4d4322c151a28c2e6b435566f63b91608759d6b7eed94f2c1d82e756
thunk_265b70:
0x265b70: JMP 0x0055e550
; END FUNCTION thunk_265b70
0x265b75: INT3 ; original byte CC, padding
0x265b76: INT3 ; original byte CC, padding
0x265b77: INT3 ; original byte CC, padding

; FUNCTION thunk_265b78 [0x265b78, 0x265b7c] | file +0x458 | ev_fdf4707818758567a82e30ec2143b122d38d08eb7ed927cd231371fdc7e00e94
thunk_265b78:
0x265b78: JMP 0x0055e680
; END FUNCTION thunk_265b78
0x265b7d: INT3 ; original byte CC, padding
0x265b7e: INT3 ; original byte CC, padding
0x265b7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b80 [0x265b80, 0x265b84] | file +0x460 | ev_799415689b58e85117b40d602cd6f0ae72c9367f920780d6dac67533b8fab27b
thunk_265b80:
0x265b80: JMP 0x00abbd80
; END FUNCTION thunk_265b80
0x265b85: INT3 ; original byte CC, padding
0x265b86: INT3 ; original byte CC, padding
0x265b87: INT3 ; original byte CC, padding

; FUNCTION thunk_265b88 [0x265b88, 0x265b8c] | file +0x468 | ev_f76ebe4feb3b350240ced19a248ba11b57b55594dfd79f35b9487d256cc6a04d
thunk_265b88:
0x265b88: JMP 0x008340e0
; END FUNCTION thunk_265b88
0x265b8d: INT3 ; original byte CC, padding
0x265b8e: INT3 ; original byte CC, padding
0x265b8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b90 [0x265b90, 0x265b94] | file +0x470 | ev_e804e814208779b292184c09528d5b06b191b5e662769ad648d37c00fa89bdff
thunk_265b90:
0x265b90: JMP 0x008f6120
; END FUNCTION thunk_265b90
0x265b95: INT3 ; original byte CC, padding
0x265b96: INT3 ; original byte CC, padding
0x265b97: INT3 ; original byte CC, padding

; FUNCTION thunk_265b98 [0x265b98, 0x265b9c] | file +0x478 | ev_8e023189980448d6df30dad824c60fca8197963af4cd274e52ca66e3592e2094
thunk_265b98:
0x265b98: JMP 0x00c42f00
; END FUNCTION thunk_265b98
0x265b9d: INT3 ; original byte CC, padding
0x265b9e: INT3 ; original byte CC, padding
0x265b9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ba0 [0x265ba0, 0x265ba4] | file +0x480 | ev_14db88a56f2d598b9fe53ff7e638f60ded442f1493152fa12749722dc00d28f1
thunk_265ba0:
0x265ba0: JMP 0x00c43010
; END FUNCTION thunk_265ba0
0x265ba5: INT3 ; original byte CC, padding
0x265ba6: INT3 ; original byte CC, padding
0x265ba7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ba8 [0x265ba8, 0x265bac] | file +0x488 | ev_32b9f7cf53a0920034e238f86f0960da31d0a690a74474aa4d053cbe623c8890
thunk_265ba8:
0x265ba8: JMP 0x00c43170
; END FUNCTION thunk_265ba8
0x265bad: INT3 ; original byte CC, padding
0x265bae: INT3 ; original byte CC, padding
0x265baf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bb0 [0x265bb0, 0x265bb4] | file +0x490 | ev_d4fef26238f87cdb8b610f00be41942cd7a349cc61e68316a81cb39b0b1c2fce
thunk_265bb0:
0x265bb0: JMP 0x00c434a0
; END FUNCTION thunk_265bb0
0x265bb5: INT3 ; original byte CC, padding
0x265bb6: INT3 ; original byte CC, padding
0x265bb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bb8 [0x265bb8, 0x265bbc] | file +0x498 | ev_4b8412f013e4a4161e3b194fda8f6cb9c414b2af1de1c4afbc24c0ea4644503e
thunk_265bb8:
0x265bb8: JMP 0x00c42760
; END FUNCTION thunk_265bb8
0x265bbd: INT3 ; original byte CC, padding
0x265bbe: INT3 ; original byte CC, padding
0x265bbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bc0 [0x265bc0, 0x265bc4] | file +0x4a0 | ev_542f037da7f8c1fbbbbe4388bc2a8965614ae5b299d19f951ab10f851c55470f
thunk_265bc0:
0x265bc0: JMP 0x00c42b90
; END FUNCTION thunk_265bc0
0x265bc5: INT3 ; original byte CC, padding
0x265bc6: INT3 ; original byte CC, padding
0x265bc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bc8 [0x265bc8, 0x265bcc] | file +0x4a8 | ev_2abf1503fb82f595215032a28e2b77328058162fd3991569beaaaa185103b9d0
thunk_265bc8:
0x265bc8: JMP 0x00c42bc0
; END FUNCTION thunk_265bc8
0x265bcd: INT3 ; original byte CC, padding
0x265bce: INT3 ; original byte CC, padding
0x265bcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bd0 [0x265bd0, 0x265bd4] | file +0x4b0 | ev_387932b9517a57a82c27fdbdcbf9e370a164e0a05fff89ca14b8746cdc73bab3
thunk_265bd0:
0x265bd0: JMP 0x00c434c0
; END FUNCTION thunk_265bd0
0x265bd5: INT3 ; original byte CC, padding
0x265bd6: INT3 ; original byte CC, padding
0x265bd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bd8 [0x265bd8, 0x265bdc] | file +0x4b8 | ev_26ee89d746438e99e644a6e16f3f2b9c9ff970be35a07e54a2046ea564c57865
thunk_265bd8:
0x265bd8: JMP 0x00c43620
; END FUNCTION thunk_265bd8
0x265bdd: INT3 ; original byte CC, padding
0x265bde: INT3 ; original byte CC, padding
0x265bdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265be0 [0x265be0, 0x265be4] | file +0x4c0 | ev_0d9cd2755c606972ae8da0395a90246782c03e5283edfa37f3d50fb9cae6a53a
thunk_265be0:
0x265be0: JMP 0x0055d0c0
; END FUNCTION thunk_265be0
0x265be5: INT3 ; original byte CC, padding
0x265be6: INT3 ; original byte CC, padding
0x265be7: INT3 ; original byte CC, padding

; FUNCTION thunk_265be8 [0x265be8, 0x265bec] | file +0x4c8 | ev_a8aa7da9f0f61c34383d7c33eac6c441db1c5fc2aa8b978bdcf95961ef7abd04
thunk_265be8:
0x265be8: JMP 0x00a07280
; END FUNCTION thunk_265be8
0x265bed: INT3 ; original byte CC, padding
0x265bee: INT3 ; original byte CC, padding
0x265bef: INT3 ; original byte CC, padding

; FUNCTION thunk_265bf0 [0x265bf0, 0x265bf4] | file +0x4d0 | ev_679c3d1f43637f11cd7695c288b451925ec6002f64d269f54c771928525841a5
thunk_265bf0:
0x265bf0: JMP 0x00c37860
; END FUNCTION thunk_265bf0
0x265bf5: INT3 ; original byte CC, padding
0x265bf6: INT3 ; original byte CC, padding
0x265bf7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bf8 [0x265bf8, 0x265bfc] | file +0x4d8 | ev_be190519692c8275063e286d6fffd6a64efe639bb6af22a923b4fd232f4105db
thunk_265bf8:
0x265bf8: JMP 0x00c37970
; END FUNCTION thunk_265bf8
0x265bfd: INT3 ; original byte CC, padding
0x265bfe: INT3 ; original byte CC, padding
0x265bff: INT3 ; original byte CC, padding

; FUNCTION thunk_265c00 [0x265c00, 0x265c04] | file +0x4e0 | ev_376b188e787a152b612ae47a3648a443bb8a8cfcaff267f96a1ec4874ac9450a
thunk_265c00:
0x265c00: JMP 0x00c37a20
; END FUNCTION thunk_265c00
0x265c05: INT3 ; original byte CC, padding
0x265c06: INT3 ; original byte CC, padding
0x265c07: INT3 ; original byte CC, padding

; FUNCTION thunk_265c08 [0x265c08, 0x265c0c] | file +0x4e8 | ev_f434a76a40f2b0300bd3a5e9385326262ff52dd8d7886dc762ba81360a2ddf87
thunk_265c08:
0x265c08: JMP 0x0055deb0
; END FUNCTION thunk_265c08
0x265c0d: INT3 ; original byte CC, padding
0x265c0e: INT3 ; original byte CC, padding
0x265c0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c10 [0x265c10, 0x265c14] | file +0x4f0 | ev_931e459cfa2bc89ce67e5db8224a8c392853e680b03a61f1c4b53790ccfef13e
thunk_265c10:
0x265c10: JMP 0x00437cf0
; END FUNCTION thunk_265c10
0x265c15: INT3 ; original byte CC, padding
0x265c16: INT3 ; original byte CC, padding
0x265c17: INT3 ; original byte CC, padding

; FUNCTION thunk_265c18 [0x265c18, 0x265c1c] | file +0x4f8 | ev_438aeee9179dc8a6bb52273c75cf0e13486940563f28b22cd10ca70617ffdc84
thunk_265c18:
0x265c18: JMP 0x004383f0
; END FUNCTION thunk_265c18
0x265c1d: INT3 ; original byte CC, padding
0x265c1e: INT3 ; original byte CC, padding
0x265c1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c20 [0x265c20, 0x265c24] | file +0x500 | ev_4c312f6e9064ce367f20897f87104b54edcf7a4040d829ac34ce64a41d5cccef
thunk_265c20:
0x265c20: JMP 0x004383c0
; END FUNCTION thunk_265c20
0x265c25: INT3 ; original byte CC, padding
0x265c26: INT3 ; original byte CC, padding
0x265c27: INT3 ; original byte CC, padding

; FUNCTION thunk_265c28 [0x265c28, 0x265c2c] | file +0x508 | ev_0ab289f3bd62320e6566baa85db7e1202ddfc9373809b3e3b041b9f8ffd735c7
thunk_265c28:
0x265c28: JMP 0x00438560
; END FUNCTION thunk_265c28
0x265c2d: INT3 ; original byte CC, padding
0x265c2e: INT3 ; original byte CC, padding
0x265c2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c30 [0x265c30, 0x265c34] | file +0x510 | ev_bb6054e8c6fb2f121bcafd7a5c5ec8cff8a0d4c62a9156a3ea7fba134abf1536
thunk_265c30:
0x265c30: JMP 0x00c433f0
; END FUNCTION thunk_265c30
0x265c35: INT3 ; original byte CC, padding
0x265c36: INT3 ; original byte CC, padding
0x265c37: INT3 ; original byte CC, padding

; FUNCTION thunk_265c38 [0x265c38, 0x265c3c] | file +0x518 | ev_1696320a0b23b1fbe9014e786637c3aa0ebe7eb95ac14323feb57d182773a829
thunk_265c38:
0x265c38: JMP 0x004388c0
; END FUNCTION thunk_265c38
0x265c3d: INT3 ; original byte CC, padding
0x265c3e: INT3 ; original byte CC, padding
0x265c3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c40 [0x265c40, 0x265c44] | file +0x520 | ev_91a591a481a2b0fa31e530f862c8de090450922e52945aee314f278a55712a96
thunk_265c40:
0x265c40: JMP 0x00438ab0
; END FUNCTION thunk_265c40
0x265c45: INT3 ; original byte CC, padding
0x265c46: INT3 ; original byte CC, padding
0x265c47: INT3 ; original byte CC, padding

; FUNCTION thunk_265c48 [0x265c48, 0x265c4c] | file +0x528 | ev_709ff95251ab30ee92ca67ec919accb694556039b483a052b3e048988602a70c
thunk_265c48:
0x265c48: JMP 0x00552c20
; END FUNCTION thunk_265c48
0x265c4d: INT3 ; original byte CC, padding
0x265c4e: INT3 ; original byte CC, padding
0x265c4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c50 [0x265c50, 0x265c54] | file +0x530 | ev_4eafb23dc2edda248c508804926a68aac0c3aea458e04a43c2944debfa602ca4
thunk_265c50:
0x265c50: JMP 0x00437de0
; END FUNCTION thunk_265c50
0x265c55: INT3 ; original byte CC, padding
0x265c56: INT3 ; original byte CC, padding
0x265c57: INT3 ; original byte CC, padding

; FUNCTION thunk_265c58 [0x265c58, 0x265c5c] | file +0x538 | ev_cc3a07b8d71a1d4520dc7a3471d16d389cb9a545dbea33c1f9ead630c8c24e8c
thunk_265c58:
0x265c58: JMP 0x0055fc20
; END FUNCTION thunk_265c58
0x265c5d: INT3 ; original byte CC, padding
0x265c5e: INT3 ; original byte CC, padding
0x265c5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c60 [0x265c60, 0x265c64] | file +0x540 | ev_a9da2e1f21296d36267a024dc9f6baa872bd760111b710b4e17e73fab083ee82
thunk_265c60:
0x265c60: JMP 0x00438b60
; END FUNCTION thunk_265c60
0x265c65: INT3 ; original byte CC, padding
0x265c66: INT3 ; original byte CC, padding
0x265c67: INT3 ; original byte CC, padding

; FUNCTION thunk_265c68 [0x265c68, 0x265c6c] | file +0x548 | ev_ade79c344fa8f9813a509184257a796302ce52c97d848f153069b605de1f1255
thunk_265c68:
0x265c68: JMP 0x004a0400
; END FUNCTION thunk_265c68
0x265c6d: INT3 ; original byte CC, padding
0x265c6e: INT3 ; original byte CC, padding
0x265c6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c70 [0x265c70, 0x265c74] | file +0x550 | ev_93839e631c81c2700fc2f343594258766f1e42358948e7d0d9f8d4bac559696a
thunk_265c70:
0x265c70: JMP 0x004ec120
; END FUNCTION thunk_265c70
0x265c75: INT3 ; original byte CC, padding
0x265c76: INT3 ; original byte CC, padding
0x265c77: INT3 ; original byte CC, padding

; FUNCTION thunk_265c78 [0x265c78, 0x265c7c] | file +0x558 | ev_10871a7c7ae092e887b02fb009ac16eb48ee7f55f6163c265dcb6fb32f10ebcd
thunk_265c78:
0x265c78: JMP 0x004ec740
; END FUNCTION thunk_265c78
0x265c7d: INT3 ; original byte CC, padding
0x265c7e: INT3 ; original byte CC, padding
0x265c7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c80 [0x265c80, 0x265c84] | file +0x560 | ev_0e11dae06b7985255741a13a2e75201ff96088ebbdc4cb6c011b2b4b9d93dddc
thunk_265c80:
0x265c80: JMP 0x00ab83c0
; END FUNCTION thunk_265c80
0x265c85: INT3 ; original byte CC, padding
0x265c86: INT3 ; original byte CC, padding
0x265c87: INT3 ; original byte CC, padding

; FUNCTION thunk_265c88 [0x265c88, 0x265c8c] | file +0x568 | ev_ca4309404d7e3f813e8c3bdf066f86347e96654cb670f2fc40c3d6f4e27ed389
thunk_265c88:
0x265c88: JMP 0x008f8ab0
; END FUNCTION thunk_265c88
0x265c8d: INT3 ; original byte CC, padding
0x265c8e: INT3 ; original byte CC, padding
0x265c8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c90 [0x265c90, 0x265c94] | file +0x570 | ev_bda1c7672eafac7c695ffd553b29b18e662a3681aa39f879c1bb0c52ae1c896d
thunk_265c90:
0x265c90: JMP 0x008fafa0
; END FUNCTION thunk_265c90
0x265c95: INT3 ; original byte CC, padding
0x265c96: INT3 ; original byte CC, padding
0x265c97: INT3 ; original byte CC, padding

; FUNCTION thunk_265c98 [0x265c98, 0x265c9c] | file +0x578 | ev_78454f2614f7a8c5aa0ce1cc9f62c1aa06794fd78c8d46cb05f945f619e752d6
thunk_265c98:
0x265c98: JMP 0x004ecf20
; END FUNCTION thunk_265c98
0x265c9d: INT3 ; original byte CC, padding
0x265c9e: INT3 ; original byte CC, padding
0x265c9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ca0 [0x265ca0, 0x265ca4] | file +0x580 | ev_260b63cf8aaa76d66b218e0f85b6398abb5808a76e2f61128df3ff7e757ecae0
thunk_265ca0:
0x265ca0: JMP 0x004386f0
; END FUNCTION thunk_265ca0
0x265ca5: INT3 ; original byte CC, padding
0x265ca6: INT3 ; original byte CC, padding
0x265ca7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ca8 [0x265ca8, 0x265cac] | file +0x588 | ev_ff272acd78e9f5676eecf4bdd04b9434bee5314e6ff5aa418a1d299d01201bb5
thunk_265ca8:
0x265ca8: JMP 0x0080d740
; END FUNCTION thunk_265ca8
0x265cad: INT3 ; original byte CC, padding
0x265cae: INT3 ; original byte CC, padding
0x265caf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cb0 [0x265cb0, 0x265cb4] | file +0x590 | ev_6f1a3bda27ebdb29a3f400241102983207b2bfad15583ecd4555d9330af029ed
thunk_265cb0:
0x265cb0: JMP 0x0080dbd0
; END FUNCTION thunk_265cb0
0x265cb5: INT3 ; original byte CC, padding
0x265cb6: INT3 ; original byte CC, padding
0x265cb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cb8 [0x265cb8, 0x265cbc] | file +0x598 | ev_e1fa139b401f6c9470b4fa81c12a54c9a5f32c84d99ca333038c5ed29ad90765
thunk_265cb8:
0x265cb8: JMP 0x0083d830
; END FUNCTION thunk_265cb8
0x265cbd: INT3 ; original byte CC, padding
0x265cbe: INT3 ; original byte CC, padding
0x265cbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cc0 [0x265cc0, 0x265cc4] | file +0x5a0 | ev_a8e7b48f6f0f8d93bd1602d0953c8af3f8fdd570ad0089e5fd0e55eab5ed37b8
thunk_265cc0:
0x265cc0: JMP 0x0083de60
; END FUNCTION thunk_265cc0
0x265cc5: INT3 ; original byte CC, padding
0x265cc6: INT3 ; original byte CC, padding
0x265cc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cc8 [0x265cc8, 0x265ccc] | file +0x5a8 | ev_88c2cc843bca285bfdccb1db75a05ab3b1a284ae03f9a895638b74e0eddca2ac
thunk_265cc8:
0x265cc8: JMP 0x0083e320
; END FUNCTION thunk_265cc8
0x265ccd: INT3 ; original byte CC, padding
0x265cce: INT3 ; original byte CC, padding
0x265ccf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cd0 [0x265cd0, 0x265cd4] | file +0x5b0 | ev_f750b507c4e2d19e5d98f168eeeb8418fecfabdb7a02fc8699620ec54d8bdb56
thunk_265cd0:
0x265cd0: JMP 0x008f6e50
; END FUNCTION thunk_265cd0
0x265cd5: INT3 ; original byte CC, padding
0x265cd6: INT3 ; original byte CC, padding
0x265cd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cd8 [0x265cd8, 0x265cdc] | file +0x5b8 | ev_6eeb7e7ddd34548c87c2bdde79cfe3f25d5b61dd128d96f044c33c798a9b1c6c
thunk_265cd8:
0x265cd8: JMP 0x0049b0b0
; END FUNCTION thunk_265cd8
0x265cdd: INT3 ; original byte CC, padding
0x265cde: INT3 ; original byte CC, padding
0x265cdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ce0 [0x265ce0, 0x265ce4] | file +0x5c0 | ev_955b59f34dcc82d326f8019b5a4ef7d192713861deb00f603f64834614e2f0db
thunk_265ce0:
0x265ce0: JMP 0x004ed3c0
; END FUNCTION thunk_265ce0
0x265ce5: INT3 ; original byte CC, padding
0x265ce6: INT3 ; original byte CC, padding
0x265ce7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ce8 [0x265ce8, 0x265cec] | file +0x5c8 | ev_ddd096685219d6ca376c0ace419e984924567abf06917bc2cdfb8084533d37cf
thunk_265ce8:
0x265ce8: JMP 0x00af0040
; END FUNCTION thunk_265ce8
0x265ced: INT3 ; original byte CC, padding
0x265cee: INT3 ; original byte CC, padding
0x265cef: INT3 ; original byte CC, padding

; FUNCTION thunk_265cf0 [0x265cf0, 0x265cf4] | file +0x5d0 | ev_eb3f8a47c49ea4c24498ce29ef78200d49662ce3715f6d19d2959697e1e145d3
thunk_265cf0:
0x265cf0: JMP 0x00705880
; END FUNCTION thunk_265cf0
0x265cf5: INT3 ; original byte CC, padding
0x265cf6: INT3 ; original byte CC, padding
0x265cf7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cf8 [0x265cf8, 0x265cfc] | file +0x5d8 | ev_11ce4b2a7e8dafd791795576150b7e1fbf7fc1d3e8daa84958e281d2f2f0500a
thunk_265cf8:
0x265cf8: JMP 0x00705c60
; END FUNCTION thunk_265cf8
0x265cfd: INT3 ; original byte CC, padding
0x265cfe: INT3 ; original byte CC, padding
0x265cff: INT3 ; original byte CC, padding

; FUNCTION thunk_265d00 [0x265d00, 0x265d04] | file +0x5e0 | ev_da3f4081ffd1cca782d99510df16611df388a87eebce2f5108c2fa7c8173b36a
thunk_265d00:
0x265d00: JMP 0x004f65f0
; END FUNCTION thunk_265d00
0x265d05: INT3 ; original byte CC, padding
0x265d06: INT3 ; original byte CC, padding
0x265d07: INT3 ; original byte CC, padding

; FUNCTION thunk_265d08 [0x265d08, 0x265d0c] | file +0x5e8 | ev_91f3053d25aad314c50b29f764dc1a5ac85bdd695d16fb9c87e18cc475c3e9f0
thunk_265d08:
0x265d08: JMP 0x004f6a70
; END FUNCTION thunk_265d08
0x265d0d: INT3 ; original byte CC, padding
0x265d0e: INT3 ; original byte CC, padding
0x265d0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d10 [0x265d10, 0x265d14] | file +0x5f0 | ev_141bedc32617e72efe65c1855a21c5bc10119939626978056e0e307ade7c92a3
thunk_265d10:
0x265d10: JMP 0x00bafa80
; END FUNCTION thunk_265d10
0x265d15: INT3 ; original byte CC, padding
0x265d16: INT3 ; original byte CC, padding
0x265d17: INT3 ; original byte CC, padding

; FUNCTION thunk_265d18 [0x265d18, 0x265d1c] | file +0x5f8 | ev_b24101c8493214775072a4b243b882c271212957cc7bac7568a9482b23581da1
thunk_265d18:
0x265d18: JMP 0x00bafcf0
; END FUNCTION thunk_265d18
0x265d1d: INT3 ; original byte CC, padding
0x265d1e: INT3 ; original byte CC, padding
0x265d1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d20 [0x265d20, 0x265d24] | file +0x600 | ev_3f2696dc3468757284ec2bbccc5407f8851ad569f6a2098b096e4c156360a8f2
thunk_265d20:
0x265d20: JMP 0x00bb0330
; END FUNCTION thunk_265d20
0x265d25: INT3 ; original byte CC, padding
0x265d26: INT3 ; original byte CC, padding
0x265d27: INT3 ; original byte CC, padding

; FUNCTION thunk_265d28 [0x265d28, 0x265d2c] | file +0x608 | ev_9e1a530419c38b63f1c5c7f52f378f12933697777c29a2da5b9ab03f35a25121
thunk_265d28:
0x265d28: JMP 0x00bb0490
; END FUNCTION thunk_265d28
0x265d2d: INT3 ; original byte CC, padding
0x265d2e: INT3 ; original byte CC, padding
0x265d2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d30 [0x265d30, 0x265d34] | file +0x610 | ev_017269beca73fffa4d0e24415f9e851d880f86cbab93db9eca9ee4b129e29848
thunk_265d30:
0x265d30: JMP 0x00bafe50
; END FUNCTION thunk_265d30
0x265d35: INT3 ; original byte CC, padding
0x265d36: INT3 ; original byte CC, padding
0x265d37: INT3 ; original byte CC, padding

; FUNCTION thunk_265d38 [0x265d38, 0x265d3c] | file +0x618 | ev_7e8aa0703fa40d1dc25c26b650facf9165e8413fb00e01a9cb67b371c16e4761
thunk_265d38:
0x265d38: JMP 0x00bb0030
; END FUNCTION thunk_265d38
0x265d3d: INT3 ; original byte CC, padding
0x265d3e: INT3 ; original byte CC, padding
0x265d3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d40 [0x265d40, 0x265d44] | file +0x620 | ev_c6bd5b3b4689c932c0734de76323ffb6e492cd71b7f45059a8ee63b1b8c956c9
thunk_265d40:
0x265d40: JMP 0x00bb0150
; END FUNCTION thunk_265d40
0x265d45: INT3 ; original byte CC, padding
0x265d46: INT3 ; original byte CC, padding
0x265d47: INT3 ; original byte CC, padding

; FUNCTION thunk_265d48 [0x265d48, 0x265d4c] | file +0x628 | ev_139615a2fdde2cf350858d9f99c761a3bffb85be8daeae5c86b4510bc7b09c47
thunk_265d48:
0x265d48: JMP 0x00bb01d0
; END FUNCTION thunk_265d48
0x265d4d: INT3 ; original byte CC, padding
0x265d4e: INT3 ; original byte CC, padding
0x265d4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d50 [0x265d50, 0x265d54] | file +0x630 | ev_8e719955e834476320223e8cef9d48b6df5226ae75bcb7e95f0b800f19159d18
thunk_265d50:
0x265d50: JMP 0x00bb0280
; END FUNCTION thunk_265d50
0x265d55: INT3 ; original byte CC, padding
0x265d56: INT3 ; original byte CC, padding
0x265d57: INT3 ; original byte CC, padding

; FUNCTION thunk_265d58 [0x265d58, 0x265d5c] | file +0x638 | ev_572d12d696e0f9e3cebbf9442f0836c3e6d0e75fa7911b310cd02e3443ebaddd
thunk_265d58:
0x265d58: JMP 0x00aba540
; END FUNCTION thunk_265d58
0x265d5d: INT3 ; original byte CC, padding
0x265d5e: INT3 ; original byte CC, padding
0x265d5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d60 [0x265d60, 0x265d64] | file +0x640 | ev_cd34b10aeff44368d17a22690ff8671d8217d50f3346247d9fa38371455636fe
thunk_265d60:
0x265d60: JMP 0x00abbe60
; END FUNCTION thunk_265d60
0x265d65: INT3 ; original byte CC, padding
0x265d66: INT3 ; original byte CC, padding
0x265d67: INT3 ; original byte CC, padding

; FUNCTION thunk_265d68 [0x265d68, 0x265d6c] | file +0x648 | ev_ee7d3692358008761769bce5e91ce6601167a43b7111c85cc4784ff8ad6d3bde
thunk_265d68:
0x265d68: JMP 0x00c16020
; END FUNCTION thunk_265d68
0x265d6d: INT3 ; original byte CC, padding
0x265d6e: INT3 ; original byte CC, padding
0x265d6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d70 [0x265d70, 0x265d74] | file +0x650 | ev_853d03a7b64b35632fb036feb750d9f78ec2536e8b530ba4ab6afc35d8f1d24d
thunk_265d70:
0x265d70: JMP 0x00c16270
; END FUNCTION thunk_265d70
0x265d75: INT3 ; original byte CC, padding
0x265d76: INT3 ; original byte CC, padding
0x265d77: INT3 ; original byte CC, padding

; FUNCTION thunk_265d78 [0x265d78, 0x265d7c] | file +0x658 | ev_470381e6a7ac04b89f9f77aa051e4885ac56ec195c7b436ac9ad7c5e0046851e
thunk_265d78:
0x265d78: JMP 0x00c16720
; END FUNCTION thunk_265d78
0x265d7d: INT3 ; original byte CC, padding
0x265d7e: INT3 ; original byte CC, padding
0x265d7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d80 [0x265d80, 0x265d84] | file +0x660 | ev_b3a359056b1cc38b9cfdd428c2a96dceba507535f64dfe81267ffcc5df21a579
thunk_265d80:
0x265d80: JMP 0x00c16880
; END FUNCTION thunk_265d80
0x265d85: INT3 ; original byte CC, padding
0x265d86: INT3 ; original byte CC, padding
0x265d87: INT3 ; original byte CC, padding

; FUNCTION thunk_265d88 [0x265d88, 0x265d8c] | file +0x668 | ev_cda830d9a5b4a90b869dad8f56aaf69560ea49a89ebde10424aa99d79655dcef
thunk_265d88:
0x265d88: JMP 0x00c163d0
; END FUNCTION thunk_265d88
0x265d8d: INT3 ; original byte CC, padding
0x265d8e: INT3 ; original byte CC, padding
0x265d8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d90 [0x265d90, 0x265d94] | file +0x670 | ev_4ea4d752366a09794902acd3fe0b4bd1ce883c98227d2b06608bfaf43c6cf3ac
thunk_265d90:
0x265d90: JMP 0x00c164f0
; END FUNCTION thunk_265d90
0x265d95: INT3 ; original byte CC, padding
0x265d96: INT3 ; original byte CC, padding
0x265d97: INT3 ; original byte CC, padding

; FUNCTION thunk_265d98 [0x265d98, 0x265d9c] | file +0x678 | ev_67145635d96053dc90aef304f72ee68efa38f57d726896667daf6347ff26cf97
thunk_265d98:
0x265d98: JMP 0x00c165d0
; END FUNCTION thunk_265d98
0x265d9d: INT3 ; original byte CC, padding
0x265d9e: INT3 ; original byte CC, padding
0x265d9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265da0 [0x265da0, 0x265da4] | file +0x680 | ev_b269cf020b1a2b49192d23123b900d40fdfd1262e814a7c11b1158bf584f301e
thunk_265da0:
0x265da0: JMP 0x00c16660
; END FUNCTION thunk_265da0
0x265da5: INT3 ; original byte CC, padding
0x265da6: INT3 ; original byte CC, padding
0x265da7: INT3 ; original byte CC, padding

; FUNCTION thunk_265da8 [0x265da8, 0x265dac] | file +0x688 | ev_8b66b6a15fdc1e32825941008d7389a84c5f3bfab207a8160af754f27c44ec26
thunk_265da8:
0x265da8: JMP 0x00ac7240
; END FUNCTION thunk_265da8
0x265dad: INT3 ; original byte CC, padding
0x265dae: INT3 ; original byte CC, padding
0x265daf: INT3 ; original byte CC, padding

; FUNCTION thunk_265db0 [0x265db0, 0x265db4] | file +0x690 | ev_caa1cbb55e05df95cb7a1c0ce004a24f59594389be3f808e779476ba59b0e12d
thunk_265db0:
0x265db0: JMP 0x00ac73c0
; END FUNCTION thunk_265db0
0x265db5: INT3 ; original byte CC, padding
0x265db6: INT3 ; original byte CC, padding
0x265db7: INT3 ; original byte CC, padding

; FUNCTION thunk_265db8 [0x265db8, 0x265dbc] | file +0x698 | ev_f72dc88d903f73c825320375b4c5b23400d62ed612ceea71d002d5806cc18bd5
thunk_265db8:
0x265db8: JMP 0x00abc510
; END FUNCTION thunk_265db8
0x265dbd: INT3 ; original byte CC, padding
0x265dbe: INT3 ; original byte CC, padding
0x265dbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265dc0 [0x265dc0, 0x265dc4] | file +0x6a0 | ev_df8ffb00941eaaf1b014b9d6c1debb830d74d4b57a56dfe8ab7727dd09742b59
thunk_265dc0:
0x265dc0: JMP 0x004f5e60
; END FUNCTION thunk_265dc0
0x265dc5: INT3 ; original byte CC, padding
0x265dc6: INT3 ; original byte CC, padding
0x265dc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265dc8 [0x265dc8, 0x265dcc] | file +0x6a8 | ev_b994f7e6a252748c518087af66f7152ad8d94eabf90061c7d242006164705cd4
thunk_265dc8:
0x265dc8: JMP 0x00602fe0
; END FUNCTION thunk_265dc8
0x265dcd: INT3 ; original byte CC, padding
0x265dce: INT3 ; original byte CC, padding
0x265dcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265dd0 [0x265dd0, 0x265dd4] | file +0x6b0 | ev_b9500ecd1e28f4f0264d22e68110cfb13a646405f1b50760c958118427d85260
thunk_265dd0:
0x265dd0: JMP 0x00603260
; END FUNCTION thunk_265dd0
0x265dd5: INT3 ; original byte CC, padding
0x265dd6: INT3 ; original byte CC, padding
0x265dd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265dd8 [0x265dd8, 0x265ddc] | file +0x6b8 | ev_7425e6bc0085d8c1456a00d22cd5d65cd23b05743dad6a46e24781fb3e860bda
thunk_265dd8:
0x265dd8: JMP 0x006034e0
; END FUNCTION thunk_265dd8
0x265ddd: INT3 ; original byte CC, padding
0x265dde: INT3 ; original byte CC, padding
0x265ddf: INT3 ; original byte CC, padding

; FUNCTION thunk_265de0 [0x265de0, 0x265de4] | file +0x6c0 | ev_c756130153707d47e6f24f71ad62949a6e53f64ef061495df5aa42fa423d1347
thunk_265de0:
0x265de0: JMP 0x00603710
; END FUNCTION thunk_265de0
0x265de5: INT3 ; original byte CC, padding
0x265de6: INT3 ; original byte CC, padding
0x265de7: INT3 ; original byte CC, padding

; FUNCTION thunk_265de8 [0x265de8, 0x265dec] | file +0x6c8 | ev_dd794267e63b1a5d75db5ef8f5a9ec6ac215c996345f89df19f48e44500dbd91
thunk_265de8:
0x265de8: JMP 0x006039d0
; END FUNCTION thunk_265de8
0x265ded: INT3 ; original byte CC, padding
0x265dee: INT3 ; original byte CC, padding
0x265def: INT3 ; original byte CC, padding

; FUNCTION thunk_265df0 [0x265df0, 0x265df4] | file +0x6d0 | ev_53445b4101b0607d7f53ee9f9b9f829a516dfcc063bd5e9678540b6141875405
thunk_265df0:
0x265df0: JMP 0x00abac50
; END FUNCTION thunk_265df0
0x265df5: INT3 ; original byte CC, padding
0x265df6: INT3 ; original byte CC, padding
0x265df7: INT3 ; original byte CC, padding

; FUNCTION thunk_265df8 [0x265df8, 0x265dfc] | file +0x6d8 | ev_9053ea6113d1fcbce07ea7bc6c773a1d6f872daaa256ef7f8d5d773b8df8a05f
thunk_265df8:
0x265df8: JMP 0x008fc610
; END FUNCTION thunk_265df8
0x265dfd: INT3 ; original byte CC, padding
0x265dfe: INT3 ; original byte CC, padding
0x265dff: INT3 ; original byte CC, padding

; FUNCTION thunk_265e00 [0x265e00, 0x265e04] | file +0x6e0 | ev_2d379c587a389af961b4e370bc502d7a019631a3244916178756499037519ad1
thunk_265e00:
0x265e00: JMP 0x004e1a70
; END FUNCTION thunk_265e00
0x265e05: INT3 ; original byte CC, padding
0x265e06: INT3 ; original byte CC, padding
0x265e07: INT3 ; original byte CC, padding

; FUNCTION thunk_265e08 [0x265e08, 0x265e0c] | file +0x6e8 | ev_722615ccce74c58107e60906b1e967da2cf0d8bcd78bf5b3a5b0de5a214caa92
thunk_265e08:
0x265e08: JMP 0x00abc5f0
; END FUNCTION thunk_265e08
0x265e0d: INT3 ; original byte CC, padding
0x265e0e: INT3 ; original byte CC, padding
0x265e0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e10 [0x265e10, 0x265e14] | file +0x6f0 | ev_37aca5cf7d1c28c8bf849e9f04e45dfb04b41d726aaf5258a5d30105bdb04598
thunk_265e10:
0x265e10: JMP 0x00a367e0
; END FUNCTION thunk_265e10
0x265e15: INT3 ; original byte CC, padding
0x265e16: INT3 ; original byte CC, padding
0x265e17: INT3 ; original byte CC, padding

; FUNCTION thunk_265e18 [0x265e18, 0x265e1c] | file +0x6f8 | ev_43884718e58292c832ea8a998b28d3eebdf76b31de0e8e8b295848bcb18f19c2
thunk_265e18:
0x265e18: JMP 0x00ca0630
; END FUNCTION thunk_265e18
0x265e1d: INT3 ; original byte CC, padding
0x265e1e: INT3 ; original byte CC, padding
0x265e1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e20 [0x265e20, 0x265e24] | file +0x700 | ev_d1bafefb5ca66c2b59f724e32941436f01a1d668cb2dcf44bb98e501c91513bb
thunk_265e20:
0x265e20: JMP 0x00a368e0
; END FUNCTION thunk_265e20
0x265e25: INT3 ; original byte CC, padding
0x265e26: INT3 ; original byte CC, padding
0x265e27: INT3 ; original byte CC, padding

; FUNCTION thunk_265e28 [0x265e28, 0x265e2c] | file +0x708 | ev_76740d04bd0fa44e04809a29e736e4d4de8c1aa42303e07fba3012a1ad03f667
thunk_265e28:
0x265e28: JMP 0x0072ecc0
; END FUNCTION thunk_265e28
0x265e2d: INT3 ; original byte CC, padding
0x265e2e: INT3 ; original byte CC, padding
0x265e2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e30 [0x265e30, 0x265e34] | file +0x710 | ev_5b470392df3096545b35171d8830430e529dc2885ed7fd63673b636ec696f9f9
thunk_265e30:
0x265e30: JMP 0x004f7370
; END FUNCTION thunk_265e30
0x265e35: INT3 ; original byte CC, padding
0x265e36: INT3 ; original byte CC, padding
0x265e37: INT3 ; original byte CC, padding

; FUNCTION thunk_265e38 [0x265e38, 0x265e3c] | file +0x718 | ev_6f9f1ce71e9ea4c394db6586515d83d76fa68b271bc3da58988e7910cbc2fb54
thunk_265e38:
0x265e38: JMP 0x00a36b00
; END FUNCTION thunk_265e38
0x265e3d: INT3 ; original byte CC, padding
0x265e3e: INT3 ; original byte CC, padding
0x265e3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e40 [0x265e40, 0x265e44] | file +0x720 | ev_ef143793367f3451c5a8e0bdc8eb37f1f6c13b48c2e7c0e098d30077555b904d
thunk_265e40:
0x265e40: JMP 0x00a36b90
; END FUNCTION thunk_265e40
0x265e45: INT3 ; original byte CC, padding
0x265e46: INT3 ; original byte CC, padding
0x265e47: INT3 ; original byte CC, padding

; FUNCTION thunk_265e48 [0x265e48, 0x265e4c] | file +0x728 | ev_2f42ab8d4c7f316be09068c535ab8450158592cf54991840e19304610d5a1d07
thunk_265e48:
0x265e48: JMP 0x00abc710
; END FUNCTION thunk_265e48
0x265e4d: INT3 ; original byte CC, padding
0x265e4e: INT3 ; original byte CC, padding
0x265e4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e50 [0x265e50, 0x265e54] | file +0x730 | ev_85c7b01fc12753dce03c87eee1509d51a78a63de5f53132f6e6614707b3c8db5
thunk_265e50:
0x265e50: JMP 0x005a7f60
; END FUNCTION thunk_265e50
0x265e55: INT3 ; original byte CC, padding
0x265e56: INT3 ; original byte CC, padding
0x265e57: INT3 ; original byte CC, padding

; FUNCTION thunk_265e58 [0x265e58, 0x265e5c] | file +0x738 | ev_df8ea304f646c11a583b14aae4ca1a483f4782e1e9354dce034d074761991e9d
thunk_265e58:
0x265e58: JMP 0x00a36bc0
; END FUNCTION thunk_265e58
0x265e5d: INT3 ; original byte CC, padding
0x265e5e: INT3 ; original byte CC, padding
0x265e5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e60 [0x265e60, 0x265e64] | file +0x740 | ev_6198524f60231153a0e06f7b2780b66fc77694781b03b7891c043a5d885ab756
thunk_265e60:
0x265e60: JMP 0x00abca10
; END FUNCTION thunk_265e60
0x265e65: INT3 ; original byte CC, padding
0x265e66: INT3 ; original byte CC, padding
0x265e67: INT3 ; original byte CC, padding

; FUNCTION thunk_265e68 [0x265e68, 0x265e6c] | file +0x748 | ev_8623a41ef8f18a1433f4d8d8d8c4ae56a20bc22464b1afdd5e3060271c537bb3
thunk_265e68:
0x265e68: JMP 0x00abcc00
; END FUNCTION thunk_265e68
0x265e6d: INT3 ; original byte CC, padding
0x265e6e: INT3 ; original byte CC, padding
0x265e6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e70 [0x265e70, 0x265e74] | file +0x750 | ev_4b8b732890c7585fee162dd206d6db0bca27e0c19731e4fc6697ccd7f847c1bf
thunk_265e70:
0x265e70: JMP 0x00438c90
; END FUNCTION thunk_265e70
0x265e75: INT3 ; original byte CC, padding
0x265e76: INT3 ; original byte CC, padding
0x265e77: INT3 ; original byte CC, padding

; FUNCTION thunk_265e78 [0x265e78, 0x265e7c] | file +0x758 | ev_1768279b2851f65325ade262735a2b5161d0b00c0cb0153a8119e17cfac138e3
thunk_265e78:
0x265e78: JMP 0x008d2570
; END FUNCTION thunk_265e78
0x265e7d: INT3 ; original byte CC, padding
0x265e7e: INT3 ; original byte CC, padding
0x265e7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e80 [0x265e80, 0x265e84] | file +0x760 | ev_4d0dc7aa1e73570e5e303d05b62b42265a0a127393c36cc0ffb723f7e92ae586
thunk_265e80:
0x265e80: JMP 0x00abd0f0
; END FUNCTION thunk_265e80
0x265e85: INT3 ; original byte CC, padding
0x265e86: INT3 ; original byte CC, padding
0x265e87: INT3 ; original byte CC, padding

; FUNCTION thunk_265e88 [0x265e88, 0x265e8c] | file +0x768 | ev_327b227bd6c213499654b0860aa855d48da53a03261343aaf271ac55682e0e1b
thunk_265e88:
0x265e88: JMP 0x00a37650
; END FUNCTION thunk_265e88
0x265e8d: INT3 ; original byte CC, padding
0x265e8e: INT3 ; original byte CC, padding
0x265e8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e90 [0x265e90, 0x265e94] | file +0x770 | ev_c570d0bb05504dfdb65b965e7ab8343f01e31ce22848c7beb6085619a0f039d1
thunk_265e90:
0x265e90: JMP 0x00abd430
; END FUNCTION thunk_265e90
0x265e95: INT3 ; original byte CC, padding
0x265e96: INT3 ; original byte CC, padding
0x265e97: INT3 ; original byte CC, padding

; FUNCTION thunk_265e98 [0x265e98, 0x265e9c] | file +0x778 | ev_9f8fcd7e7582e90f4ae8d10d3700626945970635f835f002c08ae61b8aef4e2c
thunk_265e98:
0x265e98: JMP 0x007dcd40
; END FUNCTION thunk_265e98
0x265e9d: INT3 ; original byte CC, padding
0x265e9e: INT3 ; original byte CC, padding
0x265e9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ea0 [0x265ea0, 0x265ea4] | file +0x780 | ev_5d32621c61a283e9ed381e98bbdc04f8f8e60e693addd2854e40ea89656581d7
thunk_265ea0:
0x265ea0: JMP 0x008d25a0
; END FUNCTION thunk_265ea0
0x265ea5: INT3 ; original byte CC, padding
0x265ea6: INT3 ; original byte CC, padding
0x265ea7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ea8 [0x265ea8, 0x265eac] | file +0x788 | ev_581d77043fca64b9008dbb77b35ef67701738522ff4a29c87647c8175679d453
thunk_265ea8:
0x265ea8: JMP 0x00abd4f0
; END FUNCTION thunk_265ea8
0x265ead: INT3 ; original byte CC, padding
0x265eae: INT3 ; original byte CC, padding
0x265eaf: INT3 ; original byte CC, padding

; FUNCTION thunk_265eb0 [0x265eb0, 0x265eb4] | file +0x790 | ev_98633b69352d8d9e092c2f8a57ed6c394087995b60f18753830b9031469b16fb
thunk_265eb0:
0x265eb0: JMP 0x00603c90
; END FUNCTION thunk_265eb0
0x265eb5: INT3 ; original byte CC, padding
0x265eb6: INT3 ; original byte CC, padding
0x265eb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265eb8 [0x265eb8, 0x265ebc] | file +0x798 | ev_cab9ba7fa07157798e9f5cadc43dcf8c8285cfde5e57ed64baa9330bdb4b3364
thunk_265eb8:
0x265eb8: JMP 0x00604cf0
; END FUNCTION thunk_265eb8
0x265ebd: INT3 ; original byte CC, padding
0x265ebe: INT3 ; original byte CC, padding
0x265ebf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ec0 [0x265ec0, 0x265ec4] | file +0x7a0 | ev_cac1613c2427686035e9e95ee09e19b96ec40c6b3c8b1ebaece49035e0658fe3
thunk_265ec0:
0x265ec0: JMP 0x004a2850
; END FUNCTION thunk_265ec0
0x265ec5: INT3 ; original byte CC, padding
0x265ec6: INT3 ; original byte CC, padding
0x265ec7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ec8 [0x265ec8, 0x265ecc] | file +0x7a8 | ev_b54802e9cb78880b4fcd87bbbf1e79334bfe9d710c70defaf9d16dcf467d49e5
thunk_265ec8:
0x265ec8: JMP 0x00abd540
; END FUNCTION thunk_265ec8
0x265ecd: INT3 ; original byte CC, padding
0x265ece: INT3 ; original byte CC, padding
0x265ecf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ed0 [0x265ed0, 0x265ed4] | file +0x7b0 | ev_b4dff738d0aa6573e8ba8ee944a868d36f40233c03506de9cd019889e249d2ae
thunk_265ed0:
0x265ed0: JMP 0x0091c640
; END FUNCTION thunk_265ed0
0x265ed5: INT3 ; original byte CC, padding
0x265ed6: INT3 ; original byte CC, padding
0x265ed7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ed8 [0x265ed8, 0x265edc] | file +0x7b8 | ev_2ca4a5aae0e3cb568cb359f5a033eb6c099fe6e02d90047fe6e63bfdb4e4e39a
thunk_265ed8:
0x265ed8: JMP 0x0091cc70
; END FUNCTION thunk_265ed8
0x265edd: INT3 ; original byte CC, padding
0x265ede: INT3 ; original byte CC, padding
0x265edf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ee0 [0x265ee0, 0x265ee4] | file +0x7c0 | ev_d6cb9b9d3c6df35bf074ba1290f1451b1704e84cbd4f89e4635d0a2f9a7f33cf
thunk_265ee0:
0x265ee0: JMP 0x00438e30
; END FUNCTION thunk_265ee0
0x265ee5: INT3 ; original byte CC, padding
0x265ee6: INT3 ; original byte CC, padding
0x265ee7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ee8 [0x265ee8, 0x265eec] | file +0x7c8 | ev_17e3eae79b71b98f1e0494ebf42f465c42d9d98f8fe67f6e80e7a8148ca93d38
thunk_265ee8:
0x265ee8: JMP 0x00439070
; END FUNCTION thunk_265ee8
0x265eed: INT3 ; original byte CC, padding
0x265eee: INT3 ; original byte CC, padding
0x265eef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ef0 [0x265ef0, 0x265ef4] | file +0x7d0 | ev_3d7f77fcd4287dd192f950799646d851d1d0457ce890de81f01f63e41251b5ee
thunk_265ef0:
0x265ef0: JMP 0x00439150
; END FUNCTION thunk_265ef0
0x265ef5: INT3 ; original byte CC, padding
0x265ef6: INT3 ; original byte CC, padding
0x265ef7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ef8 [0x265ef8, 0x265efc] | file +0x7d8 | ev_a4235e90b5a1ccc8ef061ee289bbbd9ef9237b96b7d7228147c2913d89618ad1
thunk_265ef8:
0x265ef8: JMP 0x004393a0
; END FUNCTION thunk_265ef8
0x265efd: INT3 ; original byte CC, padding
0x265efe: INT3 ; original byte CC, padding
0x265eff: INT3 ; original byte CC, padding

; FUNCTION thunk_265f00 [0x265f00, 0x265f04] | file +0x7e0 | ev_23d77d4e06bbb9201cb88289fdc0b83e75b775d8a447532847bc445292f7ab97
thunk_265f00:
0x265f00: JMP 0x006be4d0
; END FUNCTION thunk_265f00
0x265f05: INT3 ; original byte CC, padding
0x265f06: INT3 ; original byte CC, padding
0x265f07: INT3 ; original byte CC, padding

; FUNCTION thunk_265f08 [0x265f08, 0x265f0c] | file +0x7e8 | ev_4a3d68654cb86cabcd329a43c71f0fce03f29fb5842108f0b2d34544c0e9902d
thunk_265f08:
0x265f08: JMP 0x00abd930
; END FUNCTION thunk_265f08
0x265f0d: INT3 ; original byte CC, padding
0x265f0e: INT3 ; original byte CC, padding
0x265f0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f10 [0x265f10, 0x265f14] | file +0x7f0 | ev_660c54ded613992dab25244ea16008eaafa9d5e79b9cf48de63fec28375f1716
thunk_265f10:
0x265f10: JMP 0x006be5c0
; END FUNCTION thunk_265f10
0x265f15: INT3 ; original byte CC, padding
0x265f16: INT3 ; original byte CC, padding
0x265f17: INT3 ; original byte CC, padding

; FUNCTION thunk_265f18 [0x265f18, 0x265f1c] | file +0x7f8 | ev_15b54fa76534d52deb873287223794be86b404d5facfe580439958524b83ae50
thunk_265f18:
0x265f18: JMP 0x006be800
; END FUNCTION thunk_265f18
0x265f1d: INT3 ; original byte CC, padding
0x265f1e: INT3 ; original byte CC, padding
0x265f1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f20 [0x265f20, 0x265f24] | file +0x800 | ev_afc3f4e0d4ec43c8cc6a116e19a7e52381c8ef5e786ddb343a6f23efaab97fda
thunk_265f20:
0x265f20: JMP 0x00a90e10
; END FUNCTION thunk_265f20
0x265f25: INT3 ; original byte CC, padding
0x265f26: INT3 ; original byte CC, padding
0x265f27: INT3 ; original byte CC, padding

; FUNCTION thunk_265f28 [0x265f28, 0x265f2c] | file +0x808 | ev_9554eb5c1b3cacc00bfb98e60ea7963298dc3f5f36e79f3bc6a971a0cf819738
thunk_265f28:
0x265f28: JMP 0x004a2de0
; END FUNCTION thunk_265f28
0x265f2d: INT3 ; original byte CC, padding
0x265f2e: INT3 ; original byte CC, padding
0x265f2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f30 [0x265f30, 0x265f34] | file +0x810 | ev_166a9b8a86592e83f4fb0f60fcac35a44507e80e51f768c7d42f07b667cfdb97
thunk_265f30:
0x265f30: JMP 0x00abdad0
; END FUNCTION thunk_265f30
0x265f35: INT3 ; original byte CC, padding
0x265f36: INT3 ; original byte CC, padding
0x265f37: INT3 ; original byte CC, padding

; FUNCTION thunk_265f38 [0x265f38, 0x265f3c] | file +0x818 | ev_9d6132a5187a9c01a46635876dc1bcee476c5ffc93037fc4a301ce043d948ba3
thunk_265f38:
0x265f38: JMP 0x00a37660
; END FUNCTION thunk_265f38
0x265f3d: INT3 ; original byte CC, padding
0x265f3e: INT3 ; original byte CC, padding
0x265f3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f40 [0x265f40, 0x265f44] | file +0x820 | ev_3d107f6f1eaf2f4090a9431586134de3e3b751f954de14e4d0a0f6bf88ce19b3
thunk_265f40:
0x265f40: JMP 0x00abe1c0
; END FUNCTION thunk_265f40
0x265f45: INT3 ; original byte CC, padding
0x265f46: INT3 ; original byte CC, padding
0x265f47: INT3 ; original byte CC, padding

; FUNCTION thunk_265f48 [0x265f48, 0x265f4c] | file +0x828 | ev_90e30bd2294293ce2a3416705c0cd745a1d6ba504f8bf45f007ccdacd3dfae05
thunk_265f48:
0x265f48: JMP 0x00abe7b0
; END FUNCTION thunk_265f48
0x265f4d: INT3 ; original byte CC, padding
0x265f4e: INT3 ; original byte CC, padding
0x265f4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f50 [0x265f50, 0x265f54] | file +0x830 | ev_7a6c201331064d4f27c60fe9598670d33c09a953fe0624a08f78c3e1d95d47ae
thunk_265f50:
0x265f50: JMP 0x009f81f0
; END FUNCTION thunk_265f50
0x265f55: INT3 ; original byte CC, padding
0x265f56: INT3 ; original byte CC, padding
0x265f57: INT3 ; original byte CC, padding

; FUNCTION thunk_265f58 [0x265f58, 0x265f5c] | file +0x838 | ev_a1eb78dbbdea733c5de2d066d4df609278988e5e0cd5eb75ce20ed31a730dfcc
thunk_265f58:
0x265f58: JMP 0x00be9510
; END FUNCTION thunk_265f58
0x265f5d: INT3 ; original byte CC, padding
0x265f5e: INT3 ; original byte CC, padding
0x265f5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f60 [0x265f60, 0x265f64] | file +0x840 | ev_3ce5dde8008e04c265e5bf4d50b808fd7dde164f1b953bc506e8957fea941364
thunk_265f60:
0x265f60: JMP 0x009a7d10
; END FUNCTION thunk_265f60
0x265f65: INT3 ; original byte CC, padding
0x265f66: INT3 ; original byte CC, padding
0x265f67: INT3 ; original byte CC, padding

; FUNCTION thunk_265f68 [0x265f68, 0x265f6c] | file +0x848 | ev_30fb1503914bfcc9ed442526904c06863c13c21f71c813cb207a809a8b26e288
thunk_265f68:
0x265f68: JMP 0x009a9560
; END FUNCTION thunk_265f68
0x265f6d: INT3 ; original byte CC, padding
0x265f6e: INT3 ; original byte CC, padding
0x265f6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f70 [0x265f70, 0x265f74] | file +0x850 | ev_5a722f62fadb8a29429713bcc4bb02986a139904c60356d3956a39654cd442c6
thunk_265f70:
0x265f70: JMP 0x009a9e10
; END FUNCTION thunk_265f70
0x265f75: INT3 ; original byte CC, padding
0x265f76: INT3 ; original byte CC, padding
0x265f77: INT3 ; original byte CC, padding

; FUNCTION thunk_265f78 [0x265f78, 0x265f7c] | file +0x858 | ev_bcf43827b5c2e17a463acbcf525c45f60b468982552d619865a6bfe7665a37ba
thunk_265f78:
0x265f78: JMP 0x009a9f40
; END FUNCTION thunk_265f78
0x265f7d: INT3 ; original byte CC, padding
0x265f7e: INT3 ; original byte CC, padding
0x265f7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f80 [0x265f80, 0x265f84] | file +0x860 | ev_dd33df4d2f9001ee6ac780697739b18182526436a92e50b0414b4999641f292f
thunk_265f80:
0x265f80: JMP 0x008fb440
; END FUNCTION thunk_265f80
0x265f85: INT3 ; original byte CC, padding
0x265f86: INT3 ; original byte CC, padding
0x265f87: INT3 ; original byte CC, padding

; FUNCTION thunk_265f88 [0x265f88, 0x265f8c] | file +0x868 | ev_ba2dc3f034d56072bd875df79ad909a59c7c7208e8624ef6ffed97aa89dffa93
thunk_265f88:
0x265f88: JMP 0x004a31a0
; END FUNCTION thunk_265f88
0x265f8d: INT3 ; original byte CC, padding
0x265f8e: INT3 ; original byte CC, padding
0x265f8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f90 [0x265f90, 0x265f94] | file +0x870 | ev_095469638dfbce825802a80d7715201dbce0a7c679a97b6a1a02cf82121354f8
thunk_265f90:
0x265f90: JMP 0x00abe8b0
; END FUNCTION thunk_265f90
0x265f95: INT3 ; original byte CC, padding
0x265f96: INT3 ; original byte CC, padding
0x265f97: INT3 ; original byte CC, padding

; FUNCTION thunk_265f98 [0x265f98, 0x265f9c] | file +0x878 | ev_fb01c7296a796c2556b1d847b82e434772757b61df9e17d6c416e7579607cada
thunk_265f98:
0x265f98: JMP 0x009ab1f0
; END FUNCTION thunk_265f98
0x265f9d: INT3 ; original byte CC, padding
0x265f9e: INT3 ; original byte CC, padding
0x265f9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa0 [0x265fa0, 0x265fa4] | file +0x880 | ev_a2e5f09fdea58579b0b34f882641d1c11784819e6375326f32636cf81033081a
thunk_265fa0:
0x265fa0: JMP 0x00abb980
; END FUNCTION thunk_265fa0
0x265fa5: INT3 ; original byte CC, padding
0x265fa6: INT3 ; original byte CC, padding
0x265fa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa8 [0x265fa8, 0x265fac] | file +0x888 | ev_007d1966682d3fb2830ab3ff5fd5f30a8b0c7a994a7cf0ab704ace1290990328
thunk_265fa8:
0x265fa8: JMP 0x006f92e0
; END FUNCTION thunk_265fa8
0x265fad: INT3 ; original byte CC, padding
0x265fae: INT3 ; original byte CC, padding
0x265faf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb0 [0x265fb0, 0x265fb4] | file +0x890 | ev_b5e3fe99e245a1f4fcac38bb44ae8ede96ce62ba89baa6e030602ac74cd4e2aa
thunk_265fb0:
0x265fb0: JMP 0x00434da0
; END FUNCTION thunk_265fb0
0x265fb5: INT3 ; original byte CC, padding
0x265fb6: INT3 ; original byte CC, padding
0x265fb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb8 [0x265fb8, 0x265fbc] | file +0x898 | ev_7672c80ba3199670ff9accf5f0a035019deb6746b16a3408477b03c96a6c5a59
thunk_265fb8:
0x265fb8: JMP 0x00434db0
; END FUNCTION thunk_265fb8
0x265fbd: INT3 ; original byte CC, padding
0x265fbe: INT3 ; original byte CC, padding
0x265fbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc0 [0x265fc0, 0x265fc4] | file +0x8a0 | ev_8e2240493a12bdc4b99dadf1ed7df42990082653e92f2ff14062831045d343e0
thunk_265fc0:
0x265fc0: JMP 0x00434dc0
; END FUNCTION thunk_265fc0
0x265fc5: INT3 ; original byte CC, padding
0x265fc6: INT3 ; original byte CC, padding
0x265fc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc8 [0x265fc8, 0x265fcc] | file +0x8a8 | ev_5bc36022326d27a478db45be2056e64d81fcc7129c079daca457659d2408596e
thunk_265fc8:
0x265fc8: JMP 0x00437d90
; END FUNCTION thunk_265fc8
0x265fcd: INT3 ; original byte CC, padding
0x265fce: INT3 ; original byte CC, padding
0x265fcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd0 [0x265fd0, 0x265fd4] | file +0x8b0 | ev_085d5e1e35ff8b5e66880ad7c2e04e4467175a4f31f04ebb7d9393cf13d3f1b3
thunk_265fd0:
0x265fd0: JMP 0x00438280
; END FUNCTION thunk_265fd0
0x265fd5: INT3 ; original byte CC, padding
0x265fd6: INT3 ; original byte CC, padding
0x265fd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd8 [0x265fd8, 0x265fdc] | file +0x8b8 | ev_4c12611f4973bb95e6930c4a8e7ef5dbbee03d57b570547f98eb8d209fab5390
thunk_265fd8:
0x265fd8: JMP 0x00ae6690
; END FUNCTION thunk_265fd8
0x265fdd: INT3 ; original byte CC, padding
0x265fde: INT3 ; original byte CC, padding
0x265fdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe0 [0x265fe0, 0x265fe4] | file +0x8c0 | ev_bf6dcc0bad4786ad10277760d33efbdb7edba577f48cb79630de67009f81ffcf
thunk_265fe0:
0x265fe0: JMP 0x00ae6580
; END FUNCTION thunk_265fe0
0x265fe5: INT3 ; original byte CC, padding
0x265fe6: INT3 ; original byte CC, padding
0x265fe7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe8 [0x265fe8, 0x265fec] | file +0x8c8 | ev_71ecfb830571598653e281d3aff5b493d821d784e85e4c6587c26283338629ed
thunk_265fe8:
0x265fe8: JMP 0x004490d0
; END FUNCTION thunk_265fe8
0x265fed: INT3 ; original byte CC, padding
0x265fee: INT3 ; original byte CC, padding
0x265fef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff0 [0x265ff0, 0x265ff4] | file +0x8d0 | ev_20d51f9828264b13131e9cc56afd8f93012bd4f3f0874f592b9469011c13f2d0
thunk_265ff0:
0x265ff0: JMP 0x000a6dc0
; END FUNCTION thunk_265ff0
0x265ff5: INT3 ; original byte CC, padding
0x265ff6: INT3 ; original byte CC, padding
0x265ff7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff8 [0x265ff8, 0x265ffc] | file +0x8d8 | ev_beeb742ebbf9feeea40159b7e4e9da77f11e0cb72de20fa239ab2205a287db21
thunk_265ff8:
0x265ff8: JMP 0x0044aa70
; END FUNCTION thunk_265ff8
0x265ffd: INT3 ; original byte CC, padding
0x265ffe: INT3 ; original byte CC, padding
0x265fff: INT3 ; original byte CC, padding

; FUNCTION thunk_266000 [0x266000, 0x266004] | file +0x8e0 | ev_13271d488428427b098ed29297bd6f0d51a9592c4538b98664e46709e6fc2237
thunk_266000:
0x266000: JMP 0x009b6110
; END FUNCTION thunk_266000
0x266005: INT3 ; original byte CC, padding
0x266006: INT3 ; original byte CC, padding
0x266007: INT3 ; original byte CC, padding

; FUNCTION thunk_266008 [0x266008, 0x26600c] | file +0x8e8 | ev_75bd3fb8ec5fe183e20e5f97247dd25019c7d16cd04af1302ee4213661395ea0
thunk_266008:
0x266008: JMP 0x000a7670
; END FUNCTION thunk_266008
0x26600d: INT3 ; original byte CC, padding
0x26600e: INT3 ; original byte CC, padding
0x26600f: INT3 ; original byte CC, padding

; FUNCTION thunk_266010 [0x266010, 0x266014] | file +0x8f0 | ev_9241eefa311a80deb03ac0f658ff745e258a28a4f5240ccd14c8c8025756bf71
thunk_266010:
0x266010: JMP 0x000a7850
; END FUNCTION thunk_266010
0x266015: INT3 ; original byte CC, padding
0x266016: INT3 ; original byte CC, padding
0x266017: INT3 ; original byte CC, padding

; FUNCTION thunk_266018 [0x266018, 0x26601c] | file +0x8f8 | ev_77e192304c9e51060989921f10742631b6c86945dea766a66cde5a5603ae5a03
thunk_266018:
0x266018: JMP 0x000a7880
; END FUNCTION thunk_266018
0x26601d: INT3 ; original byte CC, padding
0x26601e: INT3 ; original byte CC, padding
0x26601f: INT3 ; original byte CC, padding

; FUNCTION thunk_266020 [0x266020, 0x266024] | file +0x900 | ev_08817f0e48324fa1734eebf5afd693d461d4f25faa9a57614305dbeec79fe7c5
thunk_266020:
0x266020: JMP 0x00452040
; END FUNCTION thunk_266020
0x266025: INT3 ; original byte CC, padding
0x266026: INT3 ; original byte CC, padding
0x266027: INT3 ; original byte CC, padding

; FUNCTION thunk_266028 [0x266028, 0x26602c] | file +0x908 | ev_1e5a04d67b16d2fa526870e464a7a9b92615f08e45de21b528d6a0e169950e95
thunk_266028:
0x266028: JMP 0x00454cc0
; END FUNCTION thunk_266028
0x26602d: INT3 ; original byte CC, padding
0x26602e: INT3 ; original byte CC, padding
0x26602f: INT3 ; original byte CC, padding

; FUNCTION thunk_266030 [0x266030, 0x266034] | file +0x910 | ev_cc10ac34cdc34cc724edd95074b755226bea7e251a7b28ab616c70c7e7e3b6f6
thunk_266030:
0x266030: JMP 0x00457820
; END FUNCTION thunk_266030
0x266035: INT3 ; original byte CC, padding
0x266036: INT3 ; original byte CC, padding
0x266037: INT3 ; original byte CC, padding

; FUNCTION thunk_266038 [0x266038, 0x26603c] | file +0x918 | ev_67aa9e5fd76f1c965fc090011e512499a3a3b198c77aab350e1d0473784fea18
thunk_266038:
0x266038: JMP 0x0046df70
; END FUNCTION thunk_266038
0x26603d: INT3 ; original byte CC, padding
0x26603e: INT3 ; original byte CC, padding
0x26603f: INT3 ; original byte CC, padding

; FUNCTION thunk_266040 [0x266040, 0x266044] | file +0x920 | ev_0284f5842ab359d45c0563372236b145cdde7902ac94bd430f6a223a9830dcd7
thunk_266040:
0x266040: JMP 0x0046e080
; END FUNCTION thunk_266040
0x266045: INT3 ; original byte CC, padding
0x266046: INT3 ; original byte CC, padding
0x266047: INT3 ; original byte CC, padding

; FUNCTION thunk_266048 [0x266048, 0x26604c] | file +0x928 | ev_274829a26a30245653849082cc72e6e35fed236ce0bbdb3ec6faab0eada81538
thunk_266048:
0x266048: JMP 0x00472990
; END FUNCTION thunk_266048
0x26604d: INT3 ; original byte CC, padding
0x26604e: INT3 ; original byte CC, padding
0x26604f: INT3 ; original byte CC, padding

; FUNCTION thunk_266050 [0x266050, 0x266054] | file +0x930 | ev_ba4f7a680946cc24f7d64ad866a978721163a825432c7cf1640b506b2eb8784d
thunk_266050:
0x266050: JMP 0x004733b0
; END FUNCTION thunk_266050
0x266055: INT3 ; original byte CC, padding
0x266056: INT3 ; original byte CC, padding
0x266057: INT3 ; original byte CC, padding

; FUNCTION thunk_266058 [0x266058, 0x26605c] | file +0x938 | ev_8d6f5eab901c31a67905fdcd53e3dc1c0fbc315b09039f6f12e50ade27b3174e
thunk_266058:
0x266058: JMP 0x004738b0
; END FUNCTION thunk_266058
0x26605d: INT3 ; original byte CC, padding
0x26605e: INT3 ; original byte CC, padding
0x26605f: INT3 ; original byte CC, padding

; FUNCTION thunk_266060 [0x266060, 0x266064] | file +0x940 | ev_e8b4123b0dba35e5d807682900886d6e11de80f9778dd14c6f7aaba6269b6938
thunk_266060:
0x266060: JMP 0x00474250
; END FUNCTION thunk_266060
0x266065: INT3 ; original byte CC, padding
0x266066: INT3 ; original byte CC, padding
0x266067: INT3 ; original byte CC, padding

; FUNCTION thunk_266068 [0x266068, 0x26606c] | file +0x948 | ev_f75afc0429bb5c477bea05f362dc59833ce7113d6a65211ba6ab62563bdc61ad
thunk_266068:
0x266068: JMP 0x00474db0
; END FUNCTION thunk_266068
0x26606d: INT3 ; original byte CC, padding
0x26606e: INT3 ; original byte CC, padding
0x26606f: INT3 ; original byte CC, padding

; FUNCTION thunk_266070 [0x266070, 0x266074] | file +0x950 | ev_f2aa6b1b31f49271e828c16308725efe4f855d10cb85de9cff13f6cdbda35fb3
thunk_266070:
0x266070: JMP 0x0047cff0
; END FUNCTION thunk_266070
0x266075: INT3 ; original byte CC, padding
0x266076: INT3 ; original byte CC, padding
0x266077: INT3 ; original byte CC, padding

; FUNCTION thunk_266078 [0x266078, 0x26607c] | file +0x958 | ev_51642329c1bbde0e93e8dec02d8735898e1286b91137062d76126033999a3d32
thunk_266078:
0x266078: JMP 0x0021dff0
; END FUNCTION thunk_266078
0x26607d: INT3 ; original byte CC, padding
0x26607e: INT3 ; original byte CC, padding
0x26607f: INT3 ; original byte CC, padding

; FUNCTION thunk_266080 [0x266080, 0x266084] | file +0x960 | ev_813edcb664f5a4436816b054fe42fdbf47ba1bcffa004d50477f7cf091d814be
thunk_266080:
0x266080: JMP 0x00490300
; END FUNCTION thunk_266080
0x266085: INT3 ; original byte CC, padding
0x266086: INT3 ; original byte CC, padding
0x266087: INT3 ; original byte CC, padding

; FUNCTION thunk_266088 [0x266088, 0x26608c] | file +0x968 | ev_bb9d9eb4c7788123aa96c895346d74ee3fcfb19ec4015518bd51902322271c89
thunk_266088:
0x266088: JMP 0x00490db0
; END FUNCTION thunk_266088
0x26608d: INT3 ; original byte CC, padding
0x26608e: INT3 ; original byte CC, padding
0x26608f: INT3 ; original byte CC, padding

; FUNCTION thunk_266090 [0x266090, 0x266094] | file +0x970 | ev_5f37661cb7d598c9dc86a7cefc47d3cf985f370da26ca037d619cb73a5ca4b8e
thunk_266090:
0x266090: JMP 0x00497fb0
; END FUNCTION thunk_266090
0x266095: INT3 ; original byte CC, padding
0x266096: INT3 ; original byte CC, padding
0x266097: INT3 ; original byte CC, padding

; FUNCTION thunk_266098 [0x266098, 0x26609c] | file +0x978 | ev_228fbdbd5af4919e2970004de3681f60847a1febed9f5d2595709cbb8462d11b
thunk_266098:
0x266098: JMP 0x00497fe0
; END FUNCTION thunk_266098
0x26609d: INT3 ; original byte CC, padding
0x26609e: INT3 ; original byte CC, padding
0x26609f: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a0 [0x2660a0, 0x2660a4] | file +0x980 | ev_ed6831e278bd783f3be5cb487656b3e4fbd09e14c5253eef5c2f3bd4fd69d74e
thunk_2660a0:
0x2660a0: JMP 0x00498630
; END FUNCTION thunk_2660a0
0x2660a5: INT3 ; original byte CC, padding
0x2660a6: INT3 ; original byte CC, padding
0x2660a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a8 [0x2660a8, 0x2660ac] | file +0x988 | ev_c8ed06089cd894204da39e1cac0194ac9499dfa20bfb4873e4db9564a46f5e29
thunk_2660a8:
0x2660a8: JMP 0x00498640
; END FUNCTION thunk_2660a8
0x2660ad: INT3 ; original byte CC, padding
0x2660ae: INT3 ; original byte CC, padding
0x2660af: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b0 [0x2660b0, 0x2660b4] | file +0x990 | ev_2504a752eb3543760284d7669f69d99c6776905f0b697402ee78f8025cb45d24
thunk_2660b0:
0x2660b0: JMP 0x008f7bc0
; END FUNCTION thunk_2660b0
0x2660b5: INT3 ; original byte CC, padding
0x2660b6: INT3 ; original byte CC, padding
0x2660b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b8 [0x2660b8, 0x2660bc] | file +0x998 | ev_e75168b4c23bf70efaf2133494a544d5d58e397acbb367674bb96a93020a891b
thunk_2660b8:
0x2660b8: JMP 0x008f6800
; END FUNCTION thunk_2660b8
0x2660bd: INT3 ; original byte CC, padding
0x2660be: INT3 ; original byte CC, padding
0x2660bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c0 [0x2660c0, 0x2660c4] | file +0x9a0 | ev_da7e97c369a81ea579dcdd4063c45b34ce659b954f7474a798c98d18f5072f48
thunk_2660c0:
0x2660c0: JMP 0x008f7420
; END FUNCTION thunk_2660c0
0x2660c5: INT3 ; original byte CC, padding
0x2660c6: INT3 ; original byte CC, padding
0x2660c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c8 [0x2660c8, 0x2660cc] | file +0x9a8 | ev_757ca60740b8f73bb6ff2a575203849b790702722e8d4687c36fb07a63dc9d6a
thunk_2660c8:
0x2660c8: JMP 0x008f9f80
; END FUNCTION thunk_2660c8
0x2660cd: INT3 ; original byte CC, padding
0x2660ce: INT3 ; original byte CC, padding
0x2660cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d0 [0x2660d0, 0x2660d4] | file +0x9b0 | ev_b14e0cde435fef81d6524b07ab25a64c832dfa4e07ec4813d36cb68c5a2542e6
thunk_2660d0:
0x2660d0: JMP 0x005df350
; END FUNCTION thunk_2660d0
0x2660d5: INT3 ; original byte CC, padding
0x2660d6: INT3 ; original byte CC, padding
0x2660d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d8 [0x2660d8, 0x2660dc] | file +0x9b8 | ev_695ca4375c51c495d91c54720b2ee5edbe4646386d7bdf42b6f1f7f1096ab7aa
thunk_2660d8:
0x2660d8: JMP 0x005df820
; END FUNCTION thunk_2660d8
0x2660dd: INT3 ; original byte CC, padding
0x2660de: INT3 ; original byte CC, padding
0x2660df: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e0 [0x2660e0, 0x2660e4] | file +0x9c0 | ev_7b89d84bc17a972cb085dda05242e82715a0d3c4e9b5c80e1d1a10d3cf703d8e
thunk_2660e0:
0x2660e0: JMP 0x00a34ce0
; END FUNCTION thunk_2660e0
0x2660e5: INT3 ; original byte CC, padding
0x2660e6: INT3 ; original byte CC, padding
0x2660e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e8 [0x2660e8, 0x2660ec] | file +0x9c8 | ev_e88176bc6d92c2a8a7349783a3ea17eb1596a47cc8519ecba94f4b20c0525334
thunk_2660e8:
0x2660e8: JMP 0x005e84a0
; END FUNCTION thunk_2660e8
0x2660ed: INT3 ; original byte CC, padding
0x2660ee: INT3 ; original byte CC, padding
0x2660ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f0 [0x2660f0, 0x2660f4] | file +0x9d0 | ev_338488211248baab7b79b0818ed3b67f3ca1443ece0ee1265a6eecf7dd0d3ecd
thunk_2660f0:
0x2660f0: JMP 0x008f81f0
; END FUNCTION thunk_2660f0
0x2660f5: INT3 ; original byte CC, padding
0x2660f6: INT3 ; original byte CC, padding
0x2660f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f8 [0x2660f8, 0x2660fc] | file +0x9d8 | ev_7967a6f62a6c6d7ec9772ad9b5eac8becd562619cecab980b52874d1b54dca4b
thunk_2660f8:
0x2660f8: JMP 0x008f9410
; END FUNCTION thunk_2660f8
0x2660fd: INT3 ; original byte CC, padding
0x2660fe: INT3 ; original byte CC, padding
0x2660ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266100 [0x266100, 0x266104] | file +0x9e0 | ev_849951bba96cef9609da76002488e8a1d20f07ec9230cefd95bfb3ad861b36a1
thunk_266100:
0x266100: JMP 0x008fc3f0
; END FUNCTION thunk_266100
0x266105: INT3 ; original byte CC, padding
0x266106: INT3 ; original byte CC, padding
0x266107: INT3 ; original byte CC, padding

; FUNCTION thunk_266108 [0x266108, 0x26610c] | file +0x9e8 | ev_1e6da3dff07fe59402a80c14648d04826df148070707dd9c0ef6a4e1fd74fafd
thunk_266108:
0x266108: JMP 0x008f6c90
; END FUNCTION thunk_266108
0x26610d: INT3 ; original byte CC, padding
0x26610e: INT3 ; original byte CC, padding
0x26610f: INT3 ; original byte CC, padding

; FUNCTION thunk_266110 [0x266110, 0x266114] | file +0x9f0 | ev_d2c807990d94f945e00cd701e68c26292cb1e2009d73f8f84b655ea38e88c052
thunk_266110:
0x266110: JMP 0x00cb1a10
; END FUNCTION thunk_266110
0x266115: INT3 ; original byte CC, padding
0x266116: INT3 ; original byte CC, padding
0x266117: INT3 ; original byte CC, padding

; FUNCTION thunk_266118 [0x266118, 0x26611c] | file +0x9f8 | ev_53472b939b20ba25a57ab4d91660139c63e4a4ba8839cddb43837794fa57e6e5
thunk_266118:
0x266118: JMP 0x00ab83a0
; END FUNCTION thunk_266118
0x26611d: INT3 ; original byte CC, padding
0x26611e: INT3 ; original byte CC, padding
0x26611f: INT3 ; original byte CC, padding

; FUNCTION thunk_266120 [0x266120, 0x266124] | file +0xa00 | ev_e3874429a2cd73930fad18d5594175104a6647df9411fdc9fdaba20f544869ac
thunk_266120:
0x266120: JMP 0x00ab83b0
; END FUNCTION thunk_266120
0x266125: INT3 ; original byte CC, padding
0x266126: INT3 ; original byte CC, padding
0x266127: INT3 ; original byte CC, padding

; FUNCTION thunk_266128 [0x266128, 0x26612c] | file +0xa08 | ev_9c8c416f951cb9e26ea8daf6254d67a2a2cb5f1e29a81b93155052ba74848071
thunk_266128:
0x266128: JMP 0x008fa1c0
; END FUNCTION thunk_266128
0x26612d: INT3 ; original byte CC, padding
0x26612e: INT3 ; original byte CC, padding
0x26612f: INT3 ; original byte CC, padding

; FUNCTION thunk_266130 [0x266130, 0x266134] | file +0xa10 | ev_f75fd383e35d1954533ca22638803f3c72f6a82546cd3a8ceccad79fa1daf4b7
thunk_266130:
0x266130: JMP 0x008f7b40
; END FUNCTION thunk_266130
0x266135: INT3 ; original byte CC, padding
0x266136: INT3 ; original byte CC, padding
0x266137: INT3 ; original byte CC, padding

; FUNCTION thunk_266138 [0x266138, 0x26613c] | file +0xa18 | ev_8207120065dabc5b19c2f962cda8ae9f598c7325173c735e6d269bcccae85a15
thunk_266138:
0x266138: JMP 0x004a0960
; END FUNCTION thunk_266138
0x26613d: INT3 ; original byte CC, padding
0x26613e: INT3 ; original byte CC, padding
0x26613f: INT3 ; original byte CC, padding

; FUNCTION thunk_266140 [0x266140, 0x266144] | file +0xa20 | ev_6d7cc7b56a7cd224e4e1ca39aa3c2a2d97be8d247b1b879fbe064c464bd07514
thunk_266140:
0x266140: JMP 0x00729780
; END FUNCTION thunk_266140
0x266145: INT3 ; original byte CC, padding
0x266146: INT3 ; original byte CC, padding
0x266147: INT3 ; original byte CC, padding

; FUNCTION thunk_266148 [0x266148, 0x26614c] | file +0xa28 | ev_62c7b086c5573b195bb72867047d219ff493c01e81f65173fdda18ed43941bca
thunk_266148:
0x266148: JMP 0x00729790
; END FUNCTION thunk_266148
0x26614d: INT3 ; original byte CC, padding
0x26614e: INT3 ; original byte CC, padding
0x26614f: INT3 ; original byte CC, padding

; FUNCTION thunk_266150 [0x266150, 0x266154] | file +0xa30 | ev_efe9729a0a63c617fe6c009276ba9db0563058f4462ea9ff1bd507ed71a70a62
thunk_266150:
0x266150: JMP 0x007297a0
; END FUNCTION thunk_266150
0x266155: INT3 ; original byte CC, padding
0x266156: INT3 ; original byte CC, padding
0x266157: INT3 ; original byte CC, padding

; FUNCTION thunk_266158 [0x266158, 0x26615c] | file +0xa38 | ev_b0621322d51d31fb36c314eb23a97a956aceffc0a88da9f9970a8a68d289a159
thunk_266158:
0x266158: JMP 0x006bb590
; END FUNCTION thunk_266158
0x26615d: INT3 ; original byte CC, padding
0x26615e: INT3 ; original byte CC, padding
0x26615f: INT3 ; original byte CC, padding

; FUNCTION thunk_266160 [0x266160, 0x266164] | file +0xa40 | ev_fcc1bfa009ab0ece3e52445710d3c3b56a294709c05cf127ebc6989ec52073a0
thunk_266160:
0x266160: JMP 0x00ab8da0
; END FUNCTION thunk_266160
0x266165: INT3 ; original byte CC, padding
0x266166: INT3 ; original byte CC, padding
0x266167: INT3 ; original byte CC, padding

; FUNCTION thunk_266168 [0x266168, 0x26616c] | file +0xa48 | ev_85fe954f6e700c0007bf50bcb5abe7fa8945362eb645e2117df19c1cb45cfd0f
thunk_266168:
0x266168: JMP 0x008fa170
; END FUNCTION thunk_266168
0x26616d: INT3 ; original byte CC, padding
0x26616e: INT3 ; original byte CC, padding
0x26616f: INT3 ; original byte CC, padding

; FUNCTION thunk_266170 [0x266170, 0x266174] | file +0xa50 | ev_c890e498bbcc6f8ac6e3e30792c03ca2289ba3e9f242a390489aa6aea5228cf5
thunk_266170:
0x266170: JMP 0x00b7f0c0
; END FUNCTION thunk_266170
0x266175: INT3 ; original byte CC, padding
0x266176: INT3 ; original byte CC, padding
0x266177: INT3 ; original byte CC, padding

; FUNCTION thunk_266178 [0x266178, 0x26617c] | file +0xa58 | ev_e1430f65ea8ac5404922d82f740706346a0b3b614afea6cb0d6d4ab94bd94f4d
thunk_266178:
0x266178: JMP 0x00b7f100
; END FUNCTION thunk_266178
0x26617d: INT3 ; original byte CC, padding
0x26617e: INT3 ; original byte CC, padding
0x26617f: INT3 ; original byte CC, padding

; FUNCTION thunk_266180 [0x266180, 0x266184] | file +0xa60 | ev_fd48f8dae2e01b6715b9a25b9598a63851195089c4d557d8e15a01f560b938a8
thunk_266180:
0x266180: JMP 0x008f9cf0
; END FUNCTION thunk_266180
0x266185: INT3 ; original byte CC, padding
0x266186: INT3 ; original byte CC, padding
0x266187: INT3 ; original byte CC, padding

; FUNCTION thunk_266188 [0x266188, 0x26618c] | file +0xa68 | ev_544cba46ca25c52016b06b1336491047811985c85719c88aca599bb88ca2fe9e
thunk_266188:
0x266188: JMP 0x008fa740
; END FUNCTION thunk_266188
0x26618d: INT3 ; original byte CC, padding
0x26618e: INT3 ; original byte CC, padding
0x26618f: INT3 ; original byte CC, padding

; FUNCTION thunk_266190 [0x266190, 0x266194] | file +0xa70 | ev_c59a83c527ec2c14aefac1b9685ab1f5033a1302df2ae7c904635b8c49564da7
thunk_266190:
0x266190: JMP 0x00552b70
; END FUNCTION thunk_266190
0x266195: INT3 ; original byte CC, padding
0x266196: INT3 ; original byte CC, padding
0x266197: INT3 ; original byte CC, padding

; FUNCTION thunk_266198 [0x266198, 0x26619c] | file +0xa78 | ev_48793e7f58ef9e0f869d5bf7e4197a1365c5204a853d9f6e86f272e062ecad5f
thunk_266198:
0x266198: JMP 0x00552bf0
; END FUNCTION thunk_266198
0x26619d: INT3 ; original byte CC, padding
0x26619e: INT3 ; original byte CC, padding
0x26619f: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a0 [0x2661a0, 0x2661a4] | file +0xa80 | ev_21f6a74ead4cf7febff2d4196b2a7986d4cd72a85ab83c1e027b9eb014c9db41
thunk_2661a0:
0x2661a0: JMP 0x00552c50
; END FUNCTION thunk_2661a0
0x2661a5: INT3 ; original byte CC, padding
0x2661a6: INT3 ; original byte CC, padding
0x2661a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a8 [0x2661a8, 0x2661ac] | file +0xa88 | ev_08c7efec6159a4231f725feeb2ae4667652444949af05bfad614ed486cc10726
thunk_2661a8:
0x2661a8: JMP 0x00552c80
; END FUNCTION thunk_2661a8
0x2661ad: INT3 ; original byte CC, padding
0x2661ae: INT3 ; original byte CC, padding
0x2661af: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b0 [0x2661b0, 0x2661b4] | file +0xa90 | ev_e62aa65b183e4f6ea7ab3b5cd9bfe757dfa71a58a3191566234425bdfd6b468c
thunk_2661b0:
0x2661b0: JMP 0x00552cb0
; END FUNCTION thunk_2661b0
0x2661b5: INT3 ; original byte CC, padding
0x2661b6: INT3 ; original byte CC, padding
0x2661b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b8 [0x2661b8, 0x2661bc] | file +0xa98 | ev_59a4649b3a618147c0f8e7d991262dccbb38b62bab46745d9dc86f95ee01c0f8
thunk_2661b8:
0x2661b8: JMP 0x00552ce0
; END FUNCTION thunk_2661b8
0x2661bd: INT3 ; original byte CC, padding
0x2661be: INT3 ; original byte CC, padding
0x2661bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c0 [0x2661c0, 0x2661c4] | file +0xaa0 | ev_6ab3dee911315061b49dc3807ba7a64a017fe2ef5e7edcc67e0a8b25af23a042
thunk_2661c0:
0x2661c0: JMP 0x00b7e800
; END FUNCTION thunk_2661c0
0x2661c5: INT3 ; original byte CC, padding
0x2661c6: INT3 ; original byte CC, padding
0x2661c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c8 [0x2661c8, 0x2661cc] | file +0xaa8 | ev_255f396dca8f49de3450f7d86252eaee6b5c42959e9628c715fbd35c890e38e7
thunk_2661c8:
0x2661c8: JMP 0x00b7ebe0
; END FUNCTION thunk_2661c8
0x2661cd: INT3 ; original byte CC, padding
0x2661ce: INT3 ; original byte CC, padding
0x2661cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d0 [0x2661d0, 0x2661d4] | file +0xab0 | ev_c9d1cac1498546eeeab2fce1f6faafc853cb664e949cc88c10d0bee8e3abeb57
thunk_2661d0:
0x2661d0: JMP 0x00b7ef70
; END FUNCTION thunk_2661d0
0x2661d5: INT3 ; original byte CC, padding
0x2661d6: INT3 ; original byte CC, padding
0x2661d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d8 [0x2661d8, 0x2661dc] | file +0xab8 | ev_0b00bb178d5769719b66fc3253ea231d0f2d95e28ca0c9c7dde96e4f42e76c33
thunk_2661d8:
0x2661d8: JMP 0x00c06d30
; END FUNCTION thunk_2661d8
0x2661dd: INT3 ; original byte CC, padding
0x2661de: INT3 ; original byte CC, padding
0x2661df: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e0 [0x2661e0, 0x2661e4] | file +0xac0 | ev_498718fb310bd1eb2b790209f3a3d38511b8173ce987d8063b228403a1c56ad7
thunk_2661e0:
0x2661e0: JMP 0x00792690
; END FUNCTION thunk_2661e0
0x2661e5: INT3 ; original byte CC, padding
0x2661e6: INT3 ; original byte CC, padding
0x2661e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e8 [0x2661e8, 0x2661ec] | file +0xac8 | ev_8a8290c5607724f7392ee63f16aadf7e18422517ed6a4e904e9edc27d524cc6b
thunk_2661e8:
0x2661e8: JMP 0x005e8b20
; END FUNCTION thunk_2661e8
0x2661ed: INT3 ; original byte CC, padding
0x2661ee: INT3 ; original byte CC, padding
0x2661ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f0 [0x2661f0, 0x2661f4] | file +0xad0 | ev_8c1ed7bc8853604e5acf55448a86e622f5ce0b7e72c7ce4cb732a0f49b42d130
thunk_2661f0:
0x2661f0: JMP 0x00552d10
; END FUNCTION thunk_2661f0
0x2661f5: INT3 ; original byte CC, padding
0x2661f6: INT3 ; original byte CC, padding
0x2661f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f8 [0x2661f8, 0x2661fc] | file +0xad8 | ev_5dd1aefd4eafac7c3e2c0dd0b2f9a465137289585f5cde83e19c612c55283277
thunk_2661f8:
0x2661f8: JMP 0x00b7f160
; END FUNCTION thunk_2661f8
0x2661fd: INT3 ; original byte CC, padding
0x2661fe: INT3 ; original byte CC, padding
0x2661ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266200 [0x266200, 0x266204] | file +0xae0 | ev_757ed4e16199c82a0c607920c217f95085b37f8a6717d7dbb7978116461ae164
thunk_266200:
0x266200: JMP 0x005de250
; END FUNCTION thunk_266200
0x266205: INT3 ; original byte CC, padding
0x266206: INT3 ; original byte CC, padding
0x266207: INT3 ; original byte CC, padding

; FUNCTION thunk_266208 [0x266208, 0x26620c] | file +0xae8 | ev_a91a98e2442ba222b625021ef2f015620cb04418f3424570d5a614e1076c3fcb
thunk_266208:
0x266208: JMP 0x00a54a30
; END FUNCTION thunk_266208
0x26620d: INT3 ; original byte CC, padding
0x26620e: INT3 ; original byte CC, padding
0x26620f: INT3 ; original byte CC, padding

; FUNCTION thunk_266210 [0x266210, 0x266214] | file +0xaf0 | ev_62abc88f2ffa6f5a0735a3c380225d00d1cc5230fe6196dbd4554708b105ba38
thunk_266210:
0x266210: JMP 0x00a54a40
; END FUNCTION thunk_266210
0x266215: INT3 ; original byte CC, padding
0x266216: INT3 ; original byte CC, padding
0x266217: INT3 ; original byte CC, padding

; FUNCTION thunk_266218 [0x266218, 0x26621c] | file +0xaf8 | ev_316646bb0eb8fd79801320346e50eaec76dfa54cb81513b797abe9e2b4888da0
thunk_266218:
0x266218: JMP 0x00a54a50
; END FUNCTION thunk_266218
0x26621d: INT3 ; original byte CC, padding
0x26621e: INT3 ; original byte CC, padding
0x26621f: INT3 ; original byte CC, padding

; FUNCTION thunk_266220 [0x266220, 0x266224] | file +0xb00 | ev_4a106cd82fbe8c86da526794caa3df2f7d5aef9eaae4cff41d637e9c2cd824be
thunk_266220:
0x266220: JMP 0x00a54a60
; END FUNCTION thunk_266220
0x266225: INT3 ; original byte CC, padding
0x266226: INT3 ; original byte CC, padding
0x266227: INT3 ; original byte CC, padding

; FUNCTION thunk_266228 [0x266228, 0x26622c] | file +0xb08 | ev_351475a479b8e03694262bc8dcef5bbd2294aeaff31eeaa55316389e51414995
thunk_266228:
0x266228: JMP 0x00a54a80
; END FUNCTION thunk_266228
0x26622d: INT3 ; original byte CC, padding
0x26622e: INT3 ; original byte CC, padding
0x26622f: INT3 ; original byte CC, padding

; FUNCTION thunk_266230 [0x266230, 0x266234] | file +0xb10 | ev_068172e45f643e23c2637d51152a476b51dec1fd8b501c50c998a097591390c2
thunk_266230:
0x266230: JMP 0x00a54a90
; END FUNCTION thunk_266230
0x266235: INT3 ; original byte CC, padding
0x266236: INT3 ; original byte CC, padding
0x266237: INT3 ; original byte CC, padding

; FUNCTION thunk_266238 [0x266238, 0x26623c] | file +0xb18 | ev_dfc19b0d494a5652a47ade31009b1e4c990f00087fde5e625a98a44c96cf0818
thunk_266238:
0x266238: JMP 0x008f9720
; END FUNCTION thunk_266238
0x26623d: INT3 ; original byte CC, padding
0x26623e: INT3 ; original byte CC, padding
0x26623f: INT3 ; original byte CC, padding

; FUNCTION thunk_266240 [0x266240, 0x266244] | file +0xb20 | ev_c4b0a4d54127ab7bacb8213d7c83b00ba3119ecb6a1ed4bcefb4af04d714bff9
thunk_266240:
0x266240: JMP 0x00a54ab0
; END FUNCTION thunk_266240
0x266245: INT3 ; original byte CC, padding
0x266246: INT3 ; original byte CC, padding
0x266247: INT3 ; original byte CC, padding

; FUNCTION thunk_266248 [0x266248, 0x26624c] | file +0xb28 | ev_3955365d4f354d375284caa65baa7fdc58b06cbf43962a43f4403daf1e6ca121
thunk_266248:
0x266248: JMP 0x008f64e0
; END FUNCTION thunk_266248
0x26624d: INT3 ; original byte CC, padding
0x26624e: INT3 ; original byte CC, padding
0x26624f: INT3 ; original byte CC, padding

; FUNCTION thunk_266250 [0x266250, 0x266254] | file +0xb30 | ev_f96adbdce6189ddf520dc792bf796a549b63d30d28bf78afb120432ba46da586
thunk_266250:
0x266250: JMP 0x008f5ef0
; END FUNCTION thunk_266250
0x266255: INT3 ; original byte CC, padding
0x266256: INT3 ; original byte CC, padding
0x266257: INT3 ; original byte CC, padding

; FUNCTION thunk_266258 [0x266258, 0x26625c] | file +0xb38 | ev_1b34325666d3c9c6d915c324fbccf4635988b46d93e5a9c542d2c00f603b09aa
thunk_266258:
0x266258: JMP 0x00a54a20
; END FUNCTION thunk_266258
0x26625d: INT3 ; original byte CC, padding
0x26625e: INT3 ; original byte CC, padding
0x26625f: INT3 ; original byte CC, padding

; FUNCTION thunk_266260 [0x266260, 0x266264] | file +0xb40 | ev_4d1b8a3331344e715a72a250a7d7161a2ccd108eb7ebf2facdfab957a5a66bb3
thunk_266260:
0x266260: JMP 0x00a54a70
; END FUNCTION thunk_266260
0x266265: INT3 ; original byte CC, padding
0x266266: INT3 ; original byte CC, padding
0x266267: INT3 ; original byte CC, padding

; FUNCTION thunk_266268 [0x266268, 0x26626c] | file +0xb48 | ev_22e4db3caf86ff04a9eee13f105b1058dc4863b54bce4a01374f8889e8a30600
thunk_266268:
0x266268: JMP 0x00a54aa0
; END FUNCTION thunk_266268
0x26626d: INT3 ; original byte CC, padding
0x26626e: INT3 ; original byte CC, padding
0x26626f: INT3 ; original byte CC, padding

; FUNCTION thunk_266270 [0x266270, 0x266274] | file +0xb50 | ev_890be6f1c7920f0033104ee575247e1908f0c97280a687224b3a7da85c57310a
thunk_266270:
0x266270: JMP 0x006e54d0
; END FUNCTION thunk_266270
0x266275: INT3 ; original byte CC, padding
0x266276: INT3 ; original byte CC, padding
0x266277: INT3 ; original byte CC, padding

; FUNCTION thunk_266278 [0x266278, 0x26627c] | file +0xb58 | ev_38a9d23e776f221c1f5b721b4f7c272ef04b2b40606ad30cb41ed2f6fe414c12
thunk_266278:
0x266278: JMP 0x00b7f4b0
; END FUNCTION thunk_266278
0x26627d: INT3 ; original byte CC, padding
0x26627e: INT3 ; original byte CC, padding
0x26627f: INT3 ; original byte CC, padding

; FUNCTION thunk_266280 [0x266280, 0x266284] | file +0xb60 | ev_2f26b0745ccafe1db376effabe7a0a78b79d483ba1574dca7a4e24346f526141
thunk_266280:
0x266280: JMP 0x0083d660
; END FUNCTION thunk_266280
0x266285: INT3 ; original byte CC, padding
0x266286: INT3 ; original byte CC, padding
0x266287: INT3 ; original byte CC, padding

; FUNCTION thunk_266288 [0x266288, 0x26628c] | file +0xb68 | ev_f9d0bb27935ce47d742649223a7e2e81d68bc42ed16701b18f269579e25bb4e0
thunk_266288:
0x266288: JMP 0x0083d7c0
; END FUNCTION thunk_266288
0x26628d: INT3 ; original byte CC, padding
0x26628e: INT3 ; original byte CC, padding
0x26628f: INT3 ; original byte CC, padding

; FUNCTION thunk_266290 [0x266290, 0x266294] | file +0xb70 | ev_a1a078ae92c7980fc788d3c99d9298c6590db02a5982d9127f09f838f9409650
thunk_266290:
0x266290: JMP 0x0083dab0
; END FUNCTION thunk_266290
0x266295: INT3 ; original byte CC, padding
0x266296: INT3 ; original byte CC, padding
0x266297: INT3 ; original byte CC, padding

; FUNCTION thunk_266298 [0x266298, 0x26629c] | file +0xb78 | ev_a78e29a1ea04bf6d30594d3b19849395bc30b22f59337d3f40a121a6320dc5ab
thunk_266298:
0x266298: JMP 0x0083de80
; END FUNCTION thunk_266298
0x26629d: INT3 ; original byte CC, padding
0x26629e: INT3 ; original byte CC, padding
0x26629f: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a0 [0x2662a0, 0x2662a4] | file +0xb80 | ev_155d45ce5e405802c8aeeaba1343bdef4231a636cf536cf310fc69c4c61f7313
thunk_2662a0:
0x2662a0: JMP 0x008f9c80
; END FUNCTION thunk_2662a0
0x2662a5: INT3 ; original byte CC, padding
0x2662a6: INT3 ; original byte CC, padding
0x2662a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a8 [0x2662a8, 0x2662ac] | file +0xb88 | ev_bd1796ad561e4782dded9a21477730f4bdf304f5dabc5868b80761969759fad6
thunk_2662a8:
0x2662a8: JMP 0x008fa110
; END FUNCTION thunk_2662a8
0x2662ad: INT3 ; original byte CC, padding
0x2662ae: INT3 ; original byte CC, padding
0x2662af: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b0 [0x2662b0, 0x2662b4] | file +0xb90 | ev_0480d28ab6222af2b93e4fd113f16ba734ff8878a8f42b06d5158480225cf901
thunk_2662b0:
0x2662b0: JMP 0x008f91b0
; END FUNCTION thunk_2662b0
0x2662b5: INT3 ; original byte CC, padding
0x2662b6: INT3 ; original byte CC, padding
0x2662b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b8 [0x2662b8, 0x2662bc] | file +0xb98 | ev_1c690d03a8e9640305178c7da5cb0928be57685cc88733f8570a0a2b2d1e3e1e
thunk_2662b8:
0x2662b8: JMP 0x008fa4f0
; END FUNCTION thunk_2662b8
0x2662bd: INT3 ; original byte CC, padding
0x2662be: INT3 ; original byte CC, padding
0x2662bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c0 [0x2662c0, 0x2662c4] | file +0xba0 | ev_719922efa405ef9eca04e783fe6e621ff2a66e1ad1adbeffd20ce01bd1b0ed53
thunk_2662c0:
0x2662c0: JMP 0x008f8090
; END FUNCTION thunk_2662c0
0x2662c5: INT3 ; original byte CC, padding
0x2662c6: INT3 ; original byte CC, padding
0x2662c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c8 [0x2662c8, 0x2662cc] | file +0xba8 | ev_a91a6620a8b9164f6f8704cd2c44855feabb5aee9594bdae24707f232e57d539
thunk_2662c8:
0x2662c8: JMP 0x008fbb80
; END FUNCTION thunk_2662c8
0x2662cd: INT3 ; original byte CC, padding
0x2662ce: INT3 ; original byte CC, padding
0x2662cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d0 [0x2662d0, 0x2662d4] | file +0xbb0 | ev_a29cf940ec7347209b1f1e1e1df6ed80e1b76b49b50c65175eeb8dbb2f48f37d
thunk_2662d0:
0x2662d0: JMP 0x008f7b80
; END FUNCTION thunk_2662d0
0x2662d5: INT3 ; original byte CC, padding
0x2662d6: INT3 ; original byte CC, padding
0x2662d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d8 [0x2662d8, 0x2662dc] | file +0xbb8 | ev_1b6cc0fa753ccd5b1d7037a0c83ca39e8938cd8ce9dae47fdab2114c3a3f30a0
thunk_2662d8:
0x2662d8: JMP 0x008f7890
; END FUNCTION thunk_2662d8
0x2662dd: INT3 ; original byte CC, padding
0x2662de: INT3 ; original byte CC, padding
0x2662df: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e0 [0x2662e0, 0x2662e4] | file +0xbc0 | ev_3f3429b265d0817f87fde71c226edb3414a5e56742e62e83e7ba9c5eb129e695
thunk_2662e0:
0x2662e0: JMP 0x008fb8a0
; END FUNCTION thunk_2662e0
0x2662e5: INT3 ; original byte CC, padding
0x2662e6: INT3 ; original byte CC, padding
0x2662e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e8 [0x2662e8, 0x2662ec] | file +0xbc8 | ev_5fc1e1d8cefa479de1df321dd78e3e0fcec232438431dd18a61fa054ab7b3e6a
thunk_2662e8:
0x2662e8: JMP 0x008f8510
; END FUNCTION thunk_2662e8
0x2662ed: INT3 ; original byte CC, padding
0x2662ee: INT3 ; original byte CC, padding
0x2662ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f0 [0x2662f0, 0x2662f4] | file +0xbd0 | ev_069bad0ed13080f7e9635297f56d86b4d2e1c4617a1fe0b1e4cf75f1ccc2c916
thunk_2662f0:
0x2662f0: JMP 0x008f8800
; END FUNCTION thunk_2662f0
0x2662f5: INT3 ; original byte CC, padding
0x2662f6: INT3 ; original byte CC, padding
0x2662f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f8 [0x2662f8, 0x2662fc] | file +0xbd8 | ev_d3234eeed367638025138ce92a20673c4286efccda25b5770c0733c2eb4a83e4
thunk_2662f8:
0x2662f8: JMP 0x0049b080
; END FUNCTION thunk_2662f8
0x2662fd: INT3 ; original byte CC, padding
0x2662fe: INT3 ; original byte CC, padding
0x2662ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266300 [0x266300, 0x266304] | file +0xbe0 | ev_75056b65a1d2bedd343eb1adcf1cef2a1c0fda4e054c7388d54dbd2caba2e0b9
thunk_266300:
0x266300: JMP 0x0049b090
; END FUNCTION thunk_266300
0x266305: INT3 ; original byte CC, padding
0x266306: INT3 ; original byte CC, padding
0x266307: INT3 ; original byte CC, padding

; FUNCTION thunk_266308 [0x266308, 0x26630c] | file +0xbe8 | ev_91ea1293d69e9c30d64b99d8801790056e6736a65b95aea27ec12055f57b1083
thunk_266308:
0x266308: JMP 0x0055fa50
; END FUNCTION thunk_266308
0x26630d: INT3 ; original byte CC, padding
0x26630e: INT3 ; original byte CC, padding
0x26630f: INT3 ; original byte CC, padding

; FUNCTION thunk_266310 [0x266310, 0x266314] | file +0xbf0 | ev_bf5a4d512d418182601ed746a6835acf3eb5afe4f7852dfadc904c056465c94b
thunk_266310:
0x266310: JMP 0x00c34870
; END FUNCTION thunk_266310
0x266315: INT3 ; original byte CC, padding
0x266316: INT3 ; original byte CC, padding
0x266317: INT3 ; original byte CC, padding

; FUNCTION thunk_266318 [0x266318, 0x26631c] | file +0xbf8 | ev_208b12d33f8755d90604b90a10a2c17d58b0947f24fd776ac8b17d17f6313ee8
thunk_266318:
0x266318: JMP 0x007dccf0
; END FUNCTION thunk_266318
0x26631d: INT3 ; original byte CC, padding
0x26631e: INT3 ; original byte CC, padding
0x26631f: INT3 ; original byte CC, padding

; FUNCTION thunk_266320 [0x266320, 0x266324] | file +0xc00 | ev_dd4ca9088204fa7e974a87d0b009a8ebc2fd2759fb8b63a52a185ba34cf8eb29
thunk_266320:
0x266320: JMP 0x007dcd00
; END FUNCTION thunk_266320
0x266325: INT3 ; original byte CC, padding
0x266326: INT3 ; original byte CC, padding
0x266327: INT3 ; original byte CC, padding

; FUNCTION thunk_266328 [0x266328, 0x26632c] | file +0xc08 | ev_69848362de2103bd5cf50d86ad439e274738f701958fe202143e54df6f1453c8
thunk_266328:
0x266328: JMP 0x007dcd10
; END FUNCTION thunk_266328
0x26632d: INT3 ; original byte CC, padding
0x26632e: INT3 ; original byte CC, padding
0x26632f: INT3 ; original byte CC, padding

; FUNCTION thunk_266330 [0x266330, 0x266334] | file +0xc10 | ev_a9629abec3308aca2457491628273649a887f0f033e06071bf19d59e7c25aeb6
thunk_266330:
0x266330: JMP 0x007dcd20
; END FUNCTION thunk_266330
0x266335: INT3 ; original byte CC, padding
0x266336: INT3 ; original byte CC, padding
0x266337: INT3 ; original byte CC, padding

; FUNCTION thunk_266338 [0x266338, 0x26633c] | file +0xc18 | ev_2c9fc9579a5e8f0951e68ec4ee69f8bab5819987d27b92dac0e5ca9ab7aa9585
thunk_266338:
0x266338: JMP 0x007dcd30
; END FUNCTION thunk_266338
0x26633d: INT3 ; original byte CC, padding
0x26633e: INT3 ; original byte CC, padding
0x26633f: INT3 ; original byte CC, padding

; FUNCTION thunk_266340 [0x266340, 0x266344] | file +0xc20 | ev_28d00ff55ee14bddc3a396e9c941f0914c680d54e45f0e7d0a0fe6bcaf0abdfd
thunk_266340:
0x266340: JMP 0x005a6c90
; END FUNCTION thunk_266340
0x266345: INT3 ; original byte CC, padding
0x266346: INT3 ; original byte CC, padding
0x266347: INT3 ; original byte CC, padding

; FUNCTION thunk_266348 [0x266348, 0x26634c] | file +0xc28 | ev_a0a92a8617b94cc57cf896b02840e085453db69e9b9b89b42fd08675b520d877
thunk_266348:
0x266348: JMP 0x005a7300
; END FUNCTION thunk_266348
0x26634d: INT3 ; original byte CC, padding
0x26634e: INT3 ; original byte CC, padding
0x26634f: INT3 ; original byte CC, padding

; FUNCTION thunk_266350 [0x266350, 0x266354] | file +0xc30 | ev_0a57f3bca0315a687f07d3f9b7f70316f45c7906a2d0cf0fa17dc9062c3dee7c
thunk_266350:
0x266350: JMP 0x005a7610
; END FUNCTION thunk_266350
0x266355: INT3 ; original byte CC, padding
0x266356: INT3 ; original byte CC, padding
0x266357: INT3 ; original byte CC, padding

; FUNCTION thunk_266358 [0x266358, 0x26635c] | file +0xc38 | ev_af4fded32a25b1dd2506f0fa8d3a6fe561debf05b2f66c733b119322209b6aaf
thunk_266358:
0x266358: JMP 0x005a7900
; END FUNCTION thunk_266358
0x26635d: INT3 ; original byte CC, padding
0x26635e: INT3 ; original byte CC, padding
0x26635f: INT3 ; original byte CC, padding

; FUNCTION thunk_266360 [0x266360, 0x266364] | file +0xc40 | ev_9c6af11e7c8dd305336c3838898236fd05099b0aa65104622374b160736ab5b6
thunk_266360:
0x266360: JMP 0x00c9c830
; END FUNCTION thunk_266360
0x266365: INT3 ; original byte CC, padding
0x266366: INT3 ; original byte CC, padding
0x266367: INT3 ; original byte CC, padding

; FUNCTION thunk_266368 [0x266368, 0x26636c] | file +0xc48 | ev_87f009c7ed6a037fc6a2e695d59a03270e62b3b2b19528404427fdbc1ab4ee9e
thunk_266368:
0x266368: JMP 0x005a7f00
; END FUNCTION thunk_266368
0x26636d: INT3 ; original byte CC, padding
0x26636e: INT3 ; original byte CC, padding
0x26636f: INT3 ; original byte CC, padding

; FUNCTION thunk_266370 [0x266370, 0x266374] | file +0xc50 | ev_3070545cbae7a2801f820e3271e277b6b50e272261694c2bd8e9e12e4aae5233
thunk_266370:
0x266370: JMP 0x005a8070
; END FUNCTION thunk_266370
0x266375: INT3 ; original byte CC, padding
0x266376: INT3 ; original byte CC, padding
0x266377: INT3 ; original byte CC, padding

; FUNCTION thunk_266378 [0x266378, 0x26637c] | file +0xc58 | ev_ca921bb3120b8324a1de915ed3013883e4fa47822426fb4cd29d45496c86f8d4
thunk_266378:
0x266378: JMP 0x00be8480
; END FUNCTION thunk_266378
0x26637d: INT3 ; original byte CC, padding
0x26637e: INT3 ; original byte CC, padding
0x26637f: INT3 ; original byte CC, padding

; FUNCTION thunk_266380 [0x266380, 0x266384] | file +0xc60 | ev_a8a021cff5d62e81b20c04597b03ae061b60365d11847b3152df272cc8acdd6f
thunk_266380:
0x266380: JMP 0x0049b0a0
; END FUNCTION thunk_266380
0x266385: INT3 ; original byte CC, padding
0x266386: INT3 ; original byte CC, padding
0x266387: INT3 ; original byte CC, padding

; FUNCTION thunk_266388 [0x266388, 0x26638c] | file +0xc68 | ev_2997099199ab42db19428062e874712cd6df17198b3e9050eab123c8e272e909
thunk_266388:
0x266388: JMP 0x0049b0c0
; END FUNCTION thunk_266388
0x26638d: INT3 ; original byte CC, padding
0x26638e: INT3 ; original byte CC, padding
0x26638f: INT3 ; original byte CC, padding

; FUNCTION thunk_266390 [0x266390, 0x266394] | file +0xc70 | ev_b65bf17266f25edcb08139f6c59009a5ffaaa52228678f32ef1ea053d7b820ea
thunk_266390:
0x266390: JMP 0x0049b0d0
; END FUNCTION thunk_266390
0x266395: INT3 ; original byte CC, padding
0x266396: INT3 ; original byte CC, padding
0x266397: INT3 ; original byte CC, padding

; FUNCTION thunk_266398 [0x266398, 0x26639c] | file +0xc78 | ev_4bf27f9aa04b2929a3570e0657827ba247a75006d293b78e64abaff44da59012
thunk_266398:
0x266398: JMP 0x0049b0e0
; END FUNCTION thunk_266398
0x26639d: INT3 ; original byte CC, padding
0x26639e: INT3 ; original byte CC, padding
0x26639f: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a0 [0x2663a0, 0x2663a4] | file +0xc80 | ev_67bb7eec5a2d6bdffe57a922696a5236cd5e44e0462ecd023f1a1790e17462b7
thunk_2663a0:
0x2663a0: JMP 0x0049b0f0
; END FUNCTION thunk_2663a0
0x2663a5: INT3 ; original byte CC, padding
0x2663a6: INT3 ; original byte CC, padding
0x2663a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a8 [0x2663a8, 0x2663ac] | file +0xc88 | ev_68a25a408bff8ab52323616e1566b09b1bdfef1050073934b37bcd78f8bff273
thunk_2663a8:
0x2663a8: JMP 0x00530720
; END FUNCTION thunk_2663a8
0x2663ad: INT3 ; original byte CC, padding
0x2663ae: INT3 ; original byte CC, padding
0x2663af: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b0 [0x2663b0, 0x2663b4] | file +0xc90 | ev_83ae655e96cd90c09eb9dc0ce6bd23f77ef191df92f56a0d59db6f4464af597e
thunk_2663b0:
0x2663b0: JMP 0x00531670
; END FUNCTION thunk_2663b0
0x2663b5: INT3 ; original byte CC, padding
0x2663b6: INT3 ; original byte CC, padding
0x2663b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b8 [0x2663b8, 0x2663bc] | file +0xc98 | ev_1afdd0cffa8bf6b0d345f517b61d8ebdb86433a05beb859e3375a00d0567815c
thunk_2663b8:
0x2663b8: JMP 0x008f96f0
; END FUNCTION thunk_2663b8
0x2663bd: INT3 ; original byte CC, padding
0x2663be: INT3 ; original byte CC, padding
0x2663bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c0 [0x2663c0, 0x2663c4] | file +0xca0 | ev_a2681b835dabbb2bbe1018977711d8e7a6b25088c1c3b1bd12d40314ae174cdd
thunk_2663c0:
0x2663c0: JMP 0x00531230
; END FUNCTION thunk_2663c0
0x2663c5: INT3 ; original byte CC, padding
0x2663c6: INT3 ; original byte CC, padding
0x2663c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c8 [0x2663c8, 0x2663cc] | file +0xca8 | ev_1202d226e0b0dc8c3cdef6d838d3717b0e0b43e88f3997d1a0aa7e109050b457
thunk_2663c8:
0x2663c8: JMP 0x00802df0
; END FUNCTION thunk_2663c8
0x2663cd: INT3 ; original byte CC, padding
0x2663ce: INT3 ; original byte CC, padding
0x2663cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d0 [0x2663d0, 0x2663d4] | file +0xcb0 | ev_22ff5ff4908294967385a694e23aaac6ac0ea8916a63f1fa973d669ba6fb8df0
thunk_2663d0:
0x2663d0: JMP 0x00b7f140
; END FUNCTION thunk_2663d0
0x2663d5: INT3 ; original byte CC, padding
0x2663d6: INT3 ; original byte CC, padding
0x2663d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d8 [0x2663d8, 0x2663dc] | file +0xcb8 | ev_34a23c6ea3b7a2d859dc68cf0179d2e6e3f54574cdd2132544206387c29aa21e
thunk_2663d8:
0x2663d8: JMP 0x00ae35e0
; END FUNCTION thunk_2663d8
0x2663dd: INT3 ; original byte CC, padding
0x2663de: INT3 ; original byte CC, padding
0x2663df: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e0 [0x2663e0, 0x2663e4] | file +0xcc0 | ev_5cb448dfe07b9a4edd1fcf0107805a9bd7ea03b9d2747e2e94001efd67a9feb3
thunk_2663e0:
0x2663e0: JMP 0x004eee20
; END FUNCTION thunk_2663e0
0x2663e5: INT3 ; original byte CC, padding
0x2663e6: INT3 ; original byte CC, padding
0x2663e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e8 [0x2663e8, 0x2663ec] | file +0xcc8 | ev_197bd45d13ebaabd9a99bf7238e2da2d83a7c121b47a589578b35369fae3ff3b
thunk_2663e8:
0x2663e8: JMP 0x008fab10
; END FUNCTION thunk_2663e8
0x2663ed: INT3 ; original byte CC, padding
0x2663ee: INT3 ; original byte CC, padding
0x2663ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f0 [0x2663f0, 0x2663f4] | file +0xcd0 | ev_390cff6484046a0500dd687e1027f4b3ccfb2934b44486aa755a95431a7fe4a2
thunk_2663f0:
0x2663f0: JMP 0x008fae30
; END FUNCTION thunk_2663f0
0x2663f5: INT3 ; original byte CC, padding
0x2663f6: INT3 ; original byte CC, padding
0x2663f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f8 [0x2663f8, 0x2663fc] | file +0xcd8 | ev_3c5fc25132a91f686abd292661e26aae09b02682ce5c53c831b4f6f03827049a
thunk_2663f8:
0x2663f8: JMP 0x009c9220
; END FUNCTION thunk_2663f8
0x2663fd: INT3 ; original byte CC, padding
0x2663fe: INT3 ; original byte CC, padding
0x2663ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266400 [0x266400, 0x266404] | file +0xce0 | ev_57db6d921f8026b55dc8e147118e9d9cb10f40830fcbb9a59701387c437a9d1b
thunk_266400:
0x266400: JMP 0x009c9100
; END FUNCTION thunk_266400
0x266405: INT3 ; original byte CC, padding
0x266406: INT3 ; original byte CC, padding
0x266407: INT3 ; original byte CC, padding

; FUNCTION thunk_266408 [0x266408, 0x26640c] | file +0xce8 | ev_d0a17fb65beb653cf741b97d5f412cf3674a53cfab34f587c8e6b0c6abb9c4c8
thunk_266408:
0x266408: JMP 0x00642310
; END FUNCTION thunk_266408
0x26640d: INT3 ; original byte CC, padding
0x26640e: INT3 ; original byte CC, padding
0x26640f: INT3 ; original byte CC, padding

; FUNCTION thunk_266410 [0x266410, 0x266414] | file +0xcf0 | ev_9fc7135a6d4d0bcf4f8046fe5a5ef91b770aeba84442b46d8339d885842b2c6b
thunk_266410:
0x266410: JMP 0x00642820
; END FUNCTION thunk_266410
0x266415: INT3 ; original byte CC, padding
0x266416: INT3 ; original byte CC, padding
0x266417: INT3 ; original byte CC, padding

; FUNCTION thunk_266418 [0x266418, 0x26641c] | file +0xcf8 | ev_2b57d9748536f30d1ad30c74b67122f3d29f2da19d2d2c776b1e549e6b375495
thunk_266418:
0x266418: JMP 0x006436e0
; END FUNCTION thunk_266418
0x26641d: INT3 ; original byte CC, padding
0x26641e: INT3 ; original byte CC, padding
0x26641f: INT3 ; original byte CC, padding

; FUNCTION thunk_266420 [0x266420, 0x266424] | file +0xd00 | ev_5731453af60ee21737f0a19f8df3841abc1185e5f887c5a2651f9da56f35dd45
thunk_266420:
0x266420: JMP 0x006438d0
; END FUNCTION thunk_266420
0x266425: INT3 ; original byte CC, padding
0x266426: INT3 ; original byte CC, padding
0x266427: INT3 ; original byte CC, padding

; FUNCTION thunk_266428 [0x266428, 0x26642c] | file +0xd08 | ev_e36675918b3af93a0ba702a21607e01ed6c6402aec3ced61dede9f937ad73f86
thunk_266428:
0x266428: JMP 0x00643c60
; END FUNCTION thunk_266428
0x26642d: INT3 ; original byte CC, padding
0x26642e: INT3 ; original byte CC, padding
0x26642f: INT3 ; original byte CC, padding

; FUNCTION thunk_266430 [0x266430, 0x266434] | file +0xd10 | ev_6a04f2314e3bd552a5cfa9f286543184288bcceb388acd83f0f89386e77844c5
thunk_266430:
0x266430: JMP 0x009f8290
; END FUNCTION thunk_266430
0x266435: INT3 ; original byte CC, padding
0x266436: INT3 ; original byte CC, padding
0x266437: INT3 ; original byte CC, padding

; FUNCTION thunk_266438 [0x266438, 0x26643c] | file +0xd18 | ev_f0f29b9b58193821f977a76d6075531fc649104ed3ff9888e799ce9604452c14
thunk_266438:
0x266438: JMP 0x009fbb70
; END FUNCTION thunk_266438
0x26643d: INT3 ; original byte CC, padding
0x26643e: INT3 ; original byte CC, padding
0x26643f: INT3 ; original byte CC, padding

; FUNCTION thunk_266440 [0x266440, 0x266444] | file +0xd20 | ev_127a5173d91f5372221bc3d6a59f5ee274647c47100ccb53d2c9971e8f04095e
thunk_266440:
0x266440: JMP 0x00a45280
; END FUNCTION thunk_266440
0x266445: INT3 ; original byte CC, padding
0x266446: INT3 ; original byte CC, padding
0x266447: INT3 ; original byte CC, padding

; FUNCTION thunk_266448 [0x266448, 0x26644c] | file +0xd28 | ev_9f62465d050ae1689681c25f188166de765fef7a456d5df8e48326754e89d912
thunk_266448:
0x266448: JMP 0x00c87ca0
; END FUNCTION thunk_266448
0x26644d: INT3 ; original byte CC, padding
0x26644e: INT3 ; original byte CC, padding
0x26644f: INT3 ; original byte CC, padding

; FUNCTION thunk_266450 [0x266450, 0x266454] | file +0xd30 | ev_c67e3645f3916bc52308fafa2c022bb81b0d570232e6162a3b5bf0e618b49e6f
thunk_266450:
0x266450: JMP 0x009ff000
; END FUNCTION thunk_266450
0x266455: INT3 ; original byte CC, padding
0x266456: INT3 ; original byte CC, padding
0x266457: INT3 ; original byte CC, padding

; FUNCTION thunk_266458 [0x266458, 0x26645c] | file +0xd38 | ev_9094c60b8bf24caf27dfc6ca1cc5af5d2c0cc59d23e15835384bc32a6ebbb651
thunk_266458:
0x266458: JMP 0x00a00780
; END FUNCTION thunk_266458
0x26645d: INT3 ; original byte CC, padding
0x26645e: INT3 ; original byte CC, padding
0x26645f: INT3 ; original byte CC, padding

; FUNCTION thunk_266460 [0x266460, 0x266464] | file +0xd40 | ev_f967dc0dce327888fc081cf3a60385a6c81a79c39a438c911569b99b2c2970f7
thunk_266460:
0x266460: JMP 0x00a007e0
; END FUNCTION thunk_266460
0x266465: INT3 ; original byte CC, padding
0x266466: INT3 ; original byte CC, padding
0x266467: INT3 ; original byte CC, padding

; FUNCTION thunk_266468 [0x266468, 0x26646c] | file +0xd48 | ev_5bb2a3a4b48b10f438f6bfd412e4c2aacf8034f0398d15e36164eea11ac8baaa
thunk_266468:
0x266468: JMP 0x00abe830
; END FUNCTION thunk_266468
0x26646d: INT3 ; original byte CC, padding
0x26646e: INT3 ; original byte CC, padding
0x26646f: INT3 ; original byte CC, padding

; FUNCTION thunk_266470 [0x266470, 0x266474] | file +0xd50 | ev_be306a0fec488868836f0d090ee9360688d8f3815794a95290c9258d1f5c9a52
thunk_266470:
0x266470: JMP 0x009fcf30
; END FUNCTION thunk_266470
0x266475: INT3 ; original byte CC, padding
0x266476: INT3 ; original byte CC, padding
0x266477: INT3 ; original byte CC, padding

; FUNCTION thunk_266478 [0x266478, 0x26647c] | file +0xd58 | ev_922487f426c1b9f1e6487c6527a855ee8b87c562dc258ff108f54fe5ecbe0a5e
thunk_266478:
0x266478: JMP 0x005f0fc0
; END FUNCTION thunk_266478
0x26647d: INT3 ; original byte CC, padding
0x26647e: INT3 ; original byte CC, padding
0x26647f: INT3 ; original byte CC, padding

; FUNCTION thunk_266480 [0x266480, 0x266484] | file +0xd60 | ev_c8ec32f779da850e6799cd8600e705890b09ee79ea421903c0972a20aa3691d5
thunk_266480:
0x266480: JMP 0x008f73f0
; END FUNCTION thunk_266480
0x266485: INT3 ; original byte CC, padding
0x266486: INT3 ; original byte CC, padding
0x266487: INT3 ; original byte CC, padding

; FUNCTION thunk_266488 [0x266488, 0x26648c] | file +0xd68 | ev_0e6780b3ab0518de85ec8cb1b1a41b5328048b27e3d70609480c76c9a729a658
thunk_266488:
0x266488: JMP 0x004f7250
; END FUNCTION thunk_266488
0x26648d: INT3 ; original byte CC, padding
0x26648e: INT3 ; original byte CC, padding
0x26648f: INT3 ; original byte CC, padding

; FUNCTION thunk_266490 [0x266490, 0x266494] | file +0xd70 | ev_eac6950051720ccdf0ce61f974ce273efefff7871ba9f2c6388e5a8e3a8cf4ee
thunk_266490:
0x266490: JMP 0x009fdad0
; END FUNCTION thunk_266490
0x266495: INT3 ; original byte CC, padding
0x266496: INT3 ; original byte CC, padding
0x266497: INT3 ; original byte CC, padding

; FUNCTION thunk_266498 [0x266498, 0x26649c] | file +0xd78 | ev_ff1c155e08e26d495cf8504aee29f9999b292832e20c7561fa400036d5c41bfd
thunk_266498:
0x266498: JMP 0x009fddb0
; END FUNCTION thunk_266498
0x26649d: INT3 ; original byte CC, padding
0x26649e: INT3 ; original byte CC, padding
0x26649f: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a0 [0x2664a0, 0x2664a4] | file +0xd80 | ev_9afec5667fabacf37cd58916e41fef67ff924e46b1463d99a0f4bf58efef7597
thunk_2664a0:
0x2664a0: JMP 0x009fdf10
; END FUNCTION thunk_2664a0
0x2664a5: INT3 ; original byte CC, padding
0x2664a6: INT3 ; original byte CC, padding
0x2664a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a8 [0x2664a8, 0x2664ac] | file +0xd88 | ev_0c5f34727f071eb6c339e4b79622768bdaf09dbe3f4ed379509e311c30490ac2
thunk_2664a8:
0x2664a8: JMP 0x006444d0
; END FUNCTION thunk_2664a8
0x2664ad: INT3 ; original byte CC, padding
0x2664ae: INT3 ; original byte CC, padding
0x2664af: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b0 [0x2664b0, 0x2664b4] | file +0xd90 | ev_d48bdaa2800476d452e672b45b77e9cd08abbf106a93632ad6021e777d43d1c0
thunk_2664b0:
0x2664b0: JMP 0x00650fd0
; END FUNCTION thunk_2664b0
0x2664b5: INT3 ; original byte CC, padding
0x2664b6: INT3 ; original byte CC, padding
0x2664b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b8 [0x2664b8, 0x2664bc] | file +0xd98 | ev_ee3d8784b8bce47b4bda93ac32d92f80e18d040dbbb0f7e18230bda96f0e6a06
thunk_2664b8:
0x2664b8: JMP 0x009fea30
; END FUNCTION thunk_2664b8
0x2664bd: INT3 ; original byte CC, padding
0x2664be: INT3 ; original byte CC, padding
0x2664bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c0 [0x2664c0, 0x2664c4] | file +0xda0 | ev_80e8082dd778c1359f914df823d4e82cdf37fdd7e497c6fd37e38b496a711883
thunk_2664c0:
0x2664c0: JMP 0x004f7940
; END FUNCTION thunk_2664c0
0x2664c5: INT3 ; original byte CC, padding
0x2664c6: INT3 ; original byte CC, padding
0x2664c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c8 [0x2664c8, 0x2664cc] | file +0xda8 | ev_f002307638dc8b0656c4f4fc065ba5bf1a73cbb551ca6838d6c478ff89f08933
thunk_2664c8:
0x2664c8: JMP 0x00ab8ae0
; END FUNCTION thunk_2664c8
0x2664cd: INT3 ; original byte CC, padding
0x2664ce: INT3 ; original byte CC, padding
0x2664cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d0 [0x2664d0, 0x2664d4] | file +0xdb0 | ev_4cb91d7ac1a88bfa50ffc18582852cbc35933f3b7c1cd09cef419b49abf1ceae
thunk_2664d0:
0x2664d0: JMP 0x00abb660
; END FUNCTION thunk_2664d0
0x2664d5: INT3 ; original byte CC, padding
0x2664d6: INT3 ; original byte CC, padding
0x2664d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d8 [0x2664d8, 0x2664dc] | file +0xdb8 | ev_93971fce626806f71b48fa88650de2f3e837cbbf7a1a5b1a01c24609d7685e42
thunk_2664d8:
0x2664d8: JMP 0x009fe260
; END FUNCTION thunk_2664d8
0x2664dd: INT3 ; original byte CC, padding
0x2664de: INT3 ; original byte CC, padding
0x2664df: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e0 [0x2664e0, 0x2664e4] | file +0xdc0 | ev_0637971ec956a822522a0d24e1a2b33abdcc31e6e0968b663d4594b931fb59c6
thunk_2664e0:
0x2664e0: JMP 0x009fe4e0
; END FUNCTION thunk_2664e0
0x2664e5: INT3 ; original byte CC, padding
0x2664e6: INT3 ; original byte CC, padding
0x2664e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e8 [0x2664e8, 0x2664ec] | file +0xdc8 | ev_96f2eb78d44e2be90df1bfac8907de11a07fd1c20a137c512007f0794700cec0
thunk_2664e8:
0x2664e8: JMP 0x009fe630
; END FUNCTION thunk_2664e8
0x2664ed: INT3 ; original byte CC, padding
0x2664ee: INT3 ; original byte CC, padding
0x2664ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f0 [0x2664f0, 0x2664f4] | file +0xdd0 | ev_d07160a37d230e28275e29ea7fc0ead6f9f93e14db0a551c24c70ee037fe8547
thunk_2664f0:
0x2664f0: JMP 0x00798330
; END FUNCTION thunk_2664f0
0x2664f5: INT3 ; original byte CC, padding
0x2664f6: INT3 ; original byte CC, padding
0x2664f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f8 [0x2664f8, 0x2664fc] | file +0xdd8 | ev_9d7c483a683c8982d49d9799eceee79a3cdf2e18a6b44d8f5196a2a5583aee1a
thunk_2664f8:
0x2664f8: JMP 0x00abd000
; END FUNCTION thunk_2664f8
0x2664fd: INT3 ; original byte CC, padding
0x2664fe: INT3 ; original byte CC, padding
0x2664ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266500 [0x266500, 0x266504] | file +0xde0 | ev_c07731e10bb7a1e470f23c0481586c9a79f74361b124421bf746e95b99a5ae93
thunk_266500:
0x266500: JMP 0x000fc890
; END FUNCTION thunk_266500
0x266505: INT3 ; original byte CC, padding
0x266506: INT3 ; original byte CC, padding
0x266507: INT3 ; original byte CC, padding

; FUNCTION thunk_266508 [0x266508, 0x26650c] | file +0xde8 | ev_1e6f012c63f03e4c7afa6e0683fef2ded8312a616632d2bc042c027e9cf07565
thunk_266508:
0x266508: JMP 0x0049f090
; END FUNCTION thunk_266508
0x26650d: INT3 ; original byte CC, padding
0x26650e: INT3 ; original byte CC, padding
0x26650f: INT3 ; original byte CC, padding

; FUNCTION thunk_266510 [0x266510, 0x266514] | file +0xdf0 | ev_dee16371c42076c27084c7b50a89913f1c7863ce6228e387f88210c14185bb3a
thunk_266510:
0x266510: JMP 0x0049f200
; END FUNCTION thunk_266510
0x266515: INT3 ; original byte CC, padding
0x266516: INT3 ; original byte CC, padding
0x266517: INT3 ; original byte CC, padding

; FUNCTION thunk_266518 [0x266518, 0x26651c] | file +0xdf8 | ev_a058a528785a3cc58198c17c8dc1925048f41e95131251d68285c6b501aafcf4
thunk_266518:
0x266518: JMP 0x004c0590
; END FUNCTION thunk_266518
0x26651d: INT3 ; original byte CC, padding
0x26651e: INT3 ; original byte CC, padding
0x26651f: INT3 ; original byte CC, padding

; FUNCTION thunk_266520 [0x266520, 0x266524] | file +0xe00 | ev_9c4b34282938bf36e1ebd5dfb17568acc7f2ae9dc7d37ca8532f66102dcc05f5
thunk_266520:
0x266520: JMP 0x004c05b0
; END FUNCTION thunk_266520
0x266525: INT3 ; original byte CC, padding
0x266526: INT3 ; original byte CC, padding
0x266527: INT3 ; original byte CC, padding

; FUNCTION thunk_266528 [0x266528, 0x26652c] | file +0xe08 | ev_510b5e50d52f5d207b82eef585db3edfcdd3041c8ffd642236f3957145d64a8f
thunk_266528:
0x266528: JMP 0x000a9430
; END FUNCTION thunk_266528
0x26652d: INT3 ; original byte CC, padding
0x26652e: INT3 ; original byte CC, padding
0x26652f: INT3 ; original byte CC, padding

; FUNCTION thunk_266530 [0x266530, 0x266534] | file +0xe10 | ev_3a5134362781c6d2c668f7e3314cc6a65b2f5285c575ecca40cd49d5040c24c1
thunk_266530:
0x266530: JMP 0x004ca350
; END FUNCTION thunk_266530
0x266535: INT3 ; original byte CC, padding
0x266536: INT3 ; original byte CC, padding
0x266537: INT3 ; original byte CC, padding

; FUNCTION thunk_266538 [0x266538, 0x26653c] | file +0xe18 | ev_8f8bff6001bcc400d3026e1885d9d081268397ec60954c6f57d10812e981a85e
thunk_266538:
0x266538: JMP 0x004caa40
; END FUNCTION thunk_266538
0x26653d: INT3 ; original byte CC, padding
0x26653e: INT3 ; original byte CC, padding
0x26653f: INT3 ; original byte CC, padding

; FUNCTION thunk_266540 [0x266540, 0x266544] | file +0xe20 | ev_d62a46be2c40b28d5f4aa8189bfefe8245f83f992b2d039b6320fa7b30c2cb03
thunk_266540:
0x266540: JMP 0x000aa510
; END FUNCTION thunk_266540
0x266545: INT3 ; original byte CC, padding
0x266546: INT3 ; original byte CC, padding
0x266547: INT3 ; original byte CC, padding

; FUNCTION thunk_266548 [0x266548, 0x26654c] | file +0xe28 | ev_4f04853bf68c590f0c12431b9a942d2d53521c34c9c89c2a5ff51e8aa24f25a9
thunk_266548:
0x266548: JMP 0x004d51d0
; END FUNCTION thunk_266548
0x26654d: INT3 ; original byte CC, padding
0x26654e: INT3 ; original byte CC, padding
0x26654f: INT3 ; original byte CC, padding

; FUNCTION thunk_266550 [0x266550, 0x266554] | file +0xe30 | ev_48c24e846bbea721b69c29780cba7eca1dd5efc88062c725a2b36e5eedc146cb
thunk_266550:
0x266550: JMP 0x008111b0
; END FUNCTION thunk_266550
0x266555: INT3 ; original byte CC, padding
0x266556: INT3 ; original byte CC, padding
0x266557: INT3 ; original byte CC, padding

; FUNCTION thunk_266558 [0x266558, 0x26655c] | file +0xe38 | ev_52e069bbab5228f4e691ccbf934368856bb89a90b72181270e08558cfea35f8a
thunk_266558:
0x266558: JMP 0x0001ae90
; END FUNCTION thunk_266558
0x26655d: INT3 ; original byte CC, padding
0x26655e: INT3 ; original byte CC, padding
0x26655f: INT3 ; original byte CC, padding

; FUNCTION thunk_266560 [0x266560, 0x266564] | file +0xe40 | ev_e91e51e4026fb5d054d11b40d42ef31bf3a18612cafbb880f2af3b25c4b6eb5d
thunk_266560:
0x266560: JMP 0x004f0030
; END FUNCTION thunk_266560
0x266565: INT3 ; original byte CC, padding
0x266566: INT3 ; original byte CC, padding
0x266567: INT3 ; original byte CC, padding

; FUNCTION thunk_266568 [0x266568, 0x26656c] | file +0xe48 | ev_aeae8c8acd7deace89e69e155c6a30e5941f3f2f11ad32f21f70ce92f24451b7
thunk_266568:
0x266568: JMP 0x004fbbd0
; END FUNCTION thunk_266568
0x26656d: INT3 ; original byte CC, padding
0x26656e: INT3 ; original byte CC, padding
0x26656f: INT3 ; original byte CC, padding

; FUNCTION thunk_266570 [0x266570, 0x266574] | file +0xe50 | ev_79da496439052e9f20d766207934d2c884760604dc1329284f73b2992d92df31
thunk_266570:
0x266570: JMP 0x0050ced0
; END FUNCTION thunk_266570
0x266575: INT3 ; original byte CC, padding
0x266576: INT3 ; original byte CC, padding
0x266577: INT3 ; original byte CC, padding

; FUNCTION thunk_266578 [0x266578, 0x26657c] | file +0xe58 | ev_964d4b815a68973efd6e7497a577ce655d463705de549f248cde2a68066a59df
thunk_266578:
0x266578: JMP 0x0050cee0
; END FUNCTION thunk_266578
0x26657d: INT3 ; original byte CC, padding
0x26657e: INT3 ; original byte CC, padding
0x26657f: INT3 ; original byte CC, padding

; FUNCTION thunk_266580 [0x266580, 0x266584] | file +0xe60 | ev_aefa1f19195c0d79f1651ddb2f1a627ca1439c9bf20aac8cc008d0961a79170e
thunk_266580:
0x266580: JMP 0x0050cf30
; END FUNCTION thunk_266580
0x266585: INT3 ; original byte CC, padding
0x266586: INT3 ; original byte CC, padding
0x266587: INT3 ; original byte CC, padding

; FUNCTION thunk_266588 [0x266588, 0x26658c] | file +0xe68 | ev_b61af5a573168b66efe96561016fef3eeca97db1adbc8414497d0cb29ba0d7a0
thunk_266588:
0x266588: JMP 0x0050cf70
; END FUNCTION thunk_266588
0x26658d: INT3 ; original byte CC, padding
0x26658e: INT3 ; original byte CC, padding
0x26658f: INT3 ; original byte CC, padding

; FUNCTION thunk_266590 [0x266590, 0x266594] | file +0xe70 | ev_380bd567410144f9738e47feb993c3d6b679a6af88094979e1d777b20bb9580b
thunk_266590:
0x266590: JMP 0x0050cfb0
; END FUNCTION thunk_266590
0x266595: INT3 ; original byte CC, padding
0x266596: INT3 ; original byte CC, padding
0x266597: INT3 ; original byte CC, padding

; FUNCTION thunk_266598 [0x266598, 0x26659c] | file +0xe78 | ev_5868fd4afe999e7d1aafb7358aece988818e1a7228a241c440d4dad25303d370
thunk_266598:
0x266598: JMP 0x0050cfe0
; END FUNCTION thunk_266598
0x26659d: INT3 ; original byte CC, padding
0x26659e: INT3 ; original byte CC, padding
0x26659f: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a0 [0x2665a0, 0x2665a4] | file +0xe80 | ev_1d3af3466642591fb9ae548773fa77f270dfa1e30126c5557abfe8798a26ea1e
thunk_2665a0:
0x2665a0: JMP 0x0051e4d0
; END FUNCTION thunk_2665a0
0x2665a5: INT3 ; original byte CC, padding
0x2665a6: INT3 ; original byte CC, padding
0x2665a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a8 [0x2665a8, 0x2665ac] | file +0xe88 | ev_632d3b384b31fc7b5fe70b62f0039def1d96dbfe25f77005039f00d57bcd942f
thunk_2665a8:
0x2665a8: JMP 0x0051ef60
; END FUNCTION thunk_2665a8
0x2665ad: INT3 ; original byte CC, padding
0x2665ae: INT3 ; original byte CC, padding
0x2665af: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b0 [0x2665b0, 0x2665b4] | file +0xe90 | ev_94edde6bfb8961eb7e729bdd77dd0bf926b17201e8338e7cb1020119fa0f2234
thunk_2665b0:
0x2665b0: JMP 0x0051f000
; END FUNCTION thunk_2665b0
0x2665b5: INT3 ; original byte CC, padding
0x2665b6: INT3 ; original byte CC, padding
0x2665b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b8 [0x2665b8, 0x2665bc] | file +0xe98 | ev_f2e9166c9f386acb417d242b86be346cf51f95e0d63976665a57af55744197ea
thunk_2665b8:
0x2665b8: JMP 0x0051f0b0
; END FUNCTION thunk_2665b8
0x2665bd: INT3 ; original byte CC, padding
0x2665be: INT3 ; original byte CC, padding
0x2665bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c0 [0x2665c0, 0x2665c4] | file +0xea0 | ev_9407f2080d4104ecd0eaff2585ea6744706bbd910f81860ffc7e9ba4d938f5e3
thunk_2665c0:
0x2665c0: JMP 0x0051f2e0
; END FUNCTION thunk_2665c0
0x2665c5: INT3 ; original byte CC, padding
0x2665c6: INT3 ; original byte CC, padding
0x2665c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c8 [0x2665c8, 0x2665cc] | file +0xea8 | ev_6c6f0cc089b1226a7d6726d9e43a828973723387ff0e9e1f51a32e4aab932f5b
thunk_2665c8:
0x2665c8: JMP 0x0051f670
; END FUNCTION thunk_2665c8
0x2665cd: INT3 ; original byte CC, padding
0x2665ce: INT3 ; original byte CC, padding
0x2665cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d0 [0x2665d0, 0x2665d4] | file +0xeb0 | ev_de593e95b52c6954e7b5a8bdf1fb7eb8da68f265b88d3ee5ca370c7dbbf35a50
thunk_2665d0:
0x2665d0: JMP 0x0051fee0
; END FUNCTION thunk_2665d0
0x2665d5: INT3 ; original byte CC, padding
0x2665d6: INT3 ; original byte CC, padding
0x2665d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d8 [0x2665d8, 0x2665dc] | file +0xeb8 | ev_4b6c006f374d6f4364ae18785bffb8f9246c17dd08eccb325d682318cb34ba97
thunk_2665d8:
0x2665d8: JMP 0x00536400
; END FUNCTION thunk_2665d8
0x2665dd: INT3 ; original byte CC, padding
0x2665de: INT3 ; original byte CC, padding
0x2665df: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e0 [0x2665e0, 0x2665e4] | file +0xec0 | ev_1d5df3f7cc5b94434a0bcdd6c8bd3650cf445e8eb753129dbf8f5e0f70a0eb1d
thunk_2665e0:
0x2665e0: JMP 0x00544ca0
; END FUNCTION thunk_2665e0
0x2665e5: INT3 ; original byte CC, padding
0x2665e6: INT3 ; original byte CC, padding
0x2665e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e8 [0x2665e8, 0x2665ec] | file +0xec8 | ev_0d9fc998f59eb9321b785945f66f8959c5918c8ad836154bb965bd9d2296264a
thunk_2665e8:
0x2665e8: JMP 0x005468f0
; END FUNCTION thunk_2665e8
0x2665ed: INT3 ; original byte CC, padding
0x2665ee: INT3 ; original byte CC, padding
0x2665ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f0 [0x2665f0, 0x2665f4] | file +0xed0 | ev_b116196a64488efd9c1b72ae3c533266522eda4a8fbb1b6e79e2733335a24e78
thunk_2665f0:
0x2665f0: JMP 0x000b1630
; END FUNCTION thunk_2665f0
0x2665f5: INT3 ; original byte CC, padding
0x2665f6: INT3 ; original byte CC, padding
0x2665f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f8 [0x2665f8, 0x2665fc] | file +0xed8 | ev_3b702acb66c6b631c54492df6681303acc0017b9df69368f5a242ed562b21de5
thunk_2665f8:
0x2665f8: JMP 0x000b1fb0
; END FUNCTION thunk_2665f8
0x2665fd: INT3 ; original byte CC, padding
0x2665fe: INT3 ; original byte CC, padding
0x2665ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266600 [0x266600, 0x266604] | file +0xee0 | ev_1e07f001454166a3d1932f149491dd8e8ad0f746dbb751dbb62e05df4eb73cec
thunk_266600:
0x266600: JMP 0x0055bf40
; END FUNCTION thunk_266600
0x266605: INT3 ; original byte CC, padding
0x266606: INT3 ; original byte CC, padding
0x266607: INT3 ; original byte CC, padding

; FUNCTION thunk_266608 [0x266608, 0x26660c] | file +0xee8 | ev_fdaa12aca219d327f7b7013a4ac2ce6fb1668e6c95796c879ae08ad0a9a4d14c
thunk_266608:
0x266608: JMP 0x0055c030
; END FUNCTION thunk_266608
0x26660d: INT3 ; original byte CC, padding
0x26660e: INT3 ; original byte CC, padding
0x26660f: INT3 ; original byte CC, padding

; FUNCTION thunk_266610 [0x266610, 0x266614] | file +0xef0 | ev_cb7af76482977ad5099e10759b4f36bd807a74c02238ba70d09d477b0787d1b8
thunk_266610:
0x266610: JMP 0x0055c050
; END FUNCTION thunk_266610
0x266615: INT3 ; original byte CC, padding
0x266616: INT3 ; original byte CC, padding
0x266617: INT3 ; original byte CC, padding

; FUNCTION thunk_266618 [0x266618, 0x26661c] | file +0xef8 | ev_2bd9ac4e5e57f7adc97febe9846d1970db4ebd1190c8f9d8982c660d0253753e
thunk_266618:
0x266618: JMP 0x0056e200
; END FUNCTION thunk_266618
0x26661d: INT3 ; original byte CC, padding
0x26661e: INT3 ; original byte CC, padding
0x26661f: INT3 ; original byte CC, padding

; FUNCTION thunk_266620 [0x266620, 0x266624] | file +0xf00 | ev_593b98f7dc50a27a5588c48f4c17f1866befccab7662293c7e2333a3d50a6f4b
thunk_266620:
0x266620: JMP 0x0057f4a0
; END FUNCTION thunk_266620
0x266625: INT3 ; original byte CC, padding
0x266626: INT3 ; original byte CC, padding
0x266627: INT3 ; original byte CC, padding

; FUNCTION thunk_266628 [0x266628, 0x26662c] | file +0xf08 | ev_c5b83f0108bf44ae90930b50d0263279ff36467be223d600ced8fc96d2ee7929
thunk_266628:
0x266628: JMP 0x009945e0
; END FUNCTION thunk_266628
0x26662d: INT3 ; original byte CC, padding
0x26662e: INT3 ; original byte CC, padding
0x26662f: INT3 ; original byte CC, padding

; FUNCTION thunk_266630 [0x266630, 0x266634] | file +0xf10 | ev_5cf6d423437e99ddbb8cd8e4b40d39012dc65b942cb0c1269e98656d4e28ed42
thunk_266630:
0x266630: JMP 0x00585950
; END FUNCTION thunk_266630
0x266635: INT3 ; original byte CC, padding
0x266636: INT3 ; original byte CC, padding
0x266637: INT3 ; original byte CC, padding

; FUNCTION thunk_266638 [0x266638, 0x26663c] | file +0xf18 | ev_d3864fbae4a854bea158517502d07e2c640eed4f08054721bfa77e8437796a78
thunk_266638:
0x266638: JMP 0x00599820
; END FUNCTION thunk_266638
0x26663d: INT3 ; original byte CC, padding
0x26663e: INT3 ; original byte CC, padding
0x26663f: INT3 ; original byte CC, padding

; FUNCTION thunk_266640 [0x266640, 0x266644] | file +0xf20 | ev_0cf72c58a29aa48fdbeb3fe7471ccca3f55d02275a6b8e57bc8b493e93cc1983
thunk_266640:
0x266640: JMP 0x0059a3e0
; END FUNCTION thunk_266640
0x266645: INT3 ; original byte CC, padding
0x266646: INT3 ; original byte CC, padding
0x266647: INT3 ; original byte CC, padding

; FUNCTION thunk_266648 [0x266648, 0x26664c] | file +0xf28 | ev_88f8129ae070b59174d6629166daaf3cda09a413acdfd11e27c52697cea4e330
thunk_266648:
0x266648: JMP 0x0059a530
; END FUNCTION thunk_266648
0x26664d: INT3 ; original byte CC, padding
0x26664e: INT3 ; original byte CC, padding
0x26664f: INT3 ; original byte CC, padding

; FUNCTION thunk_266650 [0x266650, 0x266654] | file +0xf30 | ev_29da0dc73a44fd6dd2fd8d2091508c58564f4dc190a01efc2144843c6eda23f0
thunk_266650:
0x266650: JMP 0x0059a700
; END FUNCTION thunk_266650
0x266655: INT3 ; original byte CC, padding
0x266656: INT3 ; original byte CC, padding
0x266657: INT3 ; original byte CC, padding

; FUNCTION thunk_266658 [0x266658, 0x26665c] | file +0xf38 | ev_059a725bfe974d6b155fb60d27a08b661ebed71bef5f0cce2b6d74d7843196d6
thunk_266658:
0x266658: JMP 0x0059a7d0
; END FUNCTION thunk_266658
0x26665d: INT3 ; original byte CC, padding
0x26665e: INT3 ; original byte CC, padding
0x26665f: INT3 ; original byte CC, padding

; FUNCTION thunk_266660 [0x266660, 0x266664] | file +0xf40 | ev_aa770d9229105e8de9473b32c45eeab911e8040c7ead3a62086c8d81c0d63057
thunk_266660:
0x266660: JMP 0x0059aa50
; END FUNCTION thunk_266660
0x266665: INT3 ; original byte CC, padding
0x266666: INT3 ; original byte CC, padding
0x266667: INT3 ; original byte CC, padding

; FUNCTION thunk_266668 [0x266668, 0x26666c] | file +0xf48 | ev_5d8df5e689d73705cbe7911573c11e59f4c9dd14d7742265fe52131f8ffed6b8
thunk_266668:
0x266668: JMP 0x0059ab60
; END FUNCTION thunk_266668
0x26666d: INT3 ; original byte CC, padding
0x26666e: INT3 ; original byte CC, padding
0x26666f: INT3 ; original byte CC, padding

; FUNCTION thunk_266670 [0x266670, 0x266674] | file +0xf50 | ev_7497aa6f9391ccfe9f178de8d2e7b33b9d2692702e8fa5c686d888375be21115
thunk_266670:
0x266670: JMP 0x0059ac60
; END FUNCTION thunk_266670
0x266675: INT3 ; original byte CC, padding
0x266676: INT3 ; original byte CC, padding
0x266677: INT3 ; original byte CC, padding

; FUNCTION thunk_266678 [0x266678, 0x26667c] | file +0xf58 | ev_fd4b2d5033671b632bd9ee613bf95e7cf74b995cf067e25317f6f7a4520daf2e
thunk_266678:
0x266678: JMP 0x005dbed0
; END FUNCTION thunk_266678
0x26667d: INT3 ; original byte CC, padding
0x26667e: INT3 ; original byte CC, padding
0x26667f: INT3 ; original byte CC, padding

; FUNCTION thunk_266680 [0x266680, 0x266684] | file +0xf60 | ev_004be00b548657d12bea0e98f33bf3f7a871049b0855b14afdbb795e680d4ad8
thunk_266680:
0x266680: JMP 0x005eb720
; END FUNCTION thunk_266680
0x266685: INT3 ; original byte CC, padding
0x266686: INT3 ; original byte CC, padding
0x266687: INT3 ; original byte CC, padding

; FUNCTION thunk_266688 [0x266688, 0x26668c] | file +0xf68 | ev_c2162fb02fda50b640447f399c71ba268fd1992045f11f539a8a435a1ca274d1
thunk_266688:
0x266688: JMP 0x005ec030
; END FUNCTION thunk_266688
0x26668d: INT3 ; original byte CC, padding
0x26668e: INT3 ; original byte CC, padding
0x26668f: INT3 ; original byte CC, padding

; FUNCTION thunk_266690 [0x266690, 0x266694] | file +0xf70 | ev_eba0a4a74aa12436710862f2312ae575bf8a217d97a1ddb3ccb9c80335d6bd81
thunk_266690:
0x266690: JMP 0x005ecad0
; END FUNCTION thunk_266690
0x266695: INT3 ; original byte CC, padding
0x266696: INT3 ; original byte CC, padding
0x266697: INT3 ; original byte CC, padding

; FUNCTION thunk_266698 [0x266698, 0x26669c] | file +0xf78 | ev_5fda6a92c9d55295ca631a21884e06a3cc98de9725e3b4f37061e33c265cc0b4
thunk_266698:
0x266698: JMP 0x005ed440
; END FUNCTION thunk_266698
0x26669d: INT3 ; original byte CC, padding
0x26669e: INT3 ; original byte CC, padding
0x26669f: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a0 [0x2666a0, 0x2666a4] | file +0xf80 | ev_5f098f7d02fc4507b375d5517da227a6c9a7e570c92a3cf19b16b6907dea6e73
thunk_2666a0:
0x2666a0: JMP 0x005edb30
; END FUNCTION thunk_2666a0
0x2666a5: INT3 ; original byte CC, padding
0x2666a6: INT3 ; original byte CC, padding
0x2666a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a8 [0x2666a8, 0x2666ac] | file +0xf88 | ev_368ebdf88ad88722afc8583b9a3f7b89ca149ef8151b207eaf213873b8d1b44b
thunk_2666a8:
0x2666a8: JMP 0x0014e280
; END FUNCTION thunk_2666a8
0x2666ad: INT3 ; original byte CC, padding
0x2666ae: INT3 ; original byte CC, padding
0x2666af: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b0 [0x2666b0, 0x2666b4] | file +0xf90 | ev_f48e2b21b39a7345cb8d6ccb11d68b5ddef61b23b3541819fb5f1f578f38f5fa
thunk_2666b0:
0x2666b0: JMP 0x005f18b0
; END FUNCTION thunk_2666b0
0x2666b5: INT3 ; original byte CC, padding
0x2666b6: INT3 ; original byte CC, padding
0x2666b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b8 [0x2666b8, 0x2666bc] | file +0xf98 | ev_ac4f1a25a415e295b1ecdd613c8acebed207e1359f2d047e975a29135068af7a
thunk_2666b8:
0x2666b8: JMP 0x005f2b30
; END FUNCTION thunk_2666b8
0x2666bd: INT3 ; original byte CC, padding
0x2666be: INT3 ; original byte CC, padding
0x2666bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c0 [0x2666c0, 0x2666c4] | file +0xfa0 | ev_656228c91f4b9d17f428d6dad119fc03036809e7293dbd512e9704dab45f5346
thunk_2666c0:
0x2666c0: JMP 0x005fd0c0
; END FUNCTION thunk_2666c0
0x2666c5: INT3 ; original byte CC, padding
0x2666c6: INT3 ; original byte CC, padding
0x2666c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c8 [0x2666c8, 0x2666cc] | file +0xfa8 | ev_f9890d98733cf5b105bc535a06caf9e4dbe5739cb70df00f29ea69a52a7ae404
thunk_2666c8:
0x2666c8: JMP 0x00600680
; END FUNCTION thunk_2666c8
0x2666cd: INT3 ; original byte CC, padding
0x2666ce: INT3 ; original byte CC, padding
0x2666cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d0 [0x2666d0, 0x2666d4] | file +0xfb0 | ev_5346064d60c1151772b5afcfea264e91ea0405ef3932ec33cb4e4f8798d67ef7
thunk_2666d0:
0x2666d0: JMP 0x00600f40
; END FUNCTION thunk_2666d0
0x2666d5: INT3 ; original byte CC, padding
0x2666d6: INT3 ; original byte CC, padding
0x2666d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d8 [0x2666d8, 0x2666dc] | file +0xfb8 | ev_f9366c8d734402c7bab13a139c6dd2e19a457b89a3715396d93d2b8f4fa6c02f
thunk_2666d8:
0x2666d8: JMP 0x00ae64a0
; END FUNCTION thunk_2666d8
0x2666dd: INT3 ; original byte CC, padding
0x2666de: INT3 ; original byte CC, padding
0x2666df: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e0 [0x2666e0, 0x2666e4] | file +0xfc0 | ev_921888daae08e4063aa4b63cfe29da6024b44a8fdb1f332ac4026f152cd8408b
thunk_2666e0:
0x2666e0: JMP 0x0062daa0
; END FUNCTION thunk_2666e0
0x2666e5: INT3 ; original byte CC, padding
0x2666e6: INT3 ; original byte CC, padding
0x2666e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e8 [0x2666e8, 0x2666ec] | file +0xfc8 | ev_b0ff6d81c0fda4a8690f4254c60494f3808bb2250b25c2646544d04989de6408
thunk_2666e8:
0x2666e8: JMP 0x006302d0
; END FUNCTION thunk_2666e8
0x2666ed: INT3 ; original byte CC, padding
0x2666ee: INT3 ; original byte CC, padding
0x2666ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f0 [0x2666f0, 0x2666f4] | file +0xfd0 | ev_fd18711d0a9cd1dc3c94bc30c0b90d2b0bf5a17834c0b37539f53fc9b04bada5
thunk_2666f0:
0x2666f0: JMP 0x00634f10
; END FUNCTION thunk_2666f0
0x2666f5: INT3 ; original byte CC, padding
0x2666f6: INT3 ; original byte CC, padding
0x2666f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f8 [0x2666f8, 0x2666fc] | file +0xfd8 | ev_b2d0914c0bf11ca8a6b63ad73c28879ba8112411cc44b55c9158e1f31f6828d2
thunk_2666f8:
0x2666f8: JMP 0x0063f520
; END FUNCTION thunk_2666f8
0x2666fd: INT3 ; original byte CC, padding
0x2666fe: INT3 ; original byte CC, padding
0x2666ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266700 [0x266700, 0x266704] | file +0xfe0 | ev_b3b8a09dd69c726029958431264c4518e87b5c6333736040e5583e3ffa5cfb33
thunk_266700:
0x266700: JMP 0x006579b0
; END FUNCTION thunk_266700
0x266705: INT3 ; original byte CC, padding
0x266706: INT3 ; original byte CC, padding
0x266707: INT3 ; original byte CC, padding

; FUNCTION thunk_266708 [0x266708, 0x26670c] | file +0xfe8 | ev_a1b1ecfb69ddcde3ab328e54879b2647bb27553f41929ae5021b46edd03a8fd6
thunk_266708:
0x266708: JMP 0x00ca7310
; END FUNCTION thunk_266708
0x26670d: INT3 ; original byte CC, padding
0x26670e: INT3 ; original byte CC, padding
0x26670f: INT3 ; original byte CC, padding

; FUNCTION thunk_266710 [0x266710, 0x266714] | file +0xff0 | ev_91a5d5c52dbb1d6be7f635bc2e634aa41a9d00a7b8b5d2ae096ecbfdcbfa2641
thunk_266710:
0x266710: JMP 0x00662e70
; END FUNCTION thunk_266710
0x266715: INT3 ; original byte CC, padding
0x266716: INT3 ; original byte CC, padding
0x266717: INT3 ; original byte CC, padding

; FUNCTION thunk_266718 [0x266718, 0x26671c] | file +0xff8 | ev_5d49490e833cb75f11ae327b52e57d63c8562abf36102eae069cd3b6103363e9
thunk_266718:
0x266718: JMP 0x00662e80
; END FUNCTION thunk_266718
0x26671d: INT3 ; original byte CC, padding
0x26671e: INT3 ; original byte CC, padding
0x26671f: INT3 ; original byte CC, padding


; ===== REA recovered target/context/helper functions =====

; original syscall trampoline; evidence ev_09f7171c1eb89f4876004d496f87803f6d8e5de62069bdfb5809a3a4247bb07d; body [{"start": "0x265720", "end": "0x265724"}]
<EXTERNAL>::thunk_EXT_FUN_003b01f0: ; RVA 0x265720
0x265720: JMP 0x003b01f0

; local helper / adjacent context (reachability below); evidence ev_74d5cc5f8079c896c216796da3fac7955b0326cfd5e69a1a6f8046d4cbcead50; body [{"start": "0x3b3410", "end": "0x3b3a33"}]
sub_3b3410: ; RVA 0x3b3410
0x3b3410: PUSH RBP
0x3b3411: MOV RBP, RSP
0x3b3414: PUSH R15
0x3b3416: PUSH R14
0x3b3418: PUSH R13
0x3b341a: PUSH R12
0x3b341c: PUSH RBX
0x3b341d: SUB RSP, 0x38
0x3b3421: LEA RAX, [0x391c310]
0x3b3428: MOV dword ptr [RBP + -0x48], EDI
0x3b342b: MOV RBX, RSI
0x3b342e: LEA RSI, [RBP + -0x34]
0x3b3432: MOV RAX, qword ptr [RAX]
0x3b3435: MOV qword ptr [RBP + -0x30], RAX
0x3b3439: MOV RAX, qword ptr GS:[0x0]
0x3b3442: MOV RDI, qword ptr [RAX + 0x8]
0x3b3446: MOV qword ptr [RBP + -0x58], RDI
0x3b344a: CALL 0x009f81c0
0x3b344f: TEST EAX, EAX
0x3b3451: LEA RDI, [0x34cf2e8]
0x3b3458: SETNZ byte ptr [RBP + -0x42]
0x3b345c: CMP dword ptr [RBP + -0x34], 0x1000000
0x3b3463: SETNC byte ptr [RBP + -0x41]
0x3b3467: XOR ESI, ESI
0x3b3469: XOR EDX, EDX
0x3b346b: XOR ECX, ECX
0x3b346d: CALL 0x004c6a00
0x3b3472: CMP dword ptr [RBX + 0x4a0], 0x0
0x3b3479: JZ 0x003b3502
0x3b347f: MOV R12D, 0x10
0x3b3485: JLE 0x003b34aa
0x3b3487: LEA RAX, [0x34cf8c8]
0x3b348e: XOR ECX, ECX
0x3b3490: CMP RBX, RAX
0x3b3493: CMOVZ R12D, ECX
0x3b3497: LEA R15, [0x391c310]
0x3b349e: LEA RDI, [0x34cf2e8]
0x3b34a5: JMP 0x003b37a1
0x3b34aa: LEA R13, [0x34cf2f0]
0x3b34b1: LEA R14, [0x34cf2d0]
0x3b34b8: LEA R15, [0x34cf2e8]
0x3b34bf: NOP
0x3b34c0: MOV RDI, R13
0x3b34c3: MOV RSI, R14
0x3b34c6: XOR EDX, EDX
0x3b34c8: CALL 0x0073e780
0x3b34cd: CMP dword ptr [RBX + 0x4a0], 0x0
0x3b34d4: MOV R12D, EAX
0x3b34d7: JNZ 0x003b3497
0x3b34d9: MOV RDI, R15
0x3b34dc: XOR ESI, ESI
0x3b34de: XOR EDX, EDX
0x3b34e0: XOR ECX, ECX
0x3b34e2: CALL 0x004c6fa0
0x3b34e7: MOV RDI, R15
0x3b34ea: XOR ESI, ESI
0x3b34ec: XOR EDX, EDX
0x3b34ee: XOR ECX, ECX
0x3b34f0: CALL 0x004c6a00
0x3b34f5: CMP dword ptr [RBX + 0x4a0], 0x0
0x3b34fc: JZ 0x003b3502
0x3b34fe: JLE 0x003b34c0
0x3b3500: JMP 0x003b3487
0x3b3502: CMP byte ptr [0x034d09d0], 0x0
0x3b3509: JNZ 0x003b3525
0x3b350b: LEA RDI, [0x34cf2f0]
0x3b3512: LEA RSI, [0x138ecf8]
0x3b3519: CALL 0x0073e520
0x3b351e: MOV byte ptr [0x034d09d0], 0x1
0x3b3525: LEA R12, [0x138ecff]
0x3b352c: LEA RDI, [RBX + 0xd8]
0x3b3533: MOV dword ptr [RBX + 0x4a0], 0xffffffff
0x3b353d: LEA R14, [RBX + 0x40]
0x3b3541: LEA R15, [RBX + 0x80]
0x3b3548: XOR EDX, EDX
0x3b354a: XOR ECX, ECX
0x3b354c: MOV RSI, R12
0x3b354f: CALL 0x004c7dd0
0x3b3554: LEA RDI, [RBX + 0xf8]
0x3b355b: MOV RSI, R12
0x3b355e: MOV qword ptr [RBX], 0x0
0x3b3565: MOV qword ptr [RBX + 0x8], RBX
0x3b3569: MOV qword ptr [RBX + 0x40], 0x0
0x3b3571: MOV qword ptr [RBX + 0x48], R14
0x3b3575: MOV qword ptr [RBX + 0x80], 0x0
0x3b3580: MOV qword ptr [RBX + 0x88], R15
0x3b3587: MOV dword ptr [RBX + 0x1c0], 0x0
0x3b3591: MOV dword ptr [RBX + 0x1d0], 0x0
0x3b359b: XOR EDX, EDX
0x3b359d: XOR ECX, ECX
0x3b359f: CALL 0x004c7dd0
0x3b35a4: LEA RAX, [RBX + 0x10]
0x3b35a8: LEA RDI, [RBX + 0x50]
0x3b35ac: LEA RSI, [RBX + 0x90]
0x3b35b3: MOV qword ptr [RBX + 0x10], 0x0
0x3b35bb: XOR EDX, EDX
0x3b35bd: XOR ECX, ECX
0x3b35bf: MOV qword ptr [RBX + 0x18], RAX
0x3b35c3: MOV qword ptr [RBX + 0x50], 0x0
0x3b35cb: MOV qword ptr [RBX + 0x58], RDI
0x3b35cf: MOV qword ptr [RBX + 0x90], 0x0
0x3b35da: MOV qword ptr [RBX + 0x98], RSI
0x3b35e1: LEA RDI, [RBX + 0x118]
0x3b35e8: MOV RSI, R12
0x3b35eb: MOV dword ptr [RBX + 0x1c4], 0x0
0x3b35f5: MOV dword ptr [RBX + 0x1d4], 0x0
0x3b35ff: CALL 0x004c7dd0
0x3b3604: LEA RAX, [RBX + 0x20]
0x3b3608: LEA RDI, [RBX + 0x60]
0x3b360c: LEA RSI, [RBX + 0xa0]
0x3b3613: MOV qword ptr [RBX + 0x20], 0x0
0x3b361b: XOR EDX, EDX
0x3b361d: XOR ECX, ECX
0x3b361f: MOV qword ptr [RBX + 0x28], RAX
0x3b3623: MOV qword ptr [RBX + 0x60], 0x0
0x3b362b: MOV qword ptr [RBX + 0x68], RDI
0x3b362f: MOV qword ptr [RBX + 0xa0], 0x0
0x3b363a: MOV qword ptr [RBX + 0xa8], RSI
0x3b3641: LEA RDI, [RBX + 0x138]
0x3b3648: MOV RSI, R12
0x3b364b: MOV dword ptr [RBX + 0x1c8], 0x0
0x3b3655: MOV dword ptr [RBX + 0x1d8], 0x0
0x3b365f: CALL 0x004c7dd0
0x3b3664: LEA RAX, [RBX + 0x30]
0x3b3668: LEA R8, [RBX + 0x70]
0x3b366c: LEA RDI, [RBX + 0xb0]
0x3b3673: MOV qword ptr [RBX + 0x30], 0x0
0x3b367b: XOR ESI, ESI
0x3b367d: XOR EDX, EDX
0x3b367f: XOR ECX, ECX
0x3b3681: MOV qword ptr [RBX + 0x38], RAX
0x3b3685: MOV qword ptr [RBX + 0x70], 0x0
0x3b368d: MOV qword ptr [RBX + 0x78], R8
0x3b3691: MOV qword ptr [RBX + 0xb0], 0x0
0x3b369c: MOV qword ptr [RBX + 0xb8], RDI
0x3b36a3: LEA RDI, [0x34cf2e8]
0x3b36aa: MOV dword ptr [RBX + 0x1cc], 0x0
0x3b36b4: MOV dword ptr [RBX + 0x1dc], 0x0
0x3b36be: CALL 0x004c6fa0
0x3b36c3: LEA R15, [0x12e78ee]
0x3b36ca: LEA R13, [0x12bdaa1]
0x3b36d1: LEA R14, [0x126d8c2]
0x3b36d8: MOV qword ptr [RBP + -0x40], 0x0
0x3b36e0: XOR EAX, EAX
0x3b36e2: LEA RSI, [RBX + 0x4b0]
0x3b36e9: MOV qword ptr [RBX + 0x4c8], RBX
0x3b36f0: LEA RCX, [RBX + 0x4b8]
0x3b36f7: LEA RDI, [0x261790]
0x3b36fe: LEA RDX, [RBP + -0x40]
0x3b3702: XOR R8D, R8D
0x3b3705: XOR R9D, R9D
0x3b3708: PUSH 0x0
0x3b370a: PUSH R15
0x3b370c: PUSH R13
0x3b370e: PUSH R14
0x3b3710: CALL 0x009262d0
0x3b3715: ADD RSP, 0x20
0x3b3719: TEST EAX, EAX
0x3b371b: JNZ 0x003b3771
0x3b371d: LEA RSI, [RBX + 0x528]
0x3b3724: MOV qword ptr [RBX + 0x4b0], 0x0
0x3b372f: MOV qword ptr [RBP + -0x40], 0x0
0x3b3737: XOR EAX, EAX
0x3b3739: MOV qword ptr [RBX + 0x540], RBX
0x3b3740: LEA RCX, [RBX + 0x530]
0x3b3747: LEA RDI, [0x261790]
0x3b374e: LEA RDX, [RBP + -0x40]
0x3b3752: XOR R8D, R8D
0x3b3755: XOR R9D, R9D
0x3b3758: MOV qword ptr [RBP + -0x50], RSI
0x3b375c: PUSH 0x1
0x3b375e: PUSH R15
0x3b3760: PUSH R13
0x3b3762: PUSH R14
0x3b3764: CALL 0x009262d0
0x3b3769: ADD RSP, 0x20
0x3b376d: TEST EAX, EAX
0x3b376f: JZ 0x003b37cb
0x3b3771: LEA R15, [0x391c310]
0x3b3778: LEA RBX, [0x34cf2e8]
0x3b377f: MOV R12D, EAX
0x3b3782: XOR ESI, ESI
0x3b3784: XOR EDX, EDX
0x3b3786: XOR ECX, ECX
0x3b3788: MOV RDI, RBX
0x3b378b: CALL 0x004c6a00
0x3b3790: LEA RDI, [0x34cf2f0]
0x3b3797: XOR ESI, ESI
0x3b3799: CALL 0x0073f010
0x3b379e: MOV RDI, RBX
0x3b37a1: XOR ESI, ESI
0x3b37a3: XOR EDX, EDX
0x3b37a5: XOR ECX, ECX
0x3b37a7: CALL 0x004c6fa0
0x3b37ac: MOV RAX, qword ptr [R15]
0x3b37af: CMP RAX, qword ptr [RBP + -0x30]
0x3b37b3: JNZ 0x003b3a2d
0x3b37b9: MOV EAX, R12D
0x3b37bc: ADD RSP, 0x38
0x3b37c0: POP RBX
0x3b37c1: POP R12
0x3b37c3: POP R13
0x3b37c5: POP R14
0x3b37c7: POP R15
0x3b37c9: POP RBP
0x3b37ca: RET
0x3b37cb: MOVZX R12D, byte ptr [RBP + -0x42]
0x3b37d0: MOV RAX, qword ptr [RBP + -0x50]
0x3b37d4: OR R12B, byte ptr [RBP + -0x41]
0x3b37d8: LEA RDI, [0x34cf300]
0x3b37df: XOR ESI, ESI
0x3b37e1: XOR EDX, EDX
0x3b37e3: XOR ECX, ECX
0x3b37e5: MOV qword ptr [RAX], 0x0
0x3b37ec: CALL 0x00c4bb20
0x3b37f1: CMP qword ptr [0x034d09d8], 0x0
0x3b37f9: LEA R15, [0x391c310]
0x3b3800: JNZ 0x003b395d
0x3b3806: LEA RSI, [0x1364ab4]
0x3b380d: LEA RDX, [0x267320]
0x3b3814: LEA RCX, [0x12bdaa7]
0x3b381b: MOV R9D, 0x4e20
0x3b3821: XOR R14D, R14D
0x3b3824: XOR EDI, EDI
0x3b3826: XOR R8D, R8D
0x3b3829: CALL 0x0073dd40
0x3b382e: LEA RSI, [0x12f120f]
0x3b3835: LEA RDX, [0x267328]
0x3b383c: LEA RCX, [0x128aa97]
0x3b3843: MOV R9D, 0x4e20
0x3b3849: MOV qword ptr [0x034d09d8], RAX
0x3b3850: XOR EDI, EDI
0x3b3852: XOR R8D, R8D
0x3b3855: CALL 0x0073dd40
0x3b385a: LEA RSI, [0x13a2f6d]
0x3b3861: LEA RDX, [0x267330]
0x3b3868: LEA RCX, [0x131134c]
0x3b386f: MOV R9D, 0x4e20
0x3b3875: MOV qword ptr [0x034d09e0], RAX
0x3b387c: XOR EDI, EDI
0x3b387e: XOR R8D, R8D
0x3b3881: CALL 0x0073dd40
0x3b3886: LEA RSI, [0x12e769e]
0x3b388d: LEA RDX, [0x265768]
0x3b3894: LEA RCX, [0x12955ab]
0x3b389b: MOV R9D, 0x4e20
0x3b38a1: MOV qword ptr [0x034d09e8], RAX
0x3b38a8: XOR EDI, EDI
0x3b38aa: XOR R8D, R8D
0x3b38ad: CALL 0x0073dd40
0x3b38b2: LEA RSI, [0x1276a25]
0x3b38b9: LEA RDX, [0x265770]
0x3b38c0: LEA RCX, [0x133ac86]
0x3b38c7: MOV R9D, 0x4e20
0x3b38cd: MOV qword ptr [0x034d09f0], RAX
0x3b38d4: XOR EDI, EDI
0x3b38d6: XOR R8D, R8D
0x3b38d9: CALL 0x0073dd40
0x3b38de: LEA RSI, [0x131bf16]
0x3b38e5: LEA RDX, [0x267338]
0x3b38ec: LEA RCX, [0x12dd858]
0x3b38f3: MOV R9D, 0x270f
0x3b38f9: MOV qword ptr [0x034d09f8], RAX
0x3b3900: XOR EDI, EDI
0x3b3902: XOR R8D, R8D
0x3b3905: CALL 0x0073dd40
0x3b390a: MOV qword ptr [0x034d0a00], RAX
0x3b3911: LEA RAX, [0x34d0a10]
0x3b3918: XOR ECX, ECX
0x3b391a: MOV qword ptr [0x034d09c0], 0x0
0x3b3925: NOP dword ptr CS:[RAX + RAX*0x1]
0x3b3930: MOV qword ptr [RAX + 0x8], RCX
0x3b3934: MOV RCX, RAX
0x3b3937: ADD R14, -0x10
0x3b393b: ADD RAX, 0x10
0x3b393f: CMP R14, -0x400
0x3b3946: JNZ 0x003b3930
0x3b3948: LEA RAX, [0x34d0a10]
0x3b394f: SUB RAX, R14
0x3b3952: ADD RAX, -0x10
0x3b3956: MOV qword ptr [0x034d09c8], RAX
0x3b395d: LEA RDI, [0x34cf300]
0x3b3964: XOR ESI, ESI
0x3b3966: XOR EDX, EDX
0x3b3968: CALL 0x00c4c4b0
0x3b396d: LEA RDI, [0x34cf2e8]
0x3b3974: XOR ESI, ESI
0x3b3976: XOR EDX, EDX
0x3b3978: XOR ECX, ECX
0x3b397a: CALL 0x004c6a00
0x3b397f: MOV dword ptr [RBX + 0x4a0], 0x1
0x3b3989: TEST R12B, R12B
0x3b398c: JNZ 0x003b399e
0x3b398e: MOV RDI, qword ptr [RBP + -0x58]
0x3b3992: CALL 0x009f8180
0x3b3997: MOV qword ptr [RBX + 0x4a8], RAX
0x3b399e: CMP dword ptr [RBP + -0x48], 0x0
0x3b39a2: JZ 0x003b3a17
0x3b39a4: MOV RAX, 0x100000001
0x3b39ae: MOV RDX, 0x10000000100000
0x3b39b8: MOV RCX, 0x2000000020
0x3b39c2: MOV dword ptr [RBX + 0x1ac], 0x0
0x3b39cc: MOV dword ptr [RBX + 0x1bc], 0x100000
0x3b39d6: MOV dword ptr [RBX + 0x19c], 0x100000
0x3b39e0: MOV dword ptr [RBX + 0x17c], 0x20
0x3b39ea: MOV dword ptr [RBX + 0x18c], 0x20
0x3b39f4: MOV qword ptr [RBX + 0x1a4], RAX
0x3b39fb: MOV qword ptr [RBX + 0x1b4], RDX
0x3b3a02: MOV qword ptr [RBX + 0x194], RDX
0x3b3a09: MOV qword ptr [RBX + 0x174], RCX
0x3b3a10: MOV qword ptr [RBX + 0x184], RCX
0x3b3a17: LEA RDI, [0x34cf2f0]
0x3b3a1e: XOR ESI, ESI
0x3b3a20: XOR R12D, R12D
0x3b3a23: CALL 0x0073f010
0x3b3a28: JMP 0x003b349e
0x3b3a2d: CALL 0x006fd6b0
0x3b3a32: UD2

; local helper / adjacent context (reachability below); evidence ev_694b8cff8ad74a417656cc9386c49ae271f8378872f8600cf2e7c213b1e0989f; body [{"start": "0x3b3a40", "end": "0x3b3a81"}]
sub_3b3a40: ; RVA 0x3b3a40
0x3b3a40: PUSH RBP
0x3b3a41: MOV RBP, RSP
0x3b3a44: PUSH R15
0x3b3a46: PUSH R14
0x3b3a48: PUSH RBX
0x3b3a49: PUSH RAX
0x3b3a4a: MOV R15, RDI
0x3b3a4d: MOV RDI, qword ptr GS:[0x0]
0x3b3a56: MOV R14, RSI
0x3b3a59: LEA RSI, [0x134f297]
0x3b3a60: MOV RBX, RDX
0x3b3a63: XOR EDX, EDX
0x3b3a65: CALL 0x00c1a3e0
0x3b3a6a: MOV RDI, R15
0x3b3a6d: MOV RSI, R14
0x3b3a70: MOV RDX, RBX
0x3b3a73: ADD RSP, 0x8
0x3b3a77: POP RBX
0x3b3a78: POP R14
0x3b3a7a: POP R15
0x3b3a7c: POP RBP
0x3b3a7d: JMP 0x002591d0

; local helper / adjacent context (reachability below); evidence ev_8765ebdf675588c4321ccad1b596b6e4c38ed092c1b1173e037712c3028c8a14; body [{"start": "0x3b3e90", "end": "0x3b3f00"}]
sub_3b3e90: ; RVA 0x3b3e90
0x3b3e90: PUSH RBP
0x3b3e91: MOV RBP, RSP
0x3b3e94: PUSH RBX
0x3b3e95: PUSH RAX
0x3b3e96: CMP qword ptr [RDI + 0x28], 0x0
0x3b3e9b: MOV RBX, RDI
0x3b3e9e: JZ 0x003b3eba
0x3b3ea0: LEA RDI, [0x13069f7]
0x3b3ea7: LEA RSI, [0x136fb7e]
0x3b3eae: MOV EDX, 0xb35
0x3b3eb3: XOR EAX, EAX
0x3b3eb5: CALL 0x0025d410
0x3b3eba: MOV RAX, qword ptr [RBX + 0x40]
0x3b3ebe: TEST RAX, RAX
0x3b3ec1: JZ 0x003b3eec
0x3b3ec3: MOV ECX, 0xffffffff
0x3b3ec8: XADD.LOCK dword ptr [RAX + 0x28], ECX
0x3b3ecd: CMP ECX, 0x1
0x3b3ed0: JNZ 0x003b3ee4
0x3b3ed2: MOV RDI, qword ptr [RBX + 0x40]
0x3b3ed6: MOV RSI, qword ptr GS:[0x0]
0x3b3edf: CALL 0x0072b380
0x3b3ee4: MOV qword ptr [RBX + 0x40], 0x0
0x3b3eec: LEA RSI, [0x1ab5900]
0x3b3ef3: MOV RDI, RBX
0x3b3ef6: ADD RSP, 0x8
0x3b3efa: POP RBX
0x3b3efb: POP RBP
0x3b3efc: JMP 0x00c08df0

; local helper / adjacent context (reachability below); evidence ev_9c4159689177afd755aee1ca75260a5d7102288d97838ddf3fa70b1d5cb4dd36; body [{"start": "0x3b3f50", "end": "0x3b3fa3"}, {"start": "0x3b3fb0", "end": "0x3b4188"}]
sub_3b3f50: ; RVA 0x3b3f50
0x3b3f50: PUSH RBP
0x3b3f51: MOV RBP, RSP
0x3b3f54: PUSH R15
0x3b3f56: PUSH R14
0x3b3f58: PUSH R13
0x3b3f5a: PUSH R12
0x3b3f5c: PUSH RBX
0x3b3f5d: SUB RSP, 0x58
0x3b3f61: LEA RBX, [0x391c310]
0x3b3f68: MOV qword ptr [RBP + -0x78], RDX
0x3b3f6c: MOV RAX, qword ptr [RBX]
0x3b3f6f: MOV qword ptr [RBP + -0x30], RAX
0x3b3f73: MOV EAX, dword ptr [RSI + 0x5a0]
0x3b3f79: CMP EAX, 0x60
0x3b3f7c: JZ 0x003b3f87
0x3b3f7e: CMP EAX, 0x5
0x3b3f81: JNZ 0x003b416a
0x3b3f87: TEST R9D, R9D
0x3b3f8a: JZ 0x003b416a
0x3b3f90: MOV R15D, R8D
0x3b3f93: MOV qword ptr [RBP + -0x68], RDI
0x3b3f97: XOR R12D, R12D
0x3b3f9a: XOR EAX, EAX
0x3b3f9c: XOR EDI, EDI
0x3b3f9e: MOV qword ptr [RBP + -0x60], RCX
0x3b3fa2: JMP 0x003b3fc2
0x3b3fb0: MOV R14D, EAX
0x3b3fb3: INC R12
0x3b3fb6: MOV EAX, R14D
0x3b3fb9: CMP R15, R12
0x3b3fbc: JZ 0x003b4156
0x3b3fc2: MOV R14D, dword ptr [RCX + R12*0x4]
0x3b3fc6: MOV R13D, R14D
0x3b3fc9: SAR R13D, 0x10
0x3b3fcd: AND R14D, 0xffff
0x3b3fd4: SETZ SIL
0x3b3fd8: CMP R13D, 0x7f
0x3b3fdc: SETA DL
0x3b3fdf: OR DL, SIL
0x3b3fe2: JNZ 0x003b3fb0
0x3b3fe4: CMP R14D, EAX
0x3b3fe7: JZ 0x003b401c
0x3b3fe9: TEST EDI, EDI
0x3b3feb: JZ 0x003b3ff6
0x3b3fed: MOV RDI, qword ptr [RBP + -0x50]
0x3b3ff1: CALL 0x00399eb0
0x3b3ff6: MOV RDI, qword ptr [RBP + -0x78]
0x3b3ffa: MOV ESI, R14D
0x3b3ffd: MOV EDX, 0x160
0x3b4002: LEA RCX, [RBP + -0x50]
0x3b4006: CALL 0x00399ee0
0x3b400b: TEST RAX, RAX
0x3b400e: JZ 0x003b4042
0x3b4010: MOV RCX, qword ptr [RBP + -0x60]
0x3b4014: MOV RBX, RAX
0x3b4017: MOV EDI, 0x1
0x3b401c: MOVSX EAX, word ptr [RBX]
0x3b401f: CMP R13D, EAX
0x3b4022: JGE 0x003b3fb3
0x3b4024: MOV qword ptr [RBP + -0x58], RDI
0x3b4028: MOV RDI, qword ptr [RBP + -0x50]
0x3b402c: CALL 0x00399e20
0x3b4031: TEST EAX, EAX
0x3b4033: JZ 0x003b4052
0x3b4035: MOV RCX, qword ptr [RBP + -0x60]
0x3b4039: MOV RDI, qword ptr [RBP + -0x58]
0x3b403d: JMP 0x003b3fb3
0x3b4042: MOV RCX, qword ptr [RBP + -0x60]
0x3b4046: XOR EDI, EDI
0x3b4048: XOR R14D, R14D
0x3b404b: XOR EBX, EBX
0x3b404d: JMP 0x003b3fb3
0x3b4052: MOV RAX, qword ptr [RBX + 0x28]
0x3b4056: MOV ECX, R13D
0x3b4059: MOV RDI, qword ptr [RBP + -0x58]
0x3b405d: MOV RAX, qword ptr [RAX + RCX*0x8]
0x3b4061: MOV RCX, qword ptr [RBP + -0x60]
0x3b4065: TEST RAX, RAX
0x3b4068: JZ 0x003b3fb3
0x3b406e: MOV R13D, dword ptr [RAX + 0x30]
0x3b4072: CMP R13D, 0x80020060
0x3b4079: JZ 0x003b4088
0x3b407b: CMP R13D, 0x80020005
0x3b4082: JNZ 0x003b3fb3
0x3b4088: MOV RAX, qword ptr [RAX + 0x10]
0x3b408c: LEA RSI, [RBP + -0x40]
0x3b4090: MOV RDX, 0x400000000000080
0x3b409a: MOV RCX, 0x20000000000000d
0x3b40a4: XOR EDI, EDI
0x3b40a6: XOR R8D, R8D
0x3b40a9: MOV EAX, dword ptr [RAX + 0x20]
0x3b40ac: MOV dword ptr [RBP + -0x6c], EAX
0x3b40af: XOR EAX, EAX
0x3b40b1: CALL 0x002bc220
0x3b40b6: MOV RDI, qword ptr [RBP + -0x68]
0x3b40ba: MOV ESI, dword ptr [RBP + -0x6c]
0x3b40bd: MOV RDX, RAX
0x3b40c0: LEA RCX, [RBP + -0x48]
0x3b40c4: CALL 0x0072c3d0
0x3b40c9: TEST EAX, EAX
0x3b40cb: JNZ 0x003b4035
0x3b40d1: MOV RDI, qword ptr [RBP + -0x48]
0x3b40d5: CALL 0x003b6860
0x3b40da: TEST RAX, RAX
0x3b40dd: JNZ 0x003b4108
0x3b40df: MOV RAX, qword ptr [RBP + -0x48]
0x3b40e3: MOV ECX, 0xffffffff
0x3b40e8: XADD.LOCK dword ptr [RAX + 0x28], ECX
0x3b40ed: CMP ECX, 0x1
0x3b40f0: JNZ 0x003b4035
0x3b40f6: MOV RDI, qword ptr [RBP + -0x48]
0x3b40fa: MOV RSI, qword ptr [RBP + -0x68]
0x3b40fe: CALL 0x0072b380
0x3b4103: JMP 0x003b4035
0x3b4108: MOV RCX, qword ptr GS:[0x0]
0x3b4111: OR byte ptr [RCX + 0x3a8], 0x1
0x3b4118: ADD R13D, 0x7ffe0000
0x3b411f: MOV ESI, 0x1
0x3b4124: MOV RDX, RAX
0x3b4127: XOR R8D, R8D
0x3b412a: MOV EDI, R13D
0x3b412d: CALL 0x0055a6a0
0x3b4132: MOV RAX, qword ptr [RBP + -0x48]
0x3b4136: MOV ECX, 0xffffffff
0x3b413b: XADD.LOCK dword ptr [RAX + 0x28], ECX
0x3b4140: CMP ECX, 0x1
0x3b4143: JNZ 0x003b4152
0x3b4145: MOV RDI, qword ptr [RBP + -0x48]
0x3b4149: MOV RSI, qword ptr [RBP + -0x68]
0x3b414d: CALL 0x0072b380
0x3b4152: MOV RDI, qword ptr [RBP + -0x58]
0x3b4156: LEA RBX, [0x391c310]
0x3b415d: TEST EDI, EDI
0x3b415f: JZ 0x003b416a
0x3b4161: MOV RDI, qword ptr [RBP + -0x50]
0x3b4165: CALL 0x00399eb0
0x3b416a: MOV RAX, qword ptr [RBX]
0x3b416d: CMP RAX, qword ptr [RBP + -0x30]
0x3b4171: JNZ 0x003b4182
0x3b4173: ADD RSP, 0x58
0x3b4177: POP RBX
0x3b4178: POP R12
0x3b417a: POP R13
0x3b417c: POP R14
0x3b417e: POP R15
0x3b4180: POP RBP
0x3b4181: RET
0x3b4182: CALL 0x006fd6b0
0x3b4187: UD2

; local helper / adjacent context (reachability below); evidence ev_fc99bb6787dcc738c22b502b69849b8ff29b74271f0148f9f1c3836ea0a00f8d; body [{"start": "0x3af8e0", "end": "0x3af8eb"}]
handler_668_body: ; RVA 0x3af8e0
0x3af8e0: PUSH RBP
0x3af8e1: MOV RBP, RSP
0x3af8e4: XOR ESI, ESI
0x3af8e6: POP RBP
0x3af8e7: JMP 0x00265760

; local helper / adjacent context (reachability below); evidence ev_28085dcf3678a7fd0ee9b2ec66b8e24897a27ce91f37b545aaa2bd7f6adf46dd; body [{"start": "0x3af8f0", "end": "0x3af8fb"}]
handler_661_body: ; RVA 0x3af8f0
0x3af8f0: PUSH RBP
0x3af8f1: MOV RBP, RSP
0x3af8f4: XOR ESI, ESI
0x3af8f6: POP RBP
0x3af8f7: JMP 0x00265760

; local helper / adjacent context (reachability below); evidence ev_17cf5f7c7556c4104056c11dcae597607504b869c70271155d51206e4cb0394e; body [{"start": "0x3af900", "end": "0x3af916"}]
handler_662_body: ; RVA 0x3af900
0x3af900: PUSH RBP
0x3af901: MOV RBP, RSP
0x3af904: MOV RAX, qword ptr [RSI]
0x3af907: MOV EDX, dword ptr [RSI + 0x8]
0x3af90a: MOV RCX, qword ptr [RSI + 0x10]
0x3af90e: MOV RSI, RAX
0x3af911: POP RBP
0x3af912: JMP 0x003af920

; local helper / adjacent context (reachability below); evidence ev_a36d95dbaafde34c4e74cdfc296895c750709be2e9399155d760a7b24233d251; body [{"start": "0x3af920", "end": "0x3afb82"}, {"start": "0x3afb90", "end": "0x3afc1d"}, {"start": "0x3afc20", "end": "0x3b01e7"}]
adjacent_3af920: ; RVA 0x3af920
0x3af920: PUSH RBP
0x3af921: MOV RBP, RSP
0x3af924: PUSH R15
0x3af926: PUSH R14
0x3af928: PUSH R13
0x3af92a: PUSH R12
0x3af92c: PUSH RBX
0x3af92d: AND RSP, -0x20
0x3af931: SUB RSP, 0xa0
0x3af938: MOV RBX, RSP
0x3af93b: LEA R13, [0x391c310]
0x3af942: MOV qword ptr [RBX + 0x60], RCX
0x3af946: MOV qword ptr [RBX + 0x48], RDX
0x3af94a: MOV R14, RSI
0x3af94d: MOV RAX, qword ptr [R13]
0x3af951: MOV qword ptr [RBX + 0x80], RAX
0x3af958: MOV qword ptr [RBX + 0x68], RDI
0x3af95c: MOV R12, qword ptr [RDI + 0x8]
0x3af960: MOV RAX, qword ptr [R12 + 0xc48]
0x3af968: MOV RDI, R12
0x3af96b: MOV dword ptr [RBX + 0x74], 0x0
0x3af972: MOV dword ptr [RBX + 0x70], 0x0
0x3af979: MOV qword ptr [RBX + 0x50], RAX
0x3af97d: CALL 0x009f8180
0x3af982: LEA RSI, [RBX + 0x78]
0x3af986: MOV RDI, R12
0x3af989: MOV R15, RAX
0x3af98c: CALL 0x009f81c0
0x3af991: TEST EAX, EAX
0x3af993: JNZ 0x003af9bf
0x3af995: MOV EAX, dword ptr [RBX + 0x78]
0x3af998: CMP EAX, 0xffffff
0x3af99d: JA 0x003af9bf
0x3af99f: CMP EAX, 0xffff
0x3af9a4: JBE 0x003afb28
0x3af9aa: AND EAX, 0xff0000
0x3af9af: CMP EAX, 0x10000
0x3af9b4: JNZ 0x003af9bf
0x3af9b6: LEA RSI, [0x34cfe70]
0x3af9bd: JMP 0x003af9c6
0x3af9bf: LEA RSI, [0x34cf8c8]
0x3af9c6: CMP dword ptr [RSI + 0x4a0], 0x1
0x3af9cd: JZ 0x003af9f7
0x3af9cf: MOV EDI, 0x1
0x3af9d4: CALL 0x003b3410
0x3af9d9: TEST EAX, EAX
0x3af9db: JZ 0x003af9f7
0x3af9dd: MOV R15D, EAX
0x3af9e0: LEA RDI, [0x131bf08]
0x3af9e7: LEA RSI, [0x138458c]
0x3af9ee: MOV EDX, 0xe9b
0x3af9f3: MOV ECX, EAX
0x3af9f5: JMP 0x003afa27
0x3af9f7: MOV R15, qword ptr [RBX + 0x48]
0x3af9fb: LEA EAX, [R15 + -0x81]
0x3afa02: CMP EAX, 0xffffff7f
0x3afa07: JA 0x003afa33
0x3afa09: LEA RDI, [0x131bf08]
0x3afa10: LEA RSI, [0x138458c]
0x3afa17: MOV R15D, 0x16
0x3afa1d: MOV EDX, 0xea1
0x3afa22: MOV ECX, 0x16
0x3afa27: XOR EAX, EAX
0x3afa29: CALL 0x0025d410
0x3afa2e: JMP 0x003b01aa
0x3afa33: MOV qword ptr [RBX + 0x10], R14
0x3afa37: CMP R15D, 0x2
0x3afa3b: JC 0x003afa75
0x3afa3d: LEA EAX, [0xf + R15*0x4]
0x3afa45: MOV R14, RSP
0x3afa48: LEA ESI, [R15*0x4]
0x3afa50: AND EAX, 0xfffffff0
0x3afa53: SUB R14, RAX
0x3afa56: AND R14, -0x20
0x3afa5a: MOV RSP, R14
0x3afa5d: MOV RDI, RSP
0x3afa60: SUB RDI, RAX
0x3afa63: AND RDI, -0x20
0x3afa67: MOV RSP, RDI
0x3afa6a: MOV qword ptr [RBX + 0x8], RDI
0x3afa6e: CALL 0x00258ff0
0x3afa73: JMP 0x003afa81
0x3afa75: LEA RAX, [RBX + 0x70]
0x3afa79: LEA R14, [RBX + 0x74]
0x3afa7d: MOV qword ptr [RBX + 0x8], RAX
0x3afa81: MOV RDI, qword ptr GS:[0x0]
0x3afa8a: MOV R13D, R15D
0x3afa8d: LEA RSI, [0x1397f3d]
0x3afa94: XOR EDX, EDX
0x3afa96: LEA R12, [R13*0x4]
0x3afa9e: CALL 0x00c1a3e0
0x3afaa3: MOV RDI, qword ptr [RBX + 0x10]
0x3afaa7: MOV RSI, R14
0x3afaaa: MOV RDX, R12
0x3afaad: CALL 0x00259280
0x3afab2: TEST EAX, EAX
0x3afab4: JZ 0x003afae1
0x3afab6: LEA RDI, [0x131bf08]
0x3afabd: LEA RSI, [0x138458c]
0x3afac4: MOV EDX, 0xeb0
0x3afac9: MOV ECX, EAX
0x3afacb: MOV R15D, EAX
0x3aface: XOR EAX, EAX
0x3afad0: CALL 0x0025d410
0x3afad5: LEA R13, [0x391c310]
0x3afadc: JMP 0x003b01aa
0x3afae1: MOV qword ptr [RBX + 0x18], R13
0x3afae5: MOV qword ptr [RBX + 0x10], R14
0x3afae9: CALL 0x00b078d0
0x3afaee: MOV qword ptr [RBX + 0x58], R12
0x3afaf2: TEST EAX, EAX
0x3afaf4: JZ 0x003afb60
0x3afaf6: MOV R14, qword ptr [RBX + 0x18]
0x3afafa: LEA RSI, [0x1a7d800]
0x3afb01: MOV EDX, 0x102
0x3afb06: LEA RAX, [R14*0x8]
0x3afb0e: LEA RDI, [RAX + RAX*0x2]
0x3afb12: CALL 0x00c08b50
0x3afb17: MOV RDX, qword ptr [RBX + 0x8]
0x3afb1b: MOV RSI, qword ptr [RBX + 0x10]
0x3afb1f: MOV RDI, R14
0x3afb22: MOV qword ptr [RBX + 0x40], RAX
0x3afb26: JMP 0x003afb74
0x3afb28: CMP qword ptr [0x034cf7c8], R15
0x3afb2f: JZ 0x003b01c9
0x3afb35: CMP qword ptr [0x034d08c0], R15
0x3afb3c: JZ 0x003b01d5
0x3afb42: CMP dword ptr [0x034cf7c0], 0x0
0x3afb49: LEA RAX, [0x34cf320]
0x3afb50: LEA RSI, [0x34d0418]
0x3afb57: CMOVZ RSI, RAX
0x3afb5b: JMP 0x003af9c6
0x3afb60: MOV RDX, qword ptr [RBX + 0x8]
0x3afb64: MOV RSI, qword ptr [RBX + 0x10]
0x3afb68: MOV RDI, qword ptr [RBX + 0x18]
0x3afb6c: MOV qword ptr [RBX + 0x40], 0x0
0x3afb74: XOR R13D, R13D
0x3afb77: XOR R12D, R12D
0x3afb7a: MOV dword ptr [RBX + 0x28], 0x0
0x3afb81: JMP 0x003afbaa
0x3afb90: MOV dword ptr [RDX + R13*0x4], 0x80020003
0x3afb98: MOV R15D, R12D
0x3afb9b: INC R13
0x3afb9e: MOV R12D, R15D
0x3afba1: CMP R13, RDI
0x3afba4: JZ 0x003b0110
0x3afbaa: MOV R15D, dword ptr [RSI + R13*0x4]
0x3afbae: MOV dword ptr [RDX + R13*0x4], 0x0
0x3afbb6: MOV R14D, R15D
0x3afbb9: SAR R14D, 0x10
0x3afbbd: AND R15D, 0xffff
0x3afbc4: SETNZ R8B
0x3afbc8: CMP R14D, 0x80
0x3afbcf: SETC CL
0x3afbd2: TEST R8B, CL
0x3afbd5: JZ 0x003afb90
0x3afbd7: CMP R15D, R12D
0x3afbda: JNZ 0x003afc20
0x3afbdc: TEST RAX, RAX
0x3afbdf: JNZ 0x003afc58
0x3afbe1: MOV dword ptr [RDX + R13*0x4], 0x80020003
0x3afbe9: LEA RDI, [0x135b377]
0x3afbf0: LEA RSI, [0x138458c]
0x3afbf7: MOV EDX, 0xeda
0x3afbfc: MOV ECX, R13D
0x3afbff: MOV R8D, 0x3
0x3afc05: XOR EAX, EAX
0x3afc07: CALL 0x0025d410
0x3afc0c: MOV RSI, qword ptr [RBX + 0x10]
0x3afc10: MOV RDX, qword ptr [RBX + 0x8]
0x3afc14: MOV R15D, R12D
0x3afc17: XOR EAX, EAX
0x3afc19: JMP 0x003afd03
0x3afc20: CMP dword ptr [RBX + 0x28], 0x0
0x3afc24: JZ 0x003afc2f
0x3afc26: MOV RDI, qword ptr [RBX + 0x78]
0x3afc2a: CALL 0x00399eb0
0x3afc2f: MOV RDI, qword ptr [RBX + 0x50]
0x3afc33: MOV ESI, R15D
0x3afc36: MOV EDX, 0x160
0x3afc3b: LEA RCX, [RBX + 0x78]
0x3afc3f: CALL 0x00399ee0
0x3afc44: TEST RAX, RAX
0x3afc47: JZ 0x003afce7
0x3afc4d: MOV RDX, qword ptr [RBX + 0x8]
0x3afc51: MOV dword ptr [RBX + 0x28], 0x1
0x3afc58: MOV R12, RAX
0x3afc5b: MOVSX EAX, word ptr [RAX]
0x3afc5e: CMP R14D, EAX
0x3afc61: JGE 0x003afca8
0x3afc63: MOV RDI, qword ptr [RBX + 0x78]
0x3afc67: CALL 0x00399e20
0x3afc6c: TEST EAX, EAX
0x3afc6e: JZ 0x003afd0c
0x3afc74: MOV R14, qword ptr [RBX + 0x8]
0x3afc78: LEA RDI, [0x135b377]
0x3afc7f: LEA RSI, [0x138458c]
0x3afc86: MOV EDX, 0xee9
0x3afc8b: MOV ECX, R13D
0x3afc8e: MOV R8D, 0x1
0x3afc94: MOV dword ptr [R14 + R13*0x4], 0x80020001
0x3afc9c: XOR EAX, EAX
0x3afc9e: CALL 0x0025d410
0x3afca3: MOV RDX, R14
0x3afca6: JMP 0x003afcd7
0x3afca8: MOV dword ptr [RDX + R13*0x4], 0x80020003
0x3afcb0: LEA RDI, [0x135b377]
0x3afcb7: LEA RSI, [0x138458c]
0x3afcbe: MOV EDX, 0xee3
0x3afcc3: MOV ECX, R13D
0x3afcc6: MOV R8D, 0x3
0x3afccc: XOR EAX, EAX
0x3afcce: CALL 0x0025d410
0x3afcd3: MOV RDX, qword ptr [RBX + 0x8]
0x3afcd7: MOV RSI, qword ptr [RBX + 0x10]
0x3afcdb: MOV RDI, qword ptr [RBX + 0x18]
0x3afcdf: MOV RAX, R12
0x3afce2: JMP 0x003afb9b
0x3afce7: MOV RDX, qword ptr [RBX + 0x8]
0x3afceb: MOV dword ptr [RDX + R13*0x4], 0x80020003
0x3afcf3: XOR R15D, R15D
0x3afcf6: MOV dword ptr [RBX + 0x28], 0x0
0x3afcfd: XOR EAX, EAX
0x3afcff: MOV RSI, qword ptr [RBX + 0x10]
0x3afd03: MOV RDI, qword ptr [RBX + 0x18]
0x3afd07: JMP 0x003afb9b
0x3afd0c: MOV RAX, qword ptr [R12 + 0x28]
0x3afd11: MOV ECX, R14D
0x3afd14: MOV R14, qword ptr [RAX + RCX*0x8]
0x3afd18: TEST R14, R14
0x3afd1b: JZ 0x003aff34
0x3afd21: CMP qword ptr [RBX + 0x40], 0x0
0x3afd26: MOV qword ptr [RBX + 0x30], RCX
0x3afd2a: SETNZ byte ptr [RBX + 0x38]
0x3afd2e: CALL 0x00b078d0
0x3afd33: TEST EAX, EAX
0x3afd35: MOV RSI, qword ptr [RBX + 0x10]
0x3afd39: SETNZ AL
0x3afd3c: AND AL, byte ptr [RBX + 0x38]
0x3afd3f: CMP AL, 0x1
0x3afd41: JNZ 0x003afd72
0x3afd43: MOV EAX, dword ptr [RSI + R13*0x4]
0x3afd47: MOV RDI, qword ptr [RBX + 0x40]
0x3afd4b: LEA RCX, [R13 + R13*0x2]
0x3afd50: MOV dword ptr [RDI + RCX*0x8], EAX
0x3afd53: MOV RAX, qword ptr [R14 + 0x18]
0x3afd57: MOV RAX, qword ptr [RAX]
0x3afd5a: MOV qword ptr [RDI + RCX*0x8 + 0x8], RAX
0x3afd5f: MOV RAX, qword ptr [R14 + 0x10]
0x3afd63: MOV RDX, RAX
0x3afd66: SAR RDX, 0x4
0x3afd6a: XOR RDX, RAX
0x3afd6d: MOV qword ptr [RDI + RCX*0x8 + 0x10], RDX
0x3afd72: MOV R14, qword ptr [R14 + 0x20]
0x3afd76: MOV EAX, dword ptr [R14 + 0x8]
0x3afd7a: ADD EAX, -0x3
0x3afd7d: CMP EAX, 0x2
0x3afd80: JNC 0x003aff61
0x3afd86: LEA RDI, [R14 + 0x20]
0x3afd8a: MOV ESI, 0x80000
0x3afd8f: XOR EDX, EDX
0x3afd91: XOR ECX, ECX
0x3afd93: XOR R8D, R8D
0x3afd96: XOR R9D, R9D
0x3afd99: MOV qword ptr [RBX + 0x38], RDI
0x3afd9d: PUSH 0x0
0x3afd9f: PUSH 0x0
0x3afda1: CALL 0x00bf1770
0x3afda6: ADD RSP, 0x10
0x3afdaa: CMP byte ptr [R14 + 0xc], 0x0
0x3afdaf: JNZ 0x003afddc
0x3afdb1: LEA RDI, [0x131bf08]
0x3afdb8: LEA RSI, [0x138458c]
0x3afdbf: MOV EDX, 0xf0a
0x3afdc4: MOV ECX, 0x10
0x3afdc9: XOR EAX, EAX
0x3afdcb: CALL 0x0025d410
0x3afdd0: MOV RAX, qword ptr [RBX + 0x8]
0x3afdd4: MOV dword ptr [RAX + R13*0x4], 0x80020010
0x3afddc: CMP qword ptr [R14 + 0x50], 0x0
0x3afde1: MOV qword ptr [RBX + 0x20], R14
0x3afde5: MOV R14, qword ptr [RBX + 0x8]
0x3afde9: JZ 0x003afe12
0x3afdeb: LEA RDI, [0x131bf08]
0x3afdf2: LEA RSI, [0x138458c]
0x3afdf9: MOV EDX, 0xf0f
0x3afdfe: MOV ECX, 0x10
0x3afe03: XOR EAX, EAX
0x3afe05: CALL 0x0025d410
0x3afe0a: MOV dword ptr [R14 + R13*0x4], 0x80020010
0x3afe12: MOV RDI, qword ptr [RBX + 0x38]
0x3afe16: XOR EDX, EDX
0x3afe18: MOV ESI, 0x100000
0x3afe1d: XOR ECX, ECX
0x3afe1f: XOR R8D, R8D
0x3afe22: XOR R9D, R9D
0x3afe25: PUSH 0x0
0x3afe27: PUSH 0x0
0x3afe29: CALL 0x00bf1770
0x3afe2e: ADD RSP, 0x10
0x3afe32: CMP dword ptr [R14 + R13*0x4], 0x0
0x3afe37: MOV RDX, R14
0x3afe3a: JNZ 0x003afcd7
0x3afe40: MOV RCX, qword ptr [RBX + 0x20]
0x3afe44: MOV RSI, qword ptr [RBX + 0x10]
0x3afe48: MOV RDI, qword ptr [RBX + 0x18]
0x3afe4c: MOV RAX, R12
0x3afe4f: CMP dword ptr [RCX + 0x4], 0x0
0x3afe53: JNZ 0x003afb9b
0x3afe59: CMP byte ptr [RCX + 0xc], 0x0
0x3afe5d: JZ 0x003afb9b
0x3afe63: MOV RDI, qword ptr [RBX + 0x78]
0x3afe67: CALL 0x00399eb0
0x3afe6c: MOV RDI, qword ptr [RBX + 0x50]
0x3afe70: MOV ESI, R15D
0x3afe73: MOV EDX, 0x160
0x3afe78: LEA RCX, [RBX + 0x78]
0x3afe7c: CALL 0x0039a2a0
0x3afe81: TEST RAX, RAX
0x3afe84: JZ 0x003affab
0x3afe8a: MOV RCX, qword ptr [RAX + 0x28]
0x3afe8e: MOV RDX, qword ptr [RBX + 0x30]
0x3afe92: MOVZX R8D, word ptr [RAX + 0x2]
0x3afe97: MOV RSI, qword ptr [RBX + 0x10]
0x3afe9b: MOV qword ptr [RBX + 0x20], RAX
0x3afe9f: MOV R12, qword ptr [RCX + RDX*0x8]
0x3afea3: CMP R8W, 0x1
0x3afea8: JNZ 0x003affbc
0x3afeae: TEST R12, R12
0x3afeb1: JZ 0x003b00e8
0x3afeb7: MOV R14, qword ptr [R12 + 0x18]
0x3afebc: MOV R8, qword ptr [RBX + 0x20]
0x3afec0: MOV RCX, RDX
0x3afec3: TEST R14, R14
0x3afec6: JZ 0x003afefe
0x3afec8: MOV RDI, qword ptr [R14 + 0x10]
0x3afecc: TEST RDI, RDI
0x3afecf: JZ 0x003afede
0x3afed1: CALL 0x002a9670
0x3afed6: MOV qword ptr [R14 + 0x10], 0x0
0x3afede: MOV RDI, R14
0x3afee1: LEA RSI, [0x1ab59e0]
0x3afee8: CALL 0x00c08df0
0x3afeed: MOV R8, qword ptr [RBX + 0x20]
0x3afef1: MOV RCX, qword ptr [RBX + 0x30]
0x3afef5: MOV qword ptr [R12 + 0x18], 0x0
0x3afefe: CMP word ptr [R8], 0x1
0x3aff03: JNZ 0x003b0014
0x3aff09: MOV R14, qword ptr [R12 + 0x20]
0x3aff0e: TEST R14, R14
0x3aff11: JZ 0x003b0089
0x3aff17: MOV qword ptr [R12 + 0x20], 0x0
0x3aff20: MOV EAX, dword ptr [R14]
0x3aff23: TEST EAX, EAX
0x3aff25: JZ 0x003b0075
0x3aff2b: MOV qword ptr [RBX + 0x28], R14
0x3aff2f: XOR R14D, R14D
0x3aff32: JMP 0x003aff7e
0x3aff34: MOV R14, qword ptr [RBX + 0x8]
0x3aff38: LEA RDI, [0x135b377]
0x3aff3f: LEA RSI, [0x138458c]
0x3aff46: MOV EDX, 0xef0
0x3aff4b: MOV ECX, R13D
0x3aff4e: MOV R8D, 0x3
0x3aff54: MOV dword ptr [R14 + R13*0x4], 0x80020003
0x3aff5c: JMP 0x003afc9c
0x3aff61: MOV RDX, qword ptr [RBX + 0x8]
0x3aff65: MOV dword ptr [RDX + R13*0x4], 0x80020010
0x3aff6d: JMP 0x003afcdb
0x3aff72: INC R14D
0x3aff75: CMP R14D, EAX
0x3aff78: JNC 0x003b0026
0x3aff7e: MOV RCX, qword ptr [R8 + 0x28]
0x3aff82: MOVSXD R12, R14D
0x3aff85: MOV RDI, qword ptr [RCX + R12*0x8]
0x3aff89: TEST RDI, RDI
0x3aff8c: JZ 0x003aff72
0x3aff8e: CALL 0x003b3e90
0x3aff93: MOV R8, qword ptr [RBX + 0x20]
0x3aff97: MOV RAX, qword ptr [R8 + 0x28]
0x3aff9b: MOV qword ptr [RAX + R12*0x8], 0x0
0x3affa3: MOV RAX, qword ptr [RBX + 0x28]
0x3affa7: MOV EAX, dword ptr [RAX]
0x3affa9: JMP 0x003aff72
0x3affab: MOV RDX, qword ptr [RBX + 0x8]
0x3affaf: MOV dword ptr [RDX + R13*0x4], 0x0
0x3affb7: JMP 0x003afcf3
0x3affbc: MOV RDX, qword ptr [RBX + 0x8]
0x3affc0: MOV RDI, qword ptr [RBX + 0x18]
0x3affc4: TEST R12, R12
0x3affc7: JZ 0x003afb9b
0x3affcd: DEC R8D
0x3affd0: MOV word ptr [RAX + 0x2], R8W
0x3affd5: CMP qword ptr [R12 + 0x20], 0x0
0x3affdb: JZ 0x003affef
0x3affdd: MOV RDI, qword ptr [RBX + 0x38]
0x3affe1: CALL 0x00bf1760
0x3affe6: MOV qword ptr [R12 + 0x20], 0x0
0x3affef: MOV RDI, R12
0x3afff2: CALL 0x003b3e90
0x3afff7: MOV RAX, qword ptr [RBX + 0x20]
0x3afffb: MOV RDX, qword ptr [RBX + 0x30]
0x3affff: MOV RCX, qword ptr [RAX + 0x28]
0x3b0003: MOV qword ptr [RCX + RDX*0x8], 0x0
0x3b000b: MOV RDX, qword ptr [RBX + 0x8]
0x3b000f: JMP 0x003afcff
0x3b0014: MOV RDI, R12
0x3b0017: CALL 0x003b3e90
0x3b001c: MOV RCX, qword ptr [RBX + 0x30]
0x3b0020: MOV R8, qword ptr [RBX + 0x20]
0x3b0024: JMP 0x003b0089
0x3b0026: MOV R14, qword ptr [RBX + 0x28]
0x3b002a: CMP EAX, 0x2
0x3b002d: JC 0x003b0075
0x3b002f: XOR R12D, R12D
0x3b0032: JMP 0x003b003c
0x3b0034: INC R12D
0x3b0037: CMP R12D, EAX
0x3b003a: JNC 0x003b0075
0x3b003c: MOV RCX, qword ptr [R8 + 0x28]
0x3b0040: MOVSXD RDX, R12D
0x3b0043: MOV R9, qword ptr [RCX + RDX*0x8]
0x3b0047: TEST R9, R9
0x3b004a: JZ 0x003b0034
0x3b004c: LEA RDI, [0x12dd828]
0x3b0053: LEA RSI, [0x138458c]
0x3b005a: MOV EDX, 0xf4d
0x3b005f: MOV ECX, R12D
0x3b0062: MOV R8D, R12D
0x3b0065: XOR EAX, EAX
0x3b0067: CALL 0x0025d410
0x3b006c: MOV R8, qword ptr [RBX + 0x20]
0x3b0070: MOV EAX, dword ptr [R14]
0x3b0073: JMP 0x003b0034
0x3b0075: ADD R14, 0x20
0x3b0079: MOV RDI, R14
0x3b007c: CALL 0x00bf1760
0x3b0081: MOV R8, qword ptr [RBX + 0x20]
0x3b0085: MOV RCX, qword ptr [RBX + 0x30]
0x3b0089: MOV RAX, qword ptr [R8 + 0x28]
0x3b008d: LEA RSI, [0x1ab5970]
0x3b0094: MOV R12, R8
0x3b0097: MOV qword ptr [RAX + RCX*0x8], 0x0
0x3b009f: MOV RDI, qword ptr [R8 + 0x10]
0x3b00a3: CALL 0x00c08df0
0x3b00a8: MOV RDI, qword ptr [R12 + 0x20]
0x3b00ad: LEA RSI, [0x1ab5890]
0x3b00b4: CALL 0x00c08df0
0x3b00b9: MOV RDI, qword ptr [R12 + 0x28]
0x3b00be: LEA R14, [0x1ab5a50]
0x3b00c5: MOV RSI, R14
0x3b00c8: CALL 0x00c08df0
0x3b00cd: MOV RDI, R12
0x3b00d0: MOV RSI, R14
0x3b00d3: CALL 0x00c08df0
0x3b00d8: MOV RDX, qword ptr [RBX + 0x78]
0x3b00dc: MOV RDI, qword ptr [RBX + 0x50]
0x3b00e0: MOV ESI, R15D
0x3b00e3: CALL 0x00399e30
0x3b00e8: MOV RDI, qword ptr [RBX + 0x78]
0x3b00ec: CALL 0x00399eb0
0x3b00f1: MOV RDX, qword ptr [RBX + 0x8]
0x3b00f5: MOV RSI, qword ptr [RBX + 0x10]
0x3b00f9: MOV RDI, qword ptr [RBX + 0x18]
0x3b00fd: MOV RAX, qword ptr [RBX + 0x20]
0x3b0101: XOR R15D, R15D
0x3b0104: MOV dword ptr [RBX + 0x28], 0x0
0x3b010b: JMP 0x003afb9b
0x3b0110: MOV R15, qword ptr [RBX + 0x40]
0x3b0114: TEST R15, R15
0x3b0117: SETNZ R14B
0x3b011b: CALL 0x00b078d0
0x3b0120: TEST EAX, EAX
0x3b0122: LEA R13, [0x391c310]
0x3b0129: SETNZ AL
0x3b012c: AND AL, R14B
0x3b012f: MOV R14, qword ptr [RBX + 0x68]
0x3b0133: CMP AL, 0x1
0x3b0135: JNZ 0x003b0155
0x3b0137: MOV RDI, R14
0x3b013a: MOV RDX, R15
0x3b013d: MOV RSI, qword ptr [RBX + 0x48]
0x3b0141: CALL 0x000a3960
0x3b0146: LEA RSI, [0x1a7d800]
0x3b014d: MOV RDI, R15
0x3b0150: CALL 0x00c08df0
0x3b0155: CMP dword ptr [RBX + 0x28], 0x0
0x3b0159: JZ 0x003b0164
0x3b015b: MOV RDI, qword ptr [RBX + 0x78]
0x3b015f: CALL 0x00399eb0
0x3b0164: MOV RDI, qword ptr GS:[0x0]
0x3b016d: LEA RSI, [0x134f297]
0x3b0174: XOR EDX, EDX
0x3b0176: CALL 0x00c1a3e0
0x3b017b: MOV R12, qword ptr [RBX + 0x8]
0x3b017f: MOV RSI, qword ptr [RBX + 0x60]
0x3b0183: MOV RDX, qword ptr [RBX + 0x58]
0x3b0187: MOV RDI, R12
0x3b018a: CALL 0x002591d0
0x3b018f: MOV R15D, EAX
0x3b0192: CALL 0x00b078d0
0x3b0197: TEST EAX, EAX
0x3b0199: JZ 0x003b01aa
0x3b019b: MOV RSI, R12
0x3b019e: MOV RDX, R14
0x3b01a1: MOV RDI, qword ptr [RBX + 0x48]
0x3b01a5: CALL 0x000a39f0
0x3b01aa: MOV RAX, qword ptr [R13]
0x3b01ae: CMP RAX, qword ptr [RBX + 0x80]
0x3b01b5: JNZ 0x003b01e1
0x3b01b7: MOV EAX, R15D
0x3b01ba: LEA RSP, [RBP + -0x28]
0x3b01be: POP RBX
0x3b01bf: POP R12
0x3b01c1: POP R13
0x3b01c3: POP R14
0x3b01c5: POP R15
0x3b01c7: POP RBP
0x3b01c8: RET
0x3b01c9: LEA RSI, [0x34cf320]
0x3b01d0: JMP 0x003af9c6
0x3b01d5: LEA RSI, [0x34d0418]
0x3b01dc: JMP 0x003af9c6
0x3b01e1: CALL 0x006fd6b0
0x3b01e6: UD2

; target syscall body; evidence ev_2466c2d119eee7bd3f1b638ba5258d20c1ad6bd53868611e17df66f4fc32242a; body [{"start": "0x3b01f0", "end": "0x3b020e"}]
handler_663_body: ; RVA 0x3b01f0
0x3b01f0: PUSH RBP
0x3b01f1: MOV RBP, RSP
0x3b01f4: MOV RAX, qword ptr [RSI]
0x3b01f7: MOV EDX, dword ptr [RSI + 0x8]
0x3b01fa: MOV RCX, qword ptr [RSI + 0x10]
0x3b01fe: MOV R8D, dword ptr [RSI + 0x18]
0x3b0202: MOV R9, qword ptr [RSI + 0x20]
0x3b0206: MOV RSI, RAX
0x3b0209: POP RBP
0x3b020a: JMP 0x003b0210

; local helper / adjacent context (reachability below); evidence ev_60132c6eb695d11dc24ba22220e4081cf0ec74166747aa65a369acfa98760376; body [{"start": "0x3b0210", "end": "0x3b05cd"}, {"start": "0x3b05d0", "end": "0x3b068e"}, {"start": "0x3b0690", "end": "0x3b0dad"}, {"start": "0x3b0db0", "end": "0x3b0e55"}, {"start": "0x3b0e60", "end": "0x3b0ebb"}, {"start": "0x3b0ec0", "end": "0x3b0fae"}]
adjacent_3b0210: ; RVA 0x3b0210
0x3b0210: PUSH RBP
0x3b0211: MOV RBP, RSP
0x3b0214: PUSH R15
0x3b0216: PUSH R14
0x3b0218: PUSH R13
0x3b021a: PUSH R12
0x3b021c: PUSH RBX
0x3b021d: AND RSP, -0x20
0x3b0221: SUB RSP, 0x140
0x3b0228: MOV RBX, RSP
0x3b022b: LEA RAX, [0x391c310]
0x3b0232: MOV qword ptr [RBX + 0x60], R9
0x3b0236: MOV qword ptr [RBX + 0x98], RCX
0x3b023d: MOV qword ptr [RBX + 0x70], RDX
0x3b0241: MOV R13D, R8D
0x3b0244: MOV R15, RSI
0x3b0247: MOV RAX, qword ptr [RAX]
0x3b024a: MOV qword ptr [RBX + 0x120], RAX
0x3b0251: MOV qword ptr [RBX + 0x68], RDI
0x3b0255: MOV R12, qword ptr [RDI + 0x8]
0x3b0259: MOV RAX, qword ptr [R12 + 0xc48]
0x3b0261: MOV RDI, R12
0x3b0264: MOV dword ptr [RBX + 0x114], 0x0
0x3b026e: MOV dword ptr [RBX + 0x110], 0x0
0x3b0278: MOV dword ptr [RBX + 0x108], 0x0
0x3b0282: MOV qword ptr [RBX + 0xa0], RAX
0x3b0289: CALL 0x009f8180
0x3b028e: LEA RSI, [RBX + 0xe0]
0x3b0295: MOV RDI, R12
0x3b0298: MOV R14, RAX
0x3b029b: CALL 0x009f81c0
0x3b02a0: LEA RSI, [0x34cf8c8]
0x3b02a7: XOR R12D, R12D
0x3b02aa: TEST EAX, EAX
0x3b02ac: JNZ 0x003b0339
0x3b02b2: MOV EAX, dword ptr [RBX + 0xe0]
0x3b02b8: CMP EAX, 0xffffff
0x3b02bd: JA 0x003b0339
0x3b02bf: CMP EAX, 0xffff
0x3b02c4: JBE 0x003b02f6
0x3b02c6: AND EAX, 0xff0000
0x3b02cb: LEA RCX, [0x34cfe70]
0x3b02d2: LEA RSI, [0x34cf8c8]
0x3b02d9: MOV R12D, 0x1
0x3b02df: CMP EAX, 0x10000
0x3b02e4: CMOVZ RSI, RCX
0x3b02e8: CMP dword ptr [RSI + 0x4a0], 0x1
0x3b02ef: JNZ 0x003b0342
0x3b02f1: JMP 0x003b0384
0x3b02f6: MOV R12D, 0x1
0x3b02fc: CMP qword ptr [0x034cf7c8], R14
0x3b0303: JZ 0x003b0332
0x3b0305: CMP qword ptr [0x034d08c0], R14
0x3b030c: JZ 0x003b0374
0x3b030e: CMP dword ptr [0x034cf7c0], 0x0
0x3b0315: LEA RAX, [0x34cf320]
0x3b031c: LEA RSI, [0x34d0418]
0x3b0323: CMOVZ RSI, RAX
0x3b0327: CMP dword ptr [RSI + 0x4a0], 0x1
0x3b032e: JNZ 0x003b0342
0x3b0330: JMP 0x003b0384
0x3b0332: LEA RSI, [0x34cf320]
0x3b0339: CMP dword ptr [RSI + 0x4a0], 0x1
0x3b0340: JZ 0x003b0384
0x3b0342: MOV EDI, 0x1
0x3b0347: MOV R14, RSI
0x3b034a: CALL 0x003b3410
0x3b034f: MOV RSI, R14
0x3b0352: TEST EAX, EAX
0x3b0354: JZ 0x003b0384
0x3b0356: MOV R14D, EAX
0x3b0359: LEA RDI, [0x131bf08]
0x3b0360: LEA RSI, [0x1379d7c]
0x3b0367: MOV EDX, 0xffc
0x3b036c: MOV ECX, R14D
0x3b036f: JMP 0x003b0489
0x3b0374: LEA RSI, [0x34d0418]
0x3b037b: CMP dword ptr [RSI + 0x4a0], 0x1
0x3b0382: JNZ 0x003b0342
0x3b0384: MOV RCX, qword ptr [RBX + 0x70]
0x3b0388: LEA EAX, [RCX + -0x81]
0x3b038e: CMP EAX, 0xffffff7f
0x3b0393: JA 0x003b03b8
0x3b0395: LEA RDI, [0x131bf08]
0x3b039c: LEA RSI, [0x1379d7c]
0x3b03a3: MOV R14D, 0x16
0x3b03a9: MOV EDX, 0x1002
0x3b03ae: MOV ECX, 0x16
0x3b03b3: JMP 0x003b0489
0x3b03b8: CMP R13D, 0x3
0x3b03bc: JNC 0x003b040e
0x3b03be: MOV EAX, ECX
0x3b03c0: MOV dword ptr [RBX + 0x2c], R13D
0x3b03c4: MOV qword ptr [RBX + 0x90], RSI
0x3b03cb: MOV qword ptr [RBX + 0x20], RAX
0x3b03cf: CMP ECX, 0x2
0x3b03d2: JC 0x003b042e
0x3b03d4: LEA EAX, [0xf + RCX*0x4]
0x3b03db: MOV R14, RSP
0x3b03de: LEA ESI, [RCX*0x4]
0x3b03e5: AND EAX, 0xfffffff0
0x3b03e8: SUB R14, RAX
0x3b03eb: AND R14, -0x20
0x3b03ef: MOV RSP, R14
0x3b03f2: MOV RDI, RSP
0x3b03f5: SUB RDI, RAX
0x3b03f8: AND RDI, -0x20
0x3b03fc: MOV RSP, RDI
0x3b03ff: MOV qword ptr [RBX + 0x38], RDI
0x3b0403: CALL 0x00258ff0
0x3b0408: MOV RAX, qword ptr [RBX + 0x20]
0x3b040c: JMP 0x003b0440
0x3b040e: LEA RDI, [0x131bf08]
0x3b0415: LEA RSI, [0x1379d7c]
0x3b041c: MOV R14D, 0x16
0x3b0422: MOV EDX, 0x100c
0x3b0427: MOV ECX, 0x16
0x3b042c: JMP 0x003b0489
0x3b042e: LEA RCX, [RBX + 0x110]
0x3b0435: LEA R14, [RBX + 0x114]
0x3b043c: MOV qword ptr [RBX + 0x38], RCX
0x3b0440: MOV RDI, qword ptr GS:[0x0]
0x3b0449: LEA RSI, [0x1397f3d]
0x3b0450: XOR EDX, EDX
0x3b0452: LEA R13, [RAX*0x4]
0x3b045a: CALL 0x00c1a3e0
0x3b045f: MOV RDI, R15
0x3b0462: MOV RSI, R14
0x3b0465: MOV RDX, R13
0x3b0468: CALL 0x00259280
0x3b046d: TEST EAX, EAX
0x3b046f: JZ 0x003b04b9
0x3b0471: LEA RDI, [0x131bf08]
0x3b0478: LEA RSI, [0x1379d7c]
0x3b047f: MOV EDX, 0x101b
0x3b0484: MOV ECX, EAX
0x3b0486: MOV R14D, EAX
0x3b0489: XOR EAX, EAX
0x3b048b: CALL 0x0025d410
0x3b0490: LEA RAX, [0x391c310]
0x3b0497: MOV RAX, qword ptr [RAX]
0x3b049a: CMP RAX, qword ptr [RBX + 0x120]
0x3b04a1: JNZ 0x003b0fa8
0x3b04a7: MOV EAX, R14D
0x3b04aa: LEA RSP, [RBP + -0x28]
0x3b04ae: POP RBX
0x3b04af: POP R12
0x3b04b1: POP R13
0x3b04b3: POP R14
0x3b04b5: POP R15
0x3b04b7: POP RBP
0x3b04b8: RET
0x3b04b9: MOV qword ptr [RBX + 0x30], R14
0x3b04bd: MOV R14, qword ptr [RBX + 0x60]
0x3b04c1: MOV qword ptr [RBX + 0x80], R13
0x3b04c8: TEST R14, R14
0x3b04cb: JZ 0x003b0517
0x3b04cd: MOV RDI, qword ptr GS:[0x0]
0x3b04d6: LEA RSI, [0x1397f3d]
0x3b04dd: XOR EDX, EDX
0x3b04df: CALL 0x00c1a3e0
0x3b04e4: LEA RSI, [RBX + 0x108]
0x3b04eb: MOV EDX, 0x4
0x3b04f0: MOV RDI, R14
0x3b04f3: CALL 0x00259280
0x3b04f8: TEST EAX, EAX
0x3b04fa: JZ 0x003b0517
0x3b04fc: MOV R14D, EAX
0x3b04ff: LEA RDI, [0x131bf08]
0x3b0506: LEA RSI, [0x1379d7c]
0x3b050d: MOV EDX, 0x1022
0x3b0512: JMP 0x003b036c
0x3b0517: CALL 0x00b078d0
0x3b051c: MOV dword ptr [RBX + 0x7c], R12D
0x3b0520: TEST EAX, EAX
0x3b0522: JZ 0x003b054a
0x3b0524: MOV R14, qword ptr [RBX + 0x20]
0x3b0528: LEA RSI, [0x1a7d800]
0x3b052f: MOV EDX, 0x102
0x3b0534: LEA RAX, [R14*0x8]
0x3b053c: LEA RDI, [RAX + RAX*0x2]
0x3b0540: CALL 0x00c08b50
0x3b0545: MOV R12, RAX
0x3b0548: JMP 0x003b0551
0x3b054a: MOV R14, qword ptr [RBX + 0x20]
0x3b054e: XOR R12D, R12D
0x3b0551: MOV R15D, dword ptr [RBX + 0x2c]
0x3b0555: LEA RDI, [RBX + 0xf8]
0x3b055c: LEA RSI, [0x12e78de]
0x3b0563: MOV dword ptr [RBX + 0x104], 0x0
0x3b056d: XOR EDX, EDX
0x3b056f: XOR ECX, ECX
0x3b0571: CALL 0x004c7dd0
0x3b0576: IMUL RDI, R14, 0x38
0x3b057a: LEA RSI, [0x1ab5a50]
0x3b0581: MOV EDX, 0x102
0x3b0586: CALL 0x00c08b50
0x3b058b: MOV R14, RAX
0x3b058e: CMP R15D, 0x2
0x3b0592: JNZ 0x003b05a8
0x3b0594: MOV dword ptr [RBX + 0x104], 0x1
0x3b059e: MOV dword ptr [RBX + 0x10c], 0x0
0x3b05a8: MOV RSI, qword ptr [RBX + 0x20]
0x3b05ac: MOV RDI, qword ptr [RBX + 0x30]
0x3b05b0: LEA R8, [R12 + 0x10]
0x3b05b5: MOV qword ptr [RBX + 0x88], R12
0x3b05bc: MOV qword ptr [RBX + 0x40], R14
0x3b05c0: XOR R15D, R15D
0x3b05c3: XOR EAX, EAX
0x3b05c5: MOV dword ptr [RBX + 0x14], 0x0
0x3b05cc: JMP 0x003b05f2
0x3b05d0: MOV dword ptr [R14 + 0x20], 0x80020003
0x3b05d8: MOV R12D, EAX
0x3b05db: INC R15
0x3b05de: ADD R14, 0x38
0x3b05e2: ADD R8, 0x18
0x3b05e6: MOV EAX, R12D
0x3b05e9: CMP RSI, R15
0x3b05ec: JZ 0x003b0a41
0x3b05f2: MOV R12D, dword ptr [RDI + R15*0x4]
0x3b05f6: MOV R13D, R12D
0x3b05f9: SAR R13D, 0x10
0x3b05fd: AND R12D, 0xffff
0x3b0604: SETNZ CL
0x3b0607: CMP R13D, 0x80
0x3b060e: SETC DL
0x3b0611: TEST CL, DL
0x3b0613: JZ 0x003b05d0
0x3b0615: MOV qword ptr [RBX + 0x48], R8
0x3b0619: CMP R12D, EAX
0x3b061c: JZ 0x003b064d
0x3b061e: MOV RDI, qword ptr [RBX + 0xa0]
0x3b0625: MOV ESI, R12D
0x3b0628: MOV EDX, 0x160
0x3b062d: LEA RCX, [RBX + 0x118]
0x3b0634: CALL 0x00399ee0
0x3b0639: MOV qword ptr [RBX + 0x58], RAX
0x3b063d: TEST RAX, RAX
0x3b0640: JZ 0x003b06c0
0x3b0642: MOV RAX, qword ptr [RBX + 0x118]
0x3b0649: MOV qword ptr [R14 + 0x28], RAX
0x3b064d: MOV RAX, qword ptr [RBX + 0x58]
0x3b0651: MOVSX EAX, word ptr [RAX]
0x3b0654: CMP R13D, EAX
0x3b0657: JGE 0x003b0690
0x3b0659: MOV RDI, qword ptr [RBX + 0x118]
0x3b0660: CALL 0x00399e20
0x3b0665: TEST EAX, EAX
0x3b0667: JZ 0x003b06d8
0x3b0669: MOV dword ptr [R14 + 0x20], 0x80020001
0x3b0671: LEA RDI, [0x135b377]
0x3b0678: LEA RSI, [0x1379d7c]
0x3b067f: MOV EDX, 0x106a
0x3b0684: MOV ECX, R15D
0x3b0687: MOV R8D, 0x1
0x3b068d: JMP 0x003b06b4
0x3b0690: LEA RDI, [0x135b377]
0x3b0697: LEA RSI, [0x1379d7c]
0x3b069e: MOV EDX, 0x1064
0x3b06a3: MOV dword ptr [R14 + 0x20], 0x80020003
0x3b06ab: MOV ECX, R15D
0x3b06ae: MOV R8D, 0x3
0x3b06b4: XOR EAX, EAX
0x3b06b6: CALL 0x0025d410
0x3b06bb: JMP 0x003b0a30
0x3b06c0: MOV dword ptr [R14 + 0x20], 0x80020003
0x3b06c8: XOR R12D, R12D
0x3b06cb: MOV qword ptr [RBX + 0x58], 0x0
0x3b06d3: JMP 0x003b0a30
0x3b06d8: MOV RAX, qword ptr [RBX + 0x58]
0x3b06dc: MOV ECX, R13D
0x3b06df: MOV RAX, qword ptr [RAX + 0x28]
0x3b06e3: MOV R13, qword ptr [RAX + RCX*0x8]
0x3b06e7: TEST R13, R13
0x3b06ea: JZ 0x003b0819
0x3b06f0: CMP qword ptr [RBX + 0x88], 0x0
0x3b06f8: MOV qword ptr [RBX + 0xa8], RCX
0x3b06ff: SETNZ byte ptr [RBX + 0x18]
0x3b0703: CALL 0x00b078d0
0x3b0708: TEST EAX, EAX
0x3b070a: SETNZ AL
0x3b070d: AND AL, byte ptr [RBX + 0x18]
0x3b0710: CMP AL, 0x1
0x3b0712: JNZ 0x003b073f
0x3b0714: MOV RAX, qword ptr [RBX + 0x30]
0x3b0718: MOV RDX, qword ptr [RBX + 0x48]
0x3b071c: MOV EAX, dword ptr [RAX + R15*0x4]
0x3b0720: MOV dword ptr [RDX + -0x10], EAX
0x3b0723: MOV RAX, qword ptr [R13 + 0x18]
0x3b0727: MOV RAX, qword ptr [RAX]
0x3b072a: MOV qword ptr [RDX + -0x8], RAX
0x3b072e: MOV RAX, qword ptr [R13 + 0x10]
0x3b0732: MOV RCX, RAX
0x3b0735: SAR RCX, 0x4
0x3b0739: XOR RCX, RAX
0x3b073c: MOV qword ptr [RDX], RCX
0x3b073f: MOV R13, qword ptr [R13 + 0x20]
0x3b0743: TEST R13, R13
0x3b0746: JNZ 0x003b0768
0x3b0748: LEA RDI, [0x1379d8c]
0x3b074f: LEA RSI, [0x1379d7c]
0x3b0756: MOV EDX, 0x107f
0x3b075b: MOV ECX, R15D
0x3b075e: XOR R8D, R8D
0x3b0761: XOR EAX, EAX
0x3b0763: CALL 0x0025d410
0x3b0768: LEA RDI, [R13 + 0x20]
0x3b076c: MOV ESI, 0x80000
0x3b0771: XOR EDX, EDX
0x3b0773: XOR ECX, ECX
0x3b0775: XOR R8D, R8D
0x3b0778: XOR R9D, R9D
0x3b077b: MOV qword ptr [RBX + 0x18], RDI
0x3b077f: PUSH 0x0
0x3b0781: PUSH 0x0
0x3b0783: CALL 0x00bf1770
0x3b0788: ADD RSP, 0x10
0x3b078c: MOV EAX, dword ptr [RBX + 0x2c]
0x3b078f: CMP EAX, 0x1
0x3b0792: JNZ 0x003b0839
0x3b0798: MOV EAX, dword ptr [R13 + 0x8]
0x3b079c: MOV RCX, R13
0x3b079f: MOV dword ptr [R14 + 0x20], EAX
0x3b07a3: CMP EAX, 0x2
0x3b07a6: JG 0x003b08cd
0x3b07ac: LEA R13, [RBX + 0xf8]
0x3b07b3: MOV qword ptr [RBX + 0x50], RCX
0x3b07b7: XOR ESI, ESI
0x3b07b9: XOR EDX, EDX
0x3b07bb: XOR ECX, ECX
0x3b07bd: MOV RDI, R13
0x3b07c0: CALL 0x004c6a00
0x3b07c5: INC dword ptr [RBX + 0x104]
0x3b07cb: LEA RAX, [RBX + 0x104]
0x3b07d2: MOV RDI, R13
0x3b07d5: XOR ESI, ESI
0x3b07d7: XOR EDX, EDX
0x3b07d9: XOR ECX, ECX
0x3b07db: MOV qword ptr [R14], RAX
0x3b07de: LEA RAX, [RBX + 0xe0]
0x3b07e5: MOV qword ptr [R14 + 0x10], RAX
0x3b07e9: CALL 0x004c6fa0
0x3b07ee: MOV R13, qword ptr [RBX + 0x50]
0x3b07f2: CMP dword ptr [R13 + 0x8], 0x2
0x3b07f7: JG 0x003b0976
0x3b07fd: MOV RAX, qword ptr [R13 + 0x50]
0x3b0801: MOV dword ptr [RBX + 0x14], 0x0
0x3b0808: MOV qword ptr [R14 + 0x30], RAX
0x3b080c: MOV qword ptr [R13 + 0x50], R14
0x3b0810: MOV qword ptr [R14 + 0x18], R13
0x3b0814: JMP 0x003b0a01
0x3b0819: MOV dword ptr [R14 + 0x20], 0x80020003
0x3b0821: LEA RDI, [0x135b377]
0x3b0828: LEA RSI, [0x1379d7c]
0x3b082f: MOV EDX, 0x1071
0x3b0834: JMP 0x003b06ab
0x3b0839: MOV RCX, qword ptr [RBX + 0x40]
0x3b083d: MOV qword ptr [RBX + 0x50], R13
0x3b0841: CMP EAX, 0x2
0x3b0844: JNZ 0x003b08e5
0x3b084a: MOV RCX, qword ptr [RBX + 0x50]
0x3b084e: MOV EAX, dword ptr [RCX + 0x8]
0x3b0851: MOV dword ptr [R14 + 0x20], EAX
0x3b0855: CMP EAX, 0x2
0x3b0858: JG 0x003b08cd
0x3b085a: LEA R13, [RBX + 0xf8]
0x3b0861: XOR ESI, ESI
0x3b0863: XOR EDX, EDX
0x3b0865: XOR ECX, ECX
0x3b0867: MOV RDI, R13
0x3b086a: CALL 0x004c6a00
0x3b086f: INC dword ptr [RBX + 0x10c]
0x3b0875: LEA RAX, [RBX + 0x104]
0x3b087c: MOV RDI, R13
0x3b087f: XOR ESI, ESI
0x3b0881: XOR EDX, EDX
0x3b0883: XOR ECX, ECX
0x3b0885: MOV qword ptr [R14], RAX
0x3b0888: LEA RAX, [RBX + 0xe0]
0x3b088f: MOV qword ptr [R14 + 0x10], RAX
0x3b0893: LEA RAX, [RBX + 0x10c]
0x3b089a: MOV qword ptr [R14 + 0x8], RAX
0x3b089e: CALL 0x004c6fa0
0x3b08a3: MOV RCX, qword ptr [RBX + 0x50]
0x3b08a7: CMP dword ptr [RCX + 0x8], 0x2
0x3b08ab: JG 0x003b09d9
0x3b08b1: MOV RAX, qword ptr [RCX + 0x50]
0x3b08b5: MOV dword ptr [RBX + 0x14], 0x0
0x3b08bc: MOV qword ptr [R14 + 0x30], RAX
0x3b08c0: MOV qword ptr [RCX + 0x50], R14
0x3b08c4: MOV qword ptr [R14 + 0x18], RCX
0x3b08c8: JMP 0x003b0a01
0x3b08cd: CMP byte ptr [RCX + 0xc], 0x0
0x3b08d1: JZ 0x003b09c2
0x3b08d7: OR EAX, 0x10000
0x3b08dc: MOV dword ptr [R14 + 0x20], EAX
0x3b08e0: JMP 0x003b0a01
0x3b08e5: MOV RAX, qword ptr [RBX + 0x58]
0x3b08e9: MOV RDX, qword ptr [RBX + 0xa8]
0x3b08f0: MOV RAX, qword ptr [RAX + 0x28]
0x3b08f4: MOV RAX, qword ptr [RAX + RDX*0x8]
0x3b08f8: MOV R13, qword ptr [RAX + 0x20]
0x3b08fc: MOV EAX, dword ptr [R13 + 0x8]
0x3b0900: MOV dword ptr [RCX + 0x20], EAX
0x3b0903: CMP EAX, 0x2
0x3b0906: JG 0x003b09c8
0x3b090c: LEA RDI, [RBX + 0xf8]
0x3b0913: XOR ESI, ESI
0x3b0915: XOR EDX, EDX
0x3b0917: XOR ECX, ECX
0x3b0919: CALL 0x004c6a00
0x3b091e: INC dword ptr [RBX + 0x104]
0x3b0924: MOV RCX, qword ptr [RBX + 0x40]
0x3b0928: LEA RAX, [RBX + 0x104]
0x3b092f: LEA RDI, [RBX + 0xf8]
0x3b0936: XOR ESI, ESI
0x3b0938: XOR EDX, EDX
0x3b093a: MOV qword ptr [RCX], RAX
0x3b093d: LEA RAX, [RBX + 0xe0]
0x3b0944: MOV qword ptr [RCX + 0x10], RAX
0x3b0948: XOR ECX, ECX
0x3b094a: CALL 0x004c6fa0
0x3b094f: CMP dword ptr [R13 + 0x8], 0x2
0x3b0954: JG 0x003b0976
0x3b0956: MOV RAX, qword ptr [R13 + 0x50]
0x3b095a: MOV RCX, qword ptr [RBX + 0x40]
0x3b095e: MOV dword ptr [RBX + 0x14], 0x0
0x3b0965: MOV qword ptr [RCX + 0x30], RAX
0x3b0969: MOV qword ptr [R13 + 0x50], RCX
0x3b096d: MOV qword ptr [RCX + 0x18], R13
0x3b0971: JMP 0x003b0a01
0x3b0976: LEA RDI, [0x136599c]
0x3b097d: LEA RSI, [0x12bdac0]
0x3b0984: MOV EDX, 0xfa9
0x3b0989: XOR EAX, EAX
0x3b098b: CALL 0x0025d410
0x3b0990: LEA R13, [RBX + 0xf8]
0x3b0997: XOR ESI, ESI
0x3b0999: XOR EDX, EDX
0x3b099b: XOR ECX, ECX
0x3b099d: MOV RDI, R13
0x3b09a0: CALL 0x004c6a00
0x3b09a5: DEC dword ptr [RBX + 0x104]
0x3b09ab: MOV RDI, R13
0x3b09ae: XOR ESI, ESI
0x3b09b0: XOR EDX, EDX
0x3b09b2: XOR ECX, ECX
0x3b09b4: CALL 0x004c6fa0
0x3b09b9: MOV dword ptr [RBX + 0x14], 0x10
0x3b09c0: JMP 0x003b0a01
0x3b09c2: MOV byte ptr [RCX + 0xc], 0x1
0x3b09c6: JMP 0x003b0a01
0x3b09c8: CMP byte ptr [R13 + 0xc], 0x0
0x3b09cd: JZ 0x003b09fc
0x3b09cf: OR EAX, 0x10000
0x3b09d4: MOV dword ptr [RCX + 0x20], EAX
0x3b09d7: JMP 0x003b0a01
0x3b09d9: LEA RDI, [0x136599c]
0x3b09e0: LEA RSI, [0x12bdac0]
0x3b09e7: MOV EDX, 0xfa9
0x3b09ec: XOR EAX, EAX
0x3b09ee: CALL 0x0025d410
0x3b09f3: MOV dword ptr [RBX + 0x14], 0x10
0x3b09fa: JMP 0x003b0a01
0x3b09fc: MOV byte ptr [R13 + 0xc], 0x1
0x3b0a01: MOV RDI, qword ptr [RBX + 0x18]
0x3b0a05: MOV ESI, 0x100000
0x3b0a0a: XOR EDX, EDX
0x3b0a0c: XOR ECX, ECX
0x3b0a0e: XOR R8D, R8D
0x3b0a11: XOR R9D, R9D
0x3b0a14: PUSH 0x0
0x3b0a16: PUSH 0x0
0x3b0a18: CALL 0x00bf1770
0x3b0a1d: ADD RSP, 0x10
0x3b0a21: NOP dword ptr CS:[RAX + RAX*0x1]
0x3b0a30: MOV RSI, qword ptr [RBX + 0x20]
0x3b0a34: MOV RDI, qword ptr [RBX + 0x30]
0x3b0a38: MOV R8, qword ptr [RBX + 0x48]
0x3b0a3c: JMP 0x003b05db
0x3b0a41: MOV R15, qword ptr [RBX + 0x88]
0x3b0a48: TEST R15, R15
0x3b0a4b: SETNZ R14B
0x3b0a4f: CALL 0x00b078d0
0x3b0a54: MOV RSI, qword ptr [RBX + 0x70]
0x3b0a58: MOV R12D, dword ptr [RBX + 0x2c]
0x3b0a5c: TEST EAX, EAX
0x3b0a5e: SETNZ AL
0x3b0a61: AND AL, R14B
0x3b0a64: CMP AL, 0x1
0x3b0a66: JNZ 0x003b0a8c
0x3b0a68: MOV ECX, dword ptr [RBX + 0x108]
0x3b0a6e: MOV RDI, qword ptr [RBX + 0x68]
0x3b0a72: MOV EDX, R12D
0x3b0a75: MOV R8, R15
0x3b0a78: CALL 0x000a3af0
0x3b0a7d: LEA RSI, [0x1a7d800]
0x3b0a84: MOV RDI, R15
0x3b0a87: CALL 0x00c08df0
0x3b0a8c: LEA R14, [RBX + 0xf8]
0x3b0a93: XOR ESI, ESI
0x3b0a95: XOR EDX, EDX
0x3b0a97: XOR ECX, ECX
0x3b0a99: MOV RDI, R14
0x3b0a9c: CALL 0x004c6a00
0x3b0aa1: CMP dword ptr [RBX + 0x104], 0x0
0x3b0aa8: MOV R15, qword ptr [RBX + 0x60]
0x3b0aac: JLE 0x003b0d63
0x3b0ab2: CMP R12D, 0x2
0x3b0ab6: JNZ 0x003b0ac5
0x3b0ab8: CMP dword ptr [RBX + 0x10c], 0x0
0x3b0abf: JZ 0x003b0d63
0x3b0ac5: LEA RDI, [0x34cf2e8]
0x3b0acc: XOR ESI, ESI
0x3b0ace: XOR EDX, EDX
0x3b0ad0: XOR ECX, ECX
0x3b0ad2: CALL 0x004c6a00
0x3b0ad7: MOV RAX, qword ptr [RBX + 0x90]
0x3b0ade: MOV RSI, qword ptr [RAX + 0x4b0]
0x3b0ae5: TEST RSI, RSI
0x3b0ae8: JZ 0x003b0b03
0x3b0aea: LEA RDI, [0x34cf2f0]
0x3b0af1: MOV R14, RAX
0x3b0af4: CALL 0x0073ef80
0x3b0af9: MOV RAX, R14
0x3b0afc: LEA R14, [RBX + 0xf8]
0x3b0b03: MOV RSI, qword ptr [RAX + 0x528]
0x3b0b0a: TEST RSI, RSI
0x3b0b0d: JZ 0x003b0b1b
0x3b0b0f: LEA RDI, [0x34cf2f0]
0x3b0b16: CALL 0x0073ef80
0x3b0b1b: LEA RDI, [0x34cf2e8]
0x3b0b22: XOR ESI, ESI
0x3b0b24: XOR EDX, EDX
0x3b0b26: XOR ECX, ECX
0x3b0b28: CALL 0x004c6fa0
0x3b0b2d: MOV EAX, dword ptr [RBX + 0x108]
0x3b0b33: TEST EAX, EAX
0x3b0b35: JZ 0x003b0c9c
0x3b0b3b: MOV ECX, EAX
0x3b0b3d: IMUL R13, RCX, 0x431bde83
0x3b0b44: SHR R13, 0x32
0x3b0b48: IMUL ECX, R13D, 0xf4240
0x3b0b4f: SUB EAX, ECX
0x3b0b51: IMUL R14D, EAX, 0x3e8
0x3b0b58: JMP 0x003b0b7e
0x3b0b5a: JLE 0x003b0cfa
0x3b0b60: SUB R14, RAX
0x3b0b63: LEA RAX, [R14 + 0x3b9aca00]
0x3b0b6a: TEST R14, R14
0x3b0b6d: CMOVNS RAX, R14
0x3b0b71: SAR R14, 0x3f
0x3b0b75: ADD RDX, R14
0x3b0b78: MOV R14, RAX
0x3b0b7b: MOV R13, RDX
0x3b0b7e: MOV RAX, R14
0x3b0b81: MOV RCX, 0x20c49ba5e353f7cf
0x3b0b8b: MOV qword ptr [RBX + 0xb0], R13
0x3b0b92: LEA RSI, [RBX + 0xd0]
0x3b0b99: IMUL RCX
0x3b0b9c: MOV RAX, RDX
0x3b0b9f: SAR RDX, 0x7
0x3b0ba3: SHR RAX, 0x3f
0x3b0ba7: ADD RDX, RAX
0x3b0baa: MOV qword ptr [RBX + 0xb8], RDX
0x3b0bb1: MOV R12, qword ptr GS:[0x0]
0x3b0bba: MOV RDI, R12
0x3b0bbd: CALL 0x006bc2a0
0x3b0bc2: MOV R15, qword ptr [0x039203d0]
0x3b0bc9: LEA RDI, [RBX + 0xb0]
0x3b0bd0: CALL 0x00c66c80
0x3b0bd5: MOVSXD R8, EAX
0x3b0bd8: IMUL R8, R15
0x3b0bdc: SUB RSP, 0x8
0x3b0be0: LEA RCX, [0x12f1fc8]
0x3b0be7: LEA RDI, [RBX + 0x104]
0x3b0bee: LEA RSI, [RBX + 0xe0]
0x3b0bf5: MOV EDX, 0x104c
0x3b0bfa: XOR R9D, R9D
0x3b0bfd: PUSH 0x100
0x3b0c02: CALL 0x00c06260
0x3b0c07: ADD RSP, 0x10
0x3b0c0b: MOV RDI, R12
0x3b0c0e: LEA RSI, [RBX + 0xc0]
0x3b0c15: MOV R15D, EAX
0x3b0c18: CALL 0x006bc2a0
0x3b0c1d: CMP R15D, 0x23
0x3b0c21: MOV RCX, qword ptr [RBX + 0xc0]
0x3b0c28: SETNZ AL
0x3b0c2b: TEST R15D, R15D
0x3b0c2e: SETNZ DL
0x3b0c31: SUB RCX, qword ptr [RBX + 0xd0]
0x3b0c38: TEST AL, DL
0x3b0c3a: JNZ 0x003b0ce1
0x3b0c40: CMP dword ptr [RBX + 0x104], 0x0
0x3b0c47: JLE 0x003b0ce1
0x3b0c4d: MOV qword ptr [RBX + 0xc0], RCX
0x3b0c54: MOV RAX, qword ptr [RBX + 0xc8]
0x3b0c5b: SUB RAX, qword ptr [RBX + 0xd8]
0x3b0c62: MOV qword ptr [RBX + 0xc8], RAX
0x3b0c69: JNS 0x003b0c82
0x3b0c6b: DEC RCX
0x3b0c6e: ADD RAX, 0x3b9aca00
0x3b0c74: MOV qword ptr [RBX + 0xc0], RCX
0x3b0c7b: MOV qword ptr [RBX + 0xc8], RAX
0x3b0c82: MOV RDX, R13
0x3b0c85: SUB RDX, RCX
0x3b0c88: JNZ 0x003b0b5a
0x3b0c8e: CMP R14, RAX
0x3b0c91: JG 0x003b0b60
0x3b0c97: MOV RCX, R13
0x3b0c9a: JMP 0x003b0cfa
0x3b0c9c: SUB RSP, 0x8
0x3b0ca0: LEA RCX, [0x12f1fc8]
0x3b0ca7: LEA RDI, [RBX + 0x104]
0x3b0cae: LEA RSI, [RBX + 0xe0]
0x3b0cb5: MOV EDX, 0x104c
0x3b0cba: XOR R8D, R8D
0x3b0cbd: XOR R9D, R9D
0x3b0cc0: PUSH 0x100
0x3b0cc5: CALL 0x00c06260
0x3b0cca: ADD RSP, 0x10
0x3b0cce: CMP EAX, -0x1
0x3b0cd1: MOV ECX, 0x4
0x3b0cd6: CMOVNZ ECX, EAX
0x3b0cd9: MOV dword ptr [RBX + 0x14], ECX
0x3b0cdc: JMP 0x003b0d63
0x3b0ce1: MOV RAX, qword ptr [RBX + 0xc8]
0x3b0ce8: SUB RAX, qword ptr [RBX + 0xd8]
0x3b0cef: JNS 0x003b0cfa
0x3b0cf1: DEC RCX
0x3b0cf4: ADD RAX, 0x3b9aca00
0x3b0cfa: CMP R15D, 0x23
0x3b0cfe: MOV EDX, 0x3c
0x3b0d03: MOV ESI, 0x4
0x3b0d08: LEA R14, [RBX + 0xf8]
0x3b0d0f: CMOVNZ EDX, R15D
0x3b0d13: CMP R15D, -0x1
0x3b0d17: CMOVNZ ESI, EDX
0x3b0d1a: MOV RDX, 0x20c49ba5e353f7cf
0x3b0d24: IMUL ECX, ECX, 0xf4240
0x3b0d2a: IMUL RDX
0x3b0d2d: MOV dword ptr [RBX + 0x14], ESI
0x3b0d30: MOV RAX, RDX
0x3b0d33: SHR RDX, 0x7
0x3b0d37: SHR RAX, 0x3f
0x3b0d3b: ADD EDX, EAX
0x3b0d3d: MOV EAX, dword ptr [RBX + 0x108]
0x3b0d43: ADD EDX, ECX
0x3b0d45: SUB EAX, EDX
0x3b0d47: JBE 0x003b0d55
0x3b0d49: MOV R15, qword ptr [RBX + 0x60]
0x3b0d4d: MOV dword ptr [RBX + 0x108], EAX
0x3b0d53: JMP 0x003b0d63
0x3b0d55: MOV R15, qword ptr [RBX + 0x60]
0x3b0d59: MOV dword ptr [RBX + 0x108], 0x0
0x3b0d63: MOV RDI, R14
0x3b0d66: XOR ESI, ESI
0x3b0d68: XOR EDX, EDX
0x3b0d6a: XOR ECX, ECX
0x3b0d6c: CALL 0x004c6fa0
0x3b0d71: TEST R15, R15
0x3b0d74: JZ 0x003b0da1
0x3b0d76: MOV RDI, qword ptr GS:[0x0]
0x3b0d7f: LEA RSI, [0x134f297]
0x3b0d86: XOR EDX, EDX
0x3b0d88: CALL 0x00c1a3e0
0x3b0d8d: LEA RDI, [RBX + 0x108]
0x3b0d94: MOV EDX, 0x4
0x3b0d99: MOV RSI, R15
0x3b0d9c: CALL 0x002591d0
0x3b0da1: MOV R15, qword ptr [RBX + 0x20]
0x3b0da5: MOV RDX, qword ptr [RBX + 0x40]
0x3b0da9: XOR R14D, R14D
0x3b0dac: JMP 0x003b0de3
0x3b0db0: XOR EDX, EDX
0x3b0db2: MOV RDI, R15
0x3b0db5: MOV ESI, 0x100000
0x3b0dba: XOR ECX, ECX
0x3b0dbc: XOR R8D, R8D
0x3b0dbf: XOR R9D, R9D
0x3b0dc2: PUSH 0x0
0x3b0dc4: PUSH 0x0
0x3b0dc6: CALL 0x00bf1770
0x3b0dcb: ADD RSP, 0x10
0x3b0dcf: MOV R15, qword ptr [RBX + 0x20]
0x3b0dd3: MOV RDX, qword ptr [RBX + 0x40]
0x3b0dd7: INC R14
0x3b0dda: CMP R14, R15
0x3b0ddd: JZ 0x003b0eaf
0x3b0de3: IMUL RAX, R14, 0x38
0x3b0de7: MOV R12, qword ptr [RDX + RAX*0x1 + 0x18]
0x3b0dec: LEA R13, [RDX + RAX*0x1]
0x3b0df0: TEST R12, R12
0x3b0df3: JZ 0x003b0e60
0x3b0df5: LEA R15, [R12 + 0x20]
0x3b0dfa: MOV ESI, 0x80000
0x3b0dff: XOR EDX, EDX
0x3b0e01: XOR ECX, ECX
0x3b0e03: XOR R8D, R8D
0x3b0e06: XOR R9D, R9D
0x3b0e09: MOV RDI, R15
0x3b0e0c: PUSH 0x0
0x3b0e0e: PUSH 0x0
0x3b0e10: CALL 0x00bf1770
0x3b0e15: ADD RSP, 0x10
0x3b0e19: MOV EAX, dword ptr [R13 + 0x20]
0x3b0e1d: MOV RCX, qword ptr [RBX + 0x38]
0x3b0e21: MOV dword ptr [RCX + R14*0x4], EAX
0x3b0e25: CMP qword ptr [R12 + 0x50], 0x0
0x3b0e2b: JZ 0x003b0e81
0x3b0e2d: MOV RCX, qword ptr [R13 + 0x18]
0x3b0e31: MOV RAX, qword ptr [RCX + 0x50]
0x3b0e35: CMP RAX, R13
0x3b0e38: JZ 0x003b0e71
0x3b0e3a: NOP word ptr [RAX + RAX*0x1]
0x3b0e40: MOV RCX, RAX
0x3b0e43: MOV RAX, qword ptr [RAX + 0x30]
0x3b0e47: CMP RAX, R13
0x3b0e4a: JNZ 0x003b0e40
0x3b0e4c: MOV RAX, qword ptr [RAX + 0x30]
0x3b0e50: MOV qword ptr [RCX + 0x30], RAX
0x3b0e54: JMP 0x003b0e79
0x3b0e60: MOV EAX, dword ptr [R13 + 0x20]
0x3b0e64: MOV RCX, qword ptr [RBX + 0x38]
0x3b0e68: MOV dword ptr [RCX + R14*0x4], EAX
0x3b0e6c: JMP 0x003b0dd7
0x3b0e71: MOV RAX, qword ptr [RAX + 0x30]
0x3b0e75: MOV qword ptr [RCX + 0x50], RAX
0x3b0e79: MOV qword ptr [R13 + 0x18], 0x0
0x3b0e81: CMP byte ptr [R12 + 0xc], 0x0
0x3b0e87: JZ 0x003b0e93
0x3b0e89: MOV RAX, qword ptr [RBX + 0x38]
0x3b0e8d: OR byte ptr [RAX + R14*0x4 + 0x2], 0x1
0x3b0e93: MOV EAX, dword ptr [R12 + 0x8]
0x3b0e98: ADD EAX, -0x3
0x3b0e9b: CMP EAX, 0x1
0x3b0e9e: JA 0x003b0db0
0x3b0ea4: MOV byte ptr [R12 + 0xc], 0x1
0x3b0eaa: JMP 0x003b0db0
0x3b0eaf: MOV R12D, dword ptr [RBX + 0x7c]
0x3b0eb3: MOV R14, RDX
0x3b0eb6: ADD R14, 0x28
0x3b0eba: JMP 0x003b0ec9
0x3b0ec0: ADD R14, 0x38
0x3b0ec4: DEC R15
0x3b0ec7: JZ 0x003b0ed8
0x3b0ec9: MOV RDI, qword ptr [R14]
0x3b0ecc: TEST RDI, RDI
0x3b0ecf: JZ 0x003b0ec0
0x3b0ed1: CALL 0x00399eb0
0x3b0ed6: JMP 0x003b0ec0
0x3b0ed8: LEA RDI, [RBX + 0xf8]
0x3b0edf: CALL 0x004c7e50
0x3b0ee4: MOV RDI, qword ptr [RBX + 0x68]
0x3b0ee8: MOV RSI, qword ptr [RBX + 0x90]
0x3b0eef: MOV RDX, qword ptr [RBX + 0xa0]
0x3b0ef6: MOV RCX, qword ptr [RBX + 0x30]
0x3b0efa: MOV R9D, R12D
0x3b0efd: MOV R8, qword ptr [RBX + 0x70]
0x3b0f01: CALL 0x003b3f50
0x3b0f06: MOV R14D, dword ptr [RBX + 0x14]
0x3b0f0a: CMP R14D, 0x4
0x3b0f0e: JZ 0x003b0f51
0x3b0f10: MOV RDX, qword ptr [RBX + 0x80]
0x3b0f17: TEST R14D, R14D
0x3b0f1a: JNZ 0x003b0f73
0x3b0f1c: MOV RDI, qword ptr [RBX + 0x38]
0x3b0f20: MOV RSI, qword ptr [RBX + 0x98]
0x3b0f27: CALL 0x003b3a40
0x3b0f2c: TEST EAX, EAX
0x3b0f2e: JZ 0x003b0f70
0x3b0f30: LEA RDI, [0x131bf08]
0x3b0f37: LEA RSI, [0x1379d7c]
0x3b0f3e: MOV EDX, 0x118f
0x3b0f43: MOV ECX, EAX
0x3b0f45: MOV R14D, EAX
0x3b0f48: XOR EAX, EAX
0x3b0f4a: CALL 0x0025d410
0x3b0f4f: JMP 0x003b0f73
0x3b0f51: MOV RDI, qword ptr [RBX + 0x38]
0x3b0f55: MOV RSI, qword ptr [RBX + 0x98]
0x3b0f5c: MOV RDX, qword ptr [RBX + 0x80]
0x3b0f63: CALL 0x003b3a40
0x3b0f68: MOV R14D, 0x4
0x3b0f6e: JMP 0x003b0f73
0x3b0f70: XOR R14D, R14D
0x3b0f73: CALL 0x00b078d0
0x3b0f78: TEST EAX, EAX
0x3b0f7a: JZ 0x003b0f93
0x3b0f7c: MOV ECX, dword ptr [RBX + 0x108]
0x3b0f82: MOV RDI, qword ptr [RBX + 0x68]
0x3b0f86: MOV RDX, qword ptr [RBX + 0x38]
0x3b0f8a: MOV RSI, qword ptr [RBX + 0x20]
0x3b0f8e: CALL 0x000a3b90
0x3b0f93: MOV RDI, qword ptr [RBX + 0x40]
0x3b0f97: LEA RSI, [0x1ab5a50]
0x3b0f9e: CALL 0x00c08df0
0x3b0fa3: JMP 0x003b0490
0x3b0fa8: CALL 0x006fd6b0
0x3b0fad: UD2

; local helper / adjacent context (reachability below); evidence ev_4efa00db1710a76855e7627270a97d72e85319a617ba22daef8f01fed37445c7; body [{"start": "0x3b0fb0", "end": "0x3b0fc6"}]
handler_664_body: ; RVA 0x3b0fb0
0x3b0fb0: PUSH RBP
0x3b0fb1: MOV RBP, RSP
0x3b0fb4: MOV RAX, qword ptr [RSI]
0x3b0fb7: MOV EDX, dword ptr [RSI + 0x8]
0x3b0fba: MOV RCX, qword ptr [RSI + 0x10]
0x3b0fbe: MOV RSI, RAX
0x3b0fc1: POP RBP
0x3b0fc2: JMP 0x003b0fd0

; local helper / adjacent context (reachability below); evidence ev_48934c8dbc3372567a1ec886ae810d332811cc35f5d7d4584657ac08af78630f; body [{"start": "0x3b0fd0", "end": "0x3b1290"}, {"start": "0x3b12a0", "end": "0x3b13a3"}, {"start": "0x3b13b0", "end": "0x3b1662"}]
adjacent_3b0fd0: ; RVA 0x3b0fd0
0x3b0fd0: PUSH RBP
0x3b0fd1: MOV RBP, RSP
0x3b0fd4: PUSH R15
0x3b0fd6: PUSH R14
0x3b0fd8: PUSH R13
0x3b0fda: PUSH R12
0x3b0fdc: PUSH RBX
0x3b0fdd: AND RSP, -0x20
0x3b0fe1: SUB RSP, 0xc0
0x3b0fe8: MOV RBX, RSP
0x3b0feb: LEA RAX, [0x391c310]
0x3b0ff2: MOV qword ptr [RBX + 0x78], RCX
0x3b0ff6: MOV qword ptr [RBX + 0x50], RDX
0x3b0ffa: MOV R14, RSI
0x3b0ffd: MOV RAX, qword ptr [RAX]
0x3b1000: MOV qword ptr [RBX + 0xa0], RAX
0x3b1007: MOV qword ptr [RBX + 0x80], RDI
0x3b100e: MOV R12, qword ptr [RDI + 0x8]
0x3b1012: MOV RAX, qword ptr [R12 + 0xc48]
0x3b101a: MOV RDI, R12
0x3b101d: MOV qword ptr [RBX + 0x90], 0x0
0x3b1028: MOV dword ptr [RBX + 0x8c], 0x0
0x3b1032: MOV dword ptr [RBX + 0x88], 0x0
0x3b103c: MOV qword ptr [RBX + 0x58], RAX
0x3b1040: CALL 0x009f8180
0x3b1045: LEA RSI, [RBX + 0x9c]
0x3b104c: MOV RDI, R12
0x3b104f: MOV R15, RAX
0x3b1052: CALL 0x009f81c0
0x3b1057: LEA RDX, [0x34cf8c8]
0x3b105e: XOR R12D, R12D
0x3b1061: TEST EAX, EAX
0x3b1063: JNZ 0x003b10f0
0x3b1069: MOV EAX, dword ptr [RBX + 0x9c]
0x3b106f: CMP EAX, 0xffffff
0x3b1074: JA 0x003b10f0
0x3b1076: CMP EAX, 0xffff
0x3b107b: JBE 0x003b10ad
0x3b107d: AND EAX, 0xff0000
0x3b1082: LEA RCX, [0x34cfe70]
0x3b1089: LEA RDX, [0x34cf8c8]
0x3b1090: MOV R12D, 0x1
0x3b1096: CMP EAX, 0x10000
0x3b109b: CMOVZ RDX, RCX
0x3b109f: CMP dword ptr [RDX + 0x4a0], 0x1
0x3b10a6: JNZ 0x003b10f9
0x3b10a8: JMP 0x003b113b
0x3b10ad: MOV R12D, 0x1
0x3b10b3: CMP qword ptr [0x034cf7c8], R15
0x3b10ba: JZ 0x003b10e9
0x3b10bc: CMP qword ptr [0x034d08c0], R15
0x3b10c3: JZ 0x003b112b
0x3b10c5: CMP dword ptr [0x034cf7c0], 0x0
0x3b10cc: LEA RAX, [0x34cf320]
0x3b10d3: LEA RDX, [0x34d0418]
0x3b10da: CMOVZ RDX, RAX
0x3b10de: CMP dword ptr [RDX + 0x4a0], 0x1
0x3b10e5: JNZ 0x003b10f9
0x3b10e7: JMP 0x003b113b
0x3b10e9: LEA RDX, [0x34cf320]
0x3b10f0: CMP dword ptr [RDX + 0x4a0], 0x1
0x3b10f7: JZ 0x003b113b
0x3b10f9: MOV EDI, 0x1
0x3b10fe: MOV RSI, RDX
0x3b1101: MOV R15, RDX
0x3b1104: CALL 0x003b3410
0x3b1109: MOV RDX, R15
0x3b110c: TEST EAX, EAX
0x3b110e: JZ 0x003b113b
0x3b1110: MOV R15D, EAX
0x3b1113: LEA RDI, [0x131bf08]
0x3b111a: LEA RSI, [0x1379dbb]
0x3b1121: MOV EDX, 0x13c1
0x3b1126: JMP 0x003b1211
0x3b112b: LEA RDX, [0x34d0418]
0x3b1132: CMP dword ptr [RDX + 0x4a0], 0x1
0x3b1139: JNZ 0x003b10f9
0x3b113b: MOV RCX, qword ptr [RBX + 0x50]
0x3b113f: LEA EAX, [RCX + -0x81]
0x3b1145: CMP EAX, 0xffffff7f
0x3b114a: JA 0x003b116f
0x3b114c: LEA RDI, [0x131bf08]
0x3b1153: LEA RSI, [0x1379dbb]
0x3b115a: MOV R15D, 0x16
0x3b1160: MOV EDX, 0x13c7
0x3b1165: MOV ECX, 0x16
0x3b116a: JMP 0x003b1214
0x3b116f: MOV dword ptr [RBX + 0x3c], R12D
0x3b1173: MOV R13D, ECX
0x3b1176: MOV R12, R14
0x3b1179: MOV qword ptr [RBX + 0x70], RDX
0x3b117d: CMP ECX, 0x2
0x3b1180: JC 0x003b11b8
0x3b1182: LEA EAX, [0xf + RCX*0x4]
0x3b1189: MOV R15, RSP
0x3b118c: LEA ESI, [RCX*0x4]
0x3b1193: AND EAX, 0xfffffff0
0x3b1196: SUB R15, RAX
0x3b1199: AND R15, -0x20
0x3b119d: MOV RSP, R15
0x3b11a0: MOV RDI, RSP
0x3b11a3: SUB RDI, RAX
0x3b11a6: AND RDI, -0x20
0x3b11aa: MOV RSP, RDI
0x3b11ad: MOV qword ptr [RBX + 0x10], RDI
0x3b11b1: CALL 0x00258ff0
0x3b11b6: JMP 0x003b11ca
0x3b11b8: LEA RAX, [RBX + 0x88]
0x3b11bf: LEA R15, [RBX + 0x8c]
0x3b11c6: MOV qword ptr [RBX + 0x10], RAX
0x3b11ca: MOV RDI, qword ptr GS:[0x0]
0x3b11d3: LEA RSI, [0x1397f3d]
0x3b11da: XOR EDX, EDX
0x3b11dc: LEA R14, [R13*0x4]
0x3b11e4: CALL 0x00c1a3e0
0x3b11e9: MOV RDI, R12
0x3b11ec: MOV RSI, R15
0x3b11ef: MOV RDX, R14
0x3b11f2: CALL 0x00259280
0x3b11f7: TEST EAX, EAX
0x3b11f9: JZ 0x003b1244
0x3b11fb: MOV R15D, EAX
0x3b11fe: LEA RDI, [0x131bf08]
0x3b1205: LEA RSI, [0x1379dbb]
0x3b120c: MOV EDX, 0x13d6
0x3b1211: MOV ECX, R15D
0x3b1214: XOR EAX, EAX
0x3b1216: CALL 0x0025d410
0x3b121b: LEA RAX, [0x391c310]
0x3b1222: MOV RAX, qword ptr [RAX]
0x3b1225: CMP RAX, qword ptr [RBX + 0xa0]
0x3b122c: JNZ 0x003b165c
0x3b1232: MOV EAX, R15D
0x3b1235: LEA RSP, [RBP + -0x28]
0x3b1239: POP RBX
0x3b123a: POP R12
0x3b123c: POP R13
0x3b123e: POP R14
0x3b1240: POP R15
0x3b1242: POP RBP
0x3b1243: RET
0x3b1244: MOV qword ptr [RBX + 0x30], R15
0x3b1248: CALL 0x00b078d0
0x3b124d: MOV qword ptr [RBX + 0x68], R14
0x3b1251: TEST EAX, EAX
0x3b1253: JZ 0x003b1274
0x3b1255: LEA RAX, [R13*0x8]
0x3b125d: LEA RSI, [0x1a7d800]
0x3b1264: MOV EDX, 0x102
0x3b1269: LEA RDI, [RAX + RAX*0x2]
0x3b126d: CALL 0x00c08b50
0x3b1272: JMP 0x003b1276
0x3b1274: XOR EAX, EAX
0x3b1276: MOV qword ptr [RBX + 0x40], RAX
0x3b127a: ADD RAX, 0x10
0x3b127e: XOR R15D, R15D
0x3b1281: XOR R14D, R14D
0x3b1284: MOV dword ptr [RBX + 0x1c], 0x0
0x3b128b: MOV qword ptr [RBX + 0x20], R13
0x3b128f: JMP 0x003b12e7
0x3b12a0: MOV RAX, qword ptr [RBX + 0x10]
0x3b12a4: LEA RDI, [0x135b377]
0x3b12ab: LEA RSI, [0x1379dbb]
0x3b12b2: MOV EDX, 0x13e6
0x3b12b7: MOV ECX, R15D
0x3b12ba: MOV R8D, 0x3
0x3b12c0: MOV dword ptr [RAX + R15*0x4], 0x80020003
0x3b12c8: XOR EAX, EAX
0x3b12ca: CALL 0x0025d410
0x3b12cf: MOV R13, qword ptr [RBX + 0x20]
0x3b12d3: MOV RAX, qword ptr [RBX + 0x60]
0x3b12d7: INC R15
0x3b12da: ADD RAX, 0x18
0x3b12de: CMP R13, R15
0x3b12e1: JZ 0x003b157b
0x3b12e7: MOV qword ptr [RBX + 0x60], RAX
0x3b12eb: MOV RAX, qword ptr [RBX + 0x30]
0x3b12ef: MOV R13D, dword ptr [RAX + R15*0x4]
0x3b12f3: MOV R12D, R13D
0x3b12f6: MOV EDX, R13D
0x3b12f9: SAR R12D, 0x10
0x3b12fd: AND EDX, 0xffff
0x3b1303: SETNZ AL
0x3b1306: CMP R12D, 0x80
0x3b130d: SETC CL
0x3b1310: TEST AL, CL
0x3b1312: JZ 0x003b12a0
0x3b1314: CMP EDX, R14D
0x3b1317: MOV R14, RDX
0x3b131a: JZ 0x003b135a
0x3b131c: CMP dword ptr [RBX + 0x1c], 0x0
0x3b1320: JZ 0x003b132e
0x3b1322: MOV RDI, qword ptr [RBX + 0x90]
0x3b1329: CALL 0x00399eb0
0x3b132e: MOV RDI, qword ptr [RBX + 0x58]
0x3b1332: MOV ESI, R14D
0x3b1335: MOV EDX, 0x160
0x3b133a: LEA RCX, [RBX + 0x90]
0x3b1341: CALL 0x00399ee0
0x3b1346: MOV qword ptr [RBX + 0x28], RAX
0x3b134a: TEST RAX, RAX
0x3b134d: JZ 0x003b13e8
0x3b1353: MOV dword ptr [RBX + 0x1c], 0x1
0x3b135a: MOV RAX, qword ptr [RBX + 0x28]
0x3b135e: MOVSX EAX, word ptr [RAX]
0x3b1361: CMP R12D, EAX
0x3b1364: JGE 0x003b13b0
0x3b1366: MOV RDI, qword ptr [RBX + 0x90]
0x3b136d: CALL 0x00399e20
0x3b1372: TEST EAX, EAX
0x3b1374: JZ 0x003b1432
0x3b137a: MOV RAX, qword ptr [RBX + 0x10]
0x3b137e: LEA RDI, [0x135b377]
0x3b1385: LEA RSI, [0x1379dbb]
0x3b138c: MOV EDX, 0x1408
0x3b1391: MOV ECX, R15D
0x3b1394: MOV R8D, 0x1
0x3b139a: MOV dword ptr [RAX + R15*0x4], 0x80020001
0x3b13a2: JMP 0x003b13d8
0x3b13b0: MOV RAX, qword ptr [RBX + 0x10]
0x3b13b4: LEA RDI, [0x135b377]
0x3b13bb: LEA RSI, [0x1379dbb]
0x3b13c2: MOV EDX, 0x1402
0x3b13c7: MOV ECX, R15D
0x3b13ca: MOV R8D, 0x3
0x3b13d0: MOV dword ptr [RAX + R15*0x4], 0x80020003
0x3b13d8: XOR EAX, EAX
0x3b13da: CALL 0x0025d410
0x3b13df: MOV R13, qword ptr [RBX + 0x20]
0x3b13e3: JMP 0x003b12d3
0x3b13e8: MOV RAX, qword ptr [RBX + 0x10]
0x3b13ec: LEA RDI, [0x135b377]
0x3b13f3: LEA RSI, [0x1379dbb]
0x3b13fa: MOV EDX, 0x13f4
0x3b13ff: MOV ECX, R15D
0x3b1402: MOV R8D, 0x3
0x3b1408: XOR R14D, R14D
0x3b140b: MOV dword ptr [RAX + R15*0x4], 0x80020003
0x3b1413: XOR EAX, EAX
0x3b1415: CALL 0x0025d410
0x3b141a: MOV R13, qword ptr [RBX + 0x20]
0x3b141e: MOV dword ptr [RBX + 0x1c], 0x0
0x3b1425: MOV qword ptr [RBX + 0x28], 0x0
0x3b142d: JMP 0x003b12d3
0x3b1432: MOV RAX, qword ptr [RBX + 0x28]
0x3b1436: MOV ECX, R12D
0x3b1439: MOV qword ptr [RBX + 0x48], R14
0x3b143d: MOV RAX, qword ptr [RAX + 0x28]
0x3b1441: MOV R14, qword ptr [RAX + RCX*0x8]
0x3b1445: TEST R14, R14
0x3b1448: JZ 0x003b1517
0x3b144e: CMP qword ptr [RBX + 0x40], 0x0
0x3b1453: SETNZ byte ptr [RBX + 0xf]
0x3b1457: CALL 0x00b078d0
0x3b145c: TEST EAX, EAX
0x3b145e: SETNZ AL
0x3b1461: AND AL, byte ptr [RBX + 0xf]
0x3b1464: CMP AL, 0x1
0x3b1466: JNZ 0x003b1493
0x3b1468: MOV RAX, qword ptr [RBX + 0x30]
0x3b146c: MOV RDX, qword ptr [RBX + 0x60]
0x3b1470: MOV EAX, dword ptr [RAX + R15*0x4]
0x3b1474: MOV dword ptr [RDX + -0x10], EAX
0x3b1477: MOV RAX, qword ptr [R14 + 0x18]
0x3b147b: MOV RAX, qword ptr [RAX]
0x3b147e: MOV qword ptr [RDX + -0x8], RAX
0x3b1482: MOV RAX, qword ptr [R14 + 0x10]
0x3b1486: MOV RCX, RAX
0x3b1489: SAR RCX, 0x4
0x3b148d: XOR RCX, RAX
0x3b1490: MOV qword ptr [RDX], RCX
0x3b1493: MOV R14, qword ptr [R14 + 0x20]
0x3b1497: CMP R13D, 0x10000
0x3b149e: JC 0x003b14c3
0x3b14a0: CMP dword ptr [R14], 0x2
0x3b14a4: JC 0x003b14c3
0x3b14a6: LEA RDI, [0x136595b]
0x3b14ad: LEA RSI, [0x1379dbb]
0x3b14b4: MOV EDX, 0x141f
0x3b14b9: MOV ECX, R12D
0x3b14bc: XOR EAX, EAX
0x3b14be: CALL 0x0025d410
0x3b14c3: LEA R12, [R14 + 0x20]
0x3b14c7: XOR ECX, ECX
0x3b14c9: MOV ESI, 0x80000
0x3b14ce: XOR EDX, EDX
0x3b14d0: XOR R8D, R8D
0x3b14d3: XOR R9D, R9D
0x3b14d6: MOV RDI, R12
0x3b14d9: PUSH 0x0
0x3b14db: PUSH 0x0
0x3b14dd: CALL 0x00bf1770
0x3b14e2: ADD RSP, 0x10
0x3b14e6: MOV EAX, dword ptr [R14 + 0x8]
0x3b14ea: MOV RCX, qword ptr [RBX + 0x10]
0x3b14ee: MOV R13, qword ptr [RBX + 0x20]
0x3b14f2: MOV dword ptr [RCX + R15*0x4], EAX
0x3b14f6: MOV RCX, R14
0x3b14f9: MOV R14, qword ptr [RBX + 0x48]
0x3b14fd: CMP EAX, 0x3
0x3b1500: JL 0x003b1557
0x3b1502: CMP byte ptr [RCX + 0xc], 0x0
0x3b1506: JZ 0x003b1553
0x3b1508: MOV RCX, qword ptr [RBX + 0x10]
0x3b150c: OR EAX, 0x10000
0x3b1511: MOV dword ptr [RCX + R15*0x4], EAX
0x3b1515: JMP 0x003b1557
0x3b1517: MOV RAX, qword ptr [RBX + 0x10]
0x3b151b: LEA RDI, [0x135b377]
0x3b1522: LEA RSI, [0x1379dbb]
0x3b1529: MOV EDX, 0x140f
0x3b152e: MOV ECX, R15D
0x3b1531: MOV R8D, 0x3
0x3b1537: MOV dword ptr [RAX + R15*0x4], 0x80020003
0x3b153f: XOR EAX, EAX
0x3b1541: CALL 0x0025d410
0x3b1546: MOV R13, qword ptr [RBX + 0x20]
0x3b154a: MOV R14, qword ptr [RBX + 0x48]
0x3b154e: JMP 0x003b12d3
0x3b1553: MOV byte ptr [RCX + 0xc], 0x1
0x3b1557: MOV RDI, R12
0x3b155a: MOV ESI, 0x100000
0x3b155f: XOR EDX, EDX
0x3b1561: XOR ECX, ECX
0x3b1563: XOR R8D, R8D
0x3b1566: XOR R9D, R9D
0x3b1569: PUSH 0x0
0x3b156b: PUSH 0x0
0x3b156d: CALL 0x00bf1770
0x3b1572: ADD RSP, 0x10
0x3b1576: JMP 0x003b12d3
0x3b157b: MOV R12, qword ptr [RBX + 0x40]
0x3b157f: TEST R12, R12
0x3b1582: SETNZ R14B
0x3b1586: CALL 0x00b078d0
0x3b158b: TEST EAX, EAX
0x3b158d: MOV R15, qword ptr [RBX + 0x50]
0x3b1591: SETNZ AL
0x3b1594: AND AL, R14B
0x3b1597: MOV R14, qword ptr [RBX + 0x80]
0x3b159e: CMP AL, 0x1
0x3b15a0: JNZ 0x003b15bf
0x3b15a2: MOV RDI, R14
0x3b15a5: MOV ESI, R15D
0x3b15a8: MOV RDX, R12
0x3b15ab: CALL 0x000a3fb0
0x3b15b0: LEA RSI, [0x1a7d800]
0x3b15b7: MOV RDI, R12
0x3b15ba: CALL 0x00c08df0
0x3b15bf: CMP dword ptr [RBX + 0x1c], 0x0
0x3b15c3: MOV R12D, dword ptr [RBX + 0x3c]
0x3b15c7: JZ 0x003b15d5
0x3b15c9: MOV RDI, qword ptr [RBX + 0x90]
0x3b15d0: CALL 0x00399eb0
0x3b15d5: MOV RSI, qword ptr [RBX + 0x70]
0x3b15d9: MOV RDX, qword ptr [RBX + 0x58]
0x3b15dd: MOV RCX, qword ptr [RBX + 0x30]
0x3b15e1: MOV RDI, R14
0x3b15e4: MOV R8D, R15D
0x3b15e7: MOV R9D, R12D
0x3b15ea: CALL 0x003b3f50
0x3b15ef: MOV RDI, qword ptr GS:[0x0]
0x3b15f8: LEA RSI, [0x134f297]
0x3b15ff: XOR EDX, EDX
0x3b1601: CALL 0x00c1a3e0
0x3b1606: MOV RDI, qword ptr [RBX + 0x10]
0x3b160a: MOV RSI, qword ptr [RBX + 0x78]
0x3b160e: MOV RDX, qword ptr [RBX + 0x68]
0x3b1612: CALL 0x002591d0
0x3b1617: MOV R15D, EAX
0x3b161a: TEST EAX, EAX
0x3b161c: JZ 0x003b163b
0x3b161e: LEA RDI, [0x12809c0]
0x3b1625: LEA RSI, [0x1379dbb]
0x3b162c: MOV EDX, 0x1444
0x3b1631: MOV ECX, R15D
0x3b1634: XOR EAX, EAX
0x3b1636: CALL 0x0025d410
0x3b163b: CALL 0x00b078d0
0x3b1640: TEST EAX, EAX
0x3b1642: JZ 0x003b121b
0x3b1648: MOV RDX, qword ptr [RBX + 0x10]
0x3b164c: MOV RDI, R14
0x3b164f: MOV ESI, R13D
0x3b1652: CALL 0x000a4040
0x3b1657: JMP 0x003b121b
0x3b165c: CALL 0x006fd6b0
0x3b1661: UD2

; local helper / adjacent context (reachability below); evidence ev_f5b33e92ce4feb6b9f305a500a927ca28d34e4336da8ccb2dc389ebf9f7a5cd6; body [{"start": "0x3b1670", "end": "0x3b167b"}]
handler_665_body: ; RVA 0x3b1670
0x3b1670: PUSH RBP
0x3b1671: MOV RBP, RSP
0x3b1674: XOR ESI, ESI
0x3b1676: POP RBP
0x3b1677: JMP 0x00265760

; local helper / adjacent context (reachability below); evidence ev_3f38d75afb46a2f0b6c4337446e1e056027adca39fd549d38b320feabb2676a4; body [{"start": "0x3b1680", "end": "0x3b1696"}]
adjacent_3b1680: ; RVA 0x3b1680
0x3b1680: PUSH RBP
0x3b1681: MOV RBP, RSP
0x3b1684: MOV RAX, qword ptr [RSI]
0x3b1687: MOV EDX, dword ptr [RSI + 0x8]
0x3b168a: MOV RCX, qword ptr [RSI + 0x10]
0x3b168e: MOV RSI, RAX
0x3b1691: POP RBP
0x3b1692: JMP 0x003b16a0

; local helper / adjacent context (reachability below); evidence ev_3c30bca390b38ba11d41c9bd22f81fe3d96060e0b2810a74736c62a1ab89336b; body [{"start": "0x3b16a0", "end": "0x3b1924"}, {"start": "0x3b1930", "end": "0x3b19f8"}, {"start": "0x3b1a00", "end": "0x3b1e04"}, {"start": "0x3b1e10", "end": "0x3b1edc"}, {"start": "0x3b1ee0", "end": "0x3b2058"}]
adjacent_3b16a0: ; RVA 0x3b16a0
0x3b16a0: PUSH RBP
0x3b16a1: MOV RBP, RSP
0x3b16a4: PUSH R15
0x3b16a6: PUSH R14
0x3b16a8: PUSH R13
0x3b16aa: PUSH R12
0x3b16ac: PUSH RBX
0x3b16ad: AND RSP, -0x20
0x3b16b1: SUB RSP, 0xe0
0x3b16b8: MOV RBX, RSP
0x3b16bb: LEA R13, [0x391c310]
0x3b16c2: MOV qword ptr [RBX + 0x90], RCX
0x3b16c9: MOV qword ptr [RBX + 0x60], RDX
0x3b16cd: MOV R14, RSI
0x3b16d0: MOV RAX, qword ptr [R13]
0x3b16d4: MOV qword ptr [RBX + 0xc0], RAX
0x3b16db: MOV qword ptr [RBX + 0x78], RDI
0x3b16df: MOV R12, qword ptr [RDI + 0x8]
0x3b16e3: MOV RAX, qword ptr [R12 + 0xc48]
0x3b16eb: MOV RDI, R12
0x3b16ee: MOV qword ptr [RBX + 0xb8], 0x0
0x3b16f9: MOV dword ptr [RBX + 0xb4], 0x0
0x3b1703: MOV dword ptr [RBX + 0xb0], 0x0
0x3b170d: MOV qword ptr [RBX + 0x98], RAX
0x3b1714: CALL 0x009f8180
0x3b1719: LEA RSI, [RBX + 0xa0]
0x3b1720: MOV RDI, R12
0x3b1723: MOV R15, RAX
0x3b1726: CALL 0x009f81c0
0x3b172b: TEST EAX, EAX
0x3b172d: JNZ 0x003b175c
0x3b172f: MOV EAX, dword ptr [RBX + 0xa0]
0x3b1735: CMP EAX, 0xffffff
0x3b173a: JA 0x003b175c
0x3b173c: CMP EAX, 0xffff
0x3b1741: JBE 0x003b18c4
0x3b1747: AND EAX, 0xff0000
0x3b174c: CMP EAX, 0x10000
0x3b1751: JNZ 0x003b175c
0x3b1753: LEA RSI, [0x34cfe70]
0x3b175a: JMP 0x003b1763
0x3b175c: LEA RSI, [0x34cf8c8]
0x3b1763: CMP dword ptr [RSI + 0x4a0], 0x1
0x3b176a: MOV qword ptr [RBX + 0x68], RSI
0x3b176e: JZ 0x003b1798
0x3b1770: MOV EDI, 0x1
0x3b1775: CALL 0x003b3410
0x3b177a: TEST EAX, EAX
0x3b177c: JZ 0x003b1798
0x3b177e: MOV R15D, EAX
0x3b1781: LEA RDI, [0x131bf08]
0x3b1788: LEA RSI, [0x1350787]
0x3b178f: MOV EDX, 0x11ec
0x3b1794: MOV ECX, EAX
0x3b1796: JMP 0x003b17c8
0x3b1798: MOV R15, qword ptr [RBX + 0x60]
0x3b179c: LEA EAX, [R15 + -0x81]
0x3b17a3: CMP EAX, 0xffffff7f
0x3b17a8: JA 0x003b17d4
0x3b17aa: LEA RDI, [0x131bf08]
0x3b17b1: LEA RSI, [0x1350787]
0x3b17b8: MOV R15D, 0x16
0x3b17be: MOV EDX, 0x11f4
0x3b17c3: MOV ECX, 0x16
0x3b17c8: XOR EAX, EAX
0x3b17ca: CALL 0x0025d410
0x3b17cf: JMP 0x003b1f95
0x3b17d4: MOV qword ptr [RBX + 0x28], R14
0x3b17d8: CMP R15D, 0x2
0x3b17dc: JC 0x003b1816
0x3b17de: LEA EAX, [0xf + R15*0x4]
0x3b17e6: MOV R14, RSP
0x3b17e9: LEA ESI, [R15*0x4]
0x3b17f1: AND EAX, 0xfffffff0
0x3b17f4: SUB R14, RAX
0x3b17f7: AND R14, -0x20
0x3b17fb: MOV RSP, R14
0x3b17fe: MOV RDI, RSP
0x3b1801: SUB RDI, RAX
0x3b1804: AND RDI, -0x20
0x3b1808: MOV RSP, RDI
0x3b180b: MOV qword ptr [RBX + 0x18], RDI
0x3b180f: CALL 0x00258ff0
0x3b1814: JMP 0x003b1828
0x3b1816: LEA RAX, [RBX + 0xb0]
0x3b181d: LEA R14, [RBX + 0xb4]
0x3b1824: MOV qword ptr [RBX + 0x18], RAX
0x3b1828: MOV RDI, qword ptr GS:[0x0]
0x3b1831: MOV R13D, R15D
0x3b1834: LEA RSI, [0x1397f3d]
0x3b183b: XOR EDX, EDX
0x3b183d: LEA R12, [R13*0x4]
0x3b1845: CALL 0x00c1a3e0
0x3b184a: MOV RDI, qword ptr [RBX + 0x28]
0x3b184e: MOV RSI, R14
0x3b1851: MOV RDX, R12
0x3b1854: CALL 0x00259280
0x3b1859: TEST EAX, EAX
0x3b185b: JZ 0x003b1881
0x3b185d: LEA RDI, [0x131bf08]
0x3b1864: LEA RSI, [0x1350787]
0x3b186b: MOV EDX, 0x1203
0x3b1870: MOV ECX, EAX
0x3b1872: MOV R15D, EAX
0x3b1875: XOR EAX, EAX
0x3b1877: CALL 0x0025d410
0x3b187c: JMP 0x003b1f8e
0x3b1881: MOV qword ptr [RBX + 0x38], R13
0x3b1885: MOV qword ptr [RBX + 0x20], R14
0x3b1889: CALL 0x00b078d0
0x3b188e: TEST EAX, EAX
0x3b1890: JZ 0x003b18fc
0x3b1892: MOV R14, qword ptr [RBX + 0x38]
0x3b1896: LEA RSI, [0x1a7d800]
0x3b189d: MOV EDX, 0x102
0x3b18a2: LEA RAX, [R14*0x8]
0x3b18aa: LEA RDI, [RAX + RAX*0x2]
0x3b18ae: CALL 0x00c08b50
0x3b18b3: MOV R13, qword ptr [RBX + 0x18]
0x3b18b7: MOV R8, qword ptr [RBX + 0x20]
0x3b18bb: MOV RDI, R14
0x3b18be: MOV qword ptr [RBX + 0x58], RAX
0x3b18c2: JMP 0x003b1910
0x3b18c4: CMP qword ptr [0x034cf7c8], R15
0x3b18cb: JZ 0x003b1fb8
0x3b18d1: CMP qword ptr [0x034d08c0], R15
0x3b18d8: JZ 0x003b1fc4
0x3b18de: CMP dword ptr [0x034cf7c0], 0x0
0x3b18e5: LEA RAX, [0x34cf320]
0x3b18ec: LEA RSI, [0x34d0418]
0x3b18f3: CMOVZ RSI, RAX
0x3b18f7: JMP 0x003b1763
0x3b18fc: MOV R13, qword ptr [RBX + 0x18]
0x3b1900: MOV R8, qword ptr [RBX + 0x20]
0x3b1904: MOV RDI, qword ptr [RBX + 0x38]
0x3b1908: MOV qword ptr [RBX + 0x58], 0x0
0x3b1910: MOV qword ptr [RBX + 0x88], R12
0x3b1917: XOR R14D, R14D
0x3b191a: XOR EAX, EAX
0x3b191c: MOV dword ptr [RBX + 0x34], 0x0
0x3b1923: JMP 0x003b1945
0x3b1930: MOV dword ptr [R13 + R14*0x4], 0x80020003
0x3b1939: INC R14
0x3b193c: CMP R14, RDI
0x3b193f: JZ 0x003b1d96
0x3b1945: MOV R15D, dword ptr [R8 + R14*0x4]
0x3b1949: MOV R12D, R15D
0x3b194c: MOV ESI, R15D
0x3b194f: SAR R12D, 0x10
0x3b1953: AND ESI, 0xffff
0x3b1959: SETNZ CL
0x3b195c: CMP R12D, 0x80
0x3b1963: SETC DL
0x3b1966: TEST CL, DL
0x3b1968: JZ 0x003b1930
0x3b196a: MOV dword ptr [RBX + 0x40], ESI
0x3b196d: CMP ESI, EAX
0x3b196f: JZ 0x003b19b2
0x3b1971: CMP dword ptr [RBX + 0x34], 0x0
0x3b1975: JZ 0x003b1986
0x3b1977: MOV RDI, qword ptr [RBX + 0xb8]
0x3b197e: CALL 0x00399eb0
0x3b1983: MOV ESI, dword ptr [RBX + 0x40]
0x3b1986: MOV RDI, qword ptr [RBX + 0x98]
0x3b198d: MOV EDX, 0x160
0x3b1992: LEA RCX, [RBX + 0xb8]
0x3b1999: CALL 0x00399ee0
0x3b199e: MOV qword ptr [RBX + 0x28], RAX
0x3b19a2: TEST RAX, RAX
0x3b19a5: JZ 0x003b1a3c
0x3b19ab: MOV dword ptr [RBX + 0x34], 0x1
0x3b19b2: MOV RAX, qword ptr [RBX + 0x28]
0x3b19b6: MOVSX EAX, word ptr [RAX]
0x3b19b9: CMP R12D, EAX
0x3b19bc: JGE 0x003b1a00
0x3b19be: MOV RDI, qword ptr [RBX + 0xb8]
0x3b19c5: CALL 0x00399e20
0x3b19ca: TEST EAX, EAX
0x3b19cc: JZ 0x003b1a95
0x3b19d2: MOV dword ptr [R13 + R14*0x4], 0x80020001
0x3b19db: LEA RDI, [0x135b377]
0x3b19e2: LEA RSI, [0x1350787]
0x3b19e9: MOV EDX, 0x1236
0x3b19ee: MOV ECX, R14D
0x3b19f1: MOV R8D, 0x1
0x3b19f7: JMP 0x003b1a25
0x3b1a00: LEA RDI, [0x135b377]
0x3b1a07: LEA RSI, [0x1350787]
0x3b1a0e: MOV EDX, 0x1230
0x3b1a13: MOV dword ptr [R13 + R14*0x4], 0x80020003
0x3b1a1c: MOV ECX, R14D
0x3b1a1f: MOV R8D, 0x3
0x3b1a25: XOR EAX, EAX
0x3b1a27: CALL 0x0025d410
0x3b1a2c: MOV R8, qword ptr [RBX + 0x20]
0x3b1a30: MOV RDI, qword ptr [RBX + 0x38]
0x3b1a34: MOV EAX, dword ptr [RBX + 0x40]
0x3b1a37: JMP 0x003b1939
0x3b1a3c: LEA RDI, [0x135b377]
0x3b1a43: LEA RSI, [0x1350787]
0x3b1a4a: MOV EDX, 0x1222
0x3b1a4f: MOV ECX, R14D
0x3b1a52: MOV R8D, 0x3
0x3b1a58: XOR EAX, EAX
0x3b1a5a: MOV dword ptr [R13 + R14*0x4], 0x80020003
0x3b1a63: MOV qword ptr [RBX + 0x28], 0x0
0x3b1a6b: CALL 0x0025d410
0x3b1a70: MOV RDI, qword ptr [RBX + 0x38]
0x3b1a74: MOV R8, qword ptr [RBX + 0x20]
0x3b1a78: INC R14
0x3b1a7b: MOV EAX, 0x0
0x3b1a80: MOV dword ptr [RBX + 0x34], 0x0
0x3b1a87: CMP R14, RDI
0x3b1a8a: JNZ 0x003b1945
0x3b1a90: JMP 0x003b1da8
0x3b1a95: MOV RDX, qword ptr [RBX + 0x28]
0x3b1a99: MOV ECX, R12D
0x3b1a9c: MOV RAX, qword ptr [RDX + 0x28]
0x3b1aa0: CMP word ptr [RDX], 0x2
0x3b1aa4: MOV R13, qword ptr [RAX + RCX*0x8]
0x3b1aa8: JL 0x003b1acb
0x3b1aaa: TEST R13, R13
0x3b1aad: JNZ 0x003b1acb
0x3b1aaf: MOV R13, qword ptr [RBX + 0x18]
0x3b1ab3: LEA RDI, [0x135b377]
0x3b1aba: LEA RSI, [0x1350787]
0x3b1ac1: MOV EDX, 0x123f
0x3b1ac6: JMP 0x003b1a13
0x3b1acb: CMP qword ptr [RBX + 0x58], 0x0
0x3b1ad0: SETNZ byte ptr [RBX + 0x50]
0x3b1ad4: CALL 0x00b078d0
0x3b1ad9: TEST EAX, EAX
0x3b1adb: SETNZ AL
0x3b1ade: AND AL, byte ptr [RBX + 0x50]
0x3b1ae1: CMP AL, 0x1
0x3b1ae3: JNZ 0x003b1b17
0x3b1ae5: MOV RAX, qword ptr [RBX + 0x20]
0x3b1ae9: MOV RSI, qword ptr [RBX + 0x58]
0x3b1aed: LEA RCX, [R14 + R14*0x2]
0x3b1af1: MOV EAX, dword ptr [RAX + R14*0x4]
0x3b1af5: MOV dword ptr [RSI + RCX*0x8], EAX
0x3b1af8: MOV RAX, qword ptr [R13 + 0x18]
0x3b1afc: MOV RAX, qword ptr [RAX]
0x3b1aff: MOV qword ptr [RSI + RCX*0x8 + 0x8], RAX
0x3b1b04: MOV RAX, qword ptr [R13 + 0x10]
0x3b1b08: MOV RDX, RAX
0x3b1b0b: SAR RDX, 0x4
0x3b1b0f: XOR RDX, RAX
0x3b1b12: MOV qword ptr [RSI + RCX*0x8 + 0x10], RDX
0x3b1b17: MOV R13, qword ptr [R13 + 0x20]
0x3b1b1b: CMP R15D, 0x10000
0x3b1b22: JC 0x003b1b48
0x3b1b24: CMP dword ptr [R13], 0x2
0x3b1b29: JC 0x003b1b48
0x3b1b2b: LEA RDI, [0x136595b]
0x3b1b32: LEA RSI, [0x1350787]
0x3b1b39: MOV EDX, 0x1250
0x3b1b3e: MOV ECX, R12D
0x3b1b41: XOR EAX, EAX
0x3b1b43: CALL 0x0025d410
0x3b1b48: LEA RDI, [R13 + 0x20]
0x3b1b4c: MOV ESI, 0x80000
0x3b1b51: XOR EDX, EDX
0x3b1b53: XOR ECX, ECX
0x3b1b55: XOR R8D, R8D
0x3b1b58: XOR R9D, R9D
0x3b1b5b: MOV qword ptr [RBX + 0x70], RDI
0x3b1b5f: PUSH 0x0
0x3b1b61: PUSH 0x0
0x3b1b63: CALL 0x00bf1770
0x3b1b68: ADD RSP, 0x10
0x3b1b6c: MOV EAX, dword ptr [R13 + 0x8]
0x3b1b70: MOV R15, qword ptr [RBX + 0x18]
0x3b1b74: LEA ECX, [RAX + -0x3]
0x3b1b77: CMP ECX, 0x1
0x3b1b7a: JA 0x003b1bb3
0x3b1b7c: MOV RDI, qword ptr [RBX + 0x70]
0x3b1b80: XOR R8D, R8D
0x3b1b83: MOV dword ptr [R15 + R14*0x4], EAX
0x3b1b87: MOV ESI, 0x100000
0x3b1b8c: XOR EDX, EDX
0x3b1b8e: XOR ECX, ECX
0x3b1b90: XOR R9D, R9D
0x3b1b93: PUSH 0x0
0x3b1b95: PUSH 0x0
0x3b1b97: CALL 0x00bf1770
0x3b1b9c: ADD RSP, 0x10
0x3b1ba0: MOV R8, qword ptr [RBX + 0x20]
0x3b1ba4: MOV RDI, qword ptr [RBX + 0x38]
0x3b1ba8: MOV EAX, dword ptr [RBX + 0x40]
0x3b1bab: MOV R13, R15
0x3b1bae: JMP 0x003b1939
0x3b1bb3: MOV ECX, dword ptr [R13]
0x3b1bb7: MOV dword ptr [R15 + R14*0x4], EAX
0x3b1bbb: MOV qword ptr [RBX + 0x18], R15
0x3b1bbf: CMP dword ptr [R13], 0x0
0x3b1bc4: JZ 0x003b1d5d
0x3b1bca: XOR EAX, EAX
0x3b1bcc: CMP ECX, 0x2
0x3b1bcf: MOV qword ptr [RBX + 0x80], R13
0x3b1bd6: CMOVGE R12D, EAX
0x3b1bda: JMP 0x003b1c09
0x3b1bdc: MOV RAX, qword ptr [RBX + 0x18]
0x3b1be0: MOV dword ptr [RAX + R14*0x4], 0x2
0x3b1be8: NOP dword ptr [RAX + RAX*0x1]
0x3b1bf0: MOV EAX, dword ptr [RBX + 0x50]
0x3b1bf3: MOV R13, qword ptr [RBX + 0x80]
0x3b1bfa: INC R12D
0x3b1bfd: INC EAX
0x3b1bff: CMP EAX, dword ptr [R13]
0x3b1c03: JNC 0x003b1d5d
0x3b1c09: MOV RCX, qword ptr [RBX + 0x28]
0x3b1c0d: MOV dword ptr [RBX + 0x50], EAX
0x3b1c10: MOV RAX, qword ptr [RCX + 0x28]
0x3b1c14: MOVSXD RCX, R12D
0x3b1c17: MOV R13, qword ptr [RAX + RCX*0x8]
0x3b1c1b: TEST R13, R13
0x3b1c1e: JZ 0x003b1bf0
0x3b1c20: CMP dword ptr [R13 + 0x38], 0x1
0x3b1c25: JNZ 0x003b1bf0
0x3b1c27: MOV RAX, qword ptr [RBX + 0x28]
0x3b1c2b: MOV RCX, qword ptr [RBX + 0x68]
0x3b1c2f: MOV RDI, R13
0x3b1c32: MOV EDX, 0x1
0x3b1c37: MOV ESI, dword ptr [RAX + 0x4]
0x3b1c3a: CALL 0x003b4190
0x3b1c3f: TEST EAX, EAX
0x3b1c41: JNZ 0x003b1bf0
0x3b1c43: MOV RAX, qword ptr [R13 + 0x10]
0x3b1c47: MOV RDX, R13
0x3b1c4a: CMP qword ptr [RAX + 0x18], 0x0
0x3b1c4f: JZ 0x003b1ca2
0x3b1c51: MOV qword ptr [RBX + 0xa8], 0x0
0x3b1c5c: MOV qword ptr [RBX + 0xa0], -0x7ffdffab
0x3b1c67: LEA RSI, [0x134f297]
0x3b1c6e: MOV ECX, dword ptr [RDX + 0x38]
0x3b1c71: XOR EDX, EDX
0x3b1c73: MOV dword ptr [RBX + 0xa8], ECX
0x3b1c79: MOV R15, qword ptr [RAX + 0x18]
0x3b1c7d: MOV RDI, qword ptr GS:[0x0]
0x3b1c86: CALL 0x00c1a3e0
0x3b1c8b: MOV EDX, 0x10
0x3b1c90: LEA RDI, [RBX + 0xa0]
0x3b1c97: MOV RSI, R15
0x3b1c9a: CALL 0x002591d0
0x3b1c9f: MOV RDX, R13
0x3b1ca2: MOV RCX, qword ptr [RBX + 0x80]
0x3b1ca9: MOV EAX, dword ptr [RCX + 0x4]
0x3b1cac: TEST EAX, EAX
0x3b1cae: JZ 0x003b1cc1
0x3b1cb0: DEC EAX
0x3b1cb2: MOV dword ptr [RCX + 0x4], EAX
0x3b1cb5: MOV byte ptr [RCX + 0xd], 0x1
0x3b1cb9: JNZ 0x003b1bdc
0x3b1cbf: JMP 0x003b1cc5
0x3b1cc1: MOV byte ptr [RCX + 0xd], 0x1
0x3b1cc5: MOV EAX, dword ptr [RDX + 0x38]
0x3b1cc8: MOV dword ptr [RCX + 0x8], EAX
0x3b1ccb: MOV R15, qword ptr [RCX + 0x50]
0x3b1ccf: TEST R15, R15
0x3b1cd2: JZ 0x003b1bf0
0x3b1cd8: MOV dword ptr [RBX + 0x4c], 0x0
0x3b1cdf: JMP 0x003b1d13
0x3b1ce1: MOV RDI, qword ptr [R15]
0x3b1ce4: MOV dword ptr [RBX + 0x4c], 0x1
0x3b1ceb: CALL 0x00c06910
0x3b1cf0: MOV RDI, qword ptr [R15 + 0x10]
0x3b1cf4: XOR ESI, ESI
0x3b1cf6: XOR EDX, EDX
0x3b1cf8: XOR ECX, ECX
0x3b1cfa: ADD RDI, 0x18
0x3b1cfe: CALL 0x004c6fa0
0x3b1d03: MOV R15, qword ptr [R15 + 0x30]
0x3b1d07: MOV RDX, R13
0x3b1d0a: TEST R15, R15
0x3b1d0d: JZ 0x003b1bf0
0x3b1d13: MOV EAX, dword ptr [RDX + 0x38]
0x3b1d16: XOR ESI, ESI
0x3b1d18: XOR EDX, EDX
0x3b1d1a: XOR ECX, ECX
0x3b1d1c: MOV dword ptr [R15 + 0x20], EAX
0x3b1d20: MOV RDI, qword ptr [R15 + 0x10]
0x3b1d24: ADD RDI, 0x18
0x3b1d28: CALL 0x004c6a00
0x3b1d2d: MOV RAX, qword ptr [R15]
0x3b1d30: DEC dword ptr [RAX]
0x3b1d32: MOV RDI, qword ptr [R15]
0x3b1d35: CMP dword ptr [RDI], 0x0
0x3b1d38: JG 0x003b1cf0
0x3b1d3a: MOV RAX, qword ptr [R15 + 0x8]
0x3b1d3e: TEST RAX, RAX
0x3b1d41: JZ 0x003b1ceb
0x3b1d43: DEC dword ptr [RAX]
0x3b1d45: CMP dword ptr [RBX + 0x4c], 0x0
0x3b1d49: JZ 0x003b1ce1
0x3b1d4b: MOV RAX, qword ptr [R15 + 0x8]
0x3b1d4f: MOV dword ptr [RBX + 0x4c], 0x1
0x3b1d56: CMP dword ptr [RAX], 0x0
0x3b1d59: JNZ 0x003b1cf0
0x3b1d5b: JMP 0x003b1ce1
0x3b1d5d: CMP byte ptr [R13 + 0xd], 0x0
0x3b1d62: MOV R13, qword ptr [RBX + 0x18]
0x3b1d66: JZ 0x003b1d71
0x3b1d68: MOV dword ptr [R13 + R14*0x4], 0x4
0x3b1d71: MOV RDI, qword ptr [RBX + 0x70]
0x3b1d75: MOV ESI, 0x100000
0x3b1d7a: XOR EDX, EDX
0x3b1d7c: XOR ECX, ECX
0x3b1d7e: XOR R8D, R8D
0x3b1d81: XOR R9D, R9D
0x3b1d84: PUSH 0x0
0x3b1d86: PUSH 0x0
0x3b1d88: CALL 0x00bf1770
0x3b1d8d: ADD RSP, 0x10
0x3b1d91: JMP 0x003b1a2c
0x3b1d96: CMP dword ptr [RBX + 0x34], 0x0
0x3b1d9a: JZ 0x003b1da8
0x3b1d9c: MOV RDI, qword ptr [RBX + 0xb8]
0x3b1da3: CALL 0x00399eb0
0x3b1da8: MOV R15, qword ptr [RBX + 0x58]
0x3b1dac: TEST R15, R15
0x3b1daf: SETNZ R14B
0x3b1db3: CALL 0x00b078d0
0x3b1db8: TEST EAX, EAX
0x3b1dba: SETNZ AL
0x3b1dbd: AND AL, R14B
0x3b1dc0: CMP AL, 0x1
0x3b1dc2: JNZ 0x003b1de3
0x3b1dc4: MOV RDI, qword ptr [RBX + 0x78]
0x3b1dc8: MOV RDX, R15
0x3b1dcb: MOV RSI, qword ptr [RBX + 0x60]
0x3b1dcf: CALL 0x000a3ca0
0x3b1dd4: LEA RSI, [0x1a7d800]
0x3b1ddb: MOV RDI, R15
0x3b1dde: CALL 0x00c08df0
0x3b1de3: MOV R15, qword ptr [RBX + 0x68]
0x3b1de7: MOV R14D, 0x3
0x3b1ded: LEA RAX, [R15 + 0xd8]
0x3b1df4: LEA RCX, [R15 + 0x80]
0x3b1dfb: MOV qword ptr [RBX + 0x40], RAX
0x3b1dff: MOV qword ptr [RBX + 0x50], RCX
0x3b1e03: JMP 0x003b1e3c
0x3b1e10: MOV RDI, qword ptr [RBX + 0x28]
0x3b1e14: MOV dword ptr [R8 + R14*0x4 + 0x160], 0x0
0x3b1e20: XOR ESI, ESI
0x3b1e22: XOR EDX, EDX
0x3b1e24: XOR ECX, ECX
0x3b1e26: MOV R15, R8
0x3b1e29: CALL 0x004c6fa0
0x3b1e2e: CMP R14, 0x1
0x3b1e32: LEA R14, [R14 + -0x1]
0x3b1e36: JBE 0x003b1f41
0x3b1e3c: MOV RDI, R14
0x3b1e3f: XOR ESI, ESI
0x3b1e41: XOR EDX, EDX
0x3b1e43: XOR ECX, ECX
0x3b1e45: SHL RDI, 0x5
0x3b1e49: ADD RDI, qword ptr [RBX + 0x40]
0x3b1e4d: MOV qword ptr [RBX + 0x28], RDI
0x3b1e51: CALL 0x004c6a00
0x3b1e56: CMP dword ptr [R15 + R14*0x4 + 0x160], 0x0
0x3b1e5f: MOV R8, R15
0x3b1e62: JZ 0x003b1e10
0x3b1e64: CMP dword ptr [R8 + R14*0x4 + 0x1c0], 0x0
0x3b1e6d: JZ 0x003b1e10
0x3b1e6f: MOV RAX, qword ptr [RBX + 0x50]
0x3b1e73: MOV R13, R14
0x3b1e76: SHL R13, 0x4
0x3b1e7a: LEA R15, [RAX + R13*0x1]
0x3b1e7e: JMP 0x003b1ea7
0x3b1e80: MOV qword ptr [RDI + 0x48], 0x0
0x3b1e88: MOV RAX, qword ptr [R8 + R13*0x1 + 0x48]
0x3b1e8d: MOV qword ptr [RDI + 0x50], RAX
0x3b1e91: MOV qword ptr [RAX], RDI
0x3b1e94: MOV qword ptr [R8 + R13*0x1 + 0x48], R12
0x3b1e99: DEC dword ptr [R8 + R14*0x4 + 0x160]
0x3b1ea1: JZ 0x003b1e10
0x3b1ea7: MOV RDI, qword ptr [R15]
0x3b1eaa: TEST RDI, RDI
0x3b1ead: JZ 0x003b1e10
0x3b1eb3: MOV RAX, qword ptr [RDI + 0x48]
0x3b1eb7: LEA R12, [RDI + 0x48]
0x3b1ebb: TEST RAX, RAX
0x3b1ebe: JZ 0x003b1ee0
0x3b1ec0: CMP qword ptr [RAX + 0x50], R12
0x3b1ec4: JNZ 0x003b200d
0x3b1eca: MOV RCX, qword ptr [RDI + 0x50]
0x3b1ece: CMP qword ptr [RCX], RDI
0x3b1ed1: JNZ 0x003b1fd0
0x3b1ed7: MOV qword ptr [RAX + 0x50], RCX
0x3b1edb: JMP 0x003b1ef1
0x3b1ee0: MOV RAX, qword ptr [RDI + 0x50]
0x3b1ee4: CMP qword ptr [RAX], RDI
0x3b1ee7: JNZ 0x003b1fd0
0x3b1eed: MOV qword ptr [R15 + 0x8], RAX
0x3b1ef1: MOV RAX, qword ptr [RDI + 0x48]
0x3b1ef5: MOV RCX, qword ptr [RDI + 0x50]
0x3b1ef9: MOV qword ptr [RCX], RAX
0x3b1efc: MOV EAX, dword ptr [R8 + R14*0x4 + 0x1d0]
0x3b1f04: LEA ECX, [RAX + 0x1]
0x3b1f07: MOV dword ptr [R8 + R14*0x4 + 0x1d0], ECX
0x3b1f0f: MOV dword ptr [RDI + 0x4], EAX
0x3b1f12: MOV RDX, qword ptr [RDI + 0x8]
0x3b1f16: TEST RDX, RDX
0x3b1f19: JZ 0x003b1e80
0x3b1f1f: MOV ESI, R14D
0x3b1f22: MOV RCX, R8
0x3b1f25: CALL 0x003b4440
0x3b1f2a: MOV R8, qword ptr [RBX + 0x68]
0x3b1f2e: DEC dword ptr [R8 + R14*0x4 + 0x160]
0x3b1f36: JNZ 0x003b1ea7
0x3b1f3c: JMP 0x003b1e10
0x3b1f41: MOV RDI, qword ptr GS:[0x0]
0x3b1f4a: LEA RSI, [0x134f297]
0x3b1f51: XOR EDX, EDX
0x3b1f53: CALL 0x00c1a3e0
0x3b1f58: MOV R14, qword ptr [RBX + 0x18]
0x3b1f5c: MOV RSI, qword ptr [RBX + 0x90]
0x3b1f63: MOV RDX, qword ptr [RBX + 0x88]
0x3b1f6a: MOV RDI, R14
0x3b1f6d: CALL 0x002591d0
0x3b1f72: MOV R15D, EAX
0x3b1f75: CALL 0x00b078d0
0x3b1f7a: TEST EAX, EAX
0x3b1f7c: JZ 0x003b1f8e
0x3b1f7e: MOV RDI, qword ptr [RBX + 0x78]
0x3b1f82: MOV RDX, R14
0x3b1f85: MOV RSI, qword ptr [RBX + 0x60]
0x3b1f89: CALL 0x000a3d30
0x3b1f8e: LEA R13, [0x391c310]
0x3b1f95: MOV RAX, qword ptr [R13]
0x3b1f99: CMP RAX, qword ptr [RBX + 0xc0]
0x3b1fa0: JNZ 0x003b2052
0x3b1fa6: MOV EAX, R15D
0x3b1fa9: LEA RSP, [RBP + -0x28]
0x3b1fad: POP RBX
0x3b1fae: POP R12
0x3b1fb0: POP R13
0x3b1fb2: POP R14
0x3b1fb4: POP R15
0x3b1fb6: POP RBP
0x3b1fb7: RET
0x3b1fb8: LEA RSI, [0x34cf320]
0x3b1fbf: JMP 0x003b1763
0x3b1fc4: LEA RSI, [0x34d0418]
0x3b1fcb: JMP 0x003b1763
0x3b1fd0: MOV R14, RDI
0x3b1fd3: CALL 0x007f1950
0x3b1fd8: MOV RDX, qword ptr [R14 + 0x50]
0x3b1fdc: LEA RDI, [0x3b1fd0]
0x3b1fe3: MOV RSI, R14
0x3b1fe6: MOV RCX, qword ptr [RDX]
0x3b1fe9: CALL 0x007f20c0
0x3b1fee: MOV RCX, qword ptr [R14 + 0x50]
0x3b1ff2: LEA RSI, [0x131bb64]
0x3b1ff9: MOV EDI, 0x4b
0x3b1ffe: MOV RDX, R14
0x3b2001: XOR EAX, EAX
0x3b2003: MOV R8, qword ptr [RCX]
0x3b2006: CALL 0x00c9aa10
0x3b200b: UD2
0x3b200d: MOV R14, RDI
0x3b2010: CALL 0x007f1950
0x3b2015: MOV RDX, qword ptr [R14 + 0x48]
0x3b2019: LEA RDI, [0x3b200d]
0x3b2020: MOV RSI, R14
0x3b2023: MOV R8, R12
0x3b2026: MOV RCX, qword ptr [RDX + 0x50]
0x3b202a: CALL 0x007f2180
0x3b202f: MOV RCX, qword ptr [R14 + 0x48]
0x3b2033: LEA RSI, [0x136f6f3]
0x3b203a: MOV EDI, 0x47
0x3b203f: MOV RDX, R14
0x3b2042: MOV R9, R12
0x3b2045: XOR EAX, EAX
0x3b2047: MOV R8, qword ptr [RCX + 0x50]
0x3b204b: CALL 0x00c9aa10
0x3b2050: UD2
0x3b2052: CALL 0x006fd6b0
0x3b2057: UD2

; local helper / adjacent context (reachability below); evidence ev_b1bd52ad07296e7950ec17145e6c32e839d47da28f744813fcc7e675784e6524; body [{"start": "0x3b2060", "end": "0x3b207c"}]
adjacent_3b2060: ; RVA 0x3b2060
0x3b2060: PUSH RBP
0x3b2061: MOV RBP, RSP
0x3b2064: MOV EAX, dword ptr [RSI]
0x3b2066: MOV RDX, qword ptr [RSI + 0x8]
0x3b206a: MOV ECX, dword ptr [RSI + 0x10]
0x3b206d: MOV R8D, dword ptr [RSI + 0x18]
0x3b2071: MOV R9, qword ptr [RSI + 0x20]
0x3b2075: MOV ESI, EAX
0x3b2077: POP RBP
0x3b2078: JMP 0x003b2080

; local helper / adjacent context (reachability below); evidence ev_738e06136341ecab4c7fb5594069cea83215183a710a88071e760e821b21e166; body [{"start": "0x3b2080", "end": "0x3b281d"}, {"start": "0x3b2820", "end": "0x3b28c2"}]
adjacent_3b2080: ; RVA 0x3b2080
0x3b2080: PUSH RBP
0x3b2081: MOV RBP, RSP
0x3b2084: PUSH R15
0x3b2086: PUSH R14
0x3b2088: PUSH R13
0x3b208a: PUSH R12
0x3b208c: PUSH RBX
0x3b208d: AND RSP, -0x20
0x3b2091: SUB RSP, 0xa0
0x3b2098: MOV RBX, RSP
0x3b209b: LEA RAX, [0x391c310]
0x3b20a2: MOV qword ptr [RBX + 0x68], R9
0x3b20a6: MOV qword ptr [RBX + 0x38], R8
0x3b20aa: MOV qword ptr [RBX + 0x10], RCX
0x3b20ae: MOV R12, RDX
0x3b20b1: MOV R15D, ESI
0x3b20b4: MOV RAX, qword ptr [RAX]
0x3b20b7: MOV qword ptr [RBX + 0x80], RAX
0x3b20be: MOV qword ptr [RBX + 0x60], RDI
0x3b20c2: MOV R13, qword ptr [RDI + 0x8]
0x3b20c6: MOV RAX, qword ptr [R13 + 0xc48]
0x3b20cd: MOV RDI, R13
0x3b20d0: MOV qword ptr [RBX + 0x30], RAX
0x3b20d4: CALL 0x009f8180
0x3b20d9: LEA RSI, [RBX + 0x70]
0x3b20dd: MOV RDI, R13
0x3b20e0: MOV R14, RAX
0x3b20e3: CALL 0x009f81c0
0x3b20e8: TEST EAX, EAX
0x3b20ea: JNZ 0x003b2116
0x3b20ec: MOV EAX, dword ptr [RBX + 0x70]
0x3b20ef: CMP EAX, 0xffffff
0x3b20f4: JA 0x003b2116
0x3b20f6: CMP EAX, 0xffff
0x3b20fb: JBE 0x003b228e
0x3b2101: AND EAX, 0xff0000
0x3b2106: CMP EAX, 0x10000
0x3b210b: JNZ 0x003b2116
0x3b210d: LEA R14, [0x34cfe70]
0x3b2114: JMP 0x003b211d
0x3b2116: LEA R14, [0x34cf8c8]
0x3b211d: MOV ECX, R15D
0x3b2120: MOV R13D, 0x16
0x3b2126: AND ECX, 0xfff
0x3b212c: LEA EAX, [RCX + -0x1]
0x3b212f: CMP EAX, 0x1
0x3b2132: JA 0x003b22e7
0x3b2138: CMP dword ptr [R14 + 0x4a0], 0x1
0x3b2140: JZ 0x003b2176
0x3b2142: MOV EDI, 0x1
0x3b2147: MOV RSI, R14
0x3b214a: MOV R13, RCX
0x3b214d: CALL 0x003b3410
0x3b2152: MOV RCX, R13
0x3b2155: TEST EAX, EAX
0x3b2157: JZ 0x003b2176
0x3b2159: MOV R13D, EAX
0x3b215c: LEA RDI, [0x131bf08]
0x3b2163: LEA RSI, [0x1379d6c]
0x3b216a: MOV EDX, 0xdb7
0x3b216f: MOV ECX, EAX
0x3b2171: JMP 0x003b22e0
0x3b2176: MOV qword ptr [RBX + 0x50], R14
0x3b217a: MOV R14, qword ptr [RBX + 0x10]
0x3b217e: LEA EAX, [R14 + -0x81]
0x3b2185: CMP EAX, 0xffffff7f
0x3b218a: JA 0x003b21aa
0x3b218c: LEA RDI, [0x131bf08]
0x3b2193: LEA RSI, [0x1379d6c]
0x3b219a: MOV R13D, 0x16
0x3b21a0: MOV EDX, 0xdbd
0x3b21a5: JMP 0x003b22db
0x3b21aa: MOV RAX, qword ptr [RBX + 0x38]
0x3b21ae: DEC EAX
0x3b21b0: CMP EAX, 0x3
0x3b21b3: JNC 0x003b22c2
0x3b21b9: MOV RDI, qword ptr [RBX + 0x30]
0x3b21bd: LEA RSI, [RBX + 0x70]
0x3b21c1: MOV qword ptr [RBX + 0x28], RCX
0x3b21c5: CALL 0x003998e0
0x3b21ca: MOV dword ptr [RBX + 0x7c], EAX
0x3b21cd: CMP EAX, -0x1
0x3b21d0: JZ 0x003b231c
0x3b21d6: MOV dword ptr [RBX + 0x1c], EAX
0x3b21d9: LEA EAX, [R14*0x8]
0x3b21e1: LEA RSI, [0x1ab5890]
0x3b21e8: MOV EDX, 0x102
0x3b21ed: LEA R13D, [RAX + RAX*0x4]
0x3b21f1: MOV RDI, R13
0x3b21f4: CALL 0x00c08b50
0x3b21f9: MOV RDI, qword ptr GS:[0x0]
0x3b2202: LEA RSI, [0x1397f3d]
0x3b2209: XOR EDX, EDX
0x3b220b: MOV R14, RAX
0x3b220e: CALL 0x00c1a3e0
0x3b2213: MOV RDI, R12
0x3b2216: MOV RSI, R14
0x3b2219: MOV RDX, R13
0x3b221c: CALL 0x00259280
0x3b2221: TEST EAX, EAX
0x3b2223: JZ 0x003b2348
0x3b2229: LEA R15, [0x131bf08]
0x3b2230: LEA RSI, [0x12fc41c]
0x3b2237: MOV EDX, 0xb13
0x3b223c: MOV ECX, EAX
0x3b223e: MOV R13D, EAX
0x3b2241: XOR EAX, EAX
0x3b2243: MOV RDI, R15
0x3b2246: CALL 0x0025d410
0x3b224b: LEA RSI, [0x1ab5890]
0x3b2252: MOV RDI, R14
0x3b2255: CALL 0x00c08df0
0x3b225a: LEA RSI, [0x1379d6c]
0x3b2261: MOV RDI, R15
0x3b2264: MOV EDX, 0xdd6
0x3b2269: MOV ECX, R13D
0x3b226c: XOR EAX, EAX
0x3b226e: CALL 0x0025d410
0x3b2273: MOV RDX, qword ptr [RBX + 0x70]
0x3b2277: MOV RDI, qword ptr [RBX + 0x30]
0x3b227b: MOV ESI, dword ptr [RBX + 0x1c]
0x3b227e: CALL 0x00399e30
0x3b2283: MOV RDI, qword ptr [RBX + 0x70]
0x3b2287: CALL 0x00399eb0
0x3b228c: JMP 0x003b22e7
0x3b228e: CMP qword ptr [0x034cf7c8], R14
0x3b2295: JZ 0x003b2310
0x3b2297: CMP qword ptr [0x034d08c0], R14
0x3b229e: JZ 0x003b233c
0x3b22a4: CMP dword ptr [0x034cf7c0], 0x0
0x3b22ab: LEA RAX, [0x34cf320]
0x3b22b2: LEA R14, [0x34d0418]
0x3b22b9: CMOVZ R14, RAX
0x3b22bd: JMP 0x003b211d
0x3b22c2: LEA RDI, [0x131bf08]
0x3b22c9: LEA RSI, [0x1379d6c]
0x3b22d0: MOV R13D, 0x16
0x3b22d6: MOV EDX, 0xdc7
0x3b22db: MOV ECX, 0x16
0x3b22e0: XOR EAX, EAX
0x3b22e2: CALL 0x0025d410
0x3b22e7: LEA RAX, [0x391c310]
0x3b22ee: MOV RAX, qword ptr [RAX]
0x3b22f1: CMP RAX, qword ptr [RBX + 0x80]
0x3b22f8: JNZ 0x003b28bc
0x3b22fe: MOV EAX, R13D
0x3b2301: LEA RSP, [RBP + -0x28]
0x3b2305: POP RBX
0x3b2306: POP R12
0x3b2308: POP R13
0x3b230a: POP R14
0x3b230c: POP R15
0x3b230e: POP RBP
0x3b230f: RET
0x3b2310: LEA R14, [0x34cf320]
0x3b2317: JMP 0x003b211d
0x3b231c: LEA RDI, [0x131bf08]
0x3b2323: LEA RSI, [0x1379d6c]
0x3b232a: MOV R13D, 0x23
0x3b2330: MOV EDX, 0xdcf
0x3b2335: MOV ECX, 0x23
0x3b233a: JMP 0x003b22e0
0x3b233c: LEA R14, [0x34d0418]
0x3b2343: JMP 0x003b211d
0x3b2348: MOV EAX, R15D
0x3b234b: MOV qword ptr [RBX + 0x40], R14
0x3b234f: AND EAX, 0x1000
0x3b2354: MOV dword ptr [RBX + 0xc], EAX
0x3b2357: JNZ 0x003b23ad
0x3b2359: LEA RSI, [0x1ab5970]
0x3b2360: MOV EDI, 0x58
0x3b2365: MOV EDX, 0x102
0x3b236a: CALL 0x00c08b50
0x3b236f: MOV R14, RAX
0x3b2372: MOV RAX, qword ptr [RBX + 0x10]
0x3b2376: LEA RDX, [0x1330a9f]
0x3b237d: MOV R8D, 0x1
0x3b2383: XOR ESI, ESI
0x3b2385: XOR ECX, ECX
0x3b2387: LEA RDI, [R14 + 0x20]
0x3b238b: MOV dword ptr [R14], EAX
0x3b238e: MOV dword ptr [R14 + 0x4], EAX
0x3b2392: MOV dword ptr [R14 + 0x8], 0x1
0x3b239a: MOV qword ptr [R14 + 0x50], 0x0
0x3b23a2: CALL 0x00bf1690
0x3b23a7: MOV R13D, dword ptr [RBX + 0x1c]
0x3b23ab: JMP 0x003b2415
0x3b23ad: MOV R12, qword ptr [RBX + 0x10]
0x3b23b1: LEA RSI, [0x1ab5970]
0x3b23b8: MOV EDX, 0x102
0x3b23bd: IMUL EDI, R12D, 0x58
0x3b23c1: CALL 0x00c08b50
0x3b23c6: MOV R14, RAX
0x3b23c9: MOV R13, RAX
0x3b23cc: NOP dword ptr [RAX]
0x3b23d0: MOV RAX, 0x100000001
0x3b23da: LEA RDI, [R13 + 0x20]
0x3b23de: LEA RDX, [0x1330a9f]
0x3b23e5: MOV R8D, 0x1
0x3b23eb: XOR ESI, ESI
0x3b23ed: XOR ECX, ECX
0x3b23ef: MOV qword ptr [R13], RAX
0x3b23f3: MOV dword ptr [R13 + 0x8], 0x1
0x3b23fb: MOV qword ptr [R13 + 0x50], 0x0
0x3b2403: CALL 0x00bf1690
0x3b2408: ADD R13, 0x58
0x3b240c: DEC R12D
0x3b240f: JNZ 0x003b23d0
0x3b2411: MOV R13D, dword ptr [RBX + 0x7c]
0x3b2415: LEA RSI, [0x1ab5a50]
0x3b241c: MOV EDI, 0x30
0x3b2421: MOV EDX, 0x102
0x3b2426: CALL 0x00c08b50
0x3b242b: MOV R12, RAX
0x3b242e: MOV EAX, dword ptr [RBX + 0x10]
0x3b2431: LEA RSI, [0x1ab5a50]
0x3b2438: MOV EDX, 0x102
0x3b243d: LEA RDI, [RAX*0x8]
0x3b2445: MOV qword ptr [RBX + 0x20], RAX
0x3b2449: CALL 0x00c08b50
0x3b244e: CMP dword ptr [RBX + 0xc], 0x0
0x3b2452: MOV qword ptr [R12 + 0x28], RAX
0x3b2457: MOV qword ptr [R12 + 0x10], R14
0x3b245c: MOV qword ptr [RBX + 0x48], R12
0x3b2460: MOV dword ptr [R12 + 0x8], R13D
0x3b2465: MOV R12, qword ptr [RBX + 0x40]
0x3b2469: MOV dword ptr [RBX + 0x1c], R13D
0x3b246d: JNZ 0x003b2479
0x3b246f: MOV qword ptr [R14 + 0x18], RAX
0x3b2473: MOV AX, 0x1
0x3b2477: JMP 0x003b247d
0x3b2479: MOV RAX, qword ptr [RBX + 0x10]
0x3b247d: MOV RCX, qword ptr [RBX + 0x48]
0x3b2481: MOV R13, qword ptr [RBX + 0x38]
0x3b2485: MOV word ptr [RCX + 0x2], AX
0x3b2489: MOV word ptr [RCX], AX
0x3b248c: MOV RAX, qword ptr [RBX + 0x50]
0x3b2490: MOV dword ptr [RCX + 0x4], R13D
0x3b2494: MOV qword ptr [RCX + 0x20], R12
0x3b2498: MOV qword ptr [RCX + 0x18], RAX
0x3b249c: CALL 0x00b078d0
0x3b24a1: TEST EAX, EAX
0x3b24a3: JZ 0x003b24bb
0x3b24a5: MOV RCX, qword ptr [RBX + 0x60]
0x3b24a9: MOV ESI, R15D
0x3b24ac: MOV RDX, R12
0x3b24af: MOV R8D, R13D
0x3b24b2: MOV RDI, qword ptr [RBX + 0x10]
0x3b24b6: CALL 0x000a36d0
0x3b24bb: LEA RSI, [0x1ab59e0]
0x3b24c2: MOV EDI, 0x30
0x3b24c7: MOV EDX, 0x102
0x3b24cc: CALL 0x00c08b50
0x3b24d1: MOV R15, RAX
0x3b24d4: MOV RAX, qword ptr GS:[0x0]
0x3b24dd: MOV RCX, qword ptr [RAX + 0x390]
0x3b24e4: MOV qword ptr [R15], RCX
0x3b24e7: MOV RCX, qword ptr [RAX + 0x8]
0x3b24eb: MOV qword ptr [R15 + 0x8], RCX
0x3b24ef: MOV RDI, qword ptr [RAX + 0x140]
0x3b24f6: CALL 0x002ab3a0
0x3b24fb: MOV R13, qword ptr [RBX + 0x48]
0x3b24ff: MOV qword ptr [R15 + 0x10], RAX
0x3b2503: MOV qword ptr [R15 + 0x28], R13
0x3b2507: CALL 0x005f0f50
0x3b250c: CMP dword ptr [RBX + 0xc], 0x0
0x3b2510: MOV qword ptr [RBX + 0x58], R15
0x3b2514: MOV dword ptr [R15 + 0x20], EAX
0x3b2518: JNZ 0x003b2573
0x3b251a: XOR R15D, R15D
0x3b251d: MOV qword ptr [R14 + 0x10], R13
0x3b2521: NOP dword ptr CS:[RAX + RAX*0x1]
0x3b2530: MOV EDI, 0x58
0x3b2535: LEA RSI, [0x1ab5900]
0x3b253c: MOV EDX, 0x102
0x3b2541: CALL 0x00c08b50
0x3b2546: MOV RCX, qword ptr [RBX + 0x28]
0x3b254a: MOV RSI, qword ptr [RBX + 0x58]
0x3b254e: MOV RDX, qword ptr [R13 + 0x28]
0x3b2552: MOV dword ptr [RAX], ECX
0x3b2554: MOV qword ptr [RAX + 0x10], R12
0x3b2558: MOV qword ptr [RAX + 0x18], RSI
0x3b255c: MOV qword ptr [RAX + 0x20], R14
0x3b2560: MOV qword ptr [RDX + R15*0x8], RAX
0x3b2564: INC R15
0x3b2567: ADD R12, 0x28
0x3b256b: CMP qword ptr [RBX + 0x20], R15
0x3b256f: JNZ 0x003b2530
0x3b2571: JMP 0x003b25c9
0x3b2573: MOV R15, R12
0x3b2576: XOR R12D, R12D
0x3b2579: NOP dword ptr [RAX]
0x3b2580: MOV EDI, 0x58
0x3b2585: LEA RSI, [0x1ab5900]
0x3b258c: MOV EDX, 0x102
0x3b2591: CALL 0x00c08b50
0x3b2596: MOV RCX, qword ptr [RBX + 0x28]
0x3b259a: MOV RSI, qword ptr [RBX + 0x58]
0x3b259e: MOV RDX, qword ptr [R13 + 0x28]
0x3b25a2: MOV qword ptr [R14 + 0x10], R13
0x3b25a6: MOV dword ptr [RAX], ECX
0x3b25a8: MOV qword ptr [RAX + 0x10], R15
0x3b25ac: MOV qword ptr [RAX + 0x18], RSI
0x3b25b0: MOV qword ptr [RAX + 0x20], R14
0x3b25b4: MOV qword ptr [RDX + R12*0x8], RAX
0x3b25b8: INC R12
0x3b25bb: ADD R14, 0x58
0x3b25bf: ADD R15, 0x28
0x3b25c3: CMP qword ptr [RBX + 0x20], R12
0x3b25c7: JNZ 0x003b2580
0x3b25c9: MOV RDI, qword ptr [RBX + 0x70]
0x3b25cd: MOV R14, qword ptr [RBX + 0x20]
0x3b25d1: MOV ESI, 0x160
0x3b25d6: MOV RDX, R13
0x3b25d9: XOR ECX, ECX
0x3b25db: XOR R15D, R15D
0x3b25de: CALL 0x00399de0
0x3b25e3: MOV RDI, qword ptr [RBX + 0x70]
0x3b25e7: CALL 0x00399eb0
0x3b25ec: CMP dword ptr [RBX + 0xc], 0x0
0x3b25f0: MOV R12, R13
0x3b25f3: JNZ 0x003b2604
0x3b25f5: MOV R14, qword ptr [RBX + 0x68]
0x3b25f9: LEA RDI, [RBX + 0x7c]
0x3b25fd: MOV EDX, 0x4
0x3b2602: JMP 0x003b2657
0x3b2604: LEA RAX, [0xf + R14*0x4]
0x3b260c: MOV RDI, RSP
0x3b260f: LEA RDX, [R14*0x4]
0x3b2617: MOV R8, R14
0x3b261a: AND RAX, -0x10
0x3b261e: SUB RDI, RAX
0x3b2621: AND RDI, -0x20
0x3b2625: MOV RSP, RDI
0x3b2628: MOV R14, qword ptr [RBX + 0x68]
0x3b262c: MOV ESI, dword ptr [RBX + 0x1c]
0x3b262f: XOR EAX, EAX
0x3b2631: NOP dword ptr CS:[RAX + RAX*0x1]
0x3b2640: MOV ECX, R15D
0x3b2643: ADD R15D, 0x10000
0x3b264a: OR ECX, ESI
0x3b264c: MOV dword ptr [RDI + RAX*0x4], ECX
0x3b264f: INC RAX
0x3b2652: CMP R8, RAX
0x3b2655: JNZ 0x003b2640
0x3b2657: MOV RSI, R14
0x3b265a: CALL 0x003b3a40
0x3b265f: MOV R13D, EAX
0x3b2662: TEST EAX, EAX
0x3b2664: JZ 0x003b267b
0x3b2666: LEA RDI, [0x131bf08]
0x3b266d: LEA RSI, [0x1379d6c]
0x3b2674: MOV EDX, 0xe1a
0x3b2679: JMP 0x003b26b4
0x3b267b: MOV R15, qword ptr [RBX + 0x50]
0x3b267f: MOV RCX, R12
0x3b2682: MOV RDI, qword ptr [RBX + 0x10]
0x3b2686: MOV RSI, qword ptr [RBX + 0x38]
0x3b268a: MOV RDX, qword ptr [RBX + 0x28]
0x3b268e: MOV R8, R15
0x3b2691: CALL 0x003b3a90
0x3b2696: TEST EAX, EAX
0x3b2698: JZ 0x003b2849
0x3b269e: MOV R13D, EAX
0x3b26a1: LEA RDI, [0x131bf08]
0x3b26a8: LEA RSI, [0x1379d6c]
0x3b26af: MOV EDX, 0xe21
0x3b26b4: MOV ECX, R13D
0x3b26b7: XOR EAX, EAX
0x3b26b9: CALL 0x0025d410
0x3b26be: MOV R15, qword ptr [RBX + 0x30]
0x3b26c2: MOV ESI, dword ptr [RBX + 0x7c]
0x3b26c5: LEA RCX, [RBX + 0x70]
0x3b26c9: MOV EDX, 0x160
0x3b26ce: MOV RDI, R15
0x3b26d1: CALL 0x0039a2a0
0x3b26d6: MOV ESI, dword ptr [RBX + 0x7c]
0x3b26d9: MOV RDX, qword ptr [RBX + 0x70]
0x3b26dd: MOV RDI, R15
0x3b26e0: MOV R14, RAX
0x3b26e3: CALL 0x00399e30
0x3b26e8: MOV RDI, qword ptr [RBX + 0x70]
0x3b26ec: CALL 0x00399eb0
0x3b26f1: CMP dword ptr [RBX + 0xc], 0x0
0x3b26f5: JNZ 0x003b2819
0x3b26fb: MOV RAX, qword ptr [R14 + 0x28]
0x3b26ff: MOV RAX, qword ptr [RAX]
0x3b2702: MOV RDI, qword ptr [RAX + 0x20]
0x3b2706: ADD RDI, 0x20
0x3b270a: CALL 0x00bf1760
0x3b270f: MOV RAX, qword ptr [R14 + 0x28]
0x3b2713: MOV RAX, qword ptr [RAX]
0x3b2716: MOV RAX, qword ptr [RAX + 0x18]
0x3b271a: MOV RDI, qword ptr [RAX + 0x10]
0x3b271e: CALL 0x002a9670
0x3b2723: MOV RAX, qword ptr [R14 + 0x28]
0x3b2727: LEA RSI, [0x1ab59e0]
0x3b272e: MOV RAX, qword ptr [RAX]
0x3b2731: MOV RDI, qword ptr [RAX + 0x18]
0x3b2735: CALL 0x00c08df0
0x3b273a: CMP dword ptr [RBX + 0x10], 0x0
0x3b273e: JLE 0x003b27d6
0x3b2744: XOR R15D, R15D
0x3b2747: JMP 0x003b2776
0x3b2749: MOV qword ptr [R12 + 0x40], 0x0
0x3b2752: MOV RDI, R12
0x3b2755: LEA RSI, [0x1ab5900]
0x3b275c: CALL 0x00c08df0
0x3b2761: MOV RAX, qword ptr [R14 + 0x28]
0x3b2765: MOV qword ptr [RAX + R15*0x8], 0x0
0x3b276d: INC R15
0x3b2770: CMP qword ptr [RBX + 0x20], R15
0x3b2774: JZ 0x003b27d6
0x3b2776: MOV RAX, qword ptr [R14 + 0x28]
0x3b277a: MOV R12, qword ptr [RAX + R15*0x8]
0x3b277e: TEST R12, R12
0x3b2781: JZ 0x003b276d
0x3b2783: CMP qword ptr [R12 + 0x28], 0x0
0x3b2789: JZ 0x003b27a5
0x3b278b: LEA RDI, [0x13069f7]
0x3b2792: LEA RSI, [0x136fb7e]
0x3b2799: MOV EDX, 0xb35
0x3b279e: XOR EAX, EAX
0x3b27a0: CALL 0x0025d410
0x3b27a5: MOV RAX, qword ptr [R12 + 0x40]
0x3b27aa: TEST RAX, RAX
0x3b27ad: JZ 0x003b2752
0x3b27af: MOV ECX, 0xffffffff
0x3b27b4: XADD.LOCK dword ptr [RAX + 0x28], ECX
0x3b27b9: CMP ECX, 0x1
0x3b27bc: JNZ 0x003b2749
0x3b27be: MOV RDI, qword ptr [R12 + 0x40]
0x3b27c3: MOV RSI, qword ptr GS:[0x0]
0x3b27cc: CALL 0x0072b380
0x3b27d1: JMP 0x003b2749
0x3b27d6: MOV RDI, qword ptr [R14 + 0x10]
0x3b27da: LEA RSI, [0x1ab5970]
0x3b27e1: CALL 0x00c08df0
0x3b27e6: MOV RDI, qword ptr [R14 + 0x28]
0x3b27ea: LEA R15, [0x1ab5a50]
0x3b27f1: MOV RSI, R15
0x3b27f4: CALL 0x00c08df0
0x3b27f9: MOV RDI, R14
0x3b27fc: MOV RSI, R15
0x3b27ff: CALL 0x00c08df0
0x3b2804: MOV RDI, qword ptr [RBX + 0x40]
0x3b2808: LEA RSI, [0x1ab5890]
0x3b280f: CALL 0x00c08df0
0x3b2814: JMP 0x003b22e7
0x3b2819: XOR R15D, R15D
0x3b281c: JMP 0x003b282d
0x3b2820: INC R15
0x3b2823: CMP qword ptr [RBX + 0x20], R15
0x3b2827: JZ 0x003b270f
0x3b282d: MOV RAX, qword ptr [R14 + 0x28]
0x3b2831: MOV RAX, qword ptr [RAX + R15*0x8]
0x3b2835: TEST RAX, RAX
0x3b2838: JZ 0x003b2820
0x3b283a: MOV RDI, qword ptr [RAX + 0x20]
0x3b283e: ADD RDI, 0x20
0x3b2842: CALL 0x00bf1760
0x3b2847: JMP 0x003b2820
0x3b2849: LEA RDI, [0x34cf2e8]
0x3b2850: XOR ESI, ESI
0x3b2852: XOR EDX, EDX
0x3b2854: XOR ECX, ECX
0x3b2856: CALL 0x004c6a00
0x3b285b: MOV RSI, qword ptr [R15 + 0x4b0]
0x3b2862: TEST RSI, RSI
0x3b2865: JNZ 0x003b2873
0x3b2867: MOV RSI, qword ptr [R15 + 0x528]
0x3b286e: TEST RSI, RSI
0x3b2871: JZ 0x003b287f
0x3b2873: LEA RDI, [0x34cf2f0]
0x3b287a: CALL 0x0073ef80
0x3b287f: LEA RDI, [0x34cf2e8]
0x3b2886: XOR R13D, R13D
0x3b2889: XOR ESI, ESI
0x3b288b: XOR EDX, EDX
0x3b288d: XOR ECX, ECX
0x3b288f: CALL 0x004c6fa0
0x3b2894: CALL 0x00b078d0
0x3b2899: TEST EAX, EAX
0x3b289b: JZ 0x003b22e7
0x3b28a1: MOV ESI, dword ptr [RBX + 0xc]
0x3b28a4: MOV RDX, qword ptr [RBX + 0x60]
0x3b28a8: MOV RCX, R14
0x3b28ab: MOV RDI, qword ptr [RBX + 0x10]
0x3b28af: SHR ESI, 0xc
0x3b28b2: CALL 0x000a3850
0x3b28b7: JMP 0x003b22e7
0x3b28bc: CALL 0x006fd6b0
0x3b28c1: UD2

; local helper / adjacent context (reachability below); evidence ev_2acd98848ad6938cdb05b098ec5056026c29aaf1e7e7af4f6a7ebc325a2fb2a0; body [{"start": "0x3b28d0", "end": "0x3b2d4e"}]
adjacent_3b28d0: ; RVA 0x3b28d0
0x3b28d0: PUSH RBP
0x3b28d1: MOV RBP, RSP
0x3b28d4: PUSH R15
0x3b28d6: PUSH R14
0x3b28d8: PUSH R13
0x3b28da: PUSH R12
0x3b28dc: PUSH RBX
0x3b28dd: SUB RSP, 0x58
0x3b28e1: LEA RAX, [0x391c310]
0x3b28e8: MOV RAX, qword ptr [RAX]
0x3b28eb: MOV qword ptr [RBP + -0x30], RAX
0x3b28ef: MOV qword ptr [RBP + -0x78], RDI
0x3b28f3: MOV R15, qword ptr [RDI + 0x8]
0x3b28f7: MOV EAX, dword ptr [RSI + 0x8]
0x3b28fa: MOV R12, qword ptr [RSI]
0x3b28fd: MOV R13, qword ptr [RSI + 0x10]
0x3b2901: MOV R14D, dword ptr [RSI + 0x18]
0x3b2905: MOV RDI, R15
0x3b2908: MOV dword ptr [RBP + -0x70], EAX
0x3b290b: CALL 0x009f8180
0x3b2910: LEA RSI, [RBP + -0x6c]
0x3b2914: MOV RDI, R15
0x3b2917: MOV RBX, RAX
0x3b291a: CALL 0x009f81c0
0x3b291f: LEA RCX, [0x34cf8c8]
0x3b2926: TEST EAX, EAX
0x3b2928: JNZ 0x003b2960
0x3b292a: MOV EAX, dword ptr [RBP + -0x6c]
0x3b292d: CMP EAX, 0xffffff
0x3b2932: JA 0x003b2960
0x3b2934: CMP EAX, 0xffff
0x3b2939: JBE 0x003b2a4c
0x3b293f: AND EAX, 0xff0000
0x3b2944: LEA RDX, [0x34cfe70]
0x3b294b: LEA RCX, [0x34cf8c8]
0x3b2952: MOV R15B, 0x1
0x3b2955: CMP EAX, 0x10000
0x3b295a: CMOVZ RCX, RDX
0x3b295e: JMP 0x003b2963
0x3b2960: XOR R15D, R15D
0x3b2963: TEST R13, R13
0x3b2966: JZ 0x003b2982
0x3b2968: LEA RDI, [0x131bf08]
0x3b296f: LEA RSI, [0x1379db0]
0x3b2976: MOV EBX, 0x16
0x3b297b: MOV EDX, 0x131f
0x3b2980: JMP 0x003b299f
0x3b2982: TEST R14D, R14D
0x3b2985: JZ 0x003b29d0
0x3b2987: LEA RDI, [0x131bf08]
0x3b298e: LEA RSI, [0x1379db0]
0x3b2995: MOV EBX, 0x16
0x3b299a: MOV EDX, 0x1324
0x3b299f: MOV ECX, 0x16
0x3b29a4: XOR EAX, EAX
0x3b29a6: CALL 0x0025d410
0x3b29ab: LEA RAX, [0x391c310]
0x3b29b2: MOV RAX, qword ptr [RAX]
0x3b29b5: CMP RAX, qword ptr [RBP + -0x30]
0x3b29b9: JNZ 0x003b2d48
0x3b29bf: MOV EAX, EBX
0x3b29c1: ADD RSP, 0x58
0x3b29c5: POP RBX
0x3b29c6: POP R12
0x3b29c8: POP R13
0x3b29ca: POP R14
0x3b29cc: POP R15
0x3b29ce: POP RBP
0x3b29cf: RET
0x3b29d0: LEA RDI, [0x34cf300]
0x3b29d7: MOV R14, RCX
0x3b29da: XOR EBX, EBX
0x3b29dc: XOR ESI, ESI
0x3b29de: XOR EDX, EDX
0x3b29e0: XOR ECX, ECX
0x3b29e2: CALL 0x00c4bb20
0x3b29e7: TEST R12, R12
0x3b29ea: MOV R13D, 0x1
0x3b29f0: SETZ AL
0x3b29f3: XOR R15B, 0x1
0x3b29f7: OR R15B, AL
0x3b29fa: JNZ 0x003b2a0a
0x3b29fc: CMP dword ptr [R14 + 0x4a0], 0x0
0x3b2a04: JZ 0x003b2a8b
0x3b2a0a: LEA RDI, [0x34cf300]
0x3b2a11: XOR ESI, ESI
0x3b2a13: XOR EDX, EDX
0x3b2a15: CALL 0x00c4c4b0
0x3b2a1a: MOV EDI, R13D
0x3b2a1d: MOV RSI, R14
0x3b2a20: CALL 0x003b3410
0x3b2a25: TEST EAX, EAX
0x3b2a27: JZ 0x003b29ab
0x3b2a29: LEA RDI, [0x131bf08]
0x3b2a30: LEA RSI, [0x1379db0]
0x3b2a37: MOV EDX, 0x1383
0x3b2a3c: MOV ECX, EAX
0x3b2a3e: MOV EBX, EAX
0x3b2a40: XOR EAX, EAX
0x3b2a42: CALL 0x0025d410
0x3b2a47: JMP 0x003b29ab
0x3b2a4c: MOV R15B, 0x1
0x3b2a4f: CMP qword ptr [0x034cf7c8], RBX
0x3b2a56: JZ 0x003b2a7f
0x3b2a58: CMP qword ptr [0x034d08c0], RBX
0x3b2a5f: JZ 0x003b2ad4
0x3b2a61: CMP dword ptr [0x034cf7c0], 0x0
0x3b2a68: LEA RAX, [0x34cf320]
0x3b2a6f: LEA RCX, [0x34d0418]
0x3b2a76: CMOVZ RCX, RAX
0x3b2a7a: JMP 0x003b2963
0x3b2a7f: LEA RCX, [0x34cf320]
0x3b2a86: JMP 0x003b2963
0x3b2a8b: CMP dword ptr [RBP + -0x70], 0x3c
0x3b2a8f: JNZ 0x003b2ae0
0x3b2a91: LEA RSI, [RBP + -0x6c]
0x3b2a95: MOV RDI, R12
0x3b2a98: CALL 0x003b3f10
0x3b2a9d: TEST EAX, EAX
0x3b2a9f: JZ 0x003b2b19
0x3b2aa1: LEA RDI, [0x131bf08]
0x3b2aa8: LEA RSI, [0x1379db0]
0x3b2aaf: MOV EDX, 0x133a
0x3b2ab4: MOV ECX, EAX
0x3b2ab6: MOV EBX, EAX
0x3b2ab8: XOR EAX, EAX
0x3b2aba: CALL 0x0025d410
0x3b2abf: LEA RDI, [0x34cf300]
0x3b2ac6: XOR ESI, ESI
0x3b2ac8: XOR EDX, EDX
0x3b2aca: CALL 0x00c4c4b0
0x3b2acf: JMP 0x003b2a47
0x3b2ad4: LEA RCX, [0x34d0418]
0x3b2adb: JMP 0x003b2963
0x3b2ae0: LEA RDI, [0x131bf08]
0x3b2ae7: LEA RSI, [0x1379db0]
0x3b2aee: MOV EBX, 0x16
0x3b2af3: MOV EDX, 0x1331
0x3b2af8: MOV ECX, 0x16
0x3b2afd: XOR EAX, EAX
0x3b2aff: CALL 0x0025d410
0x3b2b04: LEA RDI, [0x34cf300]
0x3b2b0b: XOR ESI, ESI
0x3b2b0d: XOR EDX, EDX
0x3b2b0f: CALL 0x00c4c4b0
0x3b2b14: JMP 0x003b29ab
0x3b2b19: MOV EAX, dword ptr [RBP + -0x6c]
0x3b2b1c: CMP EAX, 0x80
0x3b2b21: JBE 0x003b2b3d
0x3b2b23: LEA RDI, [0x131bf08]
0x3b2b2a: LEA RSI, [0x1379db0]
0x3b2b31: MOV EBX, 0x16
0x3b2b36: MOV EDX, 0x1343
0x3b2b3b: JMP 0x003b2af8
0x3b2b3d: MOV ECX, dword ptr [RBP + -0x68]
0x3b2b40: CMP ECX, 0x81
0x3b2b46: JC 0x003b2b62
0x3b2b48: LEA RDI, [0x131bf08]
0x3b2b4f: LEA RSI, [0x1379db0]
0x3b2b56: MOV EBX, 0x16
0x3b2b5b: MOV EDX, 0x134a
0x3b2b60: JMP 0x003b2af8
0x3b2b62: MOV EDX, dword ptr [RBP + -0x64]
0x3b2b65: MOV ESI, EDX
0x3b2b67: MOV EDI, EDX
0x3b2b69: TEST EDX, EDX
0x3b2b6b: JZ 0x003b2bd4
0x3b2b6d: CMP EDX, 0x1
0x3b2b70: JNZ 0x003b2d2b
0x3b2b76: MOV ESI, dword ptr [RBP + -0x60]
0x3b2b79: LEA EDI, [RSI + -0x1000001]
0x3b2b7f: CMP EDI, 0xfeffffff
0x3b2b85: JA 0x003b2ba4
0x3b2b87: LEA RDI, [0x131bf08]
0x3b2b8e: LEA RSI, [0x1379db0]
0x3b2b95: MOV EBX, 0x16
0x3b2b9a: MOV EDX, 0x1359
0x3b2b9f: JMP 0x003b2af8
0x3b2ba4: MOV EDI, dword ptr [RBP + -0x5c]
0x3b2ba7: LEA R8D, [RDI + -0x1000001]
0x3b2bae: CMP R8D, 0xfeffffff
0x3b2bb5: JA 0x003b2bd4
0x3b2bb7: LEA RDI, [0x131bf08]
0x3b2bbe: LEA RSI, [0x1379db0]
0x3b2bc5: MOV EBX, 0x16
0x3b2bca: MOV EDX, 0x1361
0x3b2bcf: JMP 0x003b2af8
0x3b2bd4: MOV dword ptr [R14 + 0x1b4], ESI
0x3b2bdb: MOV dword ptr [R14 + 0x194], EDI
0x3b2be2: MOV dword ptr [R14 + 0x1a4], EDX
0x3b2be9: MOV dword ptr [R14 + 0x174], EAX
0x3b2bf0: MOV EAX, dword ptr [RBP + -0x58]
0x3b2bf3: MOV dword ptr [R14 + 0x184], ECX
0x3b2bfa: CMP EAX, 0x80
0x3b2bff: JA 0x003b2b23
0x3b2c05: MOV ECX, dword ptr [RBP + -0x54]
0x3b2c08: CMP ECX, 0x80
0x3b2c0e: JA 0x003b2b48
0x3b2c14: MOV EDX, dword ptr [RBP + -0x50]
0x3b2c17: MOV ESI, EDX
0x3b2c19: MOV EDI, EDX
0x3b2c1b: TEST EDX, EDX
0x3b2c1d: JZ 0x003b2c54
0x3b2c1f: CMP EDX, 0x1
0x3b2c22: JNZ 0x003b2d2b
0x3b2c28: MOV ESI, dword ptr [RBP + -0x4c]
0x3b2c2b: LEA EDI, [RSI + -0x1000001]
0x3b2c31: CMP EDI, 0xff000000
0x3b2c37: JC 0x003b2b87
0x3b2c3d: MOV EDI, dword ptr [RBP + -0x48]
0x3b2c40: LEA R8D, [RDI + -0x1000001]
0x3b2c47: CMP R8D, 0xff000000
0x3b2c4e: JC 0x003b2bb7
0x3b2c54: MOV dword ptr [R14 + 0x1b8], ESI
0x3b2c5b: MOV dword ptr [R14 + 0x198], EDI
0x3b2c62: MOV dword ptr [R14 + 0x1a8], EDX
0x3b2c69: MOV dword ptr [R14 + 0x178], EAX
0x3b2c70: MOV EAX, dword ptr [RBP + -0x44]
0x3b2c73: MOV dword ptr [R14 + 0x188], ECX
0x3b2c7a: CMP EAX, 0x80
0x3b2c7f: JA 0x003b2b23
0x3b2c85: MOV ECX, dword ptr [RBP + -0x40]
0x3b2c88: CMP ECX, 0x80
0x3b2c8e: JA 0x003b2b48
0x3b2c94: MOV EDX, dword ptr [RBP + -0x3c]
0x3b2c97: MOV ESI, EDX
0x3b2c99: MOV EDI, EDX
0x3b2c9b: TEST EDX, EDX
0x3b2c9d: JZ 0x003b2cd4
0x3b2c9f: CMP EDX, 0x1
0x3b2ca2: JNZ 0x003b2d2b
0x3b2ca8: MOV ESI, dword ptr [RBP + -0x38]
0x3b2cab: LEA EDI, [RSI + -0x1000001]
0x3b2cb1: CMP EDI, 0xff000000
0x3b2cb7: JC 0x003b2b87
0x3b2cbd: MOV EDI, dword ptr [RBP + -0x34]
0x3b2cc0: LEA R8D, [RDI + -0x1000001]
0x3b2cc7: CMP R8D, 0xff000000
0x3b2cce: JC 0x003b2bb7
0x3b2cd4: MOV dword ptr [R14 + 0x1bc], ESI
0x3b2cdb: MOV dword ptr [R14 + 0x19c], EDI
0x3b2ce2: MOV dword ptr [R14 + 0x1ac], EDX
0x3b2ce9: MOV dword ptr [R14 + 0x17c], EAX
0x3b2cf0: MOV dword ptr [R14 + 0x18c], ECX
0x3b2cf7: CALL 0x00b078d0
0x3b2cfc: TEST EAX, EAX
0x3b2cfe: JZ 0x003b2d0c
0x3b2d00: MOV RDI, qword ptr [RBP + -0x78]
0x3b2d04: MOV RSI, R14
0x3b2d07: CALL 0x000a3e30
0x3b2d0c: XOR R13D, R13D
0x3b2d0f: CMP dword ptr [R14 + 0x4a0], 0x1
0x3b2d17: JNZ 0x003b2a0a
0x3b2d1d: LEA RDI, [0x34cf300]
0x3b2d24: XOR EBX, EBX
0x3b2d26: JMP 0x003b2b0b
0x3b2d2b: LEA RDI, [0x131bf08]
0x3b2d32: LEA RSI, [0x1379db0]
0x3b2d39: MOV EBX, 0x16
0x3b2d3e: MOV EDX, 0x1352
0x3b2d43: JMP 0x003b2af8
0x3b2d48: CALL 0x006fd6b0
0x3b2d4d: UD2

; local helper / adjacent context (reachability below); evidence ev_8c983cbe00e4cf56cea7c1e037756c8b58014d824fc51748084aa7e6c4520f01; body [{"start": "0x3b2d50", "end": "0x3b2f2c"}, {"start": "0x3b2f30", "end": "0x3b2f7c"}, {"start": "0x3b2f80", "end": "0x3b3080"}]
adjacent_3b2d50: ; RVA 0x3b2d50
0x3b2d50: PUSH RBP
0x3b2d51: MOV RBP, RSP
0x3b2d54: PUSH R15
0x3b2d56: PUSH R14
0x3b2d58: PUSH R13
0x3b2d5a: PUSH R12
0x3b2d5c: PUSH RBX
0x3b2d5d: SUB RSP, 0x38
0x3b2d61: LEA R13, [0x391c310]
0x3b2d68: MOV RAX, qword ptr [R13]
0x3b2d6c: MOV qword ptr [RBP + -0x30], RAX
0x3b2d70: MOV RDX, qword ptr [RSI + 0x8]
0x3b2d74: MOV R12, qword ptr [RSI + 0x18]
0x3b2d78: MOV R15D, dword ptr [RSI]
0x3b2d7b: MOV R14D, dword ptr [RSI + 0x10]
0x3b2d7f: MOV dword ptr [RBP + -0x34], 0x0
0x3b2d86: TEST RDX, RDX
0x3b2d89: SETNZ AL
0x3b2d8c: TEST R12, R12
0x3b2d8f: SETNZ CL
0x3b2d92: TEST AL, CL
0x3b2d94: JNZ 0x003b2db5
0x3b2d96: LEA RDI, [0x131bf08]
0x3b2d9d: LEA RSI, [0x13507c9]
0x3b2da4: MOV EBX, 0xe
0x3b2da9: MOV EDX, 0x14fe
0x3b2dae: MOV ECX, 0xe
0x3b2db3: JMP 0x003b2de5
0x3b2db5: MOV qword ptr [RBP + -0x58], RDX
0x3b2db9: LEA RDX, [RBP + -0x48]
0x3b2dbd: MOV EDI, R15D
0x3b2dc0: MOV ESI, 0x15
0x3b2dc5: CALL 0x0053c260
0x3b2dca: TEST EAX, EAX
0x3b2dcc: JZ 0x003b2e0b
0x3b2dce: MOV EBX, EAX
0x3b2dd0: LEA RDI, [0x131bf08]
0x3b2dd7: LEA RSI, [0x13507c9]
0x3b2dde: MOV EDX, 0x1506
0x3b2de3: MOV ECX, EAX
0x3b2de5: XOR EAX, EAX
0x3b2de7: CALL 0x0025d410
0x3b2dec: MOV RAX, qword ptr [R13]
0x3b2df0: CMP RAX, qword ptr [RBP + -0x30]
0x3b2df4: JNZ 0x003b307a
0x3b2dfa: MOV EAX, EBX
0x3b2dfc: ADD RSP, 0x38
0x3b2e00: POP RBX
0x3b2e01: POP R12
0x3b2e03: POP R13
0x3b2e05: POP R14
0x3b2e07: POP R15
0x3b2e09: POP RBP
0x3b2e0a: RET
0x3b2e0b: MOV EDI, R15D
0x3b2e0e: CALL 0x005a8110
0x3b2e13: CMP EAX, -0x1
0x3b2e16: JZ 0x003b2e59
0x3b2e18: MOV RAX, qword ptr [RBP + -0x48]
0x3b2e1c: MOV RAX, qword ptr [RAX + 0xc48]
0x3b2e23: TEST RAX, RAX
0x3b2e26: JZ 0x003b2e73
0x3b2e28: TEST R14D, R14D
0x3b2e2b: JLE 0x003b2e3a
0x3b2e2d: CMP R14D, dword ptr [RAX + 0x228]
0x3b2e34: JLE 0x003b2ef2
0x3b2e3a: LEA RDI, [0x131bf08]
0x3b2e41: LEA RSI, [0x13507c9]
0x3b2e48: MOV EBX, 0x16
0x3b2e4d: MOV EDX, 0x151c
0x3b2e52: MOV ECX, 0x16
0x3b2e57: JMP 0x003b2e90
0x3b2e59: LEA RDI, [0x131bf08]
0x3b2e60: LEA RSI, [0x13507c9]
0x3b2e67: MOV EBX, 0x3
0x3b2e6c: MOV EDX, 0x150d
0x3b2e71: JMP 0x003b2e8b
0x3b2e73: LEA RDI, [0x131bf08]
0x3b2e7a: LEA RSI, [0x13507c9]
0x3b2e81: MOV EBX, 0x3
0x3b2e86: MOV EDX, 0x1515
0x3b2e8b: MOV ECX, 0x3
0x3b2e90: XOR EAX, EAX
0x3b2e92: CALL 0x0025d410
0x3b2e97: MOV EDI, 0x148
0x3b2e9c: ADD RDI, qword ptr [RBP + -0x48]
0x3b2ea0: XOR ESI, ESI
0x3b2ea2: XOR EDX, EDX
0x3b2ea4: XOR ECX, ECX
0x3b2ea6: CALL 0x004c6a00
0x3b2eab: MOV RAX, qword ptr [RBP + -0x48]
0x3b2eaf: DEC dword ptr [RAX + 0x358]
0x3b2eb5: MOV RDI, qword ptr [RBP + -0x48]
0x3b2eb9: TEST byte ptr [RDI + 0xb1], 0x20
0x3b2ec0: JZ 0x003b2edb
0x3b2ec2: CMP dword ptr [RDI + 0x358], 0x0
0x3b2ec9: JNZ 0x003b2edb
0x3b2ecb: ADD RDI, 0x358
0x3b2ed2: CALL 0x00c06910
0x3b2ed7: MOV RDI, qword ptr [RBP + -0x48]
0x3b2edb: ADD RDI, 0x148
0x3b2ee2: XOR ESI, ESI
0x3b2ee4: XOR EDX, EDX
0x3b2ee6: XOR ECX, ECX
0x3b2ee8: CALL 0x004c6fa0
0x3b2eed: JMP 0x003b2dec
0x3b2ef2: MOV RDI, R14
0x3b2ef5: LEA RSI, [0x1ab5ac0]
0x3b2efc: MOV EDX, 0x102
0x3b2f01: MOV qword ptr [RBP + -0x50], RAX
0x3b2f05: SHL RDI, 0x4
0x3b2f09: CALL 0x00c08b50
0x3b2f0e: MOV RDI, qword ptr [RBP + -0x50]
0x3b2f12: MOV R15, RAX
0x3b2f15: MOV EAX, dword ptr [RDI + 0x220]
0x3b2f1b: SHL EAX, 0x7
0x3b2f1e: TEST EAX, EAX
0x3b2f20: JLE 0x003b2fcf
0x3b2f26: XOR EBX, EBX
0x3b2f28: XOR R13D, R13D
0x3b2f2b: JMP 0x003b2f52
0x3b2f30: MOV RDI, qword ptr [RBP + -0x40]
0x3b2f34: CALL 0x00399eb0
0x3b2f39: MOV RDI, qword ptr [RBP + -0x50]
0x3b2f3d: INC R13D
0x3b2f40: MOV EAX, dword ptr [RDI + 0x220]
0x3b2f46: SHL EAX, 0x7
0x3b2f49: CMP R13D, EAX
0x3b2f4c: JGE 0x003b2fcf
0x3b2f52: MOV ESI, R13D
0x3b2f55: MOV EDX, 0x160
0x3b2f5a: LEA RCX, [RBP + -0x40]
0x3b2f5e: CALL 0x0039a0f0
0x3b2f63: TEST RAX, RAX
0x3b2f66: JZ 0x003b2f39
0x3b2f68: MOVSX RCX, word ptr [RAX]
0x3b2f6c: TEST RCX, RCX
0x3b2f6f: JLE 0x003b2f30
0x3b2f71: MOV RDX, qword ptr [RAX + 0x28]
0x3b2f75: SHL RCX, 0x10
0x3b2f79: XOR ESI, ESI
0x3b2f7b: JMP 0x003b2f95
0x3b2f80: INC EBX
0x3b2f82: MOV dword ptr [RBP + -0x34], EBX
0x3b2f85: ADD RSI, 0x10000
0x3b2f8c: ADD RDX, 0x8
0x3b2f90: CMP RCX, RSI
0x3b2f93: JZ 0x003b2f30
0x3b2f95: MOV RDI, qword ptr [RDX]
0x3b2f98: TEST RDI, RDI
0x3b2f9b: JZ 0x003b2f85
0x3b2f9d: CMP EBX, R14D
0x3b2fa0: JGE 0x003b2f80
0x3b2fa2: MOV R8D, dword ptr [RAX + 0x8]
0x3b2fa6: MOVSXD R9, EBX
0x3b2fa9: SHL R9, 0x4
0x3b2fad: OR R8D, ESI
0x3b2fb0: MOV dword ptr [R15 + R9*0x1], R8D
0x3b2fb4: MOV R8D, dword ptr [RDI + 0x38]
0x3b2fb8: MOV dword ptr [R15 + R9*0x1 + 0x4], R8D
0x3b2fbd: MOV R8D, dword ptr [RAX + 0x4]
0x3b2fc1: MOV dword ptr [R15 + R9*0x1 + 0x8], R8D
0x3b2fc6: MOV EDI, dword ptr [RDI]
0x3b2fc8: MOV dword ptr [R15 + R9*0x1 + 0xc], EDI
0x3b2fcd: JMP 0x003b2f80
0x3b2fcf: MOV RDI, qword ptr GS:[0x0]
0x3b2fd8: LEA RSI, [0x134f297]
0x3b2fdf: XOR EDX, EDX
0x3b2fe1: XOR EBX, EBX
0x3b2fe3: CALL 0x00c1a3e0
0x3b2fe8: LEA RDI, [RBP + -0x34]
0x3b2fec: MOV EDX, 0x4
0x3b2ff1: MOV RSI, R12
0x3b2ff4: CALL 0x002591d0
0x3b2ff9: TEST EAX, EAX
0x3b2ffb: JZ 0x003b3024
0x3b2ffd: LEA RDI, [0x131bf08]
0x3b3004: LEA RSI, [0x13507c9]
0x3b300b: MOV EDX, 0x1553
0x3b3010: MOV ECX, EAX
0x3b3012: MOV EBX, EAX
0x3b3014: XOR EAX, EAX
0x3b3016: CALL 0x0025d410
0x3b301b: LEA R13, [0x391c310]
0x3b3022: JMP 0x003b3066
0x3b3024: MOVSXD RDX, dword ptr [RBP + -0x34]
0x3b3028: LEA R13, [0x391c310]
0x3b302f: CMP EDX, R14D
0x3b3032: JG 0x003b3066
0x3b3034: MOV RSI, qword ptr [RBP + -0x58]
0x3b3038: SHL RDX, 0x4
0x3b303c: MOV RDI, R15
0x3b303f: CALL 0x003b3a40
0x3b3044: TEST EAX, EAX
0x3b3046: JZ 0x003b3066
0x3b3048: LEA RDI, [0x131bf08]
0x3b304f: LEA RSI, [0x13507c9]
0x3b3056: MOV EDX, 0x1562
0x3b305b: MOV ECX, EAX
0x3b305d: MOV EBX, EAX
0x3b305f: XOR EAX, EAX
0x3b3061: CALL 0x0025d410
0x3b3066: LEA RSI, [0x1ab5ac0]
0x3b306d: MOV RDI, R15
0x3b3070: CALL 0x00c08df0
0x3b3075: JMP 0x003b2e97
0x3b307a: CALL 0x006fd6b0
0x3b307f: UD2

; local helper / adjacent context (reachability below); evidence ev_7adc3cb0f847447a466208fb954bb78650ba99926076593d2edf03bd472c1735; body [{"start": "0x3b3090", "end": "0x3b3409"}]
adjacent_3b3090: ; RVA 0x3b3090
0x3b3090: PUSH RBP
0x3b3091: MOV RBP, RSP
0x3b3094: PUSH R15
0x3b3096: PUSH R14
0x3b3098: PUSH R13
0x3b309a: PUSH R12
0x3b309c: PUSH RBX
0x3b309d: SUB RSP, 0x48
0x3b30a1: LEA R13, [0x391c310]
0x3b30a8: MOV RAX, qword ptr [R13]
0x3b30ac: MOV qword ptr [RBP + -0x30], RAX
0x3b30b0: MOV R14, qword ptr [RSI + 0x10]
0x3b30b4: MOV R12, qword ptr [RSI + 0x20]
0x3b30b8: MOV R15D, dword ptr [RSI]
0x3b30bb: MOV EDI, dword ptr [RSI + 0x8]
0x3b30be: MOV EDX, dword ptr [RSI + 0x18]
0x3b30c1: MOV dword ptr [RBP + -0x34], 0x0
0x3b30c8: TEST R14, R14
0x3b30cb: SETNZ AL
0x3b30ce: TEST R12, R12
0x3b30d1: SETNZ CL
0x3b30d4: TEST AL, CL
0x3b30d6: JNZ 0x003b30f7
0x3b30d8: LEA RDI, [0x131bf08]
0x3b30df: LEA RSI, [0x12a94cb]
0x3b30e6: MOV EBX, 0xe
0x3b30eb: MOV EDX, 0x1466
0x3b30f0: MOV ECX, 0xe
0x3b30f5: JMP 0x003b312a
0x3b30f7: MOV dword ptr [RBP + -0x4c], EDI
0x3b30fa: MOV qword ptr [RBP + -0x60], RDX
0x3b30fe: LEA RDX, [RBP + -0x48]
0x3b3102: MOV EDI, R15D
0x3b3105: MOV ESI, 0x15
0x3b310a: CALL 0x0053c260
0x3b310f: TEST EAX, EAX
0x3b3111: JZ 0x003b3150
0x3b3113: MOV EBX, EAX
0x3b3115: LEA RDI, [0x131bf08]
0x3b311c: LEA RSI, [0x12a94cb]
0x3b3123: MOV EDX, 0x146e
0x3b3128: MOV ECX, EAX
0x3b312a: XOR EAX, EAX
0x3b312c: CALL 0x0025d410
0x3b3131: MOV RAX, qword ptr [R13]
0x3b3135: CMP RAX, qword ptr [RBP + -0x30]
0x3b3139: JNZ 0x003b3403
0x3b313f: MOV EAX, EBX
0x3b3141: ADD RSP, 0x48
0x3b3145: POP RBX
0x3b3146: POP R12
0x3b3148: POP R13
0x3b314a: POP R14
0x3b314c: POP R15
0x3b314e: POP RBP
0x3b314f: RET
0x3b3150: MOV EDI, R15D
0x3b3153: CALL 0x005a8110
0x3b3158: CMP EAX, -0x1
0x3b315b: JZ 0x003b319c
0x3b315d: MOV RAX, qword ptr [RBP + -0x48]
0x3b3161: MOV RBX, qword ptr [RAX + 0xc48]
0x3b3168: TEST RBX, RBX
0x3b316b: JZ 0x003b31b6
0x3b316d: MOV RAX, qword ptr [RBP + -0x60]
0x3b3171: TEST EAX, EAX
0x3b3173: JLE 0x003b317d
0x3b3175: CMP EAX, dword ptr [RBX + 0x228]
0x3b317b: JLE 0x003b31d0
0x3b317d: LEA RDI, [0x131bf08]
0x3b3184: LEA RSI, [0x12a94cb]
0x3b318b: MOV EBX, 0x16
0x3b3190: MOV EDX, 0x1484
0x3b3195: MOV ECX, 0x16
0x3b319a: JMP 0x003b31fb
0x3b319c: LEA RDI, [0x131bf08]
0x3b31a3: LEA RSI, [0x12a94cb]
0x3b31aa: MOV EBX, 0x3
0x3b31af: MOV EDX, 0x1475
0x3b31b4: JMP 0x003b31f6
0x3b31b6: LEA RDI, [0x131bf08]
0x3b31bd: LEA RSI, [0x12a94cb]
0x3b31c4: MOV EBX, 0x3
0x3b31c9: MOV EDX, 0x147d
0x3b31ce: JMP 0x003b31f6
0x3b31d0: MOV ECX, dword ptr [RBP + -0x4c]
0x3b31d3: SAR ECX, 0x10
0x3b31d6: CMP ECX, 0x80
0x3b31dc: JC 0x003b325d
0x3b31de: LEA RDI, [0x131bf08]
0x3b31e5: LEA RSI, [0x12a94cb]
0x3b31ec: MOV EBX, 0x3
0x3b31f1: MOV EDX, 0x148d
0x3b31f6: MOV ECX, 0x3
0x3b31fb: XOR EAX, EAX
0x3b31fd: CALL 0x0025d410
0x3b3202: MOV EDI, 0x148
0x3b3207: ADD RDI, qword ptr [RBP + -0x48]
0x3b320b: XOR ESI, ESI
0x3b320d: XOR EDX, EDX
0x3b320f: XOR ECX, ECX
0x3b3211: CALL 0x004c6a00
0x3b3216: MOV RAX, qword ptr [RBP + -0x48]
0x3b321a: DEC dword ptr [RAX + 0x358]
0x3b3220: MOV RDI, qword ptr [RBP + -0x48]
0x3b3224: TEST byte ptr [RDI + 0xb1], 0x20
0x3b322b: JZ 0x003b3246
0x3b322d: CMP dword ptr [RDI + 0x358], 0x0
0x3b3234: JNZ 0x003b3246
0x3b3236: ADD RDI, 0x358
0x3b323d: CALL 0x00c06910
0x3b3242: MOV RDI, qword ptr [RBP + -0x48]
0x3b3246: ADD RDI, 0x148
0x3b324d: XOR ESI, ESI
0x3b324f: XOR EDX, EDX
0x3b3251: XOR ECX, ECX
0x3b3253: CALL 0x004c6fa0
0x3b3258: JMP 0x003b3131
0x3b325d: LEA RAX, [RAX*0x8]
0x3b3265: LEA RSI, [0x1ab5ac0]
0x3b326c: MOV EDX, 0x102
0x3b3271: MOV qword ptr [RBP + -0x68], RCX
0x3b3275: LEA RDI, [RAX + RAX*0x2]
0x3b3279: CALL 0x00c08b50
0x3b327e: MOV ECX, dword ptr [RBX + 0x220]
0x3b3284: MOV qword ptr [RBP + -0x58], RAX
0x3b3288: SHL ECX, 0x7
0x3b328b: TEST ECX, ECX
0x3b328d: JLE 0x003b3361
0x3b3293: MOV R15D, dword ptr [RBP + -0x4c]
0x3b3297: MOV EAX, dword ptr [RBP + -0x68]
0x3b329a: XOR R13D, R13D
0x3b329d: AND R15D, 0xffff0000
0x3b32a4: MOV qword ptr [RBP + -0x70], RAX
0x3b32a8: JMP 0x003b32c8
0x3b32aa: MOV RDI, qword ptr [RBP + -0x40]
0x3b32ae: CALL 0x00399eb0
0x3b32b3: MOV EAX, dword ptr [RBX + 0x220]
0x3b32b9: INC R13D
0x3b32bc: SHL EAX, 0x7
0x3b32bf: CMP R13D, EAX
0x3b32c2: JGE 0x003b3361
0x3b32c8: MOV RDI, RBX
0x3b32cb: MOV ESI, R13D
0x3b32ce: MOV EDX, 0x160
0x3b32d3: LEA RCX, [RBP + -0x40]
0x3b32d7: CALL 0x0039a0f0
0x3b32dc: TEST RAX, RAX
0x3b32df: JZ 0x003b32b3
0x3b32e1: MOV ECX, dword ptr [RAX + 0x8]
0x3b32e4: OR ECX, R15D
0x3b32e7: CMP dword ptr [RBP + -0x4c], ECX
0x3b32ea: JNZ 0x003b32aa
0x3b32ec: MOV RCX, qword ptr [RAX + 0x28]
0x3b32f0: MOV RDX, qword ptr [RBP + -0x70]
0x3b32f4: MOV RCX, qword ptr [RCX + RDX*0x8]
0x3b32f8: TEST RCX, RCX
0x3b32fb: JZ 0x003b32aa
0x3b32fd: MOV RCX, qword ptr [RCX + 0x20]
0x3b3301: MOV R10, qword ptr [RBP + -0x60]
0x3b3305: MOV R11, qword ptr [RBP + -0x58]
0x3b3309: MOV RBX, qword ptr [RBP + -0x68]
0x3b330d: MOV ECX, dword ptr [RCX]
0x3b330f: TEST ECX, ECX
0x3b3311: JZ 0x003b3358
0x3b3313: XOR EDX, EDX
0x3b3315: JMP 0x003b3320
0x3b3317: INC EDX
0x3b3319: MOV dword ptr [RBP + -0x34], EDX
0x3b331c: CMP ECX, EDX
0x3b331e: JZ 0x003b3358
0x3b3320: CMP EDX, R10D
0x3b3323: JGE 0x003b3317
0x3b3325: LEA EDI, [RBX + RDX*0x1]
0x3b3328: MOV RSI, qword ptr [RAX + 0x20]
0x3b332c: MOVSXD R9, EDX
0x3b332f: MOVSXD RDI, EDI
0x3b3332: LEA R9, [R9 + R9*0x2]
0x3b3336: LEA RDI, [RDI + RDI*0x4]
0x3b333a: MOV R8D, dword ptr [RSI + RDI*0x8 + 0x20]
0x3b333f: MOV dword ptr [R11 + R9*0x8], R8D
0x3b3343: MOV R8, qword ptr [RSI + RDI*0x8 + 0x8]
0x3b3348: MOV qword ptr [R11 + R9*0x8 + 0x8], R8
0x3b334d: MOV RSI, qword ptr [RSI + RDI*0x8]
0x3b3351: MOV qword ptr [R11 + R9*0x8 + 0x10], RSI
0x3b3356: JMP 0x003b3317
0x3b3358: MOV RDI, qword ptr [RBP + -0x40]
0x3b335c: CALL 0x00399eb0
0x3b3361: LEA RDI, [RBP + -0x34]
0x3b3365: MOV EDX, 0x4
0x3b336a: MOV RSI, R12
0x3b336d: CALL 0x003b3a40
0x3b3372: TEST EAX, EAX
0x3b3374: JZ 0x003b33a1
0x3b3376: LEA RDI, [0x131bf08]
0x3b337d: LEA RSI, [0x12a94cb]
0x3b3384: MOV EDX, 0x14d1
0x3b3389: MOV ECX, EAX
0x3b338b: MOV EBX, EAX
0x3b338d: XOR EAX, EAX
0x3b338f: CALL 0x0025d410
0x3b3394: LEA R13, [0x391c310]
0x3b339b: MOV RDI, qword ptr [RBP + -0x58]
0x3b339f: JMP 0x003b33f2
0x3b33a1: MOVSXD RAX, dword ptr [RBP + -0x34]
0x3b33a5: LEA R13, [0x391c310]
0x3b33ac: MOV RDI, qword ptr [RBP + -0x58]
0x3b33b0: XOR EBX, EBX
0x3b33b2: CMP EAX, dword ptr [RBP + -0x60]
0x3b33b5: JG 0x003b33f2
0x3b33b7: SHL RAX, 0x3
0x3b33bb: MOV RSI, R14
0x3b33be: MOV R15, RDI
0x3b33c1: LEA RDX, [RAX + RAX*0x2]
0x3b33c5: CALL 0x003b3a40
0x3b33ca: MOV RDI, R15
0x3b33cd: TEST EAX, EAX
0x3b33cf: JZ 0x003b33f2
0x3b33d1: LEA RDI, [0x131bf08]
0x3b33d8: LEA RSI, [0x12a94cb]
0x3b33df: MOV EDX, 0x14e0
0x3b33e4: MOV ECX, EAX
0x3b33e6: MOV EBX, EAX
0x3b33e8: XOR EAX, EAX
0x3b33ea: CALL 0x0025d410
0x3b33ef: MOV RDI, R15
0x3b33f2: LEA RSI, [0x1ab5ac0]
0x3b33f9: CALL 0x00c08df0
0x3b33fe: JMP 0x003b3202
0x3b3403: CALL 0x006fd6b0
0x3b3408: UD2

; local helper / adjacent context (reachability below); evidence ev_5d4518385db81b239411ef7993dd56468a80539cc287c1d4586fc1df1825fc94; body [{"start": "0x8fb210", "end": "0x8fb424"}]
handler_658_tail_helper: ; RVA 0x8fb210
0x8fb210: PUSH RBP
0x8fb211: MOV RBP, RSP
0x8fb214: PUSH R15
0x8fb216: PUSH R14
0x8fb218: PUSH R13
0x8fb21a: PUSH R12
0x8fb21c: PUSH RBX
0x8fb21d: SUB RSP, 0x48
0x8fb221: LEA R13, [0x391c310]
0x8fb228: MOV R14D, ESI
0x8fb22b: MOV RBX, RDI
0x8fb22e: MOV RAX, qword ptr [R13]
0x8fb232: MOV qword ptr [RBP + -0x30], RAX
0x8fb236: MOV R12, qword ptr GS:[0x0]
0x8fb23f: TEST byte ptr [R12 + 0xef], 0x1
0x8fb248: JZ 0x008fb252
0x8fb24a: MOV EDI, R14D
0x8fb24d: CALL 0x004440d0
0x8fb252: LEA RSI, [RBP + -0x40]
0x8fb256: MOV RDX, 0x200000000000100
0x8fb260: XOR EDI, EDI
0x8fb262: XOR ECX, ECX
0x8fb264: XOR EAX, EAX
0x8fb266: CALL 0x002bc220
0x8fb26b: MOV RCX, qword ptr [RBX + 0x8]
0x8fb26f: MOV ESI, R14D
0x8fb272: MOV RDX, RAX
0x8fb275: XOR R8D, R8D
0x8fb278: MOV RDI, qword ptr [RCX + 0x48]
0x8fb27c: LEA RCX, [RBP + -0x60]
0x8fb280: CALL 0x0072b4c0
0x8fb285: TEST EAX, EAX
0x8fb287: JZ 0x008fb2a6
0x8fb289: MOV RCX, qword ptr [R13]
0x8fb28d: CMP RCX, qword ptr [RBP + -0x30]
0x8fb291: JNZ 0x008fb41e
0x8fb297: ADD RSP, 0x48
0x8fb29b: POP RBX
0x8fb29c: POP R12
0x8fb29e: POP R13
0x8fb2a0: POP R14
0x8fb2a2: POP R15
0x8fb2a4: POP RBP
0x8fb2a5: RET
0x8fb2a6: MOV R14, qword ptr [RBP + -0x60]
0x8fb2aa: CMP qword ptr [R14 + 0x18], 0x0
0x8fb2af: JZ 0x008fb3ef
0x8fb2b5: MOV RAX, qword ptr [R14 + 0x8]
0x8fb2b9: CMP RAX, qword ptr [0x01a5d1a0]
0x8fb2c0: JZ 0x008fb3ef
0x8fb2c6: MOV R15, qword ptr [R14 + 0x18]
0x8fb2ca: LEA RSI, [RBP + -0x68]
0x8fb2ce: MOV EDX, 0x1001
0x8fb2d3: MOV RDI, R15
0x8fb2d6: CALL 0x006af4f0
0x8fb2db: TEST EAX, EAX
0x8fb2dd: JNZ 0x008fb3c7
0x8fb2e3: MOV RAX, qword ptr [RBP + -0x68]
0x8fb2e7: TEST RAX, RAX
0x8fb2ea: JNZ 0x008fb2f5
0x8fb2ec: MOV RAX, qword ptr [R15 + 0x18]
0x8fb2f0: TEST RAX, RAX
0x8fb2f3: JZ 0x008fb303
0x8fb2f5: TEST byte ptr [RAX + 0x90], 0x80
0x8fb2fc: MOV ESI, 0x200400
0x8fb301: JNZ 0x008fb308
0x8fb303: MOV ESI, 0x80400
0x8fb308: LEA RDX, [0x13753fa]
0x8fb30f: MOV RDI, R15
0x8fb312: MOV ECX, 0xe3e
0x8fb317: CALL 0x006afb50
0x8fb31c: TEST byte ptr [R12 + 0xef], 0x1
0x8fb325: JZ 0x008fb32f
0x8fb327: MOV RDI, R15
0x8fb32a: CALL 0x004449b0
0x8fb32f: MOV RDI, qword ptr [R15 + 0xf8]
0x8fb336: TEST RDI, RDI
0x8fb339: JZ 0x008fb36e
0x8fb33b: ADD RDI, 0x18
0x8fb33f: XOR ESI, ESI
0x8fb341: XOR EDX, EDX
0x8fb343: CALL 0x007d46a0
0x8fb348: MOV RDI, qword ptr [R15 + 0xf8]
0x8fb34f: XOR ESI, ESI
0x8fb351: XOR EDX, EDX
0x8fb353: XOR ECX, ECX
0x8fb355: CALL 0x00462d80
0x8fb35a: MOV RDI, qword ptr [R15 + 0xf8]
0x8fb361: XOR ESI, ESI
0x8fb363: XOR EDX, EDX
0x8fb365: ADD RDI, 0x18
0x8fb369: CALL 0x007d4eb0
0x8fb36e: LEA RAX, [0x1adbaf8]
0x8fb375: LEA RSI, [RBP + -0x60]
0x8fb379: MOV qword ptr [RBP + -0x60], RAX
0x8fb37d: MOV qword ptr [RBP + -0x58], R15
0x8fb381: MOV dword ptr [RBP + -0x50], 0x1
0x8fb388: MOV qword ptr [RBP + -0x48], RBX
0x8fb38c: MOV RDI, qword ptr [R15 + 0x8]
0x8fb390: CALL 0x0058d3a0
0x8fb395: MOV R12D, EAX
0x8fb398: LEA RAX, [0x1adcdc8]
0x8fb39f: LEA RSI, [RBP + -0x60]
0x8fb3a3: MOV qword ptr [RBP + -0x60], RAX
0x8fb3a7: MOV qword ptr [RBP + -0x58], R15
0x8fb3ab: MOV dword ptr [RBP + -0x50], 0x0
0x8fb3b2: MOV RDI, qword ptr [R15 + 0x8]
0x8fb3b6: CALL 0x0058ea90
0x8fb3bb: MOV RDI, qword ptr [RBP + -0x68]
0x8fb3bf: CALL 0x006af5e0
0x8fb3c4: MOV EAX, R12D
0x8fb3c7: MOV ECX, 0xffffffff
0x8fb3cc: XADD.LOCK dword ptr [R14 + 0x28], ECX
0x8fb3d2: CMP ECX, 0x1
0x8fb3d5: JNZ 0x008fb289
0x8fb3db: MOV RSI, RBX
0x8fb3de: MOV RDI, R14
0x8fb3e1: MOV EBX, EAX
0x8fb3e3: CALL 0x0072b380
0x8fb3e8: MOV EAX, EBX
0x8fb3ea: JMP 0x008fb289
0x8fb3ef: MOV EAX, 0x16
0x8fb3f4: MOV ECX, 0xffffffff
0x8fb3f9: XADD.LOCK dword ptr [R14 + 0x28], ECX
0x8fb3ff: CMP ECX, 0x1
0x8fb402: JNZ 0x008fb289
0x8fb408: MOV RDI, qword ptr [RBP + -0x60]
0x8fb40c: MOV RSI, RBX
0x8fb40f: CALL 0x0072b380
0x8fb414: MOV EAX, 0x16
0x8fb419: JMP 0x008fb289
0x8fb41e: CALL 0x006fd6b0
0x8fb423: UD2

; local helper / adjacent context (reachability below); evidence ev_7fa59b572b7653d27af71363a5214f1a5dba7cd2697dd1c3b653f435ca9f98b7; body [{"start": "0x8fb430", "end": "0x8fb43b"}]
adjacent_8fb430: ; RVA 0x8fb430
0x8fb430: PUSH RBP
0x8fb431: MOV RBP, RSP
0x8fb434: MOV ESI, dword ptr [RSI]
0x8fb436: POP RBP
0x8fb437: JMP 0x008fb210

; local helper / adjacent context (reachability below); evidence ev_b3f59366a82e308c18d17f4abc615800f3af536e16230b3de3f8886510ca6c65; body [{"start": "0x8fb440", "end": "0x8fb44b"}]
handler_658_body: ; RVA 0x8fb440
0x8fb440: PUSH RBP
0x8fb441: MOV RBP, RSP
0x8fb444: MOV ESI, dword ptr [RSI]
0x8fb446: POP RBP
0x8fb447: JMP 0x008fb210

; local helper / adjacent context (reachability below); evidence ev_1f47b78acb4a99c103d491cbbc7f90e422d29b00afe97b1b5ba62dd864357ea1; body [{"start": "0x8fb450", "end": "0x8fb46d"}]
adjacent_8fb450: ; RVA 0x8fb450
0x8fb450: PUSH RBP
0x8fb451: MOV RBP, RSP
0x8fb454: MOV RDX, qword ptr [RSI]
0x8fb457: MOV R8, qword ptr [RSI + 0x8]
0x8fb45b: MOV ESI, 0xffffff9c
0x8fb460: MOV ECX, 0xffffff9c
0x8fb465: XOR R9D, R9D
0x8fb468: POP RBP
0x8fb469: JMP 0x008fb470

; local helper / adjacent context (reachability below); evidence ev_c69e1610b6b54d823ae1db624d992c653627cc9728711e14c3db217eeec46882; body [{"start": "0x8fb470", "end": "0x8fb4c5"}, {"start": "0x8fb4d0", "end": "0x8fb650"}, {"start": "0x8fb660", "end": "0x8fb899"}]
adjacent_8fb470: ; RVA 0x8fb470
0x8fb470: PUSH RBP
0x8fb471: MOV RBP, RSP
0x8fb474: PUSH R15
0x8fb476: PUSH R14
0x8fb478: PUSH R13
0x8fb47a: PUSH R12
0x8fb47c: PUSH RBX
0x8fb47d: SUB RSP, 0x248
0x8fb484: LEA RAX, [0x391c310]
0x8fb48b: MOV qword ptr [RBP + -0x260], R8
0x8fb492: MOV dword ptr [RBP + -0x254], ECX
0x8fb498: MOV qword ptr [RBP + -0x268], RDX
0x8fb49f: MOV dword ptr [RBP + -0x258], ESI
0x8fb4a5: MOV R13D, R9D
0x8fb4a8: MOV R12, RDI
0x8fb4ab: LEA R15, [RBP + -0x210]
0x8fb4b2: MOV RAX, qword ptr [RAX]
0x8fb4b5: MOV qword ptr [RBP + -0x30], RAX
0x8fb4b9: MOV qword ptr [RBP + -0x250], 0x0
0x8fb4c4: JMP 0x008fb4f2
0x8fb4d0: LEA RSI, [RBP + -0x250]
0x8fb4d7: MOV EDX, 0x1004
0x8fb4dc: XOR EDI, EDI
0x8fb4de: CALL 0x006af4f0
0x8fb4e3: LEA R15, [RBP + -0x210]
0x8fb4ea: TEST EAX, EAX
0x8fb4ec: JNZ 0x008fb6a2
0x8fb4f2: XOR EDI, EDI
0x8fb4f4: CALL 0x00a9eac0
0x8fb4f9: MOV RSI, R15
0x8fb4fc: MOV RDX, 0x200000004000400
0x8fb506: XOR EDI, EDI
0x8fb508: XOR ECX, ECX
0x8fb50a: XOR EAX, EAX
0x8fb50c: CALL 0x002bc220
0x8fb511: SUB RSP, 0x8
0x8fb515: MOV R8, qword ptr [RBP + -0x268]
0x8fb51c: MOV R9D, dword ptr [RBP + -0x258]
0x8fb523: LEA RBX, [RBP + -0x118]
0x8fb52a: MOV ESI, 0x2
0x8fb52f: MOV EDX, 0x4001010
0x8fb534: MOV ECX, R13D
0x8fb537: MOV RDI, RBX
0x8fb53a: PUSH R12
0x8fb53c: PUSH RAX
0x8fb53d: PUSH 0x0
0x8fb53f: CALL 0x005fa6e0
0x8fb544: ADD RSP, 0x20
0x8fb548: MOV RDI, RBX
0x8fb54b: CALL 0x005f8c20
0x8fb550: TEST EAX, EAX
0x8fb552: JNZ 0x008fb6a2
0x8fb558: MOV RBX, qword ptr [RBP + -0xb8]
0x8fb55f: MOV RDI, RBX
0x8fb562: CALL 0x008f80f0
0x8fb567: MOV R14, RAX
0x8fb56a: MOV RSI, R15
0x8fb56d: MOV RDX, 0x200040000000400
0x8fb577: XOR EDI, EDI
0x8fb579: XOR ECX, ECX
0x8fb57b: XOR EAX, EAX
0x8fb57d: OR R14, 0x800102c
0x8fb584: CALL 0x002bc220
0x8fb589: SUB RSP, 0x8
0x8fb58d: MOV R8, qword ptr [RBP + -0x260]
0x8fb594: MOV R9D, dword ptr [RBP + -0x254]
0x8fb59b: MOV ESI, 0x3
0x8fb5a0: LEA RDI, [RBP + -0x200]
0x8fb5a7: MOV RDX, R14
0x8fb5aa: MOV ECX, R13D
0x8fb5ad: PUSH R12
0x8fb5af: PUSH RAX
0x8fb5b0: PUSH 0x0
0x8fb5b2: CALL 0x005fa6e0
0x8fb5b7: ADD RSP, 0x20
0x8fb5bb: MOV RAX, qword ptr [RBP + -0xb8]
0x8fb5c2: CMP dword ptr [RAX + 0x1d4], 0x2
0x8fb5c9: JNZ 0x008fb5d2
0x8fb5cb: OR byte ptr [RBP + -0x16e], 0x8
0x8fb5d2: LEA RDI, [RBP + -0x200]
0x8fb5d9: CALL 0x005f8c20
0x8fb5de: TEST EAX, EAX
0x8fb5e0: JNZ 0x008fb6ae
0x8fb5e6: MOV R15D, R13D
0x8fb5e9: MOV R14, qword ptr [RBP + -0x1a0]
0x8fb5f0: MOV R13, qword ptr [RBP + -0x198]
0x8fb5f7: MOV RDI, RBX
0x8fb5fa: LEA RSI, [RBP + -0x250]
0x8fb601: MOV EDX, 0x2
0x8fb606: CALL 0x006af4f0
0x8fb60b: TEST EAX, EAX
0x8fb60d: JZ 0x008fb6f9
0x8fb613: LEA RDI, [RBP + -0x118]
0x8fb61a: MOV ESI, 0xffffffdf
0x8fb61f: CALL 0x005fa780
0x8fb624: LEA RDI, [RBP + -0x200]
0x8fb62b: MOV ESI, 0xffffffdf
0x8fb630: CALL 0x005fa780
0x8fb635: TEST R14, R14
0x8fb638: JZ 0x008fb642
0x8fb63a: MOV RDI, R14
0x8fb63d: CALL 0x0054a440
0x8fb642: MOV RDI, R13
0x8fb645: CMP R13, R14
0x8fb648: JZ 0x008fb660
0x8fb64a: CALL 0x0054a440
0x8fb64f: JMP 0x008fb665
0x8fb660: CALL 0x0054a120
0x8fb665: MOV RDI, qword ptr [RBP + -0xb0]
0x8fb66c: CALL 0x0054a120
0x8fb671: MOV RDI, RBX
0x8fb674: CALL 0x0054a120
0x8fb679: MOV RDI, qword ptr [RBP + -0x1e0]
0x8fb680: CALL 0x0054a120
0x8fb685: MOV RDI, qword ptr [RBP + -0xf8]
0x8fb68c: MOV R13D, R15D
0x8fb68f: TEST RDI, RDI
0x8fb692: JZ 0x008fb4d0
0x8fb698: CALL 0x0054a120
0x8fb69d: JMP 0x008fb4d0
0x8fb6a2: LEA R12, [0x391c310]
0x8fb6a9: JMP 0x008fb877
0x8fb6ae: MOV R15D, EAX
0x8fb6b1: CMP EAX, 0x15
0x8fb6b4: JNZ 0x008fb6c8
0x8fb6b6: XOR R15D, R15D
0x8fb6b9: CMP dword ptr [RBX + 0x1d4], 0x2
0x8fb6c0: SETZ R15B
0x8fb6c4: ADD R15D, 0x15
0x8fb6c8: LEA R12, [0x391c310]
0x8fb6cf: LEA RDI, [RBP + -0x118]
0x8fb6d6: MOV ESI, 0xffffffdf
0x8fb6db: CALL 0x005fa780
0x8fb6e0: MOV RDI, qword ptr [RBP + -0xb0]
0x8fb6e7: CALL 0x0054a120
0x8fb6ec: MOV RDI, RBX
0x8fb6ef: CALL 0x0054a120
0x8fb6f4: JMP 0x008fb85c
0x8fb6f9: LEA R12, [0x391c310]
0x8fb700: TEST R14, R14
0x8fb703: JZ 0x008fb734
0x8fb705: CMP dword ptr [RBX + 0x1d4], 0x2
0x8fb70c: MOV EAX, dword ptr [R14 + 0x1d4]
0x8fb713: JNZ 0x008fb725
0x8fb715: MOV R15D, 0x14
0x8fb71b: CMP EAX, 0x2
0x8fb71e: JZ 0x008fb734
0x8fb720: JMP 0x008fb7ed
0x8fb725: MOV R15D, 0x15
0x8fb72b: CMP EAX, 0x2
0x8fb72e: JZ 0x008fb7ed
0x8fb734: CMP RBX, R13
0x8fb737: JZ 0x008fb7df
0x8fb73d: CMP RBX, R14
0x8fb740: JZ 0x008fb7e7
0x8fb746: LEA R9, [0x1adc048]
0x8fb74d: MOV RAX, qword ptr [RBP + -0xb8]
0x8fb754: MOV RCX, qword ptr [RBP + -0xb0]
0x8fb75b: MOV RSI, qword ptr [RBP + -0x1a0]
0x8fb762: MOV RDI, qword ptr [RBP + -0x198]
0x8fb769: LEA RDX, [RBP + -0x90]
0x8fb770: LEA R8, [RBP + -0x178]
0x8fb777: MOV qword ptr [RBP + -0x248], R9
0x8fb77e: MOV qword ptr [RBP + -0x240], RCX
0x8fb785: MOV qword ptr [RBP + -0x238], RAX
0x8fb78c: MOV qword ptr [RBP + -0x230], RDX
0x8fb793: MOV qword ptr [RBP + -0x228], RDI
0x8fb79a: MOV qword ptr [RBP + -0x220], RSI
0x8fb7a1: MOV qword ptr [RBP + -0x218], R8
0x8fb7a8: LEA RSI, [RBP + -0x248]
0x8fb7af: MOV RDI, qword ptr [RCX + 0x8]
0x8fb7b3: CALL 0x0058d960
0x8fb7b8: LEA RDI, [RBP + -0x118]
0x8fb7bf: MOV ESI, 0xffffffdf
0x8fb7c4: MOV R15D, EAX
0x8fb7c7: CALL 0x005fa780
0x8fb7cc: LEA RDI, [RBP + -0x200]
0x8fb7d3: MOV ESI, 0xffffffdf
0x8fb7d8: CALL 0x005fa780
0x8fb7dd: JMP 0x008fb844
0x8fb7df: MOV R15D, 0x16
0x8fb7e5: JMP 0x008fb7ed
0x8fb7e7: MOV R15D, 0xffffffff
0x8fb7ed: LEA RDI, [RBP + -0x118]
0x8fb7f4: MOV ESI, 0xffffffdf
0x8fb7f9: CALL 0x005fa780
0x8fb7fe: LEA RDI, [RBP + -0x200]
0x8fb805: MOV ESI, 0xffffffdf
0x8fb80a: CALL 0x005fa780
0x8fb80f: TEST R14, R14
0x8fb812: JZ 0x008fb81c
0x8fb814: MOV RDI, R14
0x8fb817: CALL 0x0054a440
0x8fb81c: MOV RDI, R13
0x8fb81f: CMP R13, R14
0x8fb822: JZ 0x008fb82b
0x8fb824: CALL 0x0054a440
0x8fb829: JMP 0x008fb830
0x8fb82b: CALL 0x0054a120
0x8fb830: MOV RDI, qword ptr [RBP + -0xb0]
0x8fb837: CALL 0x0054a120
0x8fb83c: MOV RDI, RBX
0x8fb83f: CALL 0x0054a120
0x8fb844: MOV RDI, qword ptr [RBP + -0x1e0]
0x8fb84b: CALL 0x0054a120
0x8fb850: MOV RDI, qword ptr [RBP + -0x250]
0x8fb857: CALL 0x006af5e0
0x8fb85c: MOV RDI, qword ptr [RBP + -0xf8]
0x8fb863: TEST RDI, RDI
0x8fb866: JZ 0x008fb86d
0x8fb868: CALL 0x0054a120
0x8fb86d: XOR EAX, EAX
0x8fb86f: CMP R15D, -0x1
0x8fb873: CMOVNZ EAX, R15D
0x8fb877: MOV RCX, qword ptr [R12]
0x8fb87b: CMP RCX, qword ptr [RBP + -0x30]
0x8fb87f: JNZ 0x008fb893
0x8fb881: ADD RSP, 0x248
0x8fb888: POP RBX
0x8fb889: POP R12
0x8fb88b: POP R13
0x8fb88d: POP R14
0x8fb88f: POP R15
0x8fb891: POP RBP
0x8fb892: RET
0x8fb893: CALL 0x006fd6b0
0x8fb898: UD2

; local helper / adjacent context (reachability below); evidence ev_a3529087295f4c573b7f89d3e82558e49918efda3c25d8a880df9a53a71b2220; body [{"start": "0x8fb8a0", "end": "0x8fb8dd"}]
adjacent_8fb8a0: ; RVA 0x8fb8a0
0x8fb8a0: PUSH RBP
0x8fb8a1: MOV RBP, RSP
0x8fb8a4: PUSH R14
0x8fb8a6: PUSH RBX
0x8fb8a7: MOV R14, RSI
0x8fb8aa: MOV ESI, 0x2ab
0x8fb8af: MOV RBX, RDI
0x8fb8b2: CALL 0x00adfa30
0x8fb8b7: TEST EAX, EAX
0x8fb8b9: JZ 0x008fb8c0
0x8fb8bb: POP RBX
0x8fb8bc: POP R14
0x8fb8be: POP RBP
0x8fb8bf: RET
0x8fb8c0: MOV ESI, dword ptr [R14]
0x8fb8c3: MOV RDX, qword ptr [R14 + 0x8]
0x8fb8c7: MOV ECX, dword ptr [R14 + 0x10]
0x8fb8cb: MOV R8, qword ptr [R14 + 0x18]
0x8fb8cf: MOV RDI, RBX
0x8fb8d2: XOR R9D, R9D
0x8fb8d5: POP RBX
0x8fb8d6: POP R14
0x8fb8d8: POP RBP
0x8fb8d9: JMP 0x008fb470

; local helper / adjacent context (reachability below); evidence ev_935f2969da2729e920e0f553c956b3da38cab565991079fd7ef8a4d2c0e473ff; body [{"start": "0x8fb8e0", "end": "0x8fb8f7"}]
adjacent_8fb8e0: ; RVA 0x8fb8e0
0x8fb8e0: PUSH RBP
0x8fb8e1: MOV RBP, RSP
0x8fb8e4: MOV RDX, qword ptr [RSI]
0x8fb8e7: MOV R8D, dword ptr [RSI + 0x8]
0x8fb8eb: MOV ESI, 0xffffff9c
0x8fb8f0: XOR ECX, ECX
0x8fb8f2: POP RBP
0x8fb8f3: JMP 0x008fb900

; local helper / adjacent context (reachability below); evidence ev_bab176c86985e2b1605950e622035135defa28c571dc7d7b52935ede7ccc3e06; body [{"start": "0x8fb900", "end": "0x8fbb7b"}]
adjacent_8fb900: ; RVA 0x8fb900
0x8fb900: PUSH RBP
0x8fb901: MOV RBP, RSP
0x8fb904: PUSH R15
0x8fb906: PUSH R14
0x8fb908: PUSH R13
0x8fb90a: PUSH R12
0x8fb90c: PUSH RBX
0x8fb90d: SUB RSP, 0x1e8
0x8fb914: LEA RAX, [0x391c310]
0x8fb91b: MOV dword ptr [RBP + -0x208], ECX
0x8fb921: MOV qword ptr [RBP + -0x210], RDI
0x8fb928: MOV EBX, R8D
0x8fb92b: MOV R12, RDX
0x8fb92e: MOV R13D, ESI
0x8fb931: MOV RAX, qword ptr [RAX]
0x8fb934: MOV qword ptr [RBP + -0x30], RAX
0x8fb938: MOV RAX, qword ptr GS:[0x0]
0x8fb941: TEST byte ptr [RAX + 0xef], 0x1
0x8fb948: JZ 0x008fb952
0x8fb94a: MOVZX EDI, BX
0x8fb94d: CALL 0x00444340
0x8fb952: MOV dword ptr [RBP + -0x204], EBX
0x8fb958: LEA RBX, [RBP + -0x118]
0x8fb95f: LEA R14, [RBP + -0x158]
0x8fb966: NOP word ptr CS:[RAX + RAX*0x1]
0x8fb970: XOR EDI, EDI
0x8fb972: CALL 0x00a9eac0
0x8fb977: LEA RSI, [RBP + -0x128]
0x8fb97e: MOV RDX, 0x200000000800400
0x8fb988: XOR EDI, EDI
0x8fb98a: XOR ECX, ECX
0x8fb98c: XOR EAX, EAX
0x8fb98e: CALL 0x002bc220
0x8fb993: SUB RSP, 0x8
0x8fb997: MOV ECX, dword ptr [RBP + -0x208]
0x8fb99d: MOV ESI, 0x1
0x8fb9a2: MOV EDX, 0x4000828
0x8fb9a7: MOV RDI, RBX
0x8fb9aa: MOV R8, R12
0x8fb9ad: MOV R9D, R13D
0x8fb9b0: PUSH qword ptr [RBP + -0x210]
0x8fb9b6: PUSH RAX
0x8fb9b7: PUSH 0x0
0x8fb9b9: CALL 0x005fa6e0
0x8fb9be: ADD RSP, 0x20
0x8fb9c2: OR byte ptr [RBP + -0x86], 0x8
0x8fb9c9: MOV RDI, RBX
0x8fb9cc: CALL 0x005f8c20
0x8fb9d1: TEST EAX, EAX
0x8fb9d3: JNZ 0x008fba29
0x8fb9d5: MOV R15, qword ptr [RBP + -0xb8]
0x8fb9dc: TEST R15, R15
0x8fb9df: JNZ 0x008fba31
0x8fb9e1: MOV RDI, qword ptr [RBP + -0xb0]
0x8fb9e8: MOV RSI, R14
0x8fb9eb: MOV EDX, 0x2
0x8fb9f0: CALL 0x006af4f0
0x8fb9f5: TEST EAX, EAX
0x8fb9f7: JZ 0x008fba5c
0x8fb9f9: MOV RDI, RBX
0x8fb9fc: MOV ESI, 0xffffffdf
0x8fba01: CALL 0x005fa780
0x8fba06: MOV RDI, qword ptr [RBP + -0xb0]
0x8fba0d: CALL 0x0054a440
0x8fba12: MOV RSI, R14
0x8fba15: MOV EDX, 0x1004
0x8fba1a: XOR EDI, EDI
0x8fba1c: CALL 0x006af4f0
0x8fba21: TEST EAX, EAX
0x8fba23: JZ 0x008fb970
0x8fba29: MOV R15D, EAX
0x8fba2c: JMP 0x008fbb34
0x8fba31: LEA RDI, [RBP + -0x118]
0x8fba38: MOV ESI, 0xffffffdf
0x8fba3d: CALL 0x005fa780
0x8fba42: MOV RDI, qword ptr [RBP + -0xb0]
0x8fba49: CMP R15, RDI
0x8fba4c: JZ 0x008fbb3d
0x8fba52: CALL 0x0054a440
0x8fba57: JMP 0x008fbb42
0x8fba5c: LEA RBX, [RBP + -0x200]
0x8fba63: LEA RSI, [0x3829a90]
0x8fba6a: MOV EDX, 0xa8
0x8fba6f: LEA R14, [RBP + -0x90]
0x8fba76: MOV RDI, RBX
0x8fba79: CALL 0x002590b0
0x8fba7e: MOV RAX, qword ptr [RBP + -0x210]
0x8fba85: MOV dword ptr [RBP + -0x200], 0x2
0x8fba8f: LEA RCX, [0x1adc1c8]
0x8fba96: LEA RSI, [RBP + -0x150]
0x8fba9d: MOV RAX, qword ptr [RAX + 0x8]
0x8fbaa1: MOV RAX, qword ptr [RAX + 0x48]
0x8fbaa5: MOV EAX, dword ptr [RAX + 0x30]
0x8fbaa8: ANDN EAX, EAX, dword ptr [RBP + -0x204]
0x8fbab1: MOV qword ptr [RBP + -0x150], RCX
0x8fbab8: LEA RCX, [RBP + -0xb8]
0x8fbabf: AND EAX, 0x1ff
0x8fbac4: MOV word ptr [RBP + -0x1fc], AX
0x8fbacb: MOV RAX, qword ptr [RBP + -0xb0]
0x8fbad2: MOV qword ptr [RBP + -0x148], RAX
0x8fbad9: MOV qword ptr [RBP + -0x140], RCX
0x8fbae0: MOV qword ptr [RBP + -0x138], R14
0x8fbae7: MOV qword ptr [RBP + -0x130], RBX
0x8fbaee: MOV RDI, qword ptr [RAX + 0x8]
0x8fbaf2: CALL 0x0058db40
0x8fbaf7: LEA RDI, [RBP + -0x118]
0x8fbafe: MOV ESI, 0xffffffdf
0x8fbb03: MOV R15D, EAX
0x8fbb06: CALL 0x005fa780
0x8fbb0b: MOV RDI, qword ptr [RBP + -0xb0]
0x8fbb12: CALL 0x0054a440
0x8fbb17: TEST R15D, R15D
0x8fbb1a: JNZ 0x008fbb28
0x8fbb1c: MOV RDI, qword ptr [RBP + -0xb8]
0x8fbb23: CALL 0x0054a440
0x8fbb28: MOV RDI, qword ptr [RBP + -0x158]
0x8fbb2f: CALL 0x006af5e0
0x8fbb34: LEA RBX, [0x391c310]
0x8fbb3b: JMP 0x008fbb57
0x8fbb3d: CALL 0x0054a120
0x8fbb42: LEA RBX, [0x391c310]
0x8fbb49: MOV RDI, R15
0x8fbb4c: CALL 0x0054a120
0x8fbb51: MOV R15D, 0x11
0x8fbb57: MOV RAX, qword ptr [RBX]
0x8fbb5a: CMP RAX, qword ptr [RBP + -0x30]
0x8fbb5e: JNZ 0x008fbb75
0x8fbb60: MOV EAX, R15D
0x8fbb63: ADD RSP, 0x1e8
0x8fbb6a: POP RBX
0x8fbb6b: POP R12
0x8fbb6d: POP R13
0x8fbb6f: POP R14
0x8fbb71: POP R15
0x8fbb73: POP RBP
0x8fbb74: RET
0x8fbb75: CALL 0x006fd6b0
0x8fbb7a: UD2

; local helper / adjacent context (reachability below); evidence ev_c6d74142bdca3ba9d5c15a89bfc336e6e090cca38741e3f0a196694b2bfb8944; body [{"start": "0x8fbb80", "end": "0x8fbbb9"}]
adjacent_8fbb80: ; RVA 0x8fbb80
0x8fbb80: PUSH RBP
0x8fbb81: MOV RBP, RSP
0x8fbb84: PUSH R14
0x8fbb86: PUSH RBX
0x8fbb87: MOV R14, RSI
0x8fbb8a: MOV ESI, 0x2ab
0x8fbb8f: MOV RBX, RDI
0x8fbb92: CALL 0x00adfa30
0x8fbb97: TEST EAX, EAX
0x8fbb99: JZ 0x008fbba0
0x8fbb9b: POP RBX
0x8fbb9c: POP R14
0x8fbb9e: POP RBP
0x8fbb9f: RET
0x8fbba0: MOV ESI, dword ptr [R14]
0x8fbba3: MOV RDX, qword ptr [R14 + 0x8]
0x8fbba7: MOVZX R8D, word ptr [R14 + 0x10]
0x8fbbac: MOV RDI, RBX
0x8fbbaf: XOR ECX, ECX
0x8fbbb1: POP RBX
0x8fbbb2: POP R14
0x8fbbb4: POP RBP
0x8fbbb5: JMP 0x008fb900

; local helper / adjacent context (reachability below); evidence ev_f299fda74984e06ddc0ab2eb6dc47f31632897224530f684da0b1d5838c584b4; body [{"start": "0x8fbbc0", "end": "0x8fbbd3"}]
adjacent_8fbbc0: ; RVA 0x8fbbc0
0x8fbbc0: PUSH RBP
0x8fbbc1: MOV RBP, RSP
0x8fbbc4: MOV RDX, qword ptr [RSI]
0x8fbbc7: MOV ESI, 0xffffff9c
0x8fbbcc: XOR ECX, ECX
0x8fbbce: POP RBP
0x8fbbcf: JMP 0x008f8870

; local helper / adjacent context (reachability below); evidence ev_373af22d4f72d80e05d0f008a5ee944baa9236f5e4880dc88501669310d0ae81; body [{"start": "0x8fbbe0", "end": "0x8fbe63"}]
adjacent_8fbbe0: ; RVA 0x8fbbe0
0x8fbbe0: PUSH RBP
0x8fbbe1: MOV RBP, RSP
0x8fbbe4: PUSH R15
0x8fbbe6: PUSH R14
0x8fbbe8: PUSH R13
0x8fbbea: PUSH R12
0x8fbbec: PUSH RBX
0x8fbbed: SUB RSP, 0x48
0x8fbbf1: LEA R15, [0x391c310]
0x8fbbf8: MOV RBX, RSI
0x8fbbfb: LEA R8, [RBP + -0x50]
0x8fbbff: MOV R14, RDI
0x8fbc02: XOR R9D, R9D
0x8fbc05: MOV RAX, qword ptr [R15]
0x8fbc08: MOV qword ptr [RBP + -0x30], RAX
0x8fbc0c: MOV ESI, dword ptr [RSI]
0x8fbc0e: MOV RDX, qword ptr [RBX + 0x8]
0x8fbc12: MOV ECX, dword ptr [RBX + 0x10]
0x8fbc15: MOV dword ptr [RSP], 0x0
0x8fbc1c: CALL 0x008fbe70
0x8fbc21: TEST EAX, EAX
0x8fbc23: JZ 0x008fbd5b
0x8fbc29: MOV RCX, qword ptr [R14 + 0x8]
0x8fbc2d: MOV R12D, EAX
0x8fbc30: CMP byte ptr [RCX + 0xc81], 0x0
0x8fbc37: JNZ 0x008fbd95
0x8fbc3d: MOV EAX, dword ptr [RBX + 0x10]
0x8fbc40: CMP EAX, 0xffff
0x8fbc45: JA 0x008fbd95
0x8fbc4b: MOV R12D, 0x16
0x8fbc51: CMP EAX, 0x200
0x8fbc56: JC 0x008fbd95
0x8fbc5c: LEA RSI, [0x2bfc080]
0x8fbc63: MOV EDI, 0x10000
0x8fbc68: MOV EDX, 0x2
0x8fbc6d: CALL 0x00c08b50
0x8fbc72: MOV ESI, dword ptr [RBX]
0x8fbc74: LEA R8, [RBP + -0x50]
0x8fbc78: LEA R9, [RBP + -0x58]
0x8fbc7c: MOV RDI, R14
0x8fbc7f: MOV RDX, RAX
0x8fbc82: MOV ECX, 0x10000
0x8fbc87: MOV R13, RAX
0x8fbc8a: MOV dword ptr [RSP], 0x1
0x8fbc91: CALL 0x008fbe70
0x8fbc96: TEST EAX, EAX
0x8fbc98: JZ 0x008fbcb1
0x8fbc9a: LEA RSI, [0x2bfc080]
0x8fbca1: MOV RDI, R13
0x8fbca4: MOV R12D, EAX
0x8fbca7: CALL 0x00c08df0
0x8fbcac: JMP 0x008fbd95
0x8fbcb1: MOVZX EAX, word ptr [R13 + 0x4]
0x8fbcb6: MOV EDI, dword ptr [RBX + 0x10]
0x8fbcb9: MOV qword ptr [RBP + -0x60], R13
0x8fbcbd: CMP AX, 0x8
0x8fbcc1: MOVZX ECX, AX
0x8fbcc4: MOV ESI, EDI
0x8fbcc6: SETC DL
0x8fbcc9: CMP EDI, ECX
0x8fbccb: SETC DIL
0x8fbccf: OR DIL, DL
0x8fbcd2: JNZ 0x008fbcea
0x8fbcd4: MOVZX EDX, byte ptr [R13 + 0x7]
0x8fbcd9: ADD EDX, 0x4
0x8fbcdc: AND EDX, 0xfffffffc
0x8fbcdf: ADD EDX, 0x8
0x8fbce2: CMP EDX, ECX
0x8fbce4: JBE 0x008fbdb4
0x8fbcea: CMP ESI, ECX
0x8fbcec: JNC 0x008fbd0a
0x8fbcee: MOVZX EAX, byte ptr [R13 + 0x7]
0x8fbcf3: ADD EAX, 0x4
0x8fbcf6: AND EAX, 0xfffffffc
0x8fbcf9: ADD EAX, 0x8
0x8fbcfc: CMP EAX, ESI
0x8fbcfe: JNC 0x008fbd0a
0x8fbd00: MOV word ptr [R13 + 0x4], SI
0x8fbd05: MOV R13, RSI
0x8fbd08: JMP 0x008fbd0d
0x8fbd0a: XOR R13D, R13D
0x8fbd0d: XOR ECX, ECX
0x8fbd0f: MOV R12, qword ptr [RBX + 0x8]
0x8fbd13: MOV RDI, qword ptr GS:[0x0]
0x8fbd1c: LEA RSI, [0x134f297]
0x8fbd23: XOR EDX, EDX
0x8fbd25: ADD R13, RCX
0x8fbd28: CALL 0x00c1a3e0
0x8fbd2d: MOV RDI, qword ptr [RBP + -0x60]
0x8fbd31: MOV RSI, R12
0x8fbd34: MOV RDX, R13
0x8fbd37: CALL 0x002591d0
0x8fbd3c: LEA RSI, [0x2bfc080]
0x8fbd43: MOV RDI, qword ptr [RBP + -0x60]
0x8fbd47: MOV R12D, EAX
0x8fbd4a: CALL 0x00c08df0
0x8fbd4f: TEST R12D, R12D
0x8fbd52: JNZ 0x008fbd95
0x8fbd54: MOV qword ptr [R14 + 0x408], R13
0x8fbd5b: MOV RBX, qword ptr [RBX + 0x18]
0x8fbd5f: MOV R12D, 0x0
0x8fbd65: TEST RBX, RBX
0x8fbd68: JZ 0x008fbd95
0x8fbd6a: MOV RDI, qword ptr GS:[0x0]
0x8fbd73: LEA RSI, [0x134f297]
0x8fbd7a: XOR EDX, EDX
0x8fbd7c: CALL 0x00c1a3e0
0x8fbd81: LEA RDI, [RBP + -0x50]
0x8fbd85: MOV EDX, 0x8
0x8fbd8a: MOV RSI, RBX
0x8fbd8d: CALL 0x002591d0
0x8fbd92: MOV R12D, EAX
0x8fbd95: MOV RAX, qword ptr [R15]
0x8fbd98: CMP RAX, qword ptr [RBP + -0x30]
0x8fbd9c: JNZ 0x008fbe5d
0x8fbda2: MOV EAX, R12D
0x8fbda5: ADD RSP, 0x48
0x8fbda9: POP RBX
0x8fbdaa: POP R12
0x8fbdac: POP R13
0x8fbdae: POP R14
0x8fbdb0: POP R15
0x8fbdb2: POP RBP
0x8fbdb3: RET
0x8fbdb4: MOV RCX, qword ptr [RBP + -0x58]
0x8fbdb8: MOV RDI, R13
0x8fbdbb: NEG RCX
0x8fbdbe: LEA RCX, [R13 + RCX*0x1 + 0x10000]
0x8fbdc6: XOR R13D, R13D
0x8fbdc9: CMP RDI, RCX
0x8fbdcc: JNC 0x008fbd0d
0x8fbdd2: MOV R9D, EAX
0x8fbdd5: MOVZX EAX, AX
0x8fbdd8: MOV RDX, RDI
0x8fbddb: ADD RDI, RAX
0x8fbdde: ADD R13, RAX
0x8fbde1: MOVZX EAX, word ptr [RDX + RAX*0x1 + 0x4]
0x8fbde6: CMP RAX, 0x8
0x8fbdea: JC 0x008fbe0c
0x8fbdec: LEA R8, [R13 + RAX*0x1]
0x8fbdf1: CMP R8, RSI
0x8fbdf4: JG 0x008fbe0c
0x8fbdf6: MOVZX R8D, byte ptr [RDI + 0x7]
0x8fbdfb: ADD R8D, 0x4
0x8fbdff: AND R8D, 0xfffffffc
0x8fbe03: ADD R8D, 0x8
0x8fbe07: CMP R8D, EAX
0x8fbe0a: JBE 0x008fbdc9
0x8fbe0c: SUB RSI, R13
0x8fbe0f: ADD R9D, ESI
0x8fbe12: MOV R12, RSI
0x8fbe15: MOV word ptr [RDX + 0x4], R9W
0x8fbe1a: CALL 0x00258ff0
0x8fbe1f: MOV EAX, dword ptr [RBX]
0x8fbe21: LEA RSI, [RBP + -0x48]
0x8fbe25: MOV RDI, R14
0x8fbe28: MOV dword ptr [RBP + -0x48], EAX
0x8fbe2b: MOV RAX, qword ptr [RBP + -0x50]
0x8fbe2f: ADD RAX, R13
0x8fbe32: MOV qword ptr [RBP + -0x40], RAX
0x8fbe36: MOV dword ptr [RBP + -0x38], 0x0
0x8fbe3d: CALL 0x008f8ab0
0x8fbe42: MOV RCX, R12
0x8fbe45: TEST EAX, EAX
0x8fbe47: JZ 0x008fbd0f
0x8fbe4d: LEA RSI, [0x2bfc080]
0x8fbe54: MOV RDI, qword ptr [RBP + -0x60]
0x8fbe58: JMP 0x008fbca4
0x8fbe5d: CALL 0x006fd6b0
0x8fbe62: UD2

; local helper / adjacent context (reachability below); evidence ev_56308fc7983b8e5fde14a393587603af92d5cff4d40144c6486caa9062157cc5; body [{"start": "0x8fbe70", "end": "0x8fc38d"}]
adjacent_8fbe70: ; RVA 0x8fbe70
0x8fbe70: PUSH RBP
0x8fbe71: MOV RBP, RSP
0x8fbe74: PUSH R15
0x8fbe76: PUSH R14
0x8fbe78: PUSH R13
0x8fbe7a: PUSH R12
0x8fbe7c: PUSH RBX
0x8fbe7d: SUB RSP, 0xc8
0x8fbe84: LEA RAX, [0x391c310]
0x8fbe8b: MOV qword ptr [RBP + -0xe8], R9
0x8fbe92: MOV qword ptr [RBP + -0xe0], R8
0x8fbe99: MOV R15D, ECX
0x8fbe9c: MOV R13, RDX
0x8fbe9f: MOV R14D, ESI
0x8fbea2: MOV RBX, RDI
0x8fbea5: MOV RAX, qword ptr [RAX]
0x8fbea8: MOV qword ptr [RBP + -0x30], RAX
0x8fbeac: MOV R12, qword ptr GS:[0x0]
0x8fbeb5: TEST byte ptr [R12 + 0xef], 0x1
0x8fbebe: JZ 0x008fbec8
0x8fbec0: MOV EDI, R14D
0x8fbec3: CALL 0x004440d0
0x8fbec8: MOV R15D, R15D
0x8fbecb: CALL 0x004ebfb0
0x8fbed0: MOV RCX, RAX
0x8fbed3: MOV EAX, 0x16
0x8fbed8: CMP RCX, R15
0x8fbedb: JC 0x008fbf1b
0x8fbedd: LEA RSI, [RBP + -0x40]
0x8fbee1: MOV RDX, 0x200000000000001
0x8fbeeb: MOV qword ptr [RBP + -0x90], R15
0x8fbef2: XOR EDI, EDI
0x8fbef4: XOR ECX, ECX
0x8fbef6: XOR EAX, EAX
0x8fbef8: CALL 0x002bc220
0x8fbefd: MOV RCX, qword ptr [RBX + 0x8]
0x8fbf01: MOV ESI, R14D
0x8fbf04: MOV RDX, RAX
0x8fbf07: XOR R8D, R8D
0x8fbf0a: MOV RDI, qword ptr [RCX + 0x48]
0x8fbf0e: LEA RCX, [RBP + -0x78]
0x8fbf12: CALL 0x0072b4c0
0x8fbf17: TEST EAX, EAX
0x8fbf19: JZ 0x008fbf41
0x8fbf1b: LEA RCX, [0x391c310]
0x8fbf22: MOV RCX, qword ptr [RCX]
0x8fbf25: CMP RCX, qword ptr [RBP + -0x30]
0x8fbf29: JNZ 0x008fc387
0x8fbf2f: ADD RSP, 0xc8
0x8fbf36: POP RBX
0x8fbf37: POP R12
0x8fbf39: POP R13
0x8fbf3b: POP R14
0x8fbf3d: POP R15
0x8fbf3f: POP RBP
0x8fbf40: RET
0x8fbf41: MOV R14, qword ptr [RBP + -0x78]
0x8fbf45: CMP qword ptr [R14 + 0x18], 0x0
0x8fbf4a: JZ 0x008fbf88
0x8fbf4c: MOV RAX, qword ptr [R14 + 0x8]
0x8fbf50: CMP RAX, qword ptr [0x01a5d1a0]
0x8fbf57: JZ 0x008fbf88
0x8fbf59: MOV EAX, dword ptr [R14 + 0x24]
0x8fbf5d: TEST AL, 0x1
0x8fbf5f: JNZ 0x008fbfb7
0x8fbf61: MOV EAX, 0x9
0x8fbf66: MOV ECX, 0xffffffff
0x8fbf6b: XADD.LOCK dword ptr [R14 + 0x28], ECX
0x8fbf71: CMP ECX, 0x1
0x8fbf74: JNZ 0x008fbf1b
0x8fbf76: MOV RDI, R14
0x8fbf79: MOV RSI, RBX
0x8fbf7c: CALL 0x0072b380
0x8fbf81: MOV EAX, 0x9
0x8fbf86: JMP 0x008fbf1b
0x8fbf88: MOV EAX, 0x16
0x8fbf8d: MOV ECX, 0xffffffff
0x8fbf92: XADD.LOCK dword ptr [R14 + 0x28], ECX
0x8fbf98: CMP ECX, 0x1
0x8fbf9b: JNZ 0x008fbf1b
0x8fbfa1: MOV RDI, qword ptr [RBP + -0x78]
0x8fbfa5: MOV RSI, RBX
0x8fbfa8: CALL 0x0072b380
0x8fbfad: MOV EAX, 0x16
0x8fbfb2: JMP 0x008fbf1b
0x8fbfb7: MOV RAX, qword ptr [R14 + 0x18]
0x8fbfbb: MOV RDI, R14
0x8fbfbe: XOR ESI, ESI
0x8fbfc0: MOV qword ptr [RBP + -0xc8], RAX
0x8fbfc7: CALL 0x006b06c0
0x8fbfcc: MOV RSI, qword ptr [RBP + -0xc8]
0x8fbfd3: MOV dword ptr [RBP + -0xc0], 0x16
0x8fbfdd: CMP dword ptr [RSI + 0x1d4], 0x2
0x8fbfe4: JNZ 0x008fc103
0x8fbfea: MOV qword ptr [RBP + -0xd8], RAX
0x8fbff1: MOV EAX, dword ptr [RBP + 0x10]
0x8fbff4: LEA RCX, [RBP + -0xb8]
0x8fbffb: MOV RDI, RSI
0x8fbffe: LEA RDX, [0x13753fa]
0x8fc005: MOV ESI, 0x200400
0x8fc00a: MOV qword ptr [RBP + -0xb8], R13
0x8fc011: MOV qword ptr [RBP + -0xb0], R15
0x8fc018: MOV qword ptr [RBP + -0xa8], RCX
0x8fc01f: MOV ECX, 0x10f0
0x8fc024: MOV dword ptr [RBP + -0xa0], 0x1
0x8fc02e: MOV dword ptr [RBP + -0x84], 0x0
0x8fc038: MOV dword ptr [RBP + -0x88], EAX
0x8fc03e: MOV qword ptr [RBP + -0x80], RBX
0x8fc042: CALL 0x006afb50
0x8fc047: TEST byte ptr [R12 + 0xef], 0x1
0x8fc050: JZ 0x008fc05e
0x8fc052: MOV RDI, qword ptr [RBP + -0xc8]
0x8fc059: CALL 0x004449b0
0x8fc05e: MOV RAX, qword ptr [RBP + -0xd8]
0x8fc065: LEA RCX, [0x1adc648]
0x8fc06c: MOV RDX, qword ptr [RBP + -0xc8]
0x8fc073: LEA RSI, [RBP + -0x78]
0x8fc077: MOV qword ptr [RBP + -0x98], RAX
0x8fc07e: MOV RAX, qword ptr [R14 + 0x10]
0x8fc082: MOV qword ptr [RBP + -0x78], RCX
0x8fc086: LEA RCX, [RBP + -0xa8]
0x8fc08d: MOV qword ptr [RBP + -0x70], RDX
0x8fc091: MOV qword ptr [RBP + -0x68], RCX
0x8fc095: MOV qword ptr [RBP + -0x60], RAX
0x8fc099: LEA RAX, [RBP + -0xbc]
0x8fc0a0: MOV qword ptr [RBP + -0x58], RAX
0x8fc0a4: MOV qword ptr [RBP + -0x50], 0x0
0x8fc0ac: MOV qword ptr [RBP + -0x48], 0x0
0x8fc0b4: MOV RDI, qword ptr [RDX + 0x8]
0x8fc0b8: CALL 0x0058e110
0x8fc0bd: MOV RCX, qword ptr [RBP + -0x98]
0x8fc0c4: TEST EAX, EAX
0x8fc0c6: JZ 0x008fc10b
0x8fc0c8: MOV R15, RCX
0x8fc0cb: MOV RCX, qword ptr [RBP + -0xc8]
0x8fc0d2: MOV dword ptr [RBP + -0xc0], EAX
0x8fc0d8: LEA RAX, [0x1adcdc8]
0x8fc0df: LEA RSI, [RBP + -0x78]
0x8fc0e3: MOV qword ptr [RBP + -0x78], RAX
0x8fc0e7: MOV qword ptr [RBP + -0x70], RCX
0x8fc0eb: MOV dword ptr [RBP + -0x68], 0x0
0x8fc0f2: MOV RDI, qword ptr [RCX + 0x8]
0x8fc0f6: CALL 0x0058ea90
0x8fc0fb: MOV RSI, R15
0x8fc0fe: JMP 0x008fc33c
0x8fc103: MOV RSI, RAX
0x8fc106: JMP 0x008fc33c
0x8fc10b: CMP qword ptr [RBP + -0x90], R15
0x8fc112: JNZ 0x008fc2d1
0x8fc118: MOV RDX, qword ptr [RBP + -0xc8]
0x8fc11f: TEST byte ptr [RDX + 0x1c8], 0x1
0x8fc126: JZ 0x008fc2d8
0x8fc12c: MOV RAX, qword ptr [RDX + 0x18]
0x8fc130: TEST byte ptr [RAX + 0x98], 0x20
0x8fc137: JZ 0x008fc2d8
0x8fc13d: MOV RDI, qword ptr [RAX + 0x48]
0x8fc141: MOV qword ptr [RBP + -0xd0], RDI
0x8fc148: CALL 0x0054a060
0x8fc14d: MOV RAX, qword ptr [RBP + -0xd0]
0x8fc154: MOV RDI, qword ptr [RBP + -0xc8]
0x8fc15b: MOV qword ptr [R14 + 0x18], RAX
0x8fc15f: MOV qword ptr [R14], RAX
0x8fc162: CALL 0x0054a440
0x8fc167: MOV RCX, qword ptr [RBP + -0xd0]
0x8fc16e: CMP dword ptr [RCX + 0x1d4], 0x2
0x8fc175: JNZ 0x008fc2cd
0x8fc17b: MOV qword ptr [RBP + -0xd8], 0x0
0x8fc186: LEA RAX, [RBP + -0xb8]
0x8fc18d: MOV RDI, RCX
0x8fc190: MOV qword ptr [RBP + -0xd0], RCX
0x8fc197: MOV ESI, 0x200400
0x8fc19c: LEA RDX, [0x13753fa]
0x8fc1a3: MOV ECX, 0x10f0
0x8fc1a8: MOV qword ptr [RBP + -0xb8], R13
0x8fc1af: MOV qword ptr [RBP + -0xb0], R15
0x8fc1b6: MOV qword ptr [RBP + -0xa8], RAX
0x8fc1bd: MOV EAX, dword ptr [RBP + 0x10]
0x8fc1c0: MOV dword ptr [RBP + -0xa0], 0x1
0x8fc1ca: MOV dword ptr [RBP + -0x84], 0x0
0x8fc1d4: MOV dword ptr [RBP + -0x88], EAX
0x8fc1da: MOV qword ptr [RBP + -0x80], RBX
0x8fc1de: CALL 0x006afb50
0x8fc1e3: TEST byte ptr [R12 + 0xef], 0x1
0x8fc1ec: JZ 0x008fc1fa
0x8fc1ee: MOV RDI, qword ptr [RBP + -0xd0]
0x8fc1f5: CALL 0x004449b0
0x8fc1fa: MOV qword ptr [RBP + -0x98], 0x0
0x8fc205: LEA RCX, [0x1adc648]
0x8fc20c: MOV RDX, qword ptr [RBP + -0xd0]
0x8fc213: LEA RSI, [RBP + -0xa8]
0x8fc21a: MOV RAX, qword ptr [R14 + 0x10]
0x8fc21e: MOV qword ptr [RBP + -0x78], RCX
0x8fc222: MOV qword ptr [RBP + -0x70], RDX
0x8fc226: MOV qword ptr [RBP + -0x68], RSI
0x8fc22a: LEA RSI, [RBP + -0x78]
0x8fc22e: MOV qword ptr [RBP + -0x60], RAX
0x8fc232: LEA RAX, [RBP + -0xbc]
0x8fc239: MOV qword ptr [RBP + -0x58], RAX
0x8fc23d: MOV qword ptr [RBP + -0x50], 0x0
0x8fc245: MOV qword ptr [RBP + -0x48], 0x0
0x8fc24d: MOV RDI, qword ptr [RDX + 0x8]
0x8fc251: CALL 0x0058e110
0x8fc256: MOV RCX, qword ptr [RBP + -0x98]
0x8fc25d: TEST EAX, EAX
0x8fc25f: JNZ 0x008fc36c
0x8fc265: CMP qword ptr [RBP + -0x90], R15
0x8fc26c: JNZ 0x008fc37b
0x8fc272: MOV RDX, qword ptr [RBP + -0xd0]
0x8fc279: TEST byte ptr [RDX + 0x1c8], 0x1
0x8fc280: JZ 0x008fc2d8
0x8fc282: MOV RAX, qword ptr [RDX + 0x18]
0x8fc286: TEST byte ptr [RAX + 0x98], 0x20
0x8fc28d: JZ 0x008fc2d8
0x8fc28f: MOV RDI, qword ptr [RAX + 0x48]
0x8fc293: MOV qword ptr [RBP + -0xc8], RDI
0x8fc29a: CALL 0x0054a060
0x8fc29f: MOV RAX, qword ptr [RBP + -0xc8]
0x8fc2a6: MOV RDI, qword ptr [RBP + -0xd0]
0x8fc2ad: MOV qword ptr [R14 + 0x18], RAX
0x8fc2b1: MOV qword ptr [R14], RAX
0x8fc2b4: CALL 0x0054a440
0x8fc2b9: MOV RCX, qword ptr [RBP + -0xc8]
0x8fc2c0: CMP dword ptr [RCX + 0x1d4], 0x2
0x8fc2c7: JZ 0x008fc186
0x8fc2cd: XOR ESI, ESI
0x8fc2cf: JMP 0x008fc33c
0x8fc2d1: MOV RDX, qword ptr [RBP + -0xc8]
0x8fc2d8: MOV R12, RCX
0x8fc2db: LEA RAX, [0x1adcdc8]
0x8fc2e2: LEA RSI, [RBP + -0x78]
0x8fc2e6: MOV qword ptr [RBP + -0x78], RAX
0x8fc2ea: MOV qword ptr [RBP + -0x70], RDX
0x8fc2ee: MOV dword ptr [RBP + -0x68], 0x0
0x8fc2f5: MOV RDI, qword ptr [RDX + 0x8]
0x8fc2f9: CALL 0x0058ea90
0x8fc2fe: MOV RAX, qword ptr [RBP + -0xe0]
0x8fc305: MOV RCX, qword ptr [RBP + -0xd8]
0x8fc30c: MOV qword ptr [RAX], RCX
0x8fc30f: MOV RCX, qword ptr [RBP + -0xe8]
0x8fc316: MOV RAX, qword ptr [RBP + -0x90]
0x8fc31d: TEST RCX, RCX
0x8fc320: JZ 0x008fc325
0x8fc322: MOV qword ptr [RCX], RAX
0x8fc325: SUB R15, RAX
0x8fc328: MOV dword ptr [RBP + -0xc0], 0x0
0x8fc332: MOV RSI, R12
0x8fc335: MOV qword ptr [RBX + 0x408], R15
0x8fc33c: MOV RDI, R14
0x8fc33f: XOR EDX, EDX
0x8fc341: CALL 0x006b0790
0x8fc346: MOV EAX, 0xffffffff
0x8fc34b: XADD.LOCK dword ptr [R14 + 0x28], EAX
0x8fc351: CMP EAX, 0x1
0x8fc354: JNZ 0x008fc361
0x8fc356: MOV RDI, R14
0x8fc359: MOV RSI, RBX
0x8fc35c: CALL 0x0072b380
0x8fc361: MOV EAX, dword ptr [RBP + -0xc0]
0x8fc367: JMP 0x008fbf1b
0x8fc36c: MOV R15, RCX
0x8fc36f: MOV RCX, qword ptr [RBP + -0xd0]
0x8fc376: JMP 0x008fc0d2
0x8fc37b: MOV RDX, qword ptr [RBP + -0xd0]
0x8fc382: JMP 0x008fc2d8
0x8fc387: CALL 0x006fd6b0
0x8fc38c: UD2

; local helper / adjacent context (reachability below); evidence ev_e05e7247722ef77cda9d81a78e8ac91aff4f6f0be32ed0636209514a297878b4; body [{"start": "0x8fc390", "end": "0x8fc3e1"}]
adjacent_8fc390: ; RVA 0x8fc390
0x8fc390: PUSH RBP
0x8fc391: MOV RBP, RSP
0x8fc394: PUSH RBX
0x8fc395: SUB RSP, 0x28
0x8fc399: LEA RBX, [0x391c310]
0x8fc3a0: MOV RAX, qword ptr [RBX]
0x8fc3a3: MOV qword ptr [RBP + -0x10], RAX
0x8fc3a7: MOV EAX, dword ptr [RSI]
0x8fc3a9: MOV dword ptr [RBP + -0x30], EAX
0x8fc3ac: MOV RAX, qword ptr [RSI + 0x8]
0x8fc3b0: MOV qword ptr [RBP + -0x28], RAX
0x8fc3b4: MOV EAX, dword ptr [RSI + 0x10]
0x8fc3b7: LEA RSI, [RBP + -0x30]
0x8fc3bb: MOV dword ptr [RBP + -0x20], EAX
0x8fc3be: MOV qword ptr [RBP + -0x18], 0x0
0x8fc3c6: CALL 0x008fbbe0
0x8fc3cb: MOV RCX, qword ptr [RBX]
0x8fc3ce: CMP RCX, qword ptr [RBP + -0x10]
0x8fc3d2: JNZ 0x008fc3db
0x8fc3d4: ADD RSP, 0x28
0x8fc3d8: POP RBX
0x8fc3d9: POP RBP
0x8fc3da: RET
0x8fc3db: CALL 0x006fd6b0
0x8fc3e0: UD2

; local helper / adjacent context (reachability below); evidence ev_c7a756773b939500ae541864787284a12b147fdc7067c23bd2e33a05499f791d; body [{"start": "0x8fc3f0", "end": "0x8fc488"}]
adjacent_8fc3f0: ; RVA 0x8fc3f0
0x8fc3f0: PUSH RBP
0x8fc3f1: MOV RBP, RSP
0x8fc3f4: PUSH R15
0x8fc3f6: PUSH R14
0x8fc3f8: PUSH R13
0x8fc3fa: PUSH R12
0x8fc3fc: PUSH RBX
0x8fc3fd: PUSH RAX
0x8fc3fe: MOV ECX, dword ptr [RSI]
0x8fc400: MOV RBX, RSI
0x8fc403: MOV R14, RDI
0x8fc406: TEST ECX, ECX
0x8fc408: JZ 0x008fc424
0x8fc40a: LEA RDI, [0x132be7b]
0x8fc411: LEA RSI, [0x1290301]
0x8fc418: MOV EDX, 0x1141
0x8fc41d: XOR EAX, EAX
0x8fc41f: CALL 0x0025d410
0x8fc424: MOV RDI, R14
0x8fc427: MOV ESI, 0x2ab
0x8fc42c: CALL 0x00adfa30
0x8fc431: TEST EAX, EAX
0x8fc433: JNZ 0x008fc47a
0x8fc435: MOV RCX, qword ptr [R14 + 0x8]
0x8fc439: XOR ESI, ESI
0x8fc43b: XOR EDX, EDX
0x8fc43d: MOV R12D, EAX
0x8fc440: MOV R13, qword ptr [RCX + 0x48]
0x8fc444: XOR ECX, ECX
0x8fc446: LEA R15, [R13 + 0x40]
0x8fc44a: MOV RDI, R15
0x8fc44d: CALL 0x00c4bb20
0x8fc452: MOVZX EAX, word ptr [R13 + 0x30]
0x8fc457: MOV RDI, R15
0x8fc45a: XOR ESI, ESI
0x8fc45c: XOR EDX, EDX
0x8fc45e: MOV qword ptr [R14 + 0x408], RAX
0x8fc465: MOVZX EAX, word ptr [RBX]
0x8fc468: AND EAX, 0xfff
0x8fc46d: MOV word ptr [R13 + 0x30], AX
0x8fc472: CALL 0x00c4c4b0
0x8fc477: MOV EAX, R12D
0x8fc47a: ADD RSP, 0x8
0x8fc47e: POP RBX
0x8fc47f: POP R12
0x8fc481: POP R13
0x8fc483: POP R14
0x8fc485: POP R15
0x8fc487: POP RBP
0x8fc488: RET

; local helper / adjacent context (reachability below); evidence ev_becb06f99af483e1ade0d4a96f4bd43d578952e5a990e96d294c59b0abef4ea3; body [{"start": "0x8fc490", "end": "0x8fc606"}]
adjacent_8fc490: ; RVA 0x8fc490
0x8fc490: PUSH RBP
0x8fc491: MOV RBP, RSP
0x8fc494: PUSH R15
0x8fc496: PUSH R14
0x8fc498: PUSH RBX
0x8fc499: SUB RSP, 0x1b8
0x8fc4a0: LEA R15, [0x391c310]
0x8fc4a7: MOV RBX, RSI
0x8fc4aa: MOV ESI, 0x2ab
0x8fc4af: MOV R14, RDI
0x8fc4b2: MOV RAX, qword ptr [R15]
0x8fc4b5: MOV qword ptr [RBP + -0x20], RAX
0x8fc4b9: CALL 0x00adfa30
0x8fc4be: TEST EAX, EAX
0x8fc4c0: JNZ 0x008fc57f
0x8fc4c6: MOV R8, qword ptr [RBX]
0x8fc4c9: SUB RSP, 0x8
0x8fc4cd: LEA RBX, [RBP + -0x108]
0x8fc4d4: MOV EDX, 0x4000044
0x8fc4d9: XOR ESI, ESI
0x8fc4db: XOR ECX, ECX
0x8fc4dd: MOV R9D, 0xffffff9c
0x8fc4e3: MOV RDI, RBX
0x8fc4e6: PUSH R14
0x8fc4e8: PUSH 0x0
0x8fc4ea: PUSH 0x0
0x8fc4ec: CALL 0x005fa6e0
0x8fc4f1: ADD RSP, 0x20
0x8fc4f5: MOV RDI, RBX
0x8fc4f8: CALL 0x005f8c20
0x8fc4fd: TEST EAX, EAX
0x8fc4ff: JNZ 0x008fc57f
0x8fc501: MOV RBX, qword ptr [RBP + -0xa8]
0x8fc508: LEA RDI, [RBP + -0x108]
0x8fc50f: MOV ESI, 0xffffffdf
0x8fc514: CALL 0x005fa780
0x8fc519: CMP dword ptr [RBX + 0x1d4], 0x4
0x8fc520: MOV EAX, 0x16
0x8fc525: JNZ 0x008fc573
0x8fc527: CMP qword ptr [RBX + 0x30], 0x0
0x8fc52c: JZ 0x008fc573
0x8fc52e: MOV RAX, qword ptr [R14 + 0x140]
0x8fc535: LEA RCX, [0x1adad78]
0x8fc53c: LEA RDX, [RBP + -0x1d0]
0x8fc543: LEA RSI, [RBP + -0x128]
0x8fc54a: MOV qword ptr [RBP + -0x128], RCX
0x8fc551: MOV qword ptr [RBP + -0x120], RBX
0x8fc558: MOV qword ptr [RBP + -0x118], RDX
0x8fc55f: MOV qword ptr [RBP + -0x110], RAX
0x8fc566: MOV RDI, qword ptr [RBX + 0x8]
0x8fc56a: CALL 0x0058c1c0
0x8fc56f: TEST EAX, EAX
0x8fc571: JZ 0x008fc596
0x8fc573: MOV RDI, RBX
0x8fc576: MOV EBX, EAX
0x8fc578: CALL 0x0054a440
0x8fc57d: MOV EAX, EBX
0x8fc57f: MOV RCX, qword ptr [R15]
0x8fc582: CMP RCX, qword ptr [RBP + -0x20]
0x8fc586: JNZ 0x008fc600
0x8fc588: ADD RSP, 0x1b8
0x8fc58f: POP RBX
0x8fc590: POP R14
0x8fc592: POP R15
0x8fc594: POP RBP
0x8fc595: RET
0x8fc596: MOV RAX, qword ptr [R14 + 0x140]
0x8fc59d: MOV EAX, dword ptr [RAX + 0x4]
0x8fc5a0: CMP EAX, dword ptr [RBP + -0x1c8]
0x8fc5a6: JZ 0x008fc5b9
0x8fc5a8: MOV RDI, R14
0x8fc5ab: MOV ESI, 0x138
0x8fc5b0: CALL 0x00adfa30
0x8fc5b5: TEST EAX, EAX
0x8fc5b7: JNZ 0x008fc573
0x8fc5b9: MOV RDI, RBX
0x8fc5bc: CALL 0x0054b650
0x8fc5c1: MOV ECX, EAX
0x8fc5c3: XOR EAX, EAX
0x8fc5c5: CMP ECX, 0x2
0x8fc5c8: JL 0x008fc573
0x8fc5ca: LEA RAX, [0x1adb978]
0x8fc5d1: LEA RSI, [RBP + -0x128]
0x8fc5d8: MOV qword ptr [RBP + -0x128], RAX
0x8fc5df: MOV qword ptr [RBP + -0x120], RBX
0x8fc5e6: MOV dword ptr [RBP + -0x118], 0x1
0x8fc5f0: MOV RDI, qword ptr [RBX + 0x8]
0x8fc5f4: CALL 0x0058d1c0
0x8fc5f9: XOR EAX, EAX
0x8fc5fb: JMP 0x008fc573
0x8fc600: CALL 0x006fd6b0
0x8fc605: UD2

; local helper / adjacent context (reachability below); evidence ev_61c8dfd3add10b611c8dd4e34715bbf964f6966f3320c1133e4bade66fcb6487; body [{"start": "0x8fc610", "end": "0x8fc666"}]
adjacent_8fc610: ; RVA 0x8fc610
0x8fc610: PUSH RBP
0x8fc611: MOV RBP, RSP
0x8fc614: PUSH R15
0x8fc616: PUSH R14
0x8fc618: PUSH RBX
0x8fc619: PUSH RAX
0x8fc61a: MOV RAX, qword ptr [RDI + 0x8]
0x8fc61e: MOV RBX, RDI
0x8fc621: XOR ESI, ESI
0x8fc623: XOR EDX, EDX
0x8fc625: XOR ECX, ECX
0x8fc627: MOV R15, qword ptr [RAX + 0x48]
0x8fc62b: LEA R14, [R15 + 0x40]
0x8fc62f: MOV RDI, R14
0x8fc632: CALL 0x00c4bb20
0x8fc637: MOV RAX, qword ptr [R15 + 0x10]
0x8fc63b: XOR ECX, ECX
0x8fc63d: CMP RAX, qword ptr [0x03e0b510]
0x8fc644: MOV RDI, R14
0x8fc647: SETNZ CL
0x8fc64a: XOR ESI, ESI
0x8fc64c: XOR EDX, EDX
0x8fc64e: MOV qword ptr [RBX + 0x408], RCX
0x8fc655: CALL 0x00c4c4b0
0x8fc65a: XOR EAX, EAX
0x8fc65c: ADD RSP, 0x8
0x8fc660: POP RBX
0x8fc661: POP R14
0x8fc663: POP R15
0x8fc665: POP RBP
0x8fc666: RET

; local helper / adjacent context (reachability below); evidence ev_16b4bd7f992970bb006340eb8a9fdcc01f904494d5144a73970351dfd37b6daf; body [{"start": "0x8fc675", "end": "0x8fc6df"}, {"start": "0x8fc6e6", "end": "0x8fc707"}]
adjacent_8fc675: ; RVA 0x8fc675
0x8fc675: PUSH RBP
0x8fc676: MOV RBP, RSP
0x8fc679: PUSH R15
0x8fc67b: PUSH R14
0x8fc67d: PUSH R13
0x8fc67f: PUSH R12
0x8fc681: PUSH RBX
0x8fc682: PUSH RAX
0x8fc683: MOV R13, RDI
0x8fc686: MOV EDI, 0x1
0x8fc68b: MOV R14D, ESI
0x8fc68e: MOV R12, RDX
0x8fc691: MOV R15, RCX
0x8fc694: MOV RBX, R8
0x8fc697: CALL 0x00ab7ea0
0x8fc69c: TEST EAX, EAX
0x8fc69e: JNZ 0x008fc6f9
0x8fc6a0: MOV RDI, R13
0x8fc6a3: CALL 0x00ac6e80
0x8fc6a8: TEST RAX, RAX
0x8fc6ab: JZ 0x008fc6e6
0x8fc6ad: MOVZX R14D, R14B
0x8fc6b1: MOV RDI, RAX
0x8fc6b4: MOV RDX, R12
0x8fc6b7: MOV RCX, R15
0x8fc6ba: MOV R8, RBX
0x8fc6bd: MOV R13, RAX
0x8fc6c0: MOV ESI, R14D
0x8fc6c3: CALL 0x00a87bf0
0x8fc6c8: TEST EAX, EAX
0x8fc6ca: JNZ 0x008fc6eb
0x8fc6cc: MOV RDI, R13
0x8fc6cf: MOV ESI, R14D
0x8fc6d2: MOV EDX, 0x1
0x8fc6d7: CALL 0x00bebb80
0x8fc6dc: XOR EAX, EAX
0x8fc6de: JMP 0x008fc6eb
0x8fc6e6: MOV EAX, 0x1001
0x8fc6eb: MOV EDI, 0x1
0x8fc6f0: MOV EBX, EAX
0x8fc6f2: CALL 0x00ab7f20
0x8fc6f7: MOV EAX, EBX
0x8fc6f9: ADD RSP, 0x8
0x8fc6fd: POP RBX
0x8fc6fe: POP R12
0x8fc700: POP R13
0x8fc702: POP R14
0x8fc704: POP R15
0x8fc706: POP RBP
0x8fc707: RET

; local helper / adjacent context (reachability below); evidence ev_3ab17f5cb5d674acad5283d236f41034004b1443423d6516bea2dbc281853d7e; body [{"start": "0x8fc715", "end": "0x8fc789"}, {"start": "0x8fc790", "end": "0x8fc805"}]
adjacent_8fc715: ; RVA 0x8fc715
0x8fc715: PUSH RBP
0x8fc716: MOV RBP, RSP
0x8fc719: PUSH R15
0x8fc71b: PUSH R14
0x8fc71d: PUSH RBX
0x8fc71e: PUSH RAX
0x8fc71f: MOV RBX, RDI
0x8fc722: MOV EDI, 0x1
0x8fc727: MOV R15D, ESI
0x8fc72a: MOV R14, RDX
0x8fc72d: CALL 0x00ab7ea0
0x8fc732: TEST EAX, EAX
0x8fc734: JNZ 0x008fc7e8
0x8fc73a: MOV RDI, RBX
0x8fc73d: CALL 0x00ac6e80
0x8fc742: MOV ECX, 0x1001
0x8fc747: TEST RAX, RAX
0x8fc74a: JZ 0x008fc7da
0x8fc750: MOVZX EDX, byte ptr [RAX + 0x9]
0x8fc754: CMP EDX, 0xd
0x8fc757: JA 0x008fc790
0x8fc759: MOV ESI, 0x3040
0x8fc75e: BT ESI, EDX
0x8fc761: JNC 0x008fc790
0x8fc763: MOV RDI, RAX
0x8fc766: CALL 0x005d91c0
0x8fc76b: TEST RAX, RAX
0x8fc76e: JZ 0x008fc7d5
0x8fc770: MOV RBX, qword ptr [RAX + 0x20]
0x8fc774: TEST RBX, RBX
0x8fc777: JZ 0x008fc7d5
0x8fc779: CMP byte ptr [RBX + 0xd], R15B
0x8fc77d: JNZ 0x008fc79b
0x8fc77f: ADD RAX, 0x20
0x8fc783: MOV ECX, 0x1001
0x8fc788: JMP 0x008fc7b6
0x8fc790: CMP RAX, qword ptr [0x039c9698]
0x8fc797: JNZ 0x008fc7da
0x8fc799: JMP 0x008fc763
0x8fc79b: MOV ECX, 0x1001
0x8fc7a0: MOV RAX, RBX
0x8fc7a3: MOV RBX, qword ptr [RBX + 0x38]
0x8fc7a7: TEST RBX, RBX
0x8fc7aa: JZ 0x008fc7d5
0x8fc7ac: CMP byte ptr [RBX + 0xd], R15B
0x8fc7b0: JNZ 0x008fc7a0
0x8fc7b2: ADD RAX, 0x38
0x8fc7b6: CMP qword ptr [RBX + 0x10], R14
0x8fc7ba: JNZ 0x008fc7da
0x8fc7bc: MOV R14, RAX
0x8fc7bf: NOP
0x8fc7c0: MOV RDI, qword ptr [RBX + 0x30]
0x8fc7c4: TEST RDI, RDI
0x8fc7c7: JZ 0x008fc7f3
0x8fc7c9: MOV ESI, 0x1
0x8fc7ce: CALL 0x00bebfb0
0x8fc7d3: JMP 0x008fc7c0
0x8fc7d5: MOV ECX, 0x6
0x8fc7da: MOV EDI, 0x1
0x8fc7df: MOV EBX, ECX
0x8fc7e1: CALL 0x00ab7f20
0x8fc7e6: MOV EAX, EBX
0x8fc7e8: ADD RSP, 0x8
0x8fc7ec: POP RBX
0x8fc7ed: POP R14
0x8fc7ef: POP R15
0x8fc7f1: POP RBP
0x8fc7f2: RET
0x8fc7f3: MOV RAX, qword ptr [RBX + 0x38]
0x8fc7f7: MOV RDI, RBX
0x8fc7fa: MOV qword ptr [R14], RAX
0x8fc7fd: CALL 0x00b4a4c0
0x8fc802: XOR ECX, ECX
0x8fc804: JMP 0x008fc7da

; local helper / adjacent context (reachability below); evidence ev_e1526c635752cc68f818c88e81bb1c86ff444a651a88e423b2774331bcc49a49; body [{"start": "0x8fc810", "end": "0x8fc819"}]
adjacent_8fc810: ; RVA 0x8fc810
0x8fc810: PUSH RBP
0x8fc811: MOV RBP, RSP
0x8fc814: POP RBP
0x8fc815: JMP 0x00265760

; local helper / adjacent context (reachability below); evidence ev_d338a86d4fc75ef2e0451cd40b1261cf949cc9319e4ce5d1894763bfdded3653; body [{"start": "0x8fc820", "end": "0x8fc829"}]
adjacent_8fc820: ; RVA 0x8fc820
0x8fc820: PUSH RBP
0x8fc821: MOV RBP, RSP
0x8fc824: POP RBP
0x8fc825: JMP 0x00265760

; local helper / adjacent context (reachability below); evidence ev_b4278bdb410341a7870eb038e14fd28310bb2474d6ba784c6b4a316bdd627920; body [{"start": "0x8fc845", "end": "0x8fc86e"}]
adjacent_8fc845: ; RVA 0x8fc845
0x8fc845: PUSH RBP
0x8fc846: MOV RBP, RSP
0x8fc849: CALL 0x007f1950
0x8fc84e: LEA RDI, [0x8fc845]
0x8fc855: CALL 0x007f1810
0x8fc85a: LEA RSI, [0x12ed5d0]
0x8fc861: MOV EDI, 0x3
0x8fc866: XOR EAX, EAX
0x8fc868: CALL 0x00c9aa10
0x8fc86d: UD2

; local helper / adjacent context (reachability below); evidence ev_86b87f507ee63b18fb01e3d54e2d17ddbd2bcdbfc9cd22abd980070dbb43ada6; body [{"start": "0x8fc877", "end": "0x8fc8a0"}]
adjacent_8fc877: ; RVA 0x8fc877
0x8fc877: PUSH RBP
0x8fc878: MOV RBP, RSP
0x8fc87b: CALL 0x007f1950
0x8fc880: LEA RDI, [0x8fc877]
0x8fc887: CALL 0x007f1810
0x8fc88c: LEA RSI, [0x12ed5d0]
0x8fc893: MOV EDI, 0x7
0x8fc898: XOR EAX, EAX
0x8fc89a: CALL 0x00c9aa10
0x8fc89f: UD2

; local helper / adjacent context (reachability below); evidence ev_14e78fb3568bf2ed6736c226788a7b3248f2b56ec12c5468d3f0b6ffa9e71caa; body [{"start": "0x8fc8b0", "end": "0x8fcdc0"}]
adjacent_8fc8b0: ; RVA 0x8fc8b0
0x8fc8b0: PUSH RBP
0x8fc8b1: MOV RBP, RSP
0x8fc8b4: PUSH R15
0x8fc8b6: PUSH R14
0x8fc8b8: PUSH R13
0x8fc8ba: PUSH R12
0x8fc8bc: PUSH RBX
0x8fc8bd: SUB RSP, 0x18
0x8fc8c1: LEA R13, [0x391c310]
0x8fc8c8: MOV RAX, qword ptr [R13]
0x8fc8cc: MOV qword ptr [RBP + -0x30], RAX
0x8fc8d0: MOV RBX, qword ptr [RDI + 0x8]
0x8fc8d4: MOV R14, qword ptr [RBX + 0x10]
0x8fc8d8: MOV qword ptr [RBP + -0x38], 0x0
0x8fc8e0: CMP word ptr [R14 + 0x8c], 0x0
0x8fc8e9: JZ 0x008fc936
0x8fc8eb: CMP dword ptr [R14 + 0x34], 0x0
0x8fc8f0: JZ 0x008fc93e
0x8fc8f2: CMP word ptr [R14 + 0x8e], 0x0
0x8fc8fb: JG 0x008fc9d3
0x8fc901: MOV RAX, qword ptr [R14 + 0x18]
0x8fc905: MOV R15, qword ptr [RAX + 0x200]
0x8fc90c: LEA RAX, [0x260ce8]
0x8fc913: SUB RAX, R15
0x8fc916: ROR RAX, 0x3
0x8fc91a: CMP RAX, 0x6ff
0x8fc920: JA 0x008fcd71
0x8fc926: MOV RDI, R14
0x8fc929: CALL R15
0x8fc92c: TEST EAX, EAX
0x8fc92e: JNZ 0x008fc9d3
0x8fc934: JMP 0x008fc94e
0x8fc936: XOR R15D, R15D
0x8fc939: JMP 0x008fcbb4
0x8fc93e: MOV RAX, qword ptr [RBX + 0x18]
0x8fc942: TEST dword ptr [RAX + 0x99], 0x1002000
0x8fc94c: JZ 0x008fc8f2
0x8fc94e: LEA RSI, [RBP + -0x38]
0x8fc952: MOV RDI, RBX
0x8fc955: MOV EDX, 0x2
0x8fc95a: CALL 0x006b0e70
0x8fc95f: TEST EAX, EAX
0x8fc961: JZ 0x008fc9d3
0x8fc963: LEA R15, [RBP + -0x38]
0x8fc967: NOP word ptr [RAX + RAX*0x1]
0x8fc970: TEST byte ptr [RBX + 0x1c4], 0x80
0x8fc977: JNZ 0x008fc9c2
0x8fc979: MOV RDI, qword ptr [RBP + -0x38]
0x8fc97d: XOR ESI, ESI
0x8fc97f: XOR EDX, EDX
0x8fc981: XOR ECX, ECX
0x8fc983: ADD RDI, 0x18
0x8fc987: CALL 0x004c6a00
0x8fc98c: MOV RDI, qword ptr [RBP + -0x38]
0x8fc990: TEST byte ptr [RDI + 0x93], 0x14
0x8fc997: JNZ 0x008fcbea
0x8fc99d: ADD RDI, 0x18
0x8fc9a1: XOR ESI, ESI
0x8fc9a3: XOR EDX, EDX
0x8fc9a5: XOR ECX, ECX
0x8fc9a7: CALL 0x004c6fa0
0x8fc9ac: MOV RDI, RBX
0x8fc9af: MOV RSI, R15
0x8fc9b2: MOV EDX, 0x2
0x8fc9b7: CALL 0x006b0e70
0x8fc9bc: TEST EAX, EAX
0x8fc9be: JNZ 0x008fc970
0x8fc9c0: JMP 0x008fc9d3
0x8fc9c2: LEA RSI, [RBP + -0x38]
0x8fc9c6: MOV RDI, RBX
0x8fc9c9: MOV EDX, 0x1
0x8fc9ce: CALL 0x006b0e70
0x8fc9d3: MOV RAX, qword ptr [R14 + 0x18]
0x8fc9d7: MOV RCX, qword ptr [R14 + 0x90]
0x8fc9de: CMP qword ptr [RAX + 0x28], 0x2
0x8fc9e3: JNZ 0x008fc9f2
0x8fc9e5: MOV RDX, qword ptr [R14 + 0xb0]
0x8fc9ec: MOV EDX, dword ptr [RDX + 0x5c]
0x8fc9ef: ADD RCX, RDX
0x8fc9f2: XOR R15D, R15D
0x8fc9f5: CMP dword ptr [R14 + 0x34], 0x0
0x8fc9fa: JG 0x008fca2c
0x8fc9fc: TEST RCX, RCX
0x8fc9ff: JZ 0x008fca2c
0x8fca01: MOV R12, qword ptr [RAX + 0x200]
0x8fca08: LEA RAX, [0x260ce8]
0x8fca0f: SUB RAX, R12
0x8fca12: ROR RAX, 0x3
0x8fca16: CMP RAX, 0x6ff
0x8fca1c: JA 0x008fcd49
0x8fca22: MOV RDI, R14
0x8fca25: CALL R12
0x8fca28: TEST EAX, EAX
0x8fca2a: JZ 0x008fca8c
0x8fca2c: CMP word ptr [R14 + 0x8e], 0x0
0x8fca35: JLE 0x008fcad7
0x8fca3b: MOV EAX, dword ptr [R14 + 0x20]
0x8fca3f: TEST AL, 0xf
0x8fca41: JZ 0x008fcba9
0x8fca47: TEST AL, 0xe
0x8fca49: MOV RAX, qword ptr [RBP + -0x38]
0x8fca4d: SETZ CL
0x8fca50: TEST RAX, RAX
0x8fca53: SETZ DL
0x8fca56: AND DL, CL
0x8fca58: CMP DL, 0x1
0x8fca5b: JNZ 0x008fcb61
0x8fca61: LEA RSI, [RBP + -0x38]
0x8fca65: MOV RDI, RBX
0x8fca68: MOV EDX, 0x2
0x8fca6d: CALL 0x006b0e70
0x8fca72: TEST EAX, EAX
0x8fca74: JZ 0x008fcb5d
0x8fca7a: MOV qword ptr [RBP + -0x38], 0x0
0x8fca82: AND byte ptr [R14 + 0x20], 0xfe
0x8fca87: JMP 0x008fcba9
0x8fca8c: MOV RAX, qword ptr [RBX + 0x18]
0x8fca90: MOV RAX, qword ptr [RAX + 0x298]
0x8fca97: MOV R15, qword ptr [RAX + 0x1d8]
0x8fca9e: LEA RAX, [0x26f7f8]
0x8fcaa5: SUB RAX, R15
0x8fcaa8: ROR RAX, 0x3
0x8fcaac: CMP RAX, 0x3
0x8fcab0: JA 0x008fcd99
0x8fcab6: MOV RDI, RBX
0x8fcab9: MOV EDX, 0xc00
0x8fcabe: XOR ESI, ESI
0x8fcac0: XOR ECX, ECX
0x8fcac2: CALL R15
0x8fcac5: MOV R15D, EAX
0x8fcac8: CMP word ptr [R14 + 0x8e], 0x0
0x8fcad1: JG 0x008fca3b
0x8fcad7: CMP word ptr [R14 + 0x8c], 0x0
0x8fcae0: JZ 0x008fca3b
0x8fcae6: MOV RAX, qword ptr [R14 + 0x18]
0x8fcaea: MOV R12, qword ptr [RAX + 0x200]
0x8fcaf1: LEA RAX, [0x260ce8]
0x8fcaf8: SUB RAX, R12
0x8fcafb: ROR RAX, 0x3
0x8fcaff: CMP RAX, 0x6ff
0x8fcb05: JA 0x008fcd85
0x8fcb0b: MOV RDI, R14
0x8fcb0e: CALL R12
0x8fcb11: TEST EAX, EAX
0x8fcb13: JNZ 0x008fca3b
0x8fcb19: MOV RAX, qword ptr [R14 + 0x18]
0x8fcb1d: MOV RAX, qword ptr [RAX + 0x28]
0x8fcb21: CMP RAX, 0x2
0x8fcb25: JNZ 0x008fcb40
0x8fcb27: MOV RAX, qword ptr [R14 + 0xb0]
0x8fcb2e: MOV dword ptr [RAX + 0xf4], 0x0
0x8fcb38: MOV RAX, qword ptr [R14 + 0x18]
0x8fcb3c: MOV RAX, qword ptr [RAX + 0x28]
0x8fcb40: MOV RCX, qword ptr [R14 + 0xb0]
0x8fcb47: CMP RAX, 0x1
0x8fcb4b: JNZ 0x008fcc2c
0x8fcb51: MOV dword ptr [RCX + 0x28], 0x0
0x8fcb58: JMP 0x008fcc34
0x8fcb5d: MOV RAX, qword ptr [RBP + -0x38]
0x8fcb61: TEST RAX, RAX
0x8fcb64: JNZ 0x008fcb77
0x8fcb66: LEA RSI, [RBP + -0x38]
0x8fcb6a: MOV RDI, RBX
0x8fcb6d: MOV EDX, 0x1
0x8fcb72: CALL 0x006b0e70
0x8fcb77: MOV RAX, qword ptr [RBX + 0x18]
0x8fcb7b: MOV RAX, qword ptr [RAX + 0x298]
0x8fcb82: MOV R12, qword ptr [RAX + 0x1e0]
0x8fcb89: LEA RAX, [0x2690e0]
0x8fcb90: SUB RAX, R12
0x8fcb93: ROR RAX, 0x3
0x8fcb97: CMP RAX, 0x72
0x8fcb9b: JA 0x008fcd5d
0x8fcba1: MOV RDI, RBX
0x8fcba4: XOR ESI, ESI
0x8fcba6: CALL R12
0x8fcba9: CMP word ptr [R14 + 0x8c], 0x0
0x8fcbb2: JNZ 0x008fcbbc
0x8fcbb4: MOV RDI, RBX
0x8fcbb7: CALL 0x0054b200
0x8fcbbc: MOV RDI, qword ptr [RBP + -0x38]
0x8fcbc0: TEST RDI, RDI
0x8fcbc3: JZ 0x008fcbca
0x8fcbc5: CALL 0x006b1020
0x8fcbca: MOV RAX, qword ptr [R13]
0x8fcbce: CMP RAX, qword ptr [RBP + -0x30]
0x8fcbd2: JNZ 0x008fcd42
0x8fcbd8: MOV EAX, R15D
0x8fcbdb: ADD RSP, 0x18
0x8fcbdf: POP RBX
0x8fcbe0: POP R12
0x8fcbe2: POP R13
0x8fcbe4: POP R14
0x8fcbe6: POP R15
0x8fcbe8: POP RBP
0x8fcbe9: RET
0x8fcbea: LEA R14, [RBX + 0xb0]
0x8fcbf1: XOR R15D, R15D
0x8fcbf4: XOR ESI, ESI
0x8fcbf6: XOR EDX, EDX
0x8fcbf8: XOR ECX, ECX
0x8fcbfa: MOV RDI, R14
0x8fcbfd: CALL 0x004c6a00
0x8fcc02: OR byte ptr [RBX + 0x1c5], 0x10
0x8fcc09: MOV RDI, R14
0x8fcc0c: XOR ESI, ESI
0x8fcc0e: XOR EDX, EDX
0x8fcc10: XOR ECX, ECX
0x8fcc12: CALL 0x004c6fa0
0x8fcc17: MOV RDI, qword ptr [RBP + -0x38]
0x8fcc1b: XOR ESI, ESI
0x8fcc1d: XOR EDX, EDX
0x8fcc1f: XOR ECX, ECX
0x8fcc21: ADD RDI, 0x18
0x8fcc25: CALL 0x004c6fa0
0x8fcc2a: JMP 0x008fcbca
0x8fcc2c: MOV qword ptr [RCX + 0x70], 0x0
0x8fcc34: MOVZX R12D, word ptr [R14 + 0x8c]
0x8fcc3c: MOV word ptr [R14 + 0x8c], 0x0
0x8fcc46: MOV RAX, qword ptr [R14 + 0xb0]
0x8fcc4d: MOV word ptr [RAX], 0x0
0x8fcc52: OR byte ptr [R14 + 0x20], 0x6
0x8fcc57: MOV RAX, qword ptr [RBX + 0x18]
0x8fcc5b: TEST dword ptr [RAX + 0x99], 0x1002000
0x8fcc65: JZ 0x008fcc85
0x8fcc67: MOV RDI, R14
0x8fcc6a: CALL 0x0041a9d0
0x8fcc6f: TEST R15D, R15D
0x8fcc72: MOV ECX, R15D
0x8fcc75: CMOVZ ECX, EAX
0x8fcc78: TEST EAX, EAX
0x8fcc7a: MOV RAX, qword ptr [RBX + 0x18]
0x8fcc7e: CMOVZ ECX, R15D
0x8fcc82: MOV R15D, ECX
0x8fcc85: MOV RAX, qword ptr [RAX + 0x298]
0x8fcc8c: MOV R13, qword ptr [RAX + 0x1f0]
0x8fcc93: LEA RAX, [0x26f740]
0x8fcc9a: CMP R13, RAX
0x8fcc9d: JNZ 0x008fcdad
0x8fcca3: MOV ESI, dword ptr [R14 + 0x30]
0x8fcca7: MOV RDI, RBX
0x8fccaa: MOV EDX, R12D
0x8fccad: CALL R13
0x8fccb0: CMP dword ptr [R14 + 0x30], 0x8100
0x8fccb8: JNZ 0x008fcd27
0x8fccba: CMP qword ptr [R14 + 0xa0], 0x202
0x8fccc5: JNZ 0x008fcd27
0x8fccc7: MOV EDI, 0x238
0x8fcccc: ADD RDI, qword ptr [RBX + 0x18]
0x8fccd0: LEA RSI, [0x136ae45]
0x8fccd7: MOV EDX, 0xb
0x8fccdc: MOV R12D, EAX
0x8fccdf: CALL 0x008d1a30
0x8fcce4: MOV ECX, EAX
0x8fcce6: MOV EAX, R12D
0x8fcce9: TEST ECX, ECX
0x8fcceb: JNZ 0x008fcd27
0x8fcced: MOV RDX, qword ptr GS:[0x0]
0x8fccf6: MOV R8D, dword ptr [R14 + 0x30]
0x8fccfa: MOV R9, qword ptr [R14 + 0xa0]
0x8fcd01: ADD RDX, 0x294
0x8fcd08: LEA RDI, [0x1375444]
0x8fcd0f: LEA RSI, [0x129aa77]
0x8fcd16: LEA RCX, [0x1360c6c]
0x8fcd1d: XOR EAX, EAX
0x8fcd1f: CALL 0x0025d410
0x8fcd24: MOV EAX, R12D
0x8fcd27: LEA R13, [0x391c310]
0x8fcd2e: TEST R15D, R15D
0x8fcd31: MOV ECX, R15D
0x8fcd34: CMOVZ ECX, EAX
0x8fcd37: TEST EAX, EAX
0x8fcd39: CMOVNZ R15D, ECX
0x8fcd3d: JMP 0x008fca3b
0x8fcd42: CALL 0x006fd6b0
0x8fcd47: UD2
0x8fcd49: LEA RDI, [0x254ece0]
0x8fcd50: MOV RSI, R12
0x8fcd53: CALL 0x0044f8c0
0x8fcd58: JMP 0x008fca22
0x8fcd5d: LEA RDI, [0x254ed60]
0x8fcd64: MOV RSI, R12
0x8fcd67: CALL 0x0044f8c0
0x8fcd6c: JMP 0x008fcba1
0x8fcd71: LEA RDI, [0x254ecc0]
0x8fcd78: MOV RSI, R15
0x8fcd7b: CALL 0x0044f8c0
0x8fcd80: JMP 0x008fc926
0x8fcd85: LEA RDI, [0x254ed20]
0x8fcd8c: MOV RSI, R12
0x8fcd8f: CALL 0x0044f8c0
0x8fcd94: JMP 0x008fcb0b
0x8fcd99: LEA RDI, [0x254ed00]
0x8fcda0: MOV RSI, R15
0x8fcda3: CALL 0x0044f8c0
0x8fcda8: JMP 0x008fcab6
0x8fcdad: LEA RDI, [0x254ed40]
0x8fcdb4: MOV RSI, R13
0x8fcdb7: CALL 0x0044f8c0
0x8fcdbc: JMP 0x008fcca3

; local helper / adjacent context (reachability below); evidence ev_c237298077e4e53150ec9fd986fac15299cee59d17c5e10e33186be3cb886b19; body [{"start": "0x8fcdd0", "end": "0x8fcdd9"}]
adjacent_8fcdd0: ; RVA 0x8fcdd0
0x8fcdd0: PUSH RBP
0x8fcdd1: MOV RBP, RSP
0x8fcdd4: POP RBP
0x8fcdd5: JMP 0x006a8530

; local helper / adjacent context (reachability below); evidence ev_0e81dcef514c0f701b91d87ad6958985f915132d2df6185f5032f46b5dc0fb6a; body [{"start": "0x8fcde0", "end": "0x8fcf07"}]
adjacent_8fcde0: ; RVA 0x8fcde0
0x8fcde0: PUSH RBP
0x8fcde1: MOV RBP, RSP
0x8fcde4: PUSH R15
0x8fcde6: PUSH R14
0x8fcde8: PUSH R12
0x8fcdea: PUSH RBX
0x8fcdeb: MOV R15, qword ptr [RDI + 0x8]
0x8fcdef: MOV RBX, qword ptr [R15 + 0x10]
0x8fcdf3: MOV R12D, dword ptr [R15 + 0x1c8]
0x8fcdfa: MOV RDI, R15
0x8fcdfd: MOV R14, qword ptr [RBX + 0x18]
0x8fce01: CALL 0x006a8530
0x8fce06: TEST R12D, 0x10000
0x8fce0d: JNZ 0x008fcead
0x8fce13: MOV EAX, dword ptr [RBX + 0x20]
0x8fce16: TEST AL, 0x40
0x8fce18: JZ 0x008fce20
0x8fce1a: OR EAX, 0x8
0x8fce1d: MOV dword ptr [RBX + 0x20], EAX
0x8fce20: MOV RAX, qword ptr [R15 + 0x18]
0x8fce24: MOV RAX, qword ptr [RAX + 0x298]
0x8fce2b: MOV R12, qword ptr [RAX + 0x1e0]
0x8fce32: LEA RAX, [0x2690e0]
0x8fce39: SUB RAX, R12
0x8fce3c: ROR RAX, 0x3
0x8fce40: CMP RAX, 0x72
0x8fce44: JA 0x008fcee3
0x8fce4a: MOV RDI, R15
0x8fce4d: XOR ESI, ESI
0x8fce4f: CALL R12
0x8fce52: MOV RDI, R15
0x8fce55: CALL 0x00adfbb0
0x8fce5a: LEA R12, [R15 + 0xb0]
0x8fce61: XOR ESI, ESI
0x8fce63: XOR EDX, EDX
0x8fce65: XOR ECX, ECX
0x8fce67: MOV RDI, R12
0x8fce6a: CALL 0x004c6a00
0x8fce6f: MOV RDI, R12
0x8fce72: MOV qword ptr [R15 + 0x10], 0x0
0x8fce7a: XOR ESI, ESI
0x8fce7c: XOR EDX, EDX
0x8fce7e: XOR ECX, ECX
0x8fce80: CALL 0x004c6fa0
0x8fce85: MOV R15, qword ptr [R14 + 0x1f8]
0x8fce8c: LEA RAX, [0x267e88]
0x8fce93: SUB RAX, R15
0x8fce96: ROR RAX, 0x3
0x8fce9a: CMP RAX, 0x197
0x8fcea0: JA 0x008fcef7
0x8fcea2: MOV RDI, R14
0x8fcea5: MOV RSI, RBX
0x8fcea8: CALL R15
0x8fceab: JMP 0x008fced8
0x8fcead: LEA RBX, [R15 + 0xb0]
0x8fceb4: XOR ESI, ESI
0x8fceb6: XOR EDX, EDX
0x8fceb8: XOR ECX, ECX
0x8fceba: MOV RDI, RBX
0x8fcebd: CALL 0x004c6a00
0x8fcec2: MOV RDI, RBX
0x8fcec5: MOV qword ptr [R15 + 0x10], 0x0
0x8fcecd: XOR ESI, ESI
0x8fcecf: XOR EDX, EDX
0x8fced1: XOR ECX, ECX
0x8fced3: CALL 0x004c6fa0
0x8fced8: XOR EAX, EAX
0x8fceda: POP RBX
0x8fcedb: POP R12
0x8fcedd: POP R14
0x8fcedf: POP R15
0x8fcee1: POP RBP
0x8fcee2: RET
0x8fcee3: LEA RDI, [0x254ed80]
0x8fceea: MOV RSI, R12
0x8fceed: CALL 0x0044f8c0
0x8fcef2: JMP 0x008fce4a
0x8fcef7: LEA RDI, [0x254eda0]
0x8fcefe: MOV RSI, R15
0x8fcf01: CALL 0x0044f8c0
0x8fcf06: JMP 0x008fcea2

; local helper / adjacent context (reachability below); evidence ev_48a38ff06064561ae56453bc0cf310802c9028da051b62ef43bbbdd1682a2da9; body [{"start": "0x8fcf10", "end": "0x8fcf26"}]
adjacent_8fcf10: ; RVA 0x8fcf10
0x8fcf10: PUSH RBP
0x8fcf11: MOV RBP, RSP
0x8fcf14: LEA RSI, [0x130c73c]
0x8fcf1b: CALL 0x002b3d30
0x8fcf20: MOV EAX, 0xffffff9c
0x8fcf25: POP RBP
0x8fcf26: RET

; local helper / adjacent context (reachability below); evidence ev_6c092865f831e003bcd0e09a2be4f5ea2d46dda50acccf798b5288ade8b59a11; body [{"start": "0x8fcf30", "end": "0x8fcf69"}]
adjacent_8fcf30: ; RVA 0x8fcf30
0x8fcf30: PUSH RBP
0x8fcf31: MOV RBP, RSP
0x8fcf34: PUSH R14
0x8fcf36: PUSH RBX
0x8fcf37: MOV RBX, RDI
0x8fcf3a: CALL 0x002b2b10
0x8fcf3f: LEA RDX, [0xe8a590]
0x8fcf46: MOV RDI, RBX
0x8fcf49: MOV ESI, 0x100000
0x8fcf4e: MOV ECX, 0x1
0x8fcf53: MOV R14, RAX
0x8fcf56: CALL 0x0081a730
0x8fcf5b: MOV RDI, R14
0x8fcf5e: CALL 0x00819390
0x8fcf63: XOR EAX, EAX
0x8fcf65: POP RBX
0x8fcf66: POP R14
0x8fcf68: POP RBP
0x8fcf69: RET

; local helper / adjacent context (reachability below); evidence ev_573a729b4490b9a10ea9a65fa281f4cb50d932c22c897dad6e413bf7bd345248; body [{"start": "0x8fcf70", "end": "0x8fcfeb"}]
adjacent_8fcf70: ; RVA 0x8fcf70
0x8fcf70: PUSH RBP
0x8fcf71: MOV RBP, RSP
0x8fcf74: PUSH R15
0x8fcf76: PUSH R14
0x8fcf78: PUSH RBX
0x8fcf79: PUSH RAX
0x8fcf7a: MOV EBX, EDX
0x8fcf7c: MOV R14, RDI
0x8fcf7f: CMP EDX, 0x1
0x8fcf82: JZ 0x008fcf93
0x8fcf84: CMP EBX, 0x2
0x8fcf87: JNZ 0x008fcfa0
0x8fcf89: MOV RDI, R14
0x8fcf8c: CALL 0x00819390
0x8fcf91: JMP 0x008fcfa0
0x8fcf93: MOV RDI, R14
0x8fcf96: CALL 0x00819a50
0x8fcf9b: CMP EAX, -0x2
0x8fcf9e: JZ 0x008fcfce
0x8fcfa0: MOV RAX, qword ptr [R14 + 0x38]
0x8fcfa4: MOV R15, qword ptr [RAX + 0x8]
0x8fcfa8: LEA RAX, [0x2652d0]
0x8fcfaf: SUB RAX, R15
0x8fcfb2: ROR RAX, 0x3
0x8fcfb6: CMP RAX, 0x8bc
0x8fcfbc: JA 0x008fcfdb
0x8fcfbe: MOV RDI, R14
0x8fcfc1: CALL R15
0x8fcfc4: MOV RDI, R14
0x8fcfc7: MOV ESI, EBX
0x8fcfc9: CALL 0x00819e90
0x8fcfce: XOR EAX, EAX
0x8fcfd0: ADD RSP, 0x8
0x8fcfd4: POP RBX
0x8fcfd5: POP R14
0x8fcfd7: POP R15
0x8fcfd9: POP RBP
0x8fcfda: RET
0x8fcfdb: LEA RDI, [0x254eec0]
0x8fcfe2: MOV RSI, R15
0x8fcfe5: CALL 0x0044f8c0
0x8fcfea: JMP 0x008fcfbe

; local helper / adjacent context (reachability below); evidence ev_e444f9d6d3a63a3203b54696cb4666d85af5b758ccb1739a71d09a30180a652e; body [{"start": "0x8fcff0", "end": "0x8fd050"}]
adjacent_8fcff0: ; RVA 0x8fcff0
0x8fcff0: PUSH RBP
0x8fcff1: MOV RBP, RSP
0x8fcff4: PUSH R14
0x8fcff6: PUSH RBX
0x8fcff7: MOV EBX, EDI
0x8fcff9: MOV EDI, 0x1
0x8fcffe: CALL 0x0099fb40
0x8fd003: CMP EAX, EBX
0x8fd005: JNZ 0x008fd04c
0x8fd007: LEA R14, [0x3b49330]
0x8fd00e: XOR ESI, ESI
0x8fd010: XOR EDX, EDX
0x8fd012: XOR ECX, ECX
0x8fd014: MOV RDI, R14
0x8fd017: CALL 0x004c7190
0x8fd01c: MOVSXD RAX, EBX
0x8fd01f: LEA RCX, [0x3b49340]
0x8fd026: MOV RDI, R14
0x8fd029: XOR ESI, ESI
0x8fd02b: XOR EDX, EDX
0x8fd02d: SHL RAX, 0x4
0x8fd031: MOV qword ptr [RAX + RCX*0x1], -0x1
0x8fd039: MOV dword ptr [RAX + RCX*0x1 + 0x8], 0x0
0x8fd041: XOR ECX, ECX
0x8fd043: POP RBX
0x8fd044: POP R14
0x8fd046: POP RBP
0x8fd047: JMP 0x004c7520
0x8fd04c: POP RBX
0x8fd04d: POP R14
0x8fd04f: POP RBP
0x8fd050: RET

; local helper / adjacent context (reachability below); evidence ev_60279860f884353e8832f4a637aa701c16b44a825f5debfed4a1511d5c4d476f; body [{"start": "0x8fd060", "end": "0x8fd0dc"}]
adjacent_8fd060: ; RVA 0x8fd060
0x8fd060: PUSH RBP
0x8fd061: MOV RBP, RSP
0x8fd064: PUSH R15
0x8fd066: PUSH R14
0x8fd068: PUSH RBX
0x8fd069: PUSH RAX
0x8fd06a: MOV EBX, EDI
0x8fd06c: MOV EDI, 0x1
0x8fd071: MOV R14D, ESI
0x8fd074: CALL 0x0099fb40
0x8fd079: CMP EAX, EBX
0x8fd07b: JNZ 0x008fd0d2
0x8fd07d: LEA R15, [0x3b49330]
0x8fd084: XOR ESI, ESI
0x8fd086: XOR EDX, EDX
0x8fd088: XOR ECX, ECX
0x8fd08a: MOV RDI, R15
0x8fd08d: CALL 0x004c7190
0x8fd092: MOV ESI, dword ptr [0x03b49310]
0x8fd098: MOVSXD RAX, EBX
0x8fd09b: MOV EDI, EBX
0x8fd09d: LEA RCX, [0x3b49340]
0x8fd0a4: SHL RAX, 0x4
0x8fd0a8: MOV qword ptr [RAX + RCX*0x1], 0x0
0x8fd0b0: MOV dword ptr [RAX + RCX*0x1 + 0x8], R14D
0x8fd0b5: CALL 0x0078e8d0
0x8fd0ba: MOV RDI, R15
0x8fd0bd: XOR ESI, ESI
0x8fd0bf: XOR EDX, EDX
0x8fd0c1: XOR ECX, ECX
0x8fd0c3: ADD RSP, 0x8
0x8fd0c7: POP RBX
0x8fd0c8: POP R14
0x8fd0ca: POP R15
0x8fd0cc: POP RBP
0x8fd0cd: JMP 0x004c7520
0x8fd0d2: ADD RSP, 0x8
0x8fd0d6: POP RBX
0x8fd0d7: POP R14
0x8fd0d9: POP R15
0x8fd0db: POP RBP
0x8fd0dc: RET

; local helper / adjacent context (reachability below); evidence ev_3c6cc27e968875b8f94c1ecf57770722369b77dbb389bacf1ac1669649007f30; body [{"start": "0x8fd0e0", "end": "0x8fd156"}]
adjacent_8fd0e0: ; RVA 0x8fd0e0
0x8fd0e0: PUSH RBP
0x8fd0e1: MOV RBP, RSP
0x8fd0e4: PUSH R15
0x8fd0e6: PUSH R14
0x8fd0e8: PUSH RBX
0x8fd0e9: PUSH RAX
0x8fd0ea: MOV R15D, EDI
0x8fd0ed: XOR EDI, EDI
0x8fd0ef: MOV RBX, RSI
0x8fd0f2: XOR R14D, R14D
0x8fd0f5: CALL 0x0099fc00
0x8fd0fa: CMP EAX, R15D
0x8fd0fd: JNZ 0x008fd149
0x8fd0ff: LEA RDI, [0x3b49330]
0x8fd106: XOR ESI, ESI
0x8fd108: XOR EDX, EDX
0x8fd10a: XOR ECX, ECX
0x8fd10c: CALL 0x004c7190
0x8fd111: MOV EDI, 0x1
0x8fd116: CALL 0x0099fb40
0x8fd11b: TEST EAX, EAX
0x8fd11d: JS 0x008fd130
0x8fd11f: MOV EAX, EAX
0x8fd121: LEA RCX, [0x3b49340]
0x8fd128: SHL RAX, 0x4
0x8fd12c: MOV qword ptr [RAX + RCX*0x1], RBX
0x8fd130: MOV R14D, dword ptr [0x03b49310]
0x8fd137: LEA RDI, [0x3b49330]
0x8fd13e: XOR ESI, ESI
0x8fd140: XOR EDX, EDX
0x8fd142: XOR ECX, ECX
0x8fd144: CALL 0x004c7520
0x8fd149: MOV EAX, R14D
0x8fd14c: ADD RSP, 0x8
0x8fd150: POP RBX
0x8fd151: POP R14
0x8fd153: POP R15
0x8fd155: POP RBP
0x8fd156: RET

; local helper / adjacent context (reachability below); evidence ev_d7dd9fc25de5f2a92dce5009270dedac06d75b18fced3961677b86ac0c40df40; body [{"start": "0x8fd160", "end": "0x8fd1e6"}]
adjacent_8fd160: ; RVA 0x8fd160
0x8fd160: PUSH RBP
0x8fd161: MOV RBP, RSP
0x8fd164: PUSH R15
0x8fd166: PUSH R14
0x8fd168: PUSH R12
0x8fd16a: PUSH RBX
0x8fd16b: MOV R12D, 0xffffffff
0x8fd171: CMP EDI, 0x1
0x8fd174: JNZ 0x008fd1db
0x8fd176: LEA RDI, [0x3b49330]
0x8fd17d: MOV RBX, RCX
0x8fd180: MOV R14, RDX
0x8fd183: MOV R15D, ESI
0x8fd186: XOR ESI, ESI
0x8fd188: XOR EDX, EDX
0x8fd18a: XOR ECX, ECX
0x8fd18c: CALL 0x004c7190
0x8fd191: MOV EDI, 0x1
0x8fd196: CALL 0x0099fb40
0x8fd19b: TEST EAX, EAX
0x8fd19d: JS 0x008fd1c9
0x8fd19f: MOV EAX, EAX
0x8fd1a1: LEA RCX, [0x3b49340]
0x8fd1a8: MOV dword ptr [0x03b49310], R15D
0x8fd1af: SHL RAX, 0x4
0x8fd1b3: MOV RDX, qword ptr [RAX + RCX*0x1]
0x8fd1b7: INC RDX
0x8fd1ba: MOV qword ptr [R14], RDX
0x8fd1bd: MOV EAX, dword ptr [RAX + RCX*0x1 + 0x8]
0x8fd1c1: CMP EAX, 0x1
0x8fd1c4: MOV dword ptr [RBX], EAX
0x8fd1c6: SBB R12D, R12D
0x8fd1c9: LEA RDI, [0x3b49330]
0x8fd1d0: XOR ESI, ESI
0x8fd1d2: XOR EDX, EDX
0x8fd1d4: XOR ECX, ECX
0x8fd1d6: CALL 0x004c7520
0x8fd1db: MOV EAX, R12D
0x8fd1de: POP RBX
0x8fd1df: POP R12
0x8fd1e1: POP R14
0x8fd1e3: POP R15
0x8fd1e5: POP RBP
0x8fd1e6: RET

; local helper / adjacent context (reachability below); evidence ev_cc6c887b0a1a840db0b07dc897a2a0dd97396b75f421139aca46d95363a71f3f; body [{"start": "0x8fd1f0", "end": "0x8fd263"}]
adjacent_8fd1f0: ; RVA 0x8fd1f0
0x8fd1f0: PUSH RBP
0x8fd1f1: MOV RBP, RSP
0x8fd1f4: LEA RDI, [0x3b49330]
0x8fd1fb: LEA RSI, [0x129aa84]
0x8fd202: MOV ECX, 0x1
0x8fd207: XOR EDX, EDX
0x8fd209: CALL 0x004c7dd0
0x8fd20e: MOV qword ptr [0x03b49340], -0x1
0x8fd219: MOV dword ptr [0x03b49348], 0x0
0x8fd223: MOV qword ptr [0x03b49350], -0x1
0x8fd22e: MOV dword ptr [0x03b49358], 0x0
0x8fd238: MOV qword ptr [0x03b49360], -0x1
0x8fd243: MOV dword ptr [0x03b49368], 0x0
0x8fd24d: MOV qword ptr [0x03b49370], -0x1
0x8fd258: MOV dword ptr [0x03b49378], 0x0
0x8fd262: POP RBP
0x8fd263: RET

; local helper / adjacent context (reachability below); evidence ev_2d521c938e3810dc7c65e59a8fab9e820fc1d0b8562450e6df3bf5d679365179; body [{"start": "0x8fd270", "end": "0x8fd280"}]
adjacent_8fd270: ; RVA 0x8fd270
0x8fd270: PUSH RBP
0x8fd271: MOV RBP, RSP
0x8fd274: LEA RDI, [0x3b49330]
0x8fd27b: POP RBP
0x8fd27c: JMP 0x004c7e50

; local helper / adjacent context (reachability below); evidence ev_bd60176cf997c45a1400a35941d2e5d96bbacbc1fb99fe7702c034dd2fd8f3b7; body [{"start": "0x8fd290", "end": "0x8fd297"}]
adjacent_8fd290: ; RVA 0x8fd290
0x8fd290: PUSH RBP
0x8fd291: MOV RBP, RSP
0x8fd294: XOR EAX, EAX
0x8fd296: POP RBP
0x8fd297: RET

; local helper / adjacent context (reachability below); evidence ev_58a5c5e539afee799a455d7cf266ee12bc0274c3b65bcb831266e6e1aa93028c; body [{"start": "0x8fd2b1", "end": "0x8fd353"}]
adjacent_8fd2b1: ; RVA 0x8fd2b1
0x8fd2b1: PUSH RBP
0x8fd2b2: MOV RBP, RSP
0x8fd2b5: PUSH R15
0x8fd2b7: PUSH R14
0x8fd2b9: PUSH R13
0x8fd2bb: PUSH R12
0x8fd2bd: PUSH RBX
0x8fd2be: PUSH RAX
0x8fd2bf: MOV R12, RDI
0x8fd2c2: XOR R15D, R15D
0x8fd2c5: CMP R8, 0x2
0x8fd2c9: LEA RDI, [0x3b5c008]
0x8fd2d0: MOV R14D, ECX
0x8fd2d3: MOV RBX, RDX
0x8fd2d6: MOV R13D, ESI
0x8fd2d9: MOV dword ptr [RBP + -0x2c], ESI
0x8fd2dc: SETZ R15B
0x8fd2e0: XOR ESI, ESI
0x8fd2e2: XOR EDX, EDX
0x8fd2e4: XOR ECX, ECX
0x8fd2e6: CALL 0x00c4bb20
0x8fd2eb: LEA RDI, [0x3b4c000]
0x8fd2f2: MOV RSI, R12
0x8fd2f5: MOV RDX, R13
0x8fd2f8: CALL 0x002590b0
0x8fd2fd: MOV EDX, dword ptr [RBP + -0x2c]
0x8fd300: MOV EDI, R14D
0x8fd303: LEA RSI, [0x3b4c000]
0x8fd30a: MOV RCX, RBX
0x8fd30d: MOV R9D, R15D
0x8fd310: XOR R8D, R8D
0x8fd313: CALL 0x00b5cbe0
0x8fd318: MOV RCX, qword ptr [0x03b5c020]
0x8fd31f: TEST CL, 0x1
0x8fd322: JNZ 0x008fd345
0x8fd324: MOV RCX, qword ptr [0x03b5c020]
0x8fd32b: CMP RCX, 0x10
0x8fd32f: JC 0x008fd345
0x8fd331: LEA RDI, [0x3b5c008]
0x8fd338: XOR ESI, ESI
0x8fd33a: XOR EDX, EDX
0x8fd33c: MOV EBX, EAX
0x8fd33e: CALL 0x00c4c4b0
0x8fd343: MOV EAX, EBX
0x8fd345: ADD RSP, 0x8
0x8fd349: POP RBX
0x8fd34a: POP R12
0x8fd34c: POP R13
0x8fd34e: POP R14
0x8fd350: POP R15
0x8fd352: POP RBP
0x8fd353: RET

; local helper / adjacent context (reachability below); evidence ev_c25fa8a2fc9ae64caf7cfd6b78fa6d7dac661b768f98ac5c912cbb7bbb99edc9; body [{"start": "0x8fd371", "end": "0x8fd42b"}]
adjacent_8fd371: ; RVA 0x8fd371
0x8fd371: PUSH RBP
0x8fd372: MOV RBP, RSP
0x8fd375: PUSH R15
0x8fd377: PUSH R14
0x8fd379: PUSH R13
0x8fd37b: PUSH R12
0x8fd37d: PUSH RBX
0x8fd37e: PUSH RAX
0x8fd37f: MOV RBX, RDI
0x8fd382: LEA RDI, [0x3b5c008]
0x8fd389: MOV R12D, ECX
0x8fd38c: MOV R15, RDX
0x8fd38f: MOV R14D, ESI
0x8fd392: MOV R13D, ESI
0x8fd395: XOR ESI, ESI
0x8fd397: XOR EDX, EDX
0x8fd399: XOR ECX, ECX
0x8fd39b: CALL 0x00c4bb20
0x8fd3a0: LEA RDI, [0x3b4c000]
0x8fd3a7: MOV RSI, RBX
0x8fd3aa: MOV RDX, R14
0x8fd3ad: MOV qword ptr [RBP + -0x30], R14
0x8fd3b1: CALL 0x002590b0
0x8fd3b6: MOV EAX, R13D
0x8fd3b9: MOV EDI, R12D
0x8fd3bc: LEA RSI, [0x3b4c000]
0x8fd3c3: MOV EDX, R13D
0x8fd3c6: SHR EAX, 0xc
0x8fd3c9: IMUL R15, RAX
0x8fd3cd: MOV RCX, R15
0x8fd3d0: CALL 0x00b5d5d0
0x8fd3d5: TEST EAX, EAX
0x8fd3d7: JNZ 0x008fd3f0
0x8fd3d9: MOV RDX, qword ptr [RBP + -0x30]
0x8fd3dd: MOV RDI, RBX
0x8fd3e0: LEA RSI, [0x3b4c000]
0x8fd3e7: MOV EBX, EAX
0x8fd3e9: CALL 0x002590b0
0x8fd3ee: MOV EAX, EBX
0x8fd3f0: MOV RCX, qword ptr [0x03b5c020]
0x8fd3f7: TEST CL, 0x1
0x8fd3fa: JNZ 0x008fd41d
0x8fd3fc: MOV RCX, qword ptr [0x03b5c020]
0x8fd403: CMP RCX, 0x10
0x8fd407: JC 0x008fd41d
0x8fd409: LEA RDI, [0x3b5c008]
0x8fd410: XOR ESI, ESI
0x8fd412: XOR EDX, EDX
0x8fd414: MOV EBX, EAX
0x8fd416: CALL 0x00c4c4b0
0x8fd41b: MOV EAX, EBX
0x8fd41d: ADD RSP, 0x8
0x8fd421: POP RBX
0x8fd422: POP R12
0x8fd424: POP R13
0x8fd426: POP R14
0x8fd428: POP R15
0x8fd42a: POP RBP
0x8fd42b: RET

; local helper / adjacent context (reachability below); evidence ev_877f8dcbcc3759159dd96279091fca9ef4214d7d0cc96ac22a14cb2657185b0c; body [{"start": "0x8fd430", "end": "0x8fd502"}]
adjacent_8fd430: ; RVA 0x8fd430
0x8fd430: PUSH RBP
0x8fd431: MOV RBP, RSP
0x8fd434: PUSH R15
0x8fd436: PUSH R14
0x8fd438: PUSH R13
0x8fd43a: PUSH R12
0x8fd43c: PUSH RBX
0x8fd43d: SUB RSP, 0x18
0x8fd441: MOV EAX, 0x37
0x8fd446: MOV qword ptr [RBP + -0x30], RDI
0x8fd44a: CMP ESI, 0x10000
0x8fd450: JA 0x008fd4f4
0x8fd456: LEA RDI, [0x3b5c008]
0x8fd45d: MOV R12D, ECX
0x8fd460: MOV R15, RDX
0x8fd463: MOV EBX, ESI
0x8fd465: MOV R13D, ESI
0x8fd468: XOR ESI, ESI
0x8fd46a: XOR EDX, EDX
0x8fd46c: XOR ECX, ECX
0x8fd46e: CALL 0x00c4bb20
0x8fd473: MOV RSI, qword ptr [RBP + -0x30]
0x8fd477: LEA R14, [0x3b4c000]
0x8fd47e: MOV RDX, RBX
0x8fd481: MOV qword ptr [RBP + -0x38], RBX
0x8fd485: MOV RDI, R14
0x8fd488: CALL 0x002590b0
0x8fd48d: MOV EAX, R13D
0x8fd490: MOV EDI, R12D
0x8fd493: MOV RSI, R14
0x8fd496: MOV RDX, R14
0x8fd499: MOV ECX, R13D
0x8fd49c: SHR EAX, 0xc
0x8fd49f: IMUL R15, RAX
0x8fd4a3: MOV R8, R15
0x8fd4a6: CALL 0x00b5d170
0x8fd4ab: TEST EAX, EAX
0x8fd4ad: JNZ 0x008fd4c7
0x8fd4af: MOV RDI, qword ptr [RBP + -0x30]
0x8fd4b3: MOV RDX, qword ptr [RBP + -0x38]
0x8fd4b7: LEA RSI, [0x3b4c000]
0x8fd4be: MOV EBX, EAX
0x8fd4c0: CALL 0x002590b0
0x8fd4c5: MOV EAX, EBX
0x8fd4c7: MOV RCX, qword ptr [0x03b5c020]
0x8fd4ce: TEST CL, 0x1
0x8fd4d1: JNZ 0x008fd4f4
0x8fd4d3: MOV RCX, qword ptr [0x03b5c020]
0x8fd4da: CMP RCX, 0x10
0x8fd4de: JC 0x008fd4f4
0x8fd4e0: LEA RDI, [0x3b5c008]
0x8fd4e7: XOR ESI, ESI
0x8fd4e9: XOR EDX, EDX
0x8fd4eb: MOV EBX, EAX
0x8fd4ed: CALL 0x00c4c4b0
0x8fd4f2: MOV EAX, EBX
0x8fd4f4: ADD RSP, 0x18
0x8fd4f8: POP RBX
0x8fd4f9: POP R12
0x8fd4fb: POP R13
0x8fd4fd: POP R14
0x8fd4ff: POP R15
0x8fd501: POP RBP
0x8fd502: RET

; local helper / adjacent context (reachability below); evidence ev_a8b24eb336b4ccb01c5c55014731ac5ffc81c110b944d7f6193850f9c2398bb1; body [{"start": "0x8fd510", "end": "0x8fd599"}]
adjacent_8fd510: ; RVA 0x8fd510
0x8fd510: PUSH RBP
0x8fd511: MOV RBP, RSP
0x8fd514: PUSH R15
0x8fd516: PUSH R14
0x8fd518: PUSH R13
0x8fd51a: PUSH R12
0x8fd51c: PUSH RBX
0x8fd51d: SUB RSP, 0x18
0x8fd521: MOV R13D, R8D
0x8fd524: MOV R15, R9
0x8fd527: MOV RBX, RCX
0x8fd52a: MOV R8, RDX
0x8fd52d: MOV R12, RSI
0x8fd530: MOV R14, RDI
0x8fd533: MOV EAX, 0x1
0x8fd538: XADD.LOCK dword ptr [0x03b5c000], EAX
0x8fd540: TEST EAX, EAX
0x8fd542: JZ 0x008fd564
0x8fd544: TEST RBX, RBX
0x8fd547: JZ 0x008fd586
0x8fd549: MOV RSI, qword ptr [RBP + 0x10]
0x8fd54d: MOV RDI, R15
0x8fd550: MOV RDX, R14
0x8fd553: MOV RCX, R12
0x8fd556: MOV R9, RBX
0x8fd559: MOV dword ptr [RSP], R13D
0x8fd55d: CALL 0x00b5cae0
0x8fd562: JMP 0x008fd58b
0x8fd564: LEA RDI, [0x3b5c008]
0x8fd56b: LEA RSI, [0x1339c5e]
0x8fd572: XOR EDX, EDX
0x8fd574: MOV qword ptr [RBP + -0x30], R8
0x8fd578: CALL 0x00c4b290
0x8fd57d: MOV R8, qword ptr [RBP + -0x30]
0x8fd581: TEST RBX, RBX
0x8fd584: JNZ 0x008fd549
0x8fd586: MOV EAX, 0x16
0x8fd58b: ADD RSP, 0x18
0x8fd58f: POP RBX
0x8fd590: POP R12
0x8fd592: POP R13
0x8fd594: POP R14
0x8fd596: POP R15
0x8fd598: POP RBP
0x8fd599: RET

; local helper / adjacent context (reachability below); evidence ev_c402b33b1393d9ce343f63b5074c26fce3e5442f723f47421d27b047ac80350c; body [{"start": "0x8fd5a0", "end": "0x8fd629"}]
adjacent_8fd5a0: ; RVA 0x8fd5a0
0x8fd5a0: PUSH RBP
0x8fd5a1: MOV RBP, RSP
0x8fd5a4: PUSH R15
0x8fd5a6: PUSH R14
0x8fd5a8: PUSH R13
0x8fd5aa: PUSH R12
0x8fd5ac: PUSH RBX
0x8fd5ad: SUB RSP, 0x18
0x8fd5b1: MOV R13D, R8D
0x8fd5b4: MOV R15, R9
0x8fd5b7: MOV RBX, RCX
0x8fd5ba: MOV R8, RDX
0x8fd5bd: MOV R12, RSI
0x8fd5c0: MOV R14, RDI
0x8fd5c3: MOV EAX, 0x1
0x8fd5c8: XADD.LOCK dword ptr [0x03b5c000], EAX
0x8fd5d0: TEST EAX, EAX
0x8fd5d2: JZ 0x008fd5f4
0x8fd5d4: TEST RBX, RBX
0x8fd5d7: JZ 0x008fd616
0x8fd5d9: MOV RSI, qword ptr [RBP + 0x10]
0x8fd5dd: MOV RDI, R15
0x8fd5e0: MOV RDX, R14
0x8fd5e3: MOV RCX, R12
0x8fd5e6: MOV R9, RBX
0x8fd5e9: MOV dword ptr [RSP], R13D
0x8fd5ed: CALL 0x00b5cb40
0x8fd5f2: JMP 0x008fd61b
0x8fd5f4: LEA RDI, [0x3b5c008]
0x8fd5fb: LEA RSI, [0x1339c5e]
0x8fd602: XOR EDX, EDX
0x8fd604: MOV qword ptr [RBP + -0x30], R8
0x8fd608: CALL 0x00c4b290
0x8fd60d: MOV R8, qword ptr [RBP + -0x30]
0x8fd611: TEST RBX, RBX
0x8fd614: JNZ 0x008fd5d9
0x8fd616: MOV EAX, 0x16
0x8fd61b: ADD RSP, 0x18
0x8fd61f: POP RBX
0x8fd620: POP R12
0x8fd622: POP R13
0x8fd624: POP R14
0x8fd626: POP R15
0x8fd628: POP RBP
0x8fd629: RET

; local helper / adjacent context (reachability below); evidence ev_7f7cb4905600f08f48708e15829cd75e7f8841774d0567385d6b14cd5be588e2; body [{"start": "0x8fd646", "end": "0x8fd66e"}]
adjacent_8fd646: ; RVA 0x8fd646
0x8fd646: PUSH RBP
0x8fd647: MOV RBP, RSP
0x8fd64a: PUSH R14
0x8fd64c: PUSH RBX
0x8fd64d: LEA RAX, [0x3b5c008]
0x8fd654: MOV EBX, EDI
0x8fd656: MOV R14D, ESI
0x8fd659: MOV RDI, RAX
0x8fd65c: CALL 0x00261090
0x8fd661: MOV EDI, EBX
0x8fd663: MOV ESI, R14D
0x8fd666: POP RBX
0x8fd667: POP R14
0x8fd669: POP RBP
0x8fd66a: JMP 0x00b5cb90

; local helper / adjacent context (reachability below); evidence ev_c351497140e2a824ea34c68244d525dd19bee7f4e065ad6dacf2b0fa99506fd5; body [{"start": "0x8fd670", "end": "0x8fd679"}, {"start": "0x8fd680", "end": "0x8fd6db"}, {"start": "0x8fd6e0", "end": "0x8fd84c"}]
adjacent_8fd670: ; RVA 0x8fd670
0x8fd670: PUSH RBP
0x8fd671: MOV RBP, RSP
0x8fd674: MOV RAX, qword ptr [RSI + 0x10]
0x8fd678: JMP 0x008fd69f
0x8fd680: MOV dword ptr [RDX + 0x18], 0x0
0x8fd687: MOV dword ptr [RAX + 0x18], 0x0
0x8fd68e: MOV RAX, RCX
0x8fd691: MOV dword ptr [RCX + 0x18], 0x1
0x8fd698: MOV RSI, RAX
0x8fd69b: MOV RAX, qword ptr [RAX + 0x10]
0x8fd69f: TEST RAX, RAX
0x8fd6a2: JZ 0x008fd841
0x8fd6a8: CMP dword ptr [RAX + 0x18], 0x1
0x8fd6ac: JNZ 0x008fd841
0x8fd6b2: MOV RCX, qword ptr [RAX + 0x10]
0x8fd6b6: MOV RDX, qword ptr [RCX]
0x8fd6b9: CMP RAX, RDX
0x8fd6bc: JZ 0x008fd6e0
0x8fd6be: TEST RDX, RDX
0x8fd6c1: JZ 0x008fd6c9
0x8fd6c3: CMP dword ptr [RDX + 0x18], 0x1
0x8fd6c7: JZ 0x008fd680
0x8fd6c9: MOV RDX, qword ptr [RAX]
0x8fd6cc: CMP RDX, RSI
0x8fd6cf: JZ 0x008fd703
0x8fd6d1: MOV RDX, RAX
0x8fd6d4: MOV RAX, RSI
0x8fd6d7: JMP 0x008fd782
0x8fd6e0: MOV RDX, qword ptr [RCX + 0x8]
0x8fd6e4: TEST RDX, RDX
0x8fd6e7: JZ 0x008fd6ef
0x8fd6e9: CMP dword ptr [RDX + 0x18], 0x1
0x8fd6ed: JZ 0x008fd680
0x8fd6ef: MOV RDX, qword ptr [RAX + 0x8]
0x8fd6f3: CMP RDX, RSI
0x8fd6f6: JZ 0x008fd72b
0x8fd6f8: MOV RDX, RAX
0x8fd6fb: MOV RAX, RSI
0x8fd6fe: JMP 0x008fd7f3
0x8fd703: MOV R8, qword ptr [RDX + 0x8]
0x8fd707: MOV qword ptr [RAX], R8
0x8fd70a: TEST R8, R8
0x8fd70d: JZ 0x008fd762
0x8fd70f: MOV qword ptr [R8 + 0x10], RAX
0x8fd713: MOV R8, qword ptr [RAX + 0x10]
0x8fd717: MOV qword ptr [RDX + 0x10], R8
0x8fd71b: TEST R8, R8
0x8fd71e: JZ 0x008fd774
0x8fd720: CMP RAX, qword ptr [R8]
0x8fd723: JZ 0x008fd76f
0x8fd725: MOV qword ptr [R8 + 0x8], RDX
0x8fd729: JMP 0x008fd777
0x8fd72b: MOV R8, qword ptr [RDX]
0x8fd72e: MOV qword ptr [RAX + 0x8], R8
0x8fd732: TEST R8, R8
0x8fd735: JZ 0x008fd7d0
0x8fd73b: MOV qword ptr [R8 + 0x10], RAX
0x8fd73f: MOV R8, qword ptr [RAX + 0x10]
0x8fd743: MOV qword ptr [RDX + 0x10], R8
0x8fd747: TEST R8, R8
0x8fd74a: JZ 0x008fd7e6
0x8fd750: CMP RAX, qword ptr [R8]
0x8fd753: JZ 0x008fd7e1
0x8fd759: MOV qword ptr [R8 + 0x8], RDX
0x8fd75d: JMP 0x008fd7e9
0x8fd762: MOV qword ptr [RDX + 0x10], RCX
0x8fd766: MOV R8, qword ptr [RAX + 0x10]
0x8fd76a: CMP RAX, qword ptr [R8]
0x8fd76d: JNZ 0x008fd725
0x8fd76f: MOV qword ptr [R8], RDX
0x8fd772: JMP 0x008fd777
0x8fd774: MOV qword ptr [RDI], RDX
0x8fd777: MOV qword ptr [RDX + 0x8], RAX
0x8fd77b: MOV qword ptr [RAX + 0x10], RDX
0x8fd77f: MOV RDX, RSI
0x8fd782: MOV dword ptr [RDX + 0x18], 0x0
0x8fd789: MOV dword ptr [RCX + 0x18], 0x1
0x8fd790: MOV RDX, qword ptr [RCX + 0x8]
0x8fd794: MOV RSI, qword ptr [RDX]
0x8fd797: MOV qword ptr [RCX + 0x8], RSI
0x8fd79b: TEST RSI, RSI
0x8fd79e: JZ 0x008fd7a4
0x8fd7a0: MOV qword ptr [RSI + 0x10], RCX
0x8fd7a4: MOV RSI, qword ptr [RCX + 0x10]
0x8fd7a8: MOV qword ptr [RDX + 0x10], RSI
0x8fd7ac: TEST RSI, RSI
0x8fd7af: JZ 0x008fd7bc
0x8fd7b1: CMP RCX, qword ptr [RSI]
0x8fd7b4: JZ 0x008fd7c1
0x8fd7b6: MOV qword ptr [RSI + 0x8], RDX
0x8fd7ba: JMP 0x008fd7c4
0x8fd7bc: MOV qword ptr [RDI], RDX
0x8fd7bf: JMP 0x008fd7c4
0x8fd7c1: MOV qword ptr [RSI], RDX
0x8fd7c4: MOV qword ptr [RDX], RCX
0x8fd7c7: MOV qword ptr [RCX + 0x10], RDX
0x8fd7cb: JMP 0x008fd698
0x8fd7d0: MOV qword ptr [RDX + 0x10], RCX
0x8fd7d4: MOV R8, qword ptr [RAX + 0x10]
0x8fd7d8: CMP RAX, qword ptr [R8]
0x8fd7db: JNZ 0x008fd759
0x8fd7e1: MOV qword ptr [R8], RDX
0x8fd7e4: JMP 0x008fd7e9
0x8fd7e6: MOV qword ptr [RDI], RDX
0x8fd7e9: MOV qword ptr [RDX], RAX
0x8fd7ec: MOV qword ptr [RAX + 0x10], RDX
0x8fd7f0: MOV RDX, RSI
0x8fd7f3: MOV dword ptr [RDX + 0x18], 0x0
0x8fd7fa: MOV dword ptr [RCX + 0x18], 0x1
0x8fd801: MOV RDX, qword ptr [RCX]
0x8fd804: MOV RSI, qword ptr [RDX + 0x8]
0x8fd808: MOV qword ptr [RCX], RSI
0x8fd80b: TEST RSI, RSI
0x8fd80e: JZ 0x008fd814
0x8fd810: MOV qword ptr [RSI + 0x10], RCX
0x8fd814: MOV RSI, qword ptr [RCX + 0x10]
0x8fd818: MOV qword ptr [RDX + 0x10], RSI
0x8fd81c: TEST RSI, RSI
0x8fd81f: JZ 0x008fd82c
0x8fd821: CMP RCX, qword ptr [RSI]
0x8fd824: JZ 0x008fd831
0x8fd826: MOV qword ptr [RSI + 0x8], RDX
0x8fd82a: JMP 0x008fd834
0x8fd82c: MOV qword ptr [RDI], RDX
0x8fd82f: JMP 0x008fd834
0x8fd831: MOV qword ptr [RSI], RDX
0x8fd834: MOV qword ptr [RDX + 0x8], RCX
0x8fd838: MOV qword ptr [RCX + 0x10], RDX
0x8fd83c: JMP 0x008fd698
0x8fd841: MOV RAX, qword ptr [RDI]
0x8fd844: MOV dword ptr [RAX + 0x18], 0x0
0x8fd84b: POP RBP
0x8fd84c: RET

; local helper / adjacent context (reachability below); evidence ev_faf53e1f5c15f29592c3f5b530d2e1b96fac32c61f7263e5b230c26246fea4db; body [{"start": "0x8fd850", "end": "0x8fd942"}, {"start": "0x8fd950", "end": "0x8fd9c3"}, {"start": "0x8fd9d0", "end": "0x8fdc29"}]
adjacent_8fd850: ; RVA 0x8fd850
0x8fd850: PUSH RBP
0x8fd851: MOV RBP, RSP
0x8fd854: MOV RCX, qword ptr [RSI]
0x8fd857: MOV R9, qword ptr [RSI + 0x8]
0x8fd85b: MOV RAX, RSI
0x8fd85e: TEST RCX, RCX
0x8fd861: JZ 0x008fd8a0
0x8fd863: TEST R9, R9
0x8fd866: JZ 0x008fd8b1
0x8fd868: NOP dword ptr [RAX + RAX*0x1]
0x8fd870: MOV R8, R9
0x8fd873: MOV R9, qword ptr [R9]
0x8fd876: TEST R9, R9
0x8fd879: JNZ 0x008fd870
0x8fd87b: MOV RCX, qword ptr [R8 + 0x8]
0x8fd87f: MOV RDX, qword ptr [R8 + 0x10]
0x8fd883: MOV ESI, dword ptr [R8 + 0x18]
0x8fd887: TEST RCX, RCX
0x8fd88a: JZ 0x008fd890
0x8fd88c: MOV qword ptr [RCX + 0x10], RDX
0x8fd890: TEST RDX, RDX
0x8fd893: JZ 0x008fd8cc
0x8fd895: CMP qword ptr [RDX], R8
0x8fd898: JZ 0x008fd8e4
0x8fd89a: MOV qword ptr [RDX + 0x8], RCX
0x8fd89e: JMP 0x008fd8e7
0x8fd8a0: MOV RDX, qword ptr [RAX + 0x10]
0x8fd8a4: MOV ESI, dword ptr [RAX + 0x18]
0x8fd8a7: TEST R9, R9
0x8fd8aa: JZ 0x008fd8d6
0x8fd8ac: MOV RCX, R9
0x8fd8af: JMP 0x008fd8b8
0x8fd8b1: MOV RDX, qword ptr [RAX + 0x10]
0x8fd8b5: MOV ESI, dword ptr [RAX + 0x18]
0x8fd8b8: MOV qword ptr [RCX + 0x10], RDX
0x8fd8bc: TEST RDX, RDX
0x8fd8bf: JZ 0x008fd8dd
0x8fd8c1: CMP qword ptr [RDX], RAX
0x8fd8c4: JZ 0x008fd8d1
0x8fd8c6: MOV qword ptr [RDX + 0x8], RCX
0x8fd8ca: JMP 0x008fd93d
0x8fd8cc: MOV qword ptr [RDI], RCX
0x8fd8cf: JMP 0x008fd8e7
0x8fd8d1: MOV qword ptr [RDX], RCX
0x8fd8d4: JMP 0x008fd93d
0x8fd8d6: XOR ECX, ECX
0x8fd8d8: TEST RDX, RDX
0x8fd8db: JNZ 0x008fd8c1
0x8fd8dd: XOR EDX, EDX
0x8fd8df: MOV qword ptr [RDI], RCX
0x8fd8e2: JMP 0x008fd93d
0x8fd8e4: MOV qword ptr [RDX], RCX
0x8fd8e7: MOV R9, qword ptr [RAX + 0x18]
0x8fd8eb: CMP qword ptr [R8 + 0x10], RAX
0x8fd8ef: MOV qword ptr [R8 + 0x18], R9
0x8fd8f3: MOV R9, qword ptr [RAX + 0x10]
0x8fd8f7: CMOVZ RDX, R8
0x8fd8fb: MOV qword ptr [R8 + 0x10], R9
0x8fd8ff: MOV R9, qword ptr [RAX]
0x8fd902: MOV R10, qword ptr [RAX + 0x8]
0x8fd906: MOV qword ptr [R8 + 0x8], R10
0x8fd90a: MOV qword ptr [R8], R9
0x8fd90d: MOV R9, qword ptr [RAX + 0x10]
0x8fd911: TEST R9, R9
0x8fd914: JZ 0x008fd921
0x8fd916: CMP qword ptr [R9], RAX
0x8fd919: JZ 0x008fd926
0x8fd91b: MOV qword ptr [R9 + 0x8], R8
0x8fd91f: JMP 0x008fd929
0x8fd921: MOV qword ptr [RDI], R8
0x8fd924: JMP 0x008fd929
0x8fd926: MOV qword ptr [R9], R8
0x8fd929: MOV R9, qword ptr [RAX]
0x8fd92c: MOV qword ptr [R9 + 0x10], R8
0x8fd930: MOV R9, qword ptr [RAX + 0x8]
0x8fd934: TEST R9, R9
0x8fd937: JZ 0x008fd93d
0x8fd939: MOV qword ptr [R9 + 0x10], R8
0x8fd93d: TEST ESI, ESI
0x8fd93f: JZ 0x008fd95b
0x8fd941: POP RBP
0x8fd942: RET
0x8fd950: MOV dword ptr [RDX + 0x18], 0x1
0x8fd957: MOV RDX, qword ptr [RCX + 0x10]
0x8fd95b: MOV RSI, RCX
0x8fd95e: MOV RCX, RDX
0x8fd961: TEST RSI, RSI
0x8fd964: JZ 0x008fd970
0x8fd966: CMP dword ptr [RSI + 0x18], 0x0
0x8fd96a: JNZ 0x008fdbab
0x8fd970: CMP RSI, qword ptr [RDI]
0x8fd973: JZ 0x008fdba2
0x8fd979: MOV RDX, qword ptr [RCX]
0x8fd97c: CMP RDX, RSI
0x8fd97f: JZ 0x008fd9d0
0x8fd981: CMP dword ptr [RDX + 0x18], 0x1
0x8fd985: JNZ 0x008fda2b
0x8fd98b: MOV dword ptr [RDX + 0x18], 0x0
0x8fd992: MOV dword ptr [RCX + 0x18], 0x1
0x8fd999: MOV RDX, qword ptr [RCX]
0x8fd99c: MOV RSI, qword ptr [RDX + 0x8]
0x8fd9a0: MOV qword ptr [RCX], RSI
0x8fd9a3: TEST RSI, RSI
0x8fd9a6: JZ 0x008fd9ac
0x8fd9a8: MOV qword ptr [RSI + 0x10], RCX
0x8fd9ac: MOV RSI, qword ptr [RCX + 0x10]
0x8fd9b0: MOV qword ptr [RDX + 0x10], RSI
0x8fd9b4: TEST RSI, RSI
0x8fd9b7: JZ 0x008fda18
0x8fd9b9: CMP RCX, qword ptr [RSI]
0x8fd9bc: JZ 0x008fda1d
0x8fd9be: MOV qword ptr [RSI + 0x8], RDX
0x8fd9c2: JMP 0x008fda20
0x8fd9d0: MOV RDX, qword ptr [RCX + 0x8]
0x8fd9d4: CMP dword ptr [RDX + 0x18], 0x1
0x8fd9d8: JNZ 0x008fda6a
0x8fd9de: MOV dword ptr [RDX + 0x18], 0x0
0x8fd9e5: MOV dword ptr [RCX + 0x18], 0x1
0x8fd9ec: MOV RDX, qword ptr [RCX + 0x8]
0x8fd9f0: MOV RSI, qword ptr [RDX]
0x8fd9f3: MOV qword ptr [RCX + 0x8], RSI
0x8fd9f7: TEST RSI, RSI
0x8fd9fa: JZ 0x008fda00
0x8fd9fc: MOV qword ptr [RSI + 0x10], RCX
0x8fda00: MOV RSI, qword ptr [RCX + 0x10]
0x8fda04: MOV qword ptr [RDX + 0x10], RSI
0x8fda08: TEST RSI, RSI
0x8fda0b: JZ 0x008fda57
0x8fda0d: CMP RCX, qword ptr [RSI]
0x8fda10: JZ 0x008fda5c
0x8fda12: MOV qword ptr [RSI + 0x8], RDX
0x8fda16: JMP 0x008fda5f
0x8fda18: MOV qword ptr [RDI], RDX
0x8fda1b: JMP 0x008fda20
0x8fda1d: MOV qword ptr [RSI], RDX
0x8fda20: MOV qword ptr [RDX + 0x8], RCX
0x8fda24: MOV qword ptr [RCX + 0x10], RDX
0x8fda28: MOV RDX, qword ptr [RCX]
0x8fda2b: MOV RSI, qword ptr [RDX]
0x8fda2e: TEST RSI, RSI
0x8fda31: JZ 0x008fda3d
0x8fda33: CMP dword ptr [RSI + 0x18], 0x0
0x8fda37: JNZ 0x008fdb48
0x8fda3d: MOV R8, qword ptr [RDX + 0x8]
0x8fda41: TEST R8, R8
0x8fda44: JZ 0x008fd950
0x8fda4a: CMP dword ptr [R8 + 0x18], 0x0
0x8fda4f: JZ 0x008fd950
0x8fda55: JMP 0x008fda94
0x8fda57: MOV qword ptr [RDI], RDX
0x8fda5a: JMP 0x008fda5f
0x8fda5c: MOV qword ptr [RSI], RDX
0x8fda5f: MOV qword ptr [RDX], RCX
0x8fda62: MOV qword ptr [RCX + 0x10], RDX
0x8fda66: MOV RDX, qword ptr [RCX + 0x8]
0x8fda6a: MOV RSI, qword ptr [RDX]
0x8fda6d: TEST RSI, RSI
0x8fda70: JZ 0x008fda78
0x8fda72: CMP dword ptr [RSI + 0x18], 0x0
0x8fda76: JNZ 0x008fdade
0x8fda78: MOV RSI, qword ptr [RDX + 0x8]
0x8fda7c: TEST RSI, RSI
0x8fda7f: JZ 0x008fd950
0x8fda85: CMP dword ptr [RSI + 0x18], 0x0
0x8fda89: JZ 0x008fd950
0x8fda8f: JMP 0x008fdbc8
0x8fda94: TEST RSI, RSI
0x8fda97: JZ 0x008fdaa3
0x8fda99: CMP dword ptr [RSI + 0x18], 0x0
0x8fda9d: JNZ 0x008fdb48
0x8fdaa3: MOV dword ptr [R8 + 0x18], 0x0
0x8fdaab: MOV RSI, qword ptr [RDX + 0x8]
0x8fdaaf: MOV dword ptr [RDX + 0x18], 0x1
0x8fdab6: MOV R8, qword ptr [RSI]
0x8fdab9: MOV qword ptr [RDX + 0x8], R8
0x8fdabd: TEST R8, R8
0x8fdac0: JZ 0x008fdac6
0x8fdac2: MOV qword ptr [R8 + 0x10], RDX
0x8fdac6: MOV R8, qword ptr [RDX + 0x10]
0x8fdaca: MOV qword ptr [RSI + 0x10], R8
0x8fdace: TEST R8, R8
0x8fdad1: JZ 0x008fdb36
0x8fdad3: CMP RDX, qword ptr [R8]
0x8fdad6: JZ 0x008fdb3b
0x8fdad8: MOV qword ptr [R8 + 0x8], RSI
0x8fdadc: JMP 0x008fdb3e
0x8fdade: MOV R8, qword ptr [RDX + 0x8]
0x8fdae2: TEST R8, R8
0x8fdae5: JZ 0x008fdaf2
0x8fdae7: CMP dword ptr [R8 + 0x18], 0x0
0x8fdaec: JNZ 0x008fdbc8
0x8fdaf2: MOV dword ptr [RSI + 0x18], 0x0
0x8fdaf9: MOV RSI, qword ptr [RDX]
0x8fdafc: MOV dword ptr [RDX + 0x18], 0x1
0x8fdb03: MOV R8, qword ptr [RSI + 0x8]
0x8fdb07: MOV qword ptr [RDX], R8
0x8fdb0a: TEST R8, R8
0x8fdb0d: JZ 0x008fdb13
0x8fdb0f: MOV qword ptr [R8 + 0x10], RDX
0x8fdb13: MOV R8, qword ptr [RDX + 0x10]
0x8fdb17: MOV qword ptr [RSI + 0x10], R8
0x8fdb1b: TEST R8, R8
0x8fdb1e: JZ 0x008fdbb4
0x8fdb24: CMP RDX, qword ptr [R8]
0x8fdb27: JZ 0x008fdbb9
0x8fdb2d: MOV qword ptr [R8 + 0x8], RSI
0x8fdb31: JMP 0x008fdbbc
0x8fdb36: MOV qword ptr [RDI], RSI
0x8fdb39: JMP 0x008fdb3e
0x8fdb3b: MOV qword ptr [R8], RSI
0x8fdb3e: MOV qword ptr [RSI], RDX
0x8fdb41: MOV qword ptr [RDX + 0x10], RSI
0x8fdb45: MOV RDX, qword ptr [RCX]
0x8fdb48: MOV ESI, dword ptr [RCX + 0x18]
0x8fdb4b: MOV dword ptr [RDX + 0x18], ESI
0x8fdb4e: MOV dword ptr [RCX + 0x18], 0x0
0x8fdb55: MOV RDX, qword ptr [RDX]
0x8fdb58: TEST RDX, RDX
0x8fdb5b: JZ 0x008fdb64
0x8fdb5d: MOV dword ptr [RDX + 0x18], 0x0
0x8fdb64: MOV RDX, qword ptr [RCX]
0x8fdb67: MOV RSI, qword ptr [RDX + 0x8]
0x8fdb6b: MOV qword ptr [RCX], RSI
0x8fdb6e: TEST RSI, RSI
0x8fdb71: JZ 0x008fdb77
0x8fdb73: MOV qword ptr [RSI + 0x10], RCX
0x8fdb77: MOV RSI, qword ptr [RCX + 0x10]
0x8fdb7b: MOV qword ptr [RDX + 0x10], RSI
0x8fdb7f: TEST RSI, RSI
0x8fdb82: JZ 0x008fdb8f
0x8fdb84: CMP RCX, qword ptr [RSI]
0x8fdb87: JZ 0x008fdb94
0x8fdb89: MOV qword ptr [RSI + 0x8], RDX
0x8fdb8d: JMP 0x008fdb97
0x8fdb8f: MOV qword ptr [RDI], RDX
0x8fdb92: JMP 0x008fdb97
0x8fdb94: MOV qword ptr [RSI], RDX
0x8fdb97: MOV qword ptr [RDX + 0x8], RCX
0x8fdb9b: MOV qword ptr [RCX + 0x10], RDX
0x8fdb9f: MOV RSI, qword ptr [RDI]
0x8fdba2: TEST RSI, RSI
0x8fdba5: JZ 0x008fd941
0x8fdbab: MOV dword ptr [RSI + 0x18], 0x0
0x8fdbb2: POP RBP
0x8fdbb3: RET
0x8fdbb4: MOV qword ptr [RDI], RSI
0x8fdbb7: JMP 0x008fdbbc
0x8fdbb9: MOV qword ptr [R8], RSI
0x8fdbbc: MOV qword ptr [RSI + 0x8], RDX
0x8fdbc0: MOV qword ptr [RDX + 0x10], RSI
0x8fdbc4: MOV RDX, qword ptr [RCX + 0x8]
0x8fdbc8: MOV ESI, dword ptr [RCX + 0x18]
0x8fdbcb: MOV dword ptr [RDX + 0x18], ESI
0x8fdbce: MOV dword ptr [RCX + 0x18], 0x0
0x8fdbd5: MOV RDX, qword ptr [RDX + 0x8]
0x8fdbd9: TEST RDX, RDX
0x8fdbdc: JZ 0x008fdbe5
0x8fdbde: MOV dword ptr [RDX + 0x18], 0x0
0x8fdbe5: MOV RDX, qword ptr [RCX + 0x8]
0x8fdbe9: MOV RSI, qword ptr [RDX]
0x8fdbec: MOV qword ptr [RCX + 0x8], RSI
0x8fdbf0: TEST RSI, RSI
0x8fdbf3: JZ 0x008fdbf9
0x8fdbf5: MOV qword ptr [RSI + 0x10], RCX
0x8fdbf9: MOV RSI, qword ptr [RCX + 0x10]
0x8fdbfd: MOV qword ptr [RDX + 0x10], RSI
0x8fdc01: TEST RSI, RSI
0x8fdc04: JZ 0x008fdc14
0x8fdc06: CMP RCX, qword ptr [RSI]
0x8fdc09: JZ 0x008fdc1f
0x8fdc0b: MOV qword ptr [RSI + 0x8], RDX
0x8fdc0f: MOV qword ptr [RDX], RCX
0x8fdc12: JMP 0x008fdb9b
0x8fdc14: MOV qword ptr [RDI], RDX
0x8fdc17: MOV qword ptr [RDX], RCX
0x8fdc1a: JMP 0x008fdb9b
0x8fdc1f: MOV qword ptr [RSI], RDX
0x8fdc22: MOV qword ptr [RDX], RCX
0x8fdc25: JMP 0x008fdb9b

; local helper / adjacent context (reachability below); evidence ev_edf39784269d1966e5a53b987dd35334e63ced2c5ad19d0a5a837ae78fe44455; body [{"start": "0x8fdc30", "end": "0x8fdc47"}, {"start": "0x8fdc50", "end": "0x8fdc7e"}]
adjacent_8fdc30: ; RVA 0x8fdc30
0x8fdc30: PUSH RBP
0x8fdc31: MOV RBP, RSP
0x8fdc34: PUSH R14
0x8fdc36: PUSH RBX
0x8fdc37: MOV RBX, qword ptr [RDI]
0x8fdc3a: TEST RBX, RBX
0x8fdc3d: JZ 0x008fdc75
0x8fdc3f: MOV R14, RSI
0x8fdc42: ADD R14, 0x20
0x8fdc46: JMP 0x008fdc58
0x8fdc50: MOV RBX, qword ptr [RBX]
0x8fdc53: TEST RBX, RBX
0x8fdc56: JZ 0x008fdc75
0x8fdc58: LEA RSI, [RBX + 0x20]
0x8fdc5c: MOV EDX, 0x10
0x8fdc61: MOV RDI, R14
0x8fdc64: CALL 0x00339bd0
0x8fdc69: TEST EAX, EAX
0x8fdc6b: JS 0x008fdc50
0x8fdc6d: JZ 0x008fdc77
0x8fdc6f: ADD RBX, 0x8
0x8fdc73: JMP 0x008fdc50
0x8fdc75: XOR EBX, EBX
0x8fdc77: MOV RAX, RBX
0x8fdc7a: POP RBX
0x8fdc7b: POP R14
0x8fdc7d: POP RBP
0x8fdc7e: RET

; local helper / adjacent context (reachability below); evidence ev_8f426ee8f080e7bdd5c233f6e8f75b715dfdce3d20e4e19bf6f883d858e630ba; body [{"start": "0x8fdc80", "end": "0x8fdcc7"}]
adjacent_8fdc80: ; RVA 0x8fdc80
0x8fdc80: PUSH RBP
0x8fdc81: MOV RBP, RSP
0x8fdc84: MOV RCX, qword ptr [RDI + 0x8]
0x8fdc88: TEST RCX, RCX
0x8fdc8b: JZ 0x008fdc9d
0x8fdc8d: NOP dword ptr [RAX]
0x8fdc90: MOV RAX, RCX
0x8fdc93: MOV RCX, qword ptr [RCX]
0x8fdc96: TEST RCX, RCX
0x8fdc99: JNZ 0x008fdc90
0x8fdc9b: POP RBP
0x8fdc9c: RET
0x8fdc9d: MOV RAX, qword ptr [RDI + 0x10]
0x8fdca1: TEST RAX, RAX
0x8fdca4: JZ 0x008fdcb0
0x8fdca6: CMP RDI, qword ptr [RAX]
0x8fdca9: JZ 0x008fdc9b
0x8fdcab: NOP dword ptr [RAX + RAX*0x1]
0x8fdcb0: MOV RAX, qword ptr [RDI + 0x10]
0x8fdcb4: TEST RAX, RAX
0x8fdcb7: JZ 0x008fdcc4
0x8fdcb9: CMP RDI, qword ptr [RAX + 0x8]
0x8fdcbd: MOV RDI, RAX
0x8fdcc0: JZ 0x008fdcb0
0x8fdcc2: JMP 0x008fdc9b
0x8fdcc4: XOR EAX, EAX
0x8fdcc6: POP RBP
0x8fdcc7: RET

; local helper / adjacent context (reachability below); evidence ev_51406acf2fb7ce312113bfaa5574a56b3f8029c228de7a447d88b326096166f7; body [{"start": "0x8fdcd8", "end": "0x8fdcfd"}]
adjacent_8fdcd8: ; RVA 0x8fdcd8
0x8fdcd8: PUSH RBP
0x8fdcd9: MOV RBP, RSP
0x8fdcdc: NOT ESI
0x8fdcde: SHR ESI, 0x1f
0x8fdce1: SHL ESI, 0x3
0x8fdce4: NOP word ptr CS:[RAX + RAX*0x1]
0x8fdcf0: MOV RAX, RCX
0x8fdcf3: MOV RCX, qword ptr [RCX + RSI*0x1]
0x8fdcf7: TEST RCX, RCX
0x8fdcfa: JNZ 0x008fdcf0
0x8fdcfc: POP RBP
0x8fdcfd: RET

; local helper / adjacent context (reachability below); evidence ev_fd1f094ae678fdd1f0e01ea17624385d555c25cb149820377955e45fade2a35e; body [{"start": "0x8fdd10", "end": "0x8fdd62"}, {"start": "0x8fdd70", "end": "0x8fde02"}, {"start": "0x8fde10", "end": "0x8fde6e"}]
adjacent_8fdd10: ; RVA 0x8fdd10
0x8fdd10: PUSH RBP
0x8fdd11: MOV RBP, RSP
0x8fdd14: PUSH R15
0x8fdd16: PUSH R14
0x8fdd18: PUSH R13
0x8fdd1a: PUSH R12
0x8fdd1c: PUSH RBX
0x8fdd1d: SUB RSP, 0x58
0x8fdd21: MOV R13, RSI
0x8fdd24: LEA RSI, [0x391c310]
0x8fdd2b: MOV RAX, qword ptr [RSI]
0x8fdd2e: MOV qword ptr [RBP + -0x30], RAX
0x8fdd32: MOV EAX, 0x1
0x8fdd37: MOV R14, qword ptr [RDI + 0x10]
0x8fdd3b: TEST R14, R14
0x8fdd3e: JZ 0x008fddb3
0x8fdd40: MOV R15, RDX
0x8fdd43: MOVZX EDX, word ptr [RDI + 0xa]
0x8fdd47: TEST RDX, RDX
0x8fdd4a: JZ 0x008fddb3
0x8fdd4c: SHL EDX, 0x3
0x8fdd4f: ADD R15, 0x8
0x8fdd53: MOV qword ptr [RBP + -0x78], RDI
0x8fdd57: MOV qword ptr [RBP + -0x80], RCX
0x8fdd5b: XOR EBX, EBX
0x8fdd5d: LEA R12, [RDX + RDX*0x2]
0x8fdd61: JMP 0x008fdd92
0x8fdd70: ADD RDI, 0x10
0x8fdd74: MOV EDX, 0x10
0x8fdd79: MOV RSI, R15
0x8fdd7c: CALL 0x00259080
0x8fdd81: TEST EAX, EAX
0x8fdd83: JZ 0x008fddcf
0x8fdd85: ADD R14, 0x8
0x8fdd89: ADD RBX, 0x18
0x8fdd8d: CMP R12D, EBX
0x8fdd90: JZ 0x008fdda7
0x8fdd92: MOV RDI, qword ptr [R14]
0x8fdd95: TEST RDI, RDI
0x8fdd98: JZ 0x008fdd85
0x8fdd9a: TEST R13, R13
0x8fdd9d: JZ 0x008fdd70
0x8fdd9f: CMP qword ptr [RDI + 0x20], R13
0x8fdda3: JNZ 0x008fdd85
0x8fdda5: JMP 0x008fdd70
0x8fdda7: LEA RSI, [0x391c310]
0x8fddae: MOV EAX, 0x1
0x8fddb3: MOV RCX, qword ptr [RSI]
0x8fddb6: CMP RCX, qword ptr [RBP + -0x30]
0x8fddba: JNZ 0x008fde68
0x8fddc0: ADD RSP, 0x58
0x8fddc4: POP RBX
0x8fddc5: POP R12
0x8fddc7: POP R13
0x8fddc9: POP R14
0x8fddcb: POP R15
0x8fddcd: POP RBP
0x8fddce: RET
0x8fddcf: MOV RAX, qword ptr [RBP + -0x78]
0x8fddd3: MOV RCX, qword ptr [RBP + -0x80]
0x8fddd7: LEA R14, [RBP + -0x50]
0x8fdddb: MOV RDI, R14
0x8fddde: MOV R12, qword ptr [RAX + 0x18]
0x8fdde2: MOV RAX, qword ptr [RCX + 0x8]
0x8fdde6: MOV RCX, qword ptr [RCX + 0x10]
0x8fddea: MOVZX R15D, byte ptr [R12 + RBX*0x1 + 0x11]
0x8fddf0: MOV qword ptr [RBP + -0x48], RCX
0x8fddf4: MOV qword ptr [RBP + -0x50], RAX
0x8fddf8: CALL 0x00b82870
0x8fddfd: MOV RBX, qword ptr [R12 + RBX*0x1]
0x8fde01: JMP 0x008fde17
0x8fde10: ADD RBX, 0x8
0x8fde14: MOV RBX, qword ptr [RBX]
0x8fde17: TEST RBX, RBX
0x8fde1a: JZ 0x008fde4b
0x8fde1c: LEA RSI, [RBX + 0x20]
0x8fde20: MOV EDX, 0x10
0x8fde25: MOV RDI, R14
0x8fde28: CALL 0x00339bd0
0x8fde2d: TEST EAX, EAX
0x8fde2f: JS 0x008fde14
0x8fde31: JNZ 0x008fde10
0x8fde33: LEA RSI, [0x391c310]
0x8fde3a: MOV EAX, 0x2
0x8fde3f: CMP byte ptr [RBX + 0x30], R15B
0x8fde43: JNZ 0x008fddb3
0x8fde49: JMP 0x008fde61
0x8fde4b: LEA RSI, [0x391c310]
0x8fde52: MOV EAX, 0x2
0x8fde57: CMP R15B, 0x1
0x8fde5b: JZ 0x008fddb3
0x8fde61: XOR EAX, EAX
0x8fde63: JMP 0x008fddb3
0x8fde68: CALL 0x006fd6b0
0x8fde6d: UD2

; local helper / adjacent context (reachability below); evidence ev_1c30186cf755d873f732df6e0b97139b300313ce2ac909680bacf1d82ab55585; body [{"start": "0x8fde70", "end": "0x8fdea6"}, {"start": "0x8fdeb0", "end": "0x8fdefa"}]
adjacent_8fde70: ; RVA 0x8fde70
0x8fde70: PUSH RBP
0x8fde71: MOV RBP, RSP
0x8fde74: PUSH R15
0x8fde76: PUSH R14
0x8fde78: PUSH R13
0x8fde7a: PUSH R12
0x8fde7c: PUSH RBX
0x8fde7d: PUSH RAX
0x8fde7e: MOV R15, qword ptr [RDI + 0x10]
0x8fde82: MOV RAX, -0x1
0x8fde89: TEST R15, R15
0x8fde8c: JZ 0x008fdeec
0x8fde8e: MOVZX R12D, word ptr [RDI + 0xa]
0x8fde93: TEST R12, R12
0x8fde96: JZ 0x008fdeec
0x8fde98: MOV RBX, RDX
0x8fde9b: MOV R14, RSI
0x8fde9e: XOR R13D, R13D
0x8fdea1: ADD RBX, 0x8
0x8fdea5: JMP 0x008fdecd
0x8fdeb0: ADD RDI, 0x10
0x8fdeb4: MOV EDX, 0x10
0x8fdeb9: MOV RSI, RBX
0x8fdebc: CALL 0x00259080
0x8fdec1: TEST EAX, EAX
0x8fdec3: JZ 0x008fdee9
0x8fdec5: INC R13
0x8fdec8: CMP R12D, R13D
0x8fdecb: JZ 0x008fdee3
0x8fdecd: MOV RDI, qword ptr [R15 + R13*0x8]
0x8fded1: TEST RDI, RDI
0x8fded4: JZ 0x008fdec5
0x8fded6: TEST R14, R14
0x8fded9: JZ 0x008fdeb0
0x8fdedb: CMP qword ptr [RDI + 0x20], R14
0x8fdedf: JNZ 0x008fdec5
0x8fdee1: JMP 0x008fdeb0
0x8fdee3: MOV R13D, 0xffffffff
0x8fdee9: MOVSXD RAX, R13D
0x8fdeec: ADD RSP, 0x8
0x8fdef0: POP RBX
0x8fdef1: POP R12
0x8fdef3: POP R13
0x8fdef5: POP R14
0x8fdef7: POP R15
0x8fdef9: POP RBP
0x8fdefa: RET

; local helper / adjacent context (reachability below); evidence ev_b5d986dc2973fd9329b20ef882efd356624611dec079edb172779f1da62fd255; body [{"start": "0x8fdf00", "end": "0x8fdf4b"}, {"start": "0x8fdf50", "end": "0x8fdf96"}]
adjacent_8fdf00: ; RVA 0x8fdf00
0x8fdf00: PUSH RBP
0x8fdf01: MOV RBP, RSP
0x8fdf04: PUSH R15
0x8fdf06: PUSH R14
0x8fdf08: PUSH R12
0x8fdf0a: PUSH RBX
0x8fdf0b: SUB RSP, 0x50
0x8fdf0f: LEA R15, [0x391c310]
0x8fdf16: MOV RAX, qword ptr [R15]
0x8fdf19: MOV qword ptr [RBP + -0x28], RAX
0x8fdf1d: MOV RBX, qword ptr [RDI + 0x18]
0x8fdf21: TEST RBX, RBX
0x8fdf24: JZ 0x008fdf75
0x8fdf26: MOV RAX, qword ptr [RDX + 0x8]
0x8fdf2a: MOV RCX, qword ptr [RDX + 0x10]
0x8fdf2e: LEA R14, [RBP + -0x48]
0x8fdf32: LEA R12, [RSI + RSI*0x2]
0x8fdf36: MOV RDI, R14
0x8fdf39: MOV qword ptr [RBP + -0x40], RCX
0x8fdf3d: MOV qword ptr [RBP + -0x48], RAX
0x8fdf41: CALL 0x00b82870
0x8fdf46: MOV RBX, qword ptr [RBX + R12*0x8]
0x8fdf4a: JMP 0x008fdf53
0x8fdf50: MOV RBX, qword ptr [RBX]
0x8fdf53: TEST RBX, RBX
0x8fdf56: JZ 0x008fdf75
0x8fdf58: LEA RSI, [RBX + 0x20]
0x8fdf5c: MOV EDX, 0x10
0x8fdf61: MOV RDI, R14
0x8fdf64: CALL 0x00339bd0
0x8fdf69: TEST EAX, EAX
0x8fdf6b: JS 0x008fdf50
0x8fdf6d: JZ 0x008fdf77
0x8fdf6f: ADD RBX, 0x8
0x8fdf73: JMP 0x008fdf50
0x8fdf75: XOR EBX, EBX
0x8fdf77: MOV RAX, qword ptr [R15]
0x8fdf7a: CMP RAX, qword ptr [RBP + -0x28]
0x8fdf7e: JNZ 0x008fdf90
0x8fdf80: MOV RAX, RBX
0x8fdf83: ADD RSP, 0x50
0x8fdf87: POP RBX
0x8fdf88: POP R12
0x8fdf8a: POP R14
0x8fdf8c: POP R15
0x8fdf8e: POP RBP
0x8fdf8f: RET
0x8fdf90: CALL 0x006fd6b0
0x8fdf95: UD2

; local helper / adjacent context (reachability below); evidence ev_bb1b5f554b545e244f436f5c38c48279e5b7f3102b3dc4345ef97c04aa0f58b0; body [{"start": "0x8fdfa0", "end": "0x8fdfa5"}]
FUN_008fdfa0: ; RVA 0x8fdfa0
0x8fdfa0: DEC dword ptr [RDI + 0x30]
0x8fdfa3: JZ 0x008fdfa6
0x8fdfa5: RET

; local helper / adjacent context (reachability below); evidence ev_a8a3ae9ce4b9a0c08377d581c8b966611c6775fc4940684616c55f74fea18a18; body [{"start": "0x8fdfa6", "end": "0x8fe03c"}, {"start": "0x8fe040", "end": "0x8fe0d6"}]
adjacent_8fdfa6: ; RVA 0x8fdfa6
0x8fdfa6: PUSH RBP
0x8fdfa7: MOV RBP, RSP
0x8fdfaa: PUSH R15
0x8fdfac: PUSH R14
0x8fdfae: PUSH R13
0x8fdfb0: PUSH R12
0x8fdfb2: PUSH RBX
0x8fdfb3: PUSH RAX
0x8fdfb4: MOV RAX, qword ptr [RDI + 0x28]
0x8fdfb8: MOV RBX, RDI
0x8fdfbb: MOV qword ptr [RAX + 0x30], 0x0
0x8fdfc3: MOV qword ptr [RBP + -0x30], RAX
0x8fdfc7: MOV RAX, qword ptr [RDI + 0x50]
0x8fdfcb: TEST RAX, RAX
0x8fdfce: JZ 0x008fe075
0x8fdfd4: LEA R15, [RBX + 0x50]
0x8fdfd8: NOP dword ptr [RAX + RAX*0x1]
0x8fdfe0: MOV R14, RAX
0x8fdfe3: MOV RAX, qword ptr [RAX]
0x8fdfe6: TEST RAX, RAX
0x8fdfe9: JNZ 0x008fdfe0
0x8fdfeb: LEA R13, [0x254f0a0]
0x8fdff2: JMP 0x008fe022
0x8fdff4: XOR R12D, R12D
0x8fdff7: NOP word ptr [RAX + RAX*0x1]
0x8fe000: MOV RDI, R15
0x8fe003: MOV RSI, R14
0x8fe006: CALL 0x008fd850
0x8fe00b: MOV RDI, R14
0x8fe00e: MOV RSI, R13
0x8fe011: CALL 0x00c08df0
0x8fe016: DEC qword ptr [RBX + 0x58]
0x8fe01a: MOV R14, R12
0x8fe01d: TEST R12, R12
0x8fe020: JZ 0x008fe075
0x8fe022: MOV RAX, qword ptr [R14 + 0x8]
0x8fe026: TEST RAX, RAX
0x8fe029: JZ 0x008fe040
0x8fe02b: NOP dword ptr [RAX + RAX*0x1]
0x8fe030: MOV R12, RAX
0x8fe033: MOV RAX, qword ptr [RAX]
0x8fe036: TEST RAX, RAX
0x8fe039: JNZ 0x008fe030
0x8fe03b: JMP 0x008fe000
0x8fe040: MOV R12, qword ptr [R14 + 0x10]
0x8fe044: TEST R12, R12
0x8fe047: JZ 0x008fe04f
0x8fe049: CMP R14, qword ptr [R12]
0x8fe04d: JZ 0x008fe000
0x8fe04f: MOV RAX, R14
0x8fe052: NOP word ptr CS:[RAX + RAX*0x1]
0x8fe060: MOV R12, qword ptr [RAX + 0x10]
0x8fe064: TEST R12, R12
0x8fe067: JZ 0x008fdff4
0x8fe069: CMP RAX, qword ptr [R12 + 0x8]
0x8fe06e: MOV RAX, R12
0x8fe071: JZ 0x008fe060
0x8fe073: JMP 0x008fe000
0x8fe075: MOV RDI, qword ptr [RBX + 0x60]
0x8fe079: LEA RAX, [RBX + 0x60]
0x8fe07d: MOV qword ptr [RBX + 0x60], 0x0
0x8fe085: MOV qword ptr [RBX + 0x68], RAX
0x8fe089: MOV dword ptr [RBX + 0x70], 0x0
0x8fe090: TEST RDI, RDI
0x8fe093: JZ 0x008fe0b1
0x8fe095: NOP dword ptr CS:[RAX + RAX*0x1]
0x8fe0a0: MOV R14, qword ptr [RDI + 0x8]
0x8fe0a4: CALL 0x0042a850
0x8fe0a9: MOV RDI, R14
0x8fe0ac: TEST R14, R14
0x8fe0af: JNZ 0x008fe0a0
0x8fe0b1: LEA RSI, [0x254f080]
0x8fe0b8: MOV RDI, RBX
0x8fe0bb: CALL 0x00c08df0
0x8fe0c0: MOV RDI, qword ptr [RBP + -0x30]
0x8fe0c4: ADD RSP, 0x8
0x8fe0c8: POP RBX
0x8fe0c9: POP R12
0x8fe0cb: POP R13
0x8fe0cd: POP R14
0x8fe0cf: POP R15
0x8fe0d1: POP RBP
0x8fe0d2: JMP 0x004bfb60

; local helper / adjacent context (reachability below); evidence ev_2449df965bcac8d07876523e47ee318441329000b0f6d02f7ce058c54005d109; body [{"start": "0x8fe0e9", "end": "0x8fe12c"}, {"start": "0x8fe130", "end": "0x8fe155"}]
adjacent_8fe0e9: ; RVA 0x8fe0e9
0x8fe0e9: PUSH RBP
0x8fe0ea: MOV RBP, RSP
0x8fe0ed: NOP dword ptr [RAX]
0x8fe0f0: MOV RCX, RAX
0x8fe0f3: MOV RAX, qword ptr [RAX]
0x8fe0f6: TEST RAX, RAX
0x8fe0f9: JNZ 0x008fe0f0
0x8fe0fb: NOP dword ptr [RAX + RAX*0x1]
0x8fe100: CMP byte ptr [RCX + 0x38], 0x0
0x8fe104: MOV RAX, RCX
0x8fe107: JZ 0x008fe114
0x8fe109: MOV byte ptr [RAX + 0x38], 0x0
0x8fe10d: DEC word ptr [RDI + 0x9e]
0x8fe114: MOV RDX, qword ptr [RAX + 0x8]
0x8fe118: TEST RDX, RDX
0x8fe11b: JZ 0x008fe130
0x8fe11d: NOP dword ptr [RAX]
0x8fe120: MOV RCX, RDX
0x8fe123: MOV RDX, qword ptr [RDX]
0x8fe126: TEST RDX, RDX
0x8fe129: JNZ 0x008fe120
0x8fe12b: JMP 0x008fe100
0x8fe130: MOV RCX, qword ptr [RAX + 0x10]
0x8fe134: TEST RCX, RCX
0x8fe137: JZ 0x008fe140
0x8fe139: CMP RAX, qword ptr [RCX]
0x8fe13c: JZ 0x008fe100
0x8fe13e: NOP
0x8fe140: MOV RCX, qword ptr [RAX + 0x10]
0x8fe144: TEST RCX, RCX
0x8fe147: JZ 0x008fe154
0x8fe149: CMP RAX, qword ptr [RCX + 0x8]
0x8fe14d: MOV RAX, RCX
0x8fe150: JZ 0x008fe140
0x8fe152: JMP 0x008fe100
0x8fe154: POP RBP
0x8fe155: RET

; local helper / adjacent context (reachability below); evidence ev_92fd1003ada597ce438867ce6622a15233e65c19f4865369547cffa61794dcc1; body [{"start": "0x8fe160", "end": "0x8fe19a"}, {"start": "0x8fe1a0", "end": "0x8fe223"}, {"start": "0x8fe230", "end": "0x8fe327"}]
adjacent_8fe160: ; RVA 0x8fe160
0x8fe160: PUSH RBP
0x8fe161: MOV RBP, RSP
0x8fe164: PUSH R15
0x8fe166: PUSH R14
0x8fe168: PUSH R13
0x8fe16a: PUSH R12
0x8fe16c: PUSH RBX
0x8fe16d: SUB RSP, 0x48
0x8fe171: LEA R15, [0x391c310]
0x8fe178: MOV RBX, RDI
0x8fe17b: LEA R12, [RBP + -0x50]
0x8fe17f: MOV RAX, qword ptr [R15]
0x8fe182: MOV qword ptr [RBP + -0x30], RAX
0x8fe186: MOV RAX, qword ptr [RSI]
0x8fe189: MOV RCX, qword ptr [RSI + 0x8]
0x8fe18d: MOV qword ptr [RBP + -0x48], RCX
0x8fe191: MOV qword ptr [RBP + -0x50], RAX
0x8fe195: MOV R14, qword ptr [RDI + 0x50]
0x8fe199: JMP 0x008fe1a3
0x8fe1a0: MOV R14, qword ptr [R14]
0x8fe1a3: TEST R14, R14
0x8fe1a6: JZ 0x008fe1c9
0x8fe1a8: LEA RSI, [R14 + 0x20]
0x8fe1ac: MOV EDX, 0x10
0x8fe1b1: MOV RDI, R12
0x8fe1b4: CALL 0x00339bd0
0x8fe1b9: TEST EAX, EAX
0x8fe1bb: JS 0x008fe1a0
0x8fe1bd: JZ 0x008fe285
0x8fe1c3: ADD R14, 0x8
0x8fe1c7: JMP 0x008fe1a0
0x8fe1c9: CMP qword ptr [RBX + 0x58], 0x200
0x8fe1d1: MOV EAX, 0xffffffe4
0x8fe1d6: JZ 0x008fe309
0x8fe1dc: LEA RSI, [0x254f0a0]
0x8fe1e3: MOV EDI, 0x40
0x8fe1e8: MOV EDX, 0x101
0x8fe1ed: CALL 0x00c08b50
0x8fe1f2: TEST RAX, RAX
0x8fe1f5: JZ 0x008fe292
0x8fe1fb: MOV RDX, qword ptr [R12]
0x8fe1ff: MOV RCX, qword ptr [R12 + 0x8]
0x8fe204: MOV R14, RAX
0x8fe207: LEA R15, [RBX + 0x50]
0x8fe20b: MOV qword ptr [R14 + 0x28], RCX
0x8fe20f: MOV qword ptr [R14 + 0x20], RDX
0x8fe213: MOV RAX, qword ptr [R15]
0x8fe216: TEST RAX, RAX
0x8fe219: JZ 0x008fe299
0x8fe21b: MOV R12, R14
0x8fe21e: ADD R12, 0x20
0x8fe222: JMP 0x008fe23d
0x8fe230: MOV RAX, qword ptr [R13]
0x8fe234: TEST RAX, RAX
0x8fe237: JZ 0x008fe2bd
0x8fe23d: LEA RSI, [RAX + 0x20]
0x8fe241: MOV EDX, 0x10
0x8fe246: MOV RDI, R12
0x8fe249: MOV R13, RAX
0x8fe24c: CALL 0x00339bd0
0x8fe251: TEST EAX, EAX
0x8fe253: JS 0x008fe230
0x8fe255: JZ 0x008fe2e7
0x8fe25b: MOV RAX, qword ptr [R13 + 0x8]
0x8fe25f: TEST RAX, RAX
0x8fe262: JNZ 0x008fe23d
0x8fe264: MOV qword ptr [R14 + 0x10], R13
0x8fe268: MOV qword ptr [R14 + 0x8], 0x0
0x8fe270: MOV qword ptr [R14], 0x0
0x8fe277: MOV dword ptr [R14 + 0x18], 0x1
0x8fe27f: MOV qword ptr [R13 + 0x8], R14
0x8fe283: JMP 0x008fe2dc
0x8fe285: XOR EAX, EAX
0x8fe287: CMP byte ptr [R14 + 0x38], 0x0
0x8fe28c: JNZ 0x008fe309
0x8fe28e: MOV AL, 0x1
0x8fe290: JMP 0x008fe2f9
0x8fe292: MOV EAX, 0xfffffff4
0x8fe297: JMP 0x008fe309
0x8fe299: MOV qword ptr [R14 + 0x10], 0x0
0x8fe2a1: MOV qword ptr [R14 + 0x8], 0x0
0x8fe2a9: MOV qword ptr [R14], 0x0
0x8fe2b0: MOV dword ptr [R14 + 0x18], 0x1
0x8fe2b8: MOV qword ptr [R15], R14
0x8fe2bb: JMP 0x008fe2dc
0x8fe2bd: MOV qword ptr [R14 + 0x10], R13
0x8fe2c1: MOV qword ptr [R14 + 0x8], 0x0
0x8fe2c9: MOV qword ptr [R14], 0x0
0x8fe2d0: MOV dword ptr [R14 + 0x18], 0x1
0x8fe2d8: MOV qword ptr [R13], R14
0x8fe2dc: MOV RDI, R15
0x8fe2df: MOV RSI, R14
0x8fe2e2: CALL 0x008fd670
0x8fe2e7: INC qword ptr [RBX + 0x58]
0x8fe2eb: LEA R15, [0x391c310]
0x8fe2f2: MOVZX EAX, byte ptr [R14 + 0x38]
0x8fe2f7: INC AL
0x8fe2f9: MOV byte ptr [R14 + 0x38], AL
0x8fe2fd: INC word ptr [RBX + 0x9e]
0x8fe304: MOV EAX, 0x1
0x8fe309: MOV RCX, qword ptr [R15]
0x8fe30c: CMP RCX, qword ptr [RBP + -0x30]
0x8fe310: JNZ 0x008fe321
0x8fe312: ADD RSP, 0x48
0x8fe316: POP RBX
0x8fe317: POP R12
0x8fe319: POP R13
0x8fe31b: POP R14
0x8fe31d: POP R15
0x8fe31f: POP RBP
0x8fe320: RET
0x8fe321: CALL 0x006fd6b0
0x8fe326: UD2

; local helper / adjacent context (reachability below); evidence ev_8095733cc2092fb3c228476b16eec6e2befa49b0506cbe39fc89c54480962450; body [{"start": "0x8fe330", "end": "0x8fe38c"}, {"start": "0x8fe390", "end": "0x8fe3d6"}]
adjacent_8fe330: ; RVA 0x8fe330
0x8fe330: PUSH RBP
0x8fe331: MOV RBP, RSP
0x8fe334: PUSH RBX
0x8fe335: PUSH RAX
0x8fe336: MOV RBX, RDI
0x8fe339: CALL 0x008fe3e0
0x8fe33e: MOV RCX, qword ptr [RBX + 0x50]
0x8fe342: TEST RCX, RCX
0x8fe345: JZ 0x008fe3b4
0x8fe347: NOP word ptr [RAX + RAX*0x1]
0x8fe350: MOV RAX, RCX
0x8fe353: MOV RCX, qword ptr [RCX]
0x8fe356: TEST RCX, RCX
0x8fe359: JNZ 0x008fe350
0x8fe35b: NOP dword ptr [RAX + RAX*0x1]
0x8fe360: MOV RCX, RAX
0x8fe363: MOV EAX, dword ptr [RAX + 0x34]
0x8fe366: MOV dword ptr [RCX + 0x30], EAX
0x8fe369: MOV RDX, qword ptr [RCX + 0x8]
0x8fe36d: TEST RDX, RDX
0x8fe370: JZ 0x008fe390
0x8fe372: NOP word ptr CS:[RAX + RAX*0x1]
0x8fe380: MOV RAX, RDX
0x8fe383: MOV RDX, qword ptr [RDX]
0x8fe386: TEST RDX, RDX
0x8fe389: JNZ 0x008fe380
0x8fe38b: JMP 0x008fe360
0x8fe390: MOV RAX, qword ptr [RCX + 0x10]
0x8fe394: TEST RAX, RAX
0x8fe397: JZ 0x008fe3a0
0x8fe399: CMP RCX, qword ptr [RAX]
0x8fe39c: JZ 0x008fe360
0x8fe39e: NOP
0x8fe3a0: MOV RAX, qword ptr [RCX + 0x10]
0x8fe3a4: TEST RAX, RAX
0x8fe3a7: JZ 0x008fe3b4
0x8fe3a9: CMP RCX, qword ptr [RAX + 0x8]
0x8fe3ad: MOV RCX, RAX
0x8fe3b0: JZ 0x008fe3a0
0x8fe3b2: JMP 0x008fe360
0x8fe3b4: MOVZX EAX, word ptr [RBX + 0x9e]
0x8fe3bb: MOV word ptr [RBX + 0x94], AX
0x8fe3c2: MOV RAX, qword ptr [RBX + 0x96]
0x8fe3c9: MOV qword ptr [RBX + 0x8c], RAX
0x8fe3d0: ADD RSP, 0x8
0x8fe3d4: POP RBX
0x8fe3d5: POP RBP
0x8fe3d6: RET

; local helper / adjacent context (reachability below); evidence ev_9b7f9c2f4baaad0eadad64f3691d731446339d3e6fc3d41e54b478f6d9d2f321; body [{"start": "0x8fe3e0", "end": "0x8fe575"}]
adjacent_8fe3e0: ; RVA 0x8fe3e0
0x8fe3e0: PUSH RBP
0x8fe3e1: MOV RBP, RSP
0x8fe3e4: PUSH R15
0x8fe3e6: PUSH R14
0x8fe3e8: PUSH R12
0x8fe3ea: PUSH RBX
0x8fe3eb: SUB RSP, 0x50
0x8fe3ef: LEA R15, [0x391c310]
0x8fe3f6: MOV RAX, qword ptr [R15]
0x8fe3f9: MOV qword ptr [RBP + -0x28], RAX
0x8fe3fd: TEST byte ptr [0x02bf8953], 0x10
0x8fe404: JZ 0x008fe559
0x8fe40a: MOV RBX, RDI
0x8fe40d: LEA RDI, [0x13405c2]
0x8fe414: LEA RSI, [0x12d8e6b]
0x8fe41b: XOR EAX, EAX
0x8fe41d: MOV RDX, RBX
0x8fe420: CALL 0x0025d410
0x8fe425: LEA RSI, [RBX + 0x10]
0x8fe429: LEA RDI, [RBP + -0x60]
0x8fe42d: CALL 0x00a85f90
0x8fe432: MOV RDX, qword ptr [RBX + 0x20]
0x8fe436: MOV R8, qword ptr [RBX + 0x28]
0x8fe43a: MOV RSI, RAX
0x8fe43d: LEA RDI, [0x139f081]
0x8fe444: XOR EAX, EAX
0x8fe446: LEA RCX, [RDX + 0x60]
0x8fe44a: CALL 0x0025d410
0x8fe44f: MOV EAX, dword ptr [RBX + 0x34]
0x8fe452: MOV ESI, dword ptr [RBX + 0x38]
0x8fe455: LEA R14, [0x139b8ec]
0x8fe45c: MOV RDX, R14
0x8fe45f: CMP RAX, 0x9
0x8fe463: JA 0x008fe473
0x8fe465: LEA RCX, [0x181cb34]
0x8fe46c: MOVSXD RDX, dword ptr [RCX + RAX*0x4]
0x8fe470: ADD RDX, RCX
0x8fe473: MOV ECX, dword ptr [RBX + 0x30]
0x8fe476: MOV R8D, dword ptr [RBX + 0x70]
0x8fe47a: LEA RDI, [0x1360c79]
0x8fe481: XOR EAX, EAX
0x8fe483: CALL 0x0025d410
0x8fe488: MOV RSI, qword ptr [RBX + 0x40]
0x8fe48c: MOV RDX, qword ptr [RBX + 0x58]
0x8fe490: MOVZX ECX, word ptr [RBX + 0x88]
0x8fe497: MOVZX R8D, word ptr [RBX + 0x8a]
0x8fe49f: LEA RDI, [0x12e2f31]
0x8fe4a6: XOR EAX, EAX
0x8fe4a8: CALL 0x0025d410
0x8fe4ad: MOVZX EAX, word ptr [RBX + 0x8c]
0x8fe4b4: LEA R12, [0xe8a5b0]
0x8fe4bb: MOV RDX, R14
0x8fe4be: CMP RAX, 0x2
0x8fe4c2: JA 0x008fe4c8
0x8fe4c4: MOV RDX, qword ptr [R12 + RAX*0x8]
0x8fe4c8: MOVZX ECX, word ptr [RBX + 0x8e]
0x8fe4cf: MOVZX R8D, word ptr [RBX + 0x90]
0x8fe4d7: MOVZX R9D, word ptr [RBX + 0x92]
0x8fe4df: MOVZX EAX, word ptr [RBX + 0x94]
0x8fe4e6: LEA RDI, [0x1316bb0]
0x8fe4ed: XOR ESI, ESI
0x8fe4ef: MOV dword ptr [RSP], EAX
0x8fe4f2: XOR EAX, EAX
0x8fe4f4: CALL 0x0025d410
0x8fe4f9: MOVZX EAX, word ptr [RBX + 0x96]
0x8fe500: CMP RAX, 0x2
0x8fe504: JA 0x008fe50a
0x8fe506: MOV R14, qword ptr [R12 + RAX*0x8]
0x8fe50a: MOVZX ECX, word ptr [RBX + 0x98]
0x8fe511: MOVZX R8D, word ptr [RBX + 0x9a]
0x8fe519: MOVZX R9D, word ptr [RBX + 0x9c]
0x8fe521: MOVZX EAX, word ptr [RBX + 0x9e]
0x8fe528: LEA RDI, [0x1316bb0]
0x8fe52f: MOV ESI, 0x1
0x8fe534: MOV RDX, R14
0x8fe537: MOV dword ptr [RSP], EAX
0x8fe53a: XOR EAX, EAX
0x8fe53c: CALL 0x0025d410
0x8fe541: LEA RDI, [0x129aa8e]
0x8fe548: LEA RSI, [0x12d8e6b]
0x8fe54f: MOV RDX, RBX
0x8fe552: XOR EAX, EAX
0x8fe554: CALL 0x0025d410
0x8fe559: MOV RAX, qword ptr [R15]
0x8fe55c: CMP RAX, qword ptr [RBP + -0x28]
0x8fe560: JNZ 0x008fe56f
0x8fe562: ADD RSP, 0x50
0x8fe566: POP RBX
0x8fe567: POP R12
0x8fe569: POP R14
0x8fe56b: POP R15
0x8fe56d: POP RBP
0x8fe56e: RET
0x8fe56f: CALL 0x006fd6b0
0x8fe574: UD2

; local helper / adjacent context (reachability below); evidence ev_50fa97aab5f869cc6455b0d1e09070ea58de8218c2c4f317b9e8bd6171251bd9; body [{"start": "0x8fe580", "end": "0x8fe634"}]
adjacent_8fe580: ; RVA 0x8fe580
0x8fe580: PUSH RBP
0x8fe581: MOV RBP, RSP
0x8fe584: PUSH R15
0x8fe586: PUSH R14
0x8fe588: PUSH R13
0x8fe58a: PUSH R12
0x8fe58c: PUSH RBX
0x8fe58d: PUSH RAX
0x8fe58e: MOV R14, RDX
0x8fe591: MOV R15, RSI
0x8fe594: MOV R12, RDI
0x8fe597: LEA RSI, [0x254f080]
0x8fe59e: MOV EDI, 0x18
0x8fe5a3: MOV EDX, 0x1
0x8fe5a8: MOV R13D, ECX
0x8fe5ab: CALL 0x00c08b50
0x8fe5b0: TEST RAX, RAX
0x8fe5b3: JZ 0x008fe61a
0x8fe5b5: MOV RBX, RAX
0x8fe5b8: LEA EAX, [R13 + R13*0x4]
0x8fe5bd: LEA RDI, [0x3b5c040]
0x8fe5c4: XOR ESI, ESI
0x8fe5c6: XOR ECX, ECX
0x8fe5c8: CDQ
0x8fe5c9: IDIV dword ptr [0x03920440]
0x8fe5cf: XOR EDX, EDX
0x8fe5d1: MOV R13D, EAX
0x8fe5d4: CALL 0x004c6a00
0x8fe5d9: MOV RDI, R12
0x8fe5dc: MOV RSI, R15
0x8fe5df: MOV RCX, RBX
0x8fe5e2: MOV R8D, R13D
0x8fe5e5: XOR EDX, EDX
0x8fe5e7: CALL 0x008fe7b0
0x8fe5ec: LEA RDI, [0x3b5c040]
0x8fe5f3: MOV R15D, EAX
0x8fe5f6: XOR ESI, ESI
0x8fe5f8: XOR EDX, EDX
0x8fe5fa: XOR ECX, ECX
0x8fe5fc: CALL 0x004c6fa0
0x8fe601: TEST R15D, R15D
0x8fe604: JZ 0x008fe623
0x8fe606: LEA RSI, [0x254f080]
0x8fe60d: MOV RDI, RBX
0x8fe610: MOV dword ptr [R14], R15D
0x8fe613: CALL 0x00c08df0
0x8fe618: JMP 0x008fe621
0x8fe61a: MOV dword ptr [R14], 0x37
0x8fe621: XOR EBX, EBX
0x8fe623: MOV RAX, RBX
0x8fe626: ADD RSP, 0x8
0x8fe62a: POP RBX
0x8fe62b: POP R12
0x8fe62d: POP R13
0x8fe62f: POP R14
0x8fe631: POP R15
0x8fe633: POP RBP
0x8fe634: RET

; local helper / adjacent context (reachability below); evidence ev_ab35d0dbd9e02967246c346477c15cb9342c2ee74d8137abbbd81e015be38859; body [{"start": "0x8fe640", "end": "0x8fe6fa"}]
adjacent_8fe640: ; RVA 0x8fe640
0x8fe640: PUSH RBP
0x8fe641: MOV RBP, RSP
0x8fe644: PUSH R15
0x8fe646: PUSH R14
0x8fe648: PUSH R13
0x8fe64a: PUSH R12
0x8fe64c: PUSH RBX
0x8fe64d: SUB RSP, 0x28
0x8fe651: LEA R12, [0x391c310]
0x8fe658: MOV RAX, qword ptr [R12]
0x8fe65c: MOV qword ptr [RBP + -0x30], RAX
0x8fe660: MOV RBX, qword ptr [RDI]
0x8fe663: TEST RBX, RBX
0x8fe666: JZ 0x008fe6cd
0x8fe668: LEA R14, [0x3b5c040]
0x8fe66f: MOV R13, RDI
0x8fe672: XOR ESI, ESI
0x8fe674: XOR EDX, EDX
0x8fe676: XOR ECX, ECX
0x8fe678: MOV RDI, R14
0x8fe67b: CALL 0x004c6a00
0x8fe680: LEA R15, [RBP + -0x48]
0x8fe684: MOV ESI, 0x18
0x8fe689: MOV RDI, R15
0x8fe68c: CALL 0x00258ff0
0x8fe691: MOV RDI, RBX
0x8fe694: MOV RSI, R15
0x8fe697: MOV qword ptr [RBP + -0x48], 0x0
0x8fe69f: MOV word ptr [RBP + -0x38], 0x2
0x8fe6a5: CALL 0x008fea20
0x8fe6aa: MOV RDI, RBX
0x8fe6ad: XOR ESI, ESI
0x8fe6af: CALL 0x006a5650
0x8fe6b4: MOV RDI, RBX
0x8fe6b7: CALL 0x008fdfa0
0x8fe6bc: MOV RDI, R14
0x8fe6bf: XOR ESI, ESI
0x8fe6c1: XOR EDX, EDX
0x8fe6c3: XOR ECX, ECX
0x8fe6c5: CALL 0x004c6fa0
0x8fe6ca: MOV RDI, R13
0x8fe6cd: LEA RSI, [0x254f080]
0x8fe6d4: CALL 0x00c08df0
0x8fe6d9: MOV RAX, qword ptr [R12]
0x8fe6dd: CMP RAX, qword ptr [RBP + -0x30]
0x8fe6e1: JNZ 0x008fe6f4
0x8fe6e3: XOR EAX, EAX
0x8fe6e5: ADD RSP, 0x28
0x8fe6e9: POP RBX
0x8fe6ea: POP R12
0x8fe6ec: POP R13
0x8fe6ee: POP R14
0x8fe6f0: POP R15
0x8fe6f2: POP RBP
0x8fe6f3: RET
0x8fe6f4: CALL 0x006fd6b0
0x8fe6f9: UD2

; local helper / adjacent context (reachability below); evidence ev_c8637b38f72633cf899686c1cd5ea1b49783af128220b06f249a082fdf613c95; body [{"start": "0x8fe700", "end": "0x8fe7a6"}]
adjacent_8fe700: ; RVA 0x8fe700
0x8fe700: PUSH RBP
0x8fe701: MOV RBP, RSP
0x8fe704: PUSH R15
0x8fe706: PUSH R14
0x8fe708: PUSH RBX
0x8fe709: SUB RSP, 0x28
0x8fe70d: LEA R15, [0x391c310]
0x8fe714: MOV RBX, RDI
0x8fe717: LEA RDI, [0x3b5c040]
0x8fe71e: MOV R14, RSI
0x8fe721: XOR ESI, ESI
0x8fe723: XOR EDX, EDX
0x8fe725: XOR ECX, ECX
0x8fe727: MOV RAX, qword ptr [R15]
0x8fe72a: MOV qword ptr [RBP + -0x20], RAX
0x8fe72e: CALL 0x004c6a00
0x8fe733: TEST R14, R14
0x8fe736: JNZ 0x008fe757
0x8fe738: LEA R14, [RBP + -0x38]
0x8fe73c: MOV ESI, 0x18
0x8fe741: MOV RDI, R14
0x8fe744: CALL 0x00258ff0
0x8fe749: MOV qword ptr [RBP + -0x38], 0x0
0x8fe751: MOV word ptr [RBP + -0x28], 0x2
0x8fe757: MOV RDI, RBX
0x8fe75a: MOV RSI, R14
0x8fe75d: CALL 0x008fea20
0x8fe762: MOV RDI, RBX
0x8fe765: XOR ESI, ESI
0x8fe767: CALL 0x006a5650
0x8fe76c: MOV RDI, RBX
0x8fe76f: MOV R14D, EAX
0x8fe772: CALL 0x008fdfa0
0x8fe777: LEA RDI, [0x3b5c040]
0x8fe77e: XOR ESI, ESI
0x8fe780: XOR EDX, EDX
0x8fe782: XOR ECX, ECX
0x8fe784: CALL 0x004c6fa0
0x8fe789: MOV RAX, qword ptr [R15]
0x8fe78c: CMP RAX, qword ptr [RBP + -0x20]
0x8fe790: JNZ 0x008fe7a0
0x8fe792: MOV EAX, R14D
0x8fe795: ADD RSP, 0x28
0x8fe799: POP RBX
0x8fe79a: POP R14
0x8fe79c: POP R15
0x8fe79e: POP RBP
0x8fe79f: RET
0x8fe7a0: CALL 0x006fd6b0
0x8fe7a5: UD2

; local helper / adjacent context (reachability below); evidence ev_6f11c361947793b9000661eb9577898cf95e7f2c15bbab18c29d8081a22d6ee7; body [{"start": "0x8fe7b0", "end": "0x8fe826"}, {"start": "0x8fe830", "end": "0x8fea16"}]
adjacent_8fe7b0: ; RVA 0x8fe7b0
0x8fe7b0: PUSH RBP
0x8fe7b1: MOV RBP, RSP
0x8fe7b4: PUSH R15
0x8fe7b6: PUSH R14
0x8fe7b8: PUSH R13
0x8fe7ba: PUSH R12
0x8fe7bc: PUSH RBX
0x8fe7bd: SUB RSP, 0x68
0x8fe7c1: LEA RAX, [0x391c310]
0x8fe7c8: MOV dword ptr [RBP + -0x74], R8D
0x8fe7cc: MOV qword ptr [RBP + -0x80], RCX
0x8fe7d0: MOV R14, RDX
0x8fe7d3: MOV RBX, RSI
0x8fe7d6: MOV R13, RDI
0x8fe7d9: MOV RAX, qword ptr [RAX]
0x8fe7dc: MOV qword ptr [RBP + -0x30], RAX
0x8fe7e0: TEST RDX, RDX
0x8fe7e3: JNZ 0x008fe804
0x8fe7e5: LEA R14, [RBP + -0x68]
0x8fe7e9: MOV ESI, 0x18
0x8fe7ee: MOV RDI, R14
0x8fe7f1: CALL 0x00258ff0
0x8fe7f6: MOV qword ptr [RBP + -0x68], 0x0
0x8fe7fe: MOV word ptr [RBP + -0x58], 0x200
0x8fe804: LEA R12, [R13 + 0x278]
0x8fe80b: MOV qword ptr [RBP + -0x88], R14
0x8fe812: XOR ESI, ESI
0x8fe814: XOR EDX, EDX
0x8fe816: MOV RDI, R12
0x8fe819: CALL 0x007d46a0
0x8fe81e: MOV R15, qword ptr [R13 + 0x290]
0x8fe825: JMP 0x008fe833
0x8fe830: MOV R15, qword ptr [R15]
0x8fe833: TEST R15, R15
0x8fe836: JZ 0x008fe860
0x8fe838: MOV RAX, qword ptr [R15 + 0x10]
0x8fe83c: CMP byte ptr [RAX + 0x1], 0x1c
0x8fe840: JNZ 0x008fe830
0x8fe842: MOV R14, qword ptr [R15 + 0x30]
0x8fe846: MOV EDX, 0x10
0x8fe84b: MOV RSI, RBX
0x8fe84e: LEA RDI, [R14 + 0x10]
0x8fe852: CALL 0x00259080
0x8fe857: TEST EAX, EAX
0x8fe859: JNZ 0x008fe830
0x8fe85b: TEST R14, R14
0x8fe85e: JNZ 0x008fe8c5
0x8fe860: LEA R14, [RBP + -0x4c]
0x8fe864: MOV ESI, 0x1c
0x8fe869: MOV RDI, R14
0x8fe86c: CALL 0x00258ff0
0x8fe871: MOV word ptr [RBP + -0x4c], 0x1c1c
0x8fe877: MOV RDI, R12
0x8fe87a: XOR ESI, ESI
0x8fe87c: XOR EDX, EDX
0x8fe87e: MOV RAX, qword ptr [RBX]
0x8fe881: MOV RCX, qword ptr [RBX + 0x8]
0x8fe885: MOV qword ptr [RBP + -0x44], RAX
0x8fe889: MOV qword ptr [RBP + -0x3c], RCX
0x8fe88d: CALL 0x007d4eb0
0x8fe892: LEA RDX, [RBP + -0x70]
0x8fe896: MOV RDI, R13
0x8fe899: MOV RSI, R14
0x8fe89c: CALL 0x004be540
0x8fe8a1: MOV R15D, EAX
0x8fe8a4: TEST EAX, EAX
0x8fe8a6: JNZ 0x008fe921
0x8fe8a8: MOV RDI, R12
0x8fe8ab: XOR ESI, ESI
0x8fe8ad: XOR EDX, EDX
0x8fe8af: CALL 0x007d46a0
0x8fe8b4: MOV RAX, qword ptr [RBP + -0x70]
0x8fe8b8: MOV R14, qword ptr [RAX + 0x30]
0x8fe8bc: TEST R14, R14
0x8fe8bf: JZ 0x008fe947
0x8fe8c5: INC dword ptr [R14 + 0x30]
0x8fe8c9: MOV RDI, R12
0x8fe8cc: XOR ESI, ESI
0x8fe8ce: XOR EDX, EDX
0x8fe8d0: CALL 0x007d4eb0
0x8fe8d5: CMP dword ptr [R14 + 0x34], 0x9
0x8fe8da: JNZ 0x008fe8f0
0x8fe8dc: MOV word ptr [R14 + 0x8c], 0x0
0x8fe8e6: MOV word ptr [R14 + 0x96], 0x0
0x8fe8f0: MOV RSI, qword ptr [RBP + -0x88]
0x8fe8f7: MOV RDI, R14
0x8fe8fa: CALL 0x008fea20
0x8fe8ff: TEST EAX, EAX
0x8fe901: JNZ 0x008fe916
0x8fe903: MOV ESI, dword ptr [RBP + -0x74]
0x8fe906: MOV RDI, R14
0x8fe909: CALL 0x006a5650
0x8fe90e: TEST EAX, EAX
0x8fe910: JZ 0x008fe9e1
0x8fe916: MOV RDI, R14
0x8fe919: MOV R15D, EAX
0x8fe91c: CALL 0x008fdfa0
0x8fe921: LEA RAX, [0x391c310]
0x8fe928: MOV RAX, qword ptr [RAX]
0x8fe92b: CMP RAX, qword ptr [RBP + -0x30]
0x8fe92f: JNZ 0x008fea10
0x8fe935: MOV EAX, R15D
0x8fe938: ADD RSP, 0x68
0x8fe93c: POP RBX
0x8fe93d: POP R12
0x8fe93f: POP R13
0x8fe941: POP R14
0x8fe943: POP R15
0x8fe945: POP RBP
0x8fe946: RET
0x8fe947: LEA RSI, [0x254f080]
0x8fe94e: MOV EDI, 0xa0
0x8fe953: MOV EDX, 0x101
0x8fe958: CALL 0x00c08b50
0x8fe95d: TEST RAX, RAX
0x8fe960: JZ 0x008fe9f0
0x8fe966: MOV RDX, qword ptr [RBX]
0x8fe969: MOV RCX, qword ptr [RBX + 0x8]
0x8fe96d: MOV R14, RAX
0x8fe970: MOV RSI, qword ptr [RBP + -0x70]
0x8fe974: MOV qword ptr [R14 + 0x18], RCX
0x8fe978: MOV qword ptr [R14 + 0x10], RDX
0x8fe97c: MOV qword ptr [R14 + 0x20], R13
0x8fe980: MOV RCX, R14
0x8fe983: MOV RDX, 0x1800000000
0x8fe98d: MOV RAX, qword ptr [R13 + 0x3b8]
0x8fe994: ADD RCX, 0x60
0x8fe998: MOV RAX, qword ptr [RAX + 0x28]
0x8fe99c: MOV qword ptr [R14 + 0x40], RAX
0x8fe9a0: MOV qword ptr [R14 + 0x28], RSI
0x8fe9a4: MOV qword ptr [R14 + 0x30], 0x1
0x8fe9ac: MOV qword ptr [R14 + 0x60], 0x0
0x8fe9b4: MOV qword ptr [R14 + 0x68], RCX
0x8fe9b8: MOV qword ptr [R14 + 0x70], RDX
0x8fe9bc: MOV word ptr [R14 + 0x8c], 0x0
0x8fe9c6: MOV word ptr [R14 + 0x96], 0x0
0x8fe9d0: MOV qword ptr [R14 + 0x50], 0x0
0x8fe9d8: MOV qword ptr [RSI + 0x30], R14
0x8fe9dc: JMP 0x008fe8c9
0x8fe9e1: MOV RAX, qword ptr [RBP + -0x80]
0x8fe9e5: XOR R15D, R15D
0x8fe9e8: MOV qword ptr [RAX], R14
0x8fe9eb: JMP 0x008fe921
0x8fe9f0: MOV RDI, R12
0x8fe9f3: XOR ESI, ESI
0x8fe9f5: XOR EDX, EDX
0x8fe9f7: CALL 0x007d4eb0
0x8fe9fc: MOV RDI, qword ptr [RBP + -0x70]
0x8fea00: CALL 0x004bfb60
0x8fea05: MOV R15D, 0xc
0x8fea0b: JMP 0x008fe921
0x8fea10: CALL 0x006fd6b0
0x8fea15: UD2

; local helper / adjacent context (reachability below); evidence ev_824c23684a26e5f6f19e41f14177507d13c43dd6459100a67386844580943c9a; body [{"start": "0x8fea20", "end": "0x8feac4"}, {"start": "0x8fead0", "end": "0x8feb05"}, {"start": "0x8feb10", "end": "0x8feb39"}, {"start": "0x8feb40", "end": "0x8feb9a"}, {"start": "0x8feba0", "end": "0x8fed02"}, {"start": "0x8fed10", "end": "0x8fee73"}, {"start": "0x8fee80", "end": "0x8feef4"}, {"start": "0x8fef00", "end": "0x8fefeb"}, {"start": "0x8feff0", "end": "0x8ff034"}, {"start": "0x8ff040", "end": "0x8ff0a8"}]
adjacent_8fea20: ; RVA 0x8fea20
0x8fea20: PUSH RBP
0x8fea21: MOV RBP, RSP
0x8fea24: PUSH R15
0x8fea26: PUSH R14
0x8fea28: PUSH R13
0x8fea2a: PUSH R12
0x8fea2c: PUSH RBX
0x8fea2d: SUB RSP, 0x78
0x8fea31: LEA RAX, [0x391c310]
0x8fea38: MOV RBX, RDI
0x8fea3b: MOV RAX, qword ptr [RAX]
0x8fea3e: MOV qword ptr [RBP + -0x30], RAX
0x8fea42: MOV qword ptr [RBP + -0x90], RDI
0x8fea49: MOV RCX, qword ptr [RSI]
0x8fea4c: TEST RCX, RCX
0x8fea4f: JZ 0x008fed52
0x8fea55: NOP dword ptr CS:[RAX + RAX*0x1]
0x8fea60: MOV RAX, RCX
0x8fea63: MOV RCX, qword ptr [RCX]
0x8fea66: TEST RCX, RCX
0x8fea69: JNZ 0x008fea60
0x8fea6b: LEA RCX, [RBX + 0x50]
0x8fea6f: XOR EDI, EDI
0x8fea71: XOR EDX, EDX
0x8fea73: MOV dword ptr [RBP + -0x78], 0x0
0x8fea7a: MOV qword ptr [RBP + -0x98], RSI
0x8fea81: MOV qword ptr [RBP + -0x80], RCX
0x8fea85: NOP dword ptr CS:[RAX + RAX*0x1]
0x8fea90: MOV R12, RAX
0x8fea93: MOVZX EAX, byte ptr [RAX + 0x30]
0x8fea97: XOR R14D, R14D
0x8fea9a: CMP AL, byte ptr [RSI + 0x10]
0x8fea9d: MOVZX ECX, byte ptr [R12 + 0x31]
0x8feaa3: SETZ byte ptr [RBP + -0x72]
0x8feaa7: CMP CL, byte ptr [RSI + 0x11]
0x8feaaa: SETZ byte ptr [RBP + -0x71]
0x8feaae: CMP AL, CL
0x8feab0: JNZ 0x008fead0
0x8feab2: MOVZX ECX, byte ptr [RBP + -0x71]
0x8feab6: MOVZX R8D, byte ptr [RBP + -0x72]
0x8feabb: MOV R13, R15
0x8feabe: XOR EAX, EAX
0x8feac0: JMP 0x008fecd1
0x8fead0: MOV RCX, qword ptr [R12 + 0x28]
0x8fead5: MOV dword ptr [RBP + -0x84], EDX
0x8feadb: MOV RSI, qword ptr [R12 + 0x20]
0x8feae0: LEA RDX, [RBP + -0x50]
0x8feae4: LEA RAX, [R12 + 0x20]
0x8feae9: MOV dword ptr [RBP + -0x88], EDI
0x8feaef: MOV qword ptr [RBP + -0xa0], RAX
0x8feaf6: MOV qword ptr [RDX + 0x8], RCX
0x8feafa: MOV RCX, qword ptr [RBP + -0x80]
0x8feafe: MOV qword ptr [RDX], RSI
0x8feb01: MOV R13, qword ptr [RCX]
0x8feb04: JMP 0x008feb18
0x8feb10: ADD R13, 0x8
0x8feb14: MOV R13, qword ptr [R13]
0x8feb18: TEST R13, R13
0x8feb1b: JZ 0x008feb40
0x8feb1d: LEA RSI, [R13 + 0x20]
0x8feb21: MOV EDX, 0x10
0x8feb26: LEA RDI, [RBP + -0x50]
0x8feb2a: CALL 0x00339bd0
0x8feb2f: TEST EAX, EAX
0x8feb31: JS 0x008feb14
0x8feb33: JNZ 0x008feb10
0x8feb35: JMP 0x008fec4c
0x8feb40: CMP qword ptr [RBX + 0x58], 0x200
0x8feb48: JZ 0x008fef65
0x8feb4e: MOV EDI, 0x40
0x8feb53: LEA RSI, [0x254f0a0]
0x8feb5a: MOV EDX, 0x101
0x8feb5f: CALL 0x00c08b50
0x8feb64: TEST RAX, RAX
0x8feb67: JZ 0x008fef6d
0x8feb6d: MOV RCX, qword ptr [RBP + -0xa0]
0x8feb74: MOV R13, RAX
0x8feb77: MOV RDI, qword ptr [RBP + -0x80]
0x8feb7b: MOV RAX, qword ptr [RCX]
0x8feb7e: MOV RCX, qword ptr [RCX + 0x8]
0x8feb82: MOV qword ptr [R13 + 0x28], RCX
0x8feb86: MOV qword ptr [R13 + 0x20], RAX
0x8feb8a: MOV RAX, qword ptr [RDI]
0x8feb8d: TEST RAX, RAX
0x8feb90: JZ 0x008febf1
0x8feb92: MOV R15, R13
0x8feb95: ADD R15, 0x20
0x8feb99: JMP 0x008feba8
0x8feba0: MOV RAX, qword ptr [RBX]
0x8feba3: TEST RAX, RAX
0x8feba6: JZ 0x008fec16
0x8feba8: LEA RSI, [RAX + 0x20]
0x8febac: MOV EDX, 0x10
0x8febb1: MOV RDI, R15
0x8febb4: MOV RBX, RAX
0x8febb7: CALL 0x00339bd0
0x8febbc: TEST EAX, EAX
0x8febbe: JS 0x008feba0
0x8febc0: JZ 0x008fec41
0x8febc2: MOV RAX, qword ptr [RBX + 0x8]
0x8febc6: TEST RAX, RAX
0x8febc9: JNZ 0x008feba8
0x8febcb: MOV RDI, qword ptr [RBP + -0x80]
0x8febcf: MOV qword ptr [R13 + 0x10], RBX
0x8febd3: MOV qword ptr [R13 + 0x8], 0x0
0x8febdb: MOV qword ptr [R13], 0x0
0x8febe3: MOV dword ptr [R13 + 0x18], 0x1
0x8febeb: MOV qword ptr [RBX + 0x8], R13
0x8febef: JMP 0x008fec39
0x8febf1: MOV qword ptr [R13 + 0x10], 0x0
0x8febf9: MOV qword ptr [R13 + 0x8], 0x0
0x8fec01: MOV qword ptr [R13], 0x0
0x8fec09: MOV dword ptr [R13 + 0x18], 0x1
0x8fec11: MOV qword ptr [RDI], R13
0x8fec14: JMP 0x008fec39
0x8fec16: MOV RDI, qword ptr [RBP + -0x80]
0x8fec1a: MOV qword ptr [R13 + 0x10], RBX
0x8fec1e: MOV qword ptr [R13 + 0x8], 0x0
0x8fec26: MOV qword ptr [R13], 0x0
0x8fec2e: MOV dword ptr [R13 + 0x18], 0x1
0x8fec36: MOV qword ptr [RBX], R13
0x8fec39: MOV RSI, R13
0x8fec3c: CALL 0x008fd670
0x8fec41: MOV RBX, qword ptr [RBP + -0x90]
0x8fec48: INC qword ptr [RBX + 0x58]
0x8fec4c: MOV RSI, qword ptr [RBP + -0xa0]
0x8fec53: LEA RDI, [RBP + -0x70]
0x8fec57: CALL 0x00a85f90
0x8fec5c: MOVZX EAX, byte ptr [R12 + 0x30]
0x8fec62: MOVZX R8D, byte ptr [RBP + -0x72]
0x8fec67: CMP EAX, 0x1
0x8fec6a: JZ 0x008fec8f
0x8fec6c: MOV RSI, qword ptr [RBP + -0x98]
0x8fec73: MOV EDI, dword ptr [RBP + -0x88]
0x8fec79: MOV EDX, dword ptr [RBP + -0x84]
0x8fec7f: MOVZX ECX, byte ptr [RBP + -0x71]
0x8fec83: CMP EAX, 0x2
0x8fec86: JNZ 0x008fecab
0x8fec88: DEC word ptr [R13 + 0x34]
0x8fec8d: JMP 0x008fecab
0x8fec8f: DEC word ptr [R13 + 0x36]
0x8fec94: MOV RSI, qword ptr [RBP + -0x98]
0x8fec9b: MOV EDI, dword ptr [RBP + -0x88]
0x8feca1: MOV EDX, dword ptr [RBP + -0x84]
0x8feca7: MOVZX ECX, byte ptr [RBP + -0x71]
0x8fecab: MOVZX EAX, byte ptr [R12 + 0x31]
0x8fecb1: CMP EAX, 0x1
0x8fecb4: JZ 0x008fecc7
0x8fecb6: CMP EAX, 0x2
0x8fecb9: MOV EAX, 0x0
0x8fecbe: JNZ 0x008fecce
0x8fecc0: INC word ptr [R13 + 0x34]
0x8fecc5: JMP 0x008fecce
0x8fecc7: INC word ptr [R13 + 0x36]
0x8feccc: XOR EAX, EAX
0x8fecce: INC dword ptr [RBP + -0x78]
0x8fecd1: MOV AL, CL
0x8fecd3: MOV RCX, qword ptr [R12 + 0x8]
0x8fecd8: MOV R14B, R8B
0x8fecdb: ADD EDX, R14D
0x8fecde: ADD EDI, EAX
0x8fece0: TEST RCX, RCX
0x8fece3: JZ 0x008fed10
0x8fece5: NOP dword ptr CS:[RAX + RAX*0x1]
0x8fecf0: MOV RAX, RCX
0x8fecf3: MOV RCX, qword ptr [RCX]
0x8fecf6: TEST RCX, RCX
0x8fecf9: JNZ 0x008fecf0
0x8fecfb: MOV R15, R13
0x8fecfe: JMP 0x008fea90
0x8fed10: MOV RAX, qword ptr [R12 + 0x10]
0x8fed15: TEST RAX, RAX
0x8fed18: JZ 0x008fed30
0x8fed1a: MOV R15, R13
0x8fed1d: CMP R12, qword ptr [RAX]
0x8fed20: JZ 0x008fea90
0x8fed26: NOP word ptr CS:[RAX + RAX*0x1]
0x8fed30: MOV RAX, qword ptr [R12 + 0x10]
0x8fed35: TEST RAX, RAX
0x8fed38: JZ 0x008fed4b
0x8fed3a: CMP R12, qword ptr [RAX + 0x8]
0x8fed3e: MOV R12, RAX
0x8fed41: JZ 0x008fed30
0x8fed43: MOV R15, R13
0x8fed46: JMP 0x008fea90
0x8fed4b: TEST EDX, EDX
0x8fed4d: SETZ AL
0x8fed50: JMP 0x008fed5d
0x8fed52: MOV AL, 0x1
0x8fed54: MOV dword ptr [RBP + -0x78], 0x0
0x8fed5b: XOR EDI, EDI
0x8fed5d: MOVZX EDX, byte ptr [RSI + 0x10]
0x8fed61: MOVZX ECX, byte ptr [RSI + 0x11]
0x8fed65: CMP DL, CL
0x8fed67: JNZ 0x008fed81
0x8fed69: CMP DL, 0x1
0x8fed6c: JNZ 0x008fedc2
0x8fed6e: TEST EDI, EDI
0x8fed70: JNZ 0x008fedc2
0x8fed72: DEC word ptr [RBX + 0x9c]
0x8fed79: MOVZX EDX, byte ptr [RSI + 0x10]
0x8fed7d: MOVZX ECX, byte ptr [RSI + 0x11]
0x8fed81: CMP DL, CL
0x8fed83: JZ 0x008fedc2
0x8fed85: CMP DL, 0x2
0x8fed88: JZ 0x008fed99
0x8fed8a: MOVZX EDX, DL
0x8fed8d: CMP EDX, 0x1
0x8fed90: JNZ 0x008feda6
0x8fed92: MOV ECX, 0x9c
0x8fed97: JMP 0x008fed9e
0x8fed99: MOV ECX, 0x9a
0x8fed9e: DEC word ptr [RBX + RCX*0x1]
0x8feda2: MOVZX ECX, byte ptr [RSI + 0x11]
0x8feda6: MOV EDX, 0x9a
0x8fedab: CMP CL, 0x2
0x8fedae: JZ 0x008fedbe
0x8fedb0: CMP CL, 0x1
0x8fedb3: JNZ 0x008fedc2
0x8fedb5: MOV EDX, 0x9c
0x8fedba: TEST EDI, EDI
0x8fedbc: JLE 0x008fedc2
0x8fedbe: INC word ptr [RBX + RDX*0x1]
0x8fedc2: CMP word ptr [RBX + 0x9a], 0x0
0x8fedca: MOV CX, 0x2
0x8fedce: JNZ 0x008feddd
0x8fedd0: XOR ECX, ECX
0x8fedd2: CMP word ptr [RBX + 0x9c], 0x0
0x8fedda: SETNZ CL
0x8feddd: MOV word ptr [RBX + 0x96], CX
0x8fede4: CMP byte ptr [RSI + 0x10], 0x2
0x8fede8: MOVZX ECX, byte ptr [RSI + 0x11]
0x8fedec: SETZ DL
0x8fedef: AND DL, AL
0x8fedf1: CMP DL, 0x1
0x8fedf4: JNZ 0x008fee0c
0x8fedf6: CMP CL, 0x2
0x8fedf9: JNZ 0x008fee01
0x8fedfb: MOV CL, 0x2
0x8fedfd: TEST EDI, EDI
0x8fedff: JLE 0x008fee0c
0x8fee01: DEC word ptr [RBX + 0x98]
0x8fee08: MOVZX ECX, byte ptr [RSI + 0x11]
0x8fee0c: CMP CL, 0x2
0x8fee0f: JNZ 0x008fee1c
0x8fee11: TEST EDI, EDI
0x8fee13: JNZ 0x008fee1c
0x8fee15: INC word ptr [RBX + 0x98]
0x8fee1c: MOV RDI, RBX
0x8fee1f: CALL 0x008fe3e0
0x8fee24: XOR R12D, R12D
0x8fee27: MOV EAX, dword ptr [RBP + -0x78]
0x8fee2a: TEST EAX, EAX
0x8fee2c: JLE 0x008fef3f
0x8fee32: MOV RAX, qword ptr [RBP + -0x90]
0x8fee39: MOV RAX, qword ptr [RAX + 0x50]
0x8fee3d: TEST RAX, RAX
0x8fee40: JZ 0x008fef3f
0x8fee46: MOV RCX, qword ptr [RBP + -0x90]
0x8fee4d: LEA RBX, [RCX + 0x50]
0x8fee51: NOP dword ptr CS:[RAX + RAX*0x1]
0x8fee60: MOV R13, RAX
0x8fee63: MOV RAX, qword ptr [RAX]
0x8fee66: TEST RAX, RAX
0x8fee69: JNZ 0x008fee60
0x8fee6b: LEA R14, [0x254f0a0]
0x8fee72: JMP 0x008fee89
0x8fee80: TEST R13, R13
0x8fee83: JZ 0x008fef3f
0x8fee89: MOV RAX, qword ptr [R13 + 0x8]
0x8fee8d: MOV R15, R13
0x8fee90: TEST RAX, RAX
0x8fee93: JZ 0x008fef00
0x8fee95: NOP dword ptr CS:[RAX + RAX*0x1]
0x8feea0: MOV R13, RAX
0x8feea3: MOV RAX, qword ptr [RAX]
0x8feea6: TEST RAX, RAX
0x8feea9: JNZ 0x008feea0
0x8feeab: CMP word ptr [R15 + 0x30], 0x0
0x8feeb1: JNZ 0x008fee80
0x8feeb3: CMP word ptr [R15 + 0x32], 0x0
0x8feeb9: JNZ 0x008fee80
0x8feebb: CMP word ptr [R15 + 0x34], 0x0
0x8feec1: JNZ 0x008fee80
0x8feec3: CMP word ptr [R15 + 0x36], 0x0
0x8feec9: JNZ 0x008fee80
0x8feecb: CMP byte ptr [R15 + 0x38], 0x0
0x8feed0: JNZ 0x008fee80
0x8feed2: MOV RDI, RBX
0x8feed5: MOV RSI, R15
0x8feed8: CALL 0x008fd850
0x8feedd: MOV RDI, R15
0x8feee0: MOV RSI, R14
0x8feee3: CALL 0x00c08df0
0x8feee8: MOV RAX, qword ptr [RBP + -0x90]
0x8feeef: DEC qword ptr [RAX + 0x58]
0x8feef3: JMP 0x008fee80
0x8fef00: MOV R13, qword ptr [R15 + 0x10]
0x8fef04: TEST R13, R13
0x8fef07: JZ 0x008fef0f
0x8fef09: CMP R15, qword ptr [R13]
0x8fef0d: JZ 0x008feeab
0x8fef0f: MOV RAX, R15
0x8fef12: NOP word ptr CS:[RAX + RAX*0x1]
0x8fef20: MOV R13, qword ptr [RAX + 0x10]
0x8fef24: TEST R13, R13
0x8fef27: JZ 0x008fef37
0x8fef29: CMP RAX, qword ptr [R13 + 0x8]
0x8fef2d: MOV RAX, R13
0x8fef30: JZ 0x008fef20
0x8fef32: JMP 0x008feeab
0x8fef37: XOR R13D, R13D
0x8fef3a: JMP 0x008feeab
0x8fef3f: LEA RAX, [0x391c310]
0x8fef46: MOV RAX, qword ptr [RAX]
0x8fef49: CMP RAX, qword ptr [RBP + -0x30]
0x8fef4d: JNZ 0x008ff0a2
0x8fef53: MOV EAX, R12D
0x8fef56: ADD RSP, 0x78
0x8fef5a: POP RBX
0x8fef5b: POP R12
0x8fef5d: POP R13
0x8fef5f: POP R14
0x8fef61: POP R15
0x8fef63: POP RBP
0x8fef64: RET
0x8fef65: MOV R12D, 0x1c
0x8fef6b: JMP 0x008fef73
0x8fef6d: MOV R12D, 0xc
0x8fef73: MOV EAX, dword ptr [RBP + -0x78]
0x8fef76: INC EAX
0x8fef78: TEST R15, R15
0x8fef7b: JZ 0x008fee2a
0x8fef81: MOV dword ptr [RBP + -0x78], EAX
0x8fef84: JMP 0x008fef99
0x8fef86: DEC word ptr [RBX + 0x36]
0x8fef8a: NOP word ptr [RAX + RAX*0x1]
0x8fef90: TEST R15, R15
0x8fef93: JZ 0x008fee27
0x8fef99: MOV RAX, qword ptr [R15]
0x8fef9c: MOV R14, R15
0x8fef9f: TEST RAX, RAX
0x8fefa2: JZ 0x008ff040
0x8fefa8: NOP dword ptr [RAX + RAX*0x1]
0x8fefb0: MOV R15, RAX
0x8fefb3: MOV RAX, qword ptr [RAX + 0x8]
0x8fefb7: TEST RAX, RAX
0x8fefba: JNZ 0x008fefb0
0x8fefbc: MOVZX EAX, byte ptr [R14 + 0x30]
0x8fefc1: CMP AL, byte ptr [R14 + 0x31]
0x8fefc5: JZ 0x008fef90
0x8fefc7: MOV RCX, qword ptr [R14 + 0x28]
0x8fefcb: MOV RAX, qword ptr [R14 + 0x20]
0x8fefcf: LEA RDX, [RBP + -0x50]
0x8fefd3: MOV qword ptr [RDX + 0x8], RCX
0x8fefd7: MOV RCX, qword ptr [RBP + -0x80]
0x8fefdb: MOV qword ptr [RDX], RAX
0x8fefde: MOV RBX, qword ptr [RCX]
0x8fefe1: TEST RBX, RBX
0x8fefe4: JZ 0x008fef90
0x8fefe6: LEA R13, [R14 + 0x20]
0x8fefea: JMP 0x008feffc
0x8feff0: ADD RBX, 0x8
0x8feff4: MOV RBX, qword ptr [RBX]
0x8feff7: TEST RBX, RBX
0x8feffa: JZ 0x008fef90
0x8feffc: LEA RSI, [RBX + 0x20]
0x8ff000: MOV EDX, 0x10
0x8ff005: LEA RDI, [RBP + -0x50]
0x8ff009: CALL 0x00339bd0
0x8ff00e: TEST EAX, EAX
0x8ff010: JS 0x008feff4
0x8ff012: JNZ 0x008feff0
0x8ff014: LEA RDI, [RBP + -0x70]
0x8ff018: MOV RSI, R13
0x8ff01b: CALL 0x00a85f90
0x8ff020: MOVZX EAX, byte ptr [R14 + 0x30]
0x8ff025: CMP EAX, 0x1
0x8ff028: JZ 0x008ff07e
0x8ff02a: CMP EAX, 0x2
0x8ff02d: JNZ 0x008ff082
0x8ff02f: INC word ptr [RBX + 0x34]
0x8ff033: JMP 0x008ff082
0x8ff040: MOV R15, qword ptr [R14 + 0x10]
0x8ff044: TEST R15, R15
0x8ff047: JZ 0x008ff053
0x8ff049: CMP R14, qword ptr [R15 + 0x8]
0x8ff04d: JZ 0x008fefbc
0x8ff053: MOV RAX, R14
0x8ff056: NOP word ptr CS:[RAX + RAX*0x1]
0x8ff060: MOV R15, qword ptr [RAX + 0x10]
0x8ff064: TEST R15, R15
0x8ff067: JZ 0x008ff076
0x8ff069: CMP RAX, qword ptr [R15]
0x8ff06c: MOV RAX, R15
0x8ff06f: JZ 0x008ff060
0x8ff071: JMP 0x008fefbc
0x8ff076: XOR R15D, R15D
0x8ff079: JMP 0x008fefbc
0x8ff07e: INC word ptr [RBX + 0x36]
0x8ff082: MOVZX EAX, byte ptr [R14 + 0x31]
0x8ff087: CMP EAX, 0x1
0x8ff08a: JZ 0x008fef86
0x8ff090: CMP EAX, 0x2
0x8ff093: JNZ 0x008fef90
0x8ff099: DEC word ptr [RBX + 0x34]
0x8ff09d: JMP 0x008fef90
0x8ff0a2: CALL 0x006fd6b0
0x8ff0a7: UD2

; local helper / adjacent context (reachability below); evidence ev_4de4bdf0db56484a614545420da1ee2b997000d566f42708ca3a66a359338a58; body [{"start": "0x8ff0b0", "end": "0x8ff129"}]
adjacent_8ff0b0: ; RVA 0x8ff0b0
0x8ff0b0: PUSH RBP
0x8ff0b1: MOV RBP, RSP
0x8ff0b4: PUSH R15
0x8ff0b6: PUSH R14
0x8ff0b8: PUSH RBX
0x8ff0b9: SUB RSP, 0x28
0x8ff0bd: LEA R15, [0x391c310]
0x8ff0c4: MOV RBX, RDI
0x8ff0c7: MOV RAX, qword ptr [R15]
0x8ff0ca: MOV qword ptr [RBP + -0x20], RAX
0x8ff0ce: TEST RSI, RSI
0x8ff0d1: JNZ 0x008ff0f5
0x8ff0d3: LEA R14, [RBP + -0x38]
0x8ff0d7: MOV ESI, 0x18
0x8ff0dc: MOV RDI, R14
0x8ff0df: CALL 0x00258ff0
0x8ff0e4: MOV RSI, R14
0x8ff0e7: MOV qword ptr [RBP + -0x38], 0x0
0x8ff0ef: MOV word ptr [RBP + -0x28], 0x2
0x8ff0f5: MOV RDI, RBX
0x8ff0f8: CALL 0x008fea20
0x8ff0fd: MOV RDI, RBX
0x8ff100: XOR ESI, ESI
0x8ff102: CALL 0x006a5650
0x8ff107: MOV RDI, RBX
0x8ff10a: CALL 0x008fdfa0
0x8ff10f: MOV RAX, qword ptr [R15]
0x8ff112: CMP RAX, qword ptr [RBP + -0x20]
0x8ff116: JNZ 0x008ff123
0x8ff118: ADD RSP, 0x28
0x8ff11c: POP RBX
0x8ff11d: POP R14
0x8ff11f: POP R15
0x8ff121: POP RBP
0x8ff122: RET
0x8ff123: CALL 0x006fd6b0
0x8ff128: UD2

; local helper / adjacent context (reachability below); evidence ev_db023f0556857b5baf029cdedb23afa1133ec11e48c7522ee3e0ea769fe32c67; body [{"start": "0x8ff130", "end": "0x8ff175"}, {"start": "0x8ff180", "end": "0x8ff24c"}, {"start": "0x8ff250", "end": "0x8ff283"}, {"start": "0x8ff290", "end": "0x8ff33c"}, {"start": "0x8ff340", "end": "0x8ff373"}, {"start": "0x8ff380", "end": "0x8ff3e7"}]
adjacent_8ff130: ; RVA 0x8ff130
0x8ff130: PUSH RBP
0x8ff131: MOV RBP, RSP
0x8ff134: PUSH R15
0x8ff136: PUSH R14
0x8ff138: PUSH R13
0x8ff13a: PUSH R12
0x8ff13c: PUSH RBX
0x8ff13d: SUB RSP, 0x38
0x8ff141: LEA RAX, [0x391c310]
0x8ff148: MOV RBX, RDI
0x8ff14b: MOV RAX, qword ptr [RAX]
0x8ff14e: MOV qword ptr [RBP + -0x30], RAX
0x8ff152: MOVZX EAX, word ptr [RDI + 0xa]
0x8ff156: MOV qword ptr [RBP + -0x58], RAX
0x8ff15a: TEST RAX, RAX
0x8ff15d: JZ 0x008ff390
0x8ff163: LEA R12, [0x254f0c0]
0x8ff16a: XOR R14D, R14D
0x8ff16d: MOV qword ptr [RBP + -0x50], RBX
0x8ff171: JMP 0x008ff1f5
0x8ff180: MOV RAX, qword ptr [RBX + 0x10]
0x8ff184: LEA RDI, [0x3b5c040]
0x8ff18b: XOR ESI, ESI
0x8ff18d: XOR EDX, EDX
0x8ff18f: XOR ECX, ECX
0x8ff191: MOV R15, qword ptr [RAX + R14*0x8]
0x8ff195: CALL 0x004c6a00
0x8ff19a: LEA R13, [RBP + -0x48]
0x8ff19e: MOV ESI, 0x18
0x8ff1a3: MOV RDI, R13
0x8ff1a6: CALL 0x00258ff0
0x8ff1ab: MOV RDI, R15
0x8ff1ae: MOV RSI, R13
0x8ff1b1: MOV qword ptr [RBP + -0x48], 0x0
0x8ff1b9: MOV word ptr [RBP + -0x38], 0x2
0x8ff1bf: CALL 0x008fea20
0x8ff1c4: MOV RDI, R15
0x8ff1c7: XOR ESI, ESI
0x8ff1c9: CALL 0x006a5650
0x8ff1ce: MOV RDI, R15
0x8ff1d1: CALL 0x008fdfa0
0x8ff1d6: LEA RDI, [0x3b5c040]
0x8ff1dd: XOR ESI, ESI
0x8ff1df: XOR EDX, EDX
0x8ff1e1: XOR ECX, ECX
0x8ff1e3: CALL 0x004c6fa0
0x8ff1e8: INC R14
0x8ff1eb: CMP R14, qword ptr [RBP + -0x58]
0x8ff1ef: JZ 0x008ff390
0x8ff1f5: MOV RAX, qword ptr [RBX + 0x18]
0x8ff1f9: LEA R13, [R14 + R14*0x2]
0x8ff1fd: TEST RAX, RAX
0x8ff200: SETZ CL
0x8ff203: SHL R13, 0x3
0x8ff207: ADD R13, RAX
0x8ff20a: SETZ AL
0x8ff20d: OR AL, CL
0x8ff20f: JNZ 0x008ff180
0x8ff215: MOV RCX, qword ptr [R13]
0x8ff219: TEST RCX, RCX
0x8ff21c: JZ 0x008ff290
0x8ff21e: NOP
0x8ff220: MOV RAX, RCX
0x8ff223: MOV RCX, qword ptr [RCX]
0x8ff226: TEST RCX, RCX
0x8ff229: JNZ 0x008ff220
0x8ff22b: NOP dword ptr [RAX + RAX*0x1]
0x8ff230: MOV byte ptr [RAX + 0x31], 0x0
0x8ff234: MOV RDX, qword ptr [RAX + 0x8]
0x8ff238: TEST RDX, RDX
0x8ff23b: JZ 0x008ff250
0x8ff23d: NOP dword ptr [RAX]
0x8ff240: MOV RAX, RDX
0x8ff243: MOV RDX, qword ptr [RDX]
0x8ff246: TEST RDX, RDX
0x8ff249: JNZ 0x008ff240
0x8ff24b: JMP 0x008ff230
0x8ff250: MOV RCX, RAX
0x8ff253: MOV RAX, qword ptr [RAX + 0x10]
0x8ff257: TEST RAX, RAX
0x8ff25a: JZ 0x008ff270
0x8ff25c: CMP RCX, qword ptr [RAX]
0x8ff25f: JZ 0x008ff230
0x8ff261: NOP dword ptr CS:[RAX + RAX*0x1]
0x8ff270: MOV RAX, qword ptr [RCX + 0x10]
0x8ff274: TEST RAX, RAX
0x8ff277: JZ 0x008ff290
0x8ff279: CMP RCX, qword ptr [RAX + 0x8]
0x8ff27d: MOV RCX, RAX
0x8ff280: JZ 0x008ff270
0x8ff282: JMP 0x008ff230
0x8ff290: MOV byte ptr [R13 + 0x11], 0x1
0x8ff295: XOR ESI, ESI
0x8ff297: XOR EDX, EDX
0x8ff299: XOR ECX, ECX
0x8ff29b: MOV RAX, qword ptr [RBX + 0x10]
0x8ff29f: LEA RBX, [0x3b5c040]
0x8ff2a6: MOV RDI, RBX
0x8ff2a9: MOV R15, qword ptr [RAX + R14*0x8]
0x8ff2ad: CALL 0x004c6a00
0x8ff2b2: MOV RDI, R15
0x8ff2b5: MOV RSI, R13
0x8ff2b8: CALL 0x008fea20
0x8ff2bd: MOV RDI, R15
0x8ff2c0: XOR ESI, ESI
0x8ff2c2: CALL 0x006a5650
0x8ff2c7: MOV RDI, R15
0x8ff2ca: CALL 0x008fdfa0
0x8ff2cf: MOV RDI, RBX
0x8ff2d2: XOR ESI, ESI
0x8ff2d4: XOR EDX, EDX
0x8ff2d6: XOR ECX, ECX
0x8ff2d8: CALL 0x004c6fa0
0x8ff2dd: MOV RAX, qword ptr [R13]
0x8ff2e1: TEST RAX, RAX
0x8ff2e4: JZ 0x008ff380
0x8ff2ea: NOP word ptr [RAX + RAX*0x1]
0x8ff2f0: MOV RBX, RAX
0x8ff2f3: MOV RAX, qword ptr [RAX]
0x8ff2f6: TEST RAX, RAX
0x8ff2f9: JNZ 0x008ff2f0
0x8ff2fb: JMP 0x008ff322
0x8ff2fd: XOR R15D, R15D
0x8ff300: MOV RDI, R13
0x8ff303: MOV RSI, RBX
0x8ff306: CALL 0x008fd850
0x8ff30b: MOV RDI, RBX
0x8ff30e: MOV RSI, R12
0x8ff311: CALL 0x00c08df0
0x8ff316: DEC qword ptr [R13 + 0x8]
0x8ff31a: MOV RBX, R15
0x8ff31d: TEST R15, R15
0x8ff320: JZ 0x008ff380
0x8ff322: MOV RAX, qword ptr [RBX + 0x8]
0x8ff326: TEST RAX, RAX
0x8ff329: JZ 0x008ff340
0x8ff32b: NOP dword ptr [RAX + RAX*0x1]
0x8ff330: MOV R15, RAX
0x8ff333: MOV RAX, qword ptr [RAX]
0x8ff336: TEST RAX, RAX
0x8ff339: JNZ 0x008ff330
0x8ff33b: JMP 0x008ff300
0x8ff340: MOV R15, qword ptr [RBX + 0x10]
0x8ff344: TEST R15, R15
0x8ff347: JZ 0x008ff34e
0x8ff349: CMP RBX, qword ptr [R15]
0x8ff34c: JZ 0x008ff300
0x8ff34e: MOV RAX, RBX
0x8ff351: NOP dword ptr CS:[RAX + RAX*0x1]
0x8ff360: MOV R15, qword ptr [RAX + 0x10]
0x8ff364: TEST R15, R15
0x8ff367: JZ 0x008ff2fd
0x8ff369: CMP RAX, qword ptr [R15 + 0x8]
0x8ff36d: MOV RAX, R15
0x8ff370: JZ 0x008ff360
0x8ff372: JMP 0x008ff300
0x8ff380: MOV RBX, qword ptr [RBP + -0x50]
0x8ff384: MOV word ptr [R13 + 0x10], 0x0
0x8ff38b: JMP 0x008ff1e8
0x8ff390: MOV RDI, qword ptr [RBX + 0x18]
0x8ff394: TEST RDI, RDI
0x8ff397: JZ 0x008ff3a5
0x8ff399: LEA RSI, [0x254f0c0]
0x8ff3a0: CALL 0x00c08df0
0x8ff3a5: MOV RDI, qword ptr [RBX + 0x10]
0x8ff3a9: LEA R14, [0x254f0e0]
0x8ff3b0: MOV RSI, R14
0x8ff3b3: CALL 0x00c08df0
0x8ff3b8: LEA RAX, [0x391c310]
0x8ff3bf: MOV RAX, qword ptr [RAX]
0x8ff3c2: CMP RAX, qword ptr [RBP + -0x30]
0x8ff3c6: JNZ 0x008ff3e1
0x8ff3c8: MOV RDI, RBX
0x8ff3cb: MOV RSI, R14
0x8ff3ce: ADD RSP, 0x38
0x8ff3d2: POP RBX
0x8ff3d3: POP R12
0x8ff3d5: POP R13
0x8ff3d7: POP R14
0x8ff3d9: POP R15
0x8ff3db: POP RBP
0x8ff3dc: JMP 0x00c08df0
0x8ff3e1: CALL 0x006fd6b0
0x8ff3e6: UD2

; local helper / adjacent context (reachability below); evidence ev_a71fdb660e561243b80de13ba58a6195a1a721f683bb618895e7b15bf590fe8d; body [{"start": "0x8ff3f8", "end": "0x8ff42c"}, {"start": "0x8ff430", "end": "0x8ff43e"}]
adjacent_8ff3f8: ; RVA 0x8ff3f8
0x8ff3f8: PUSH RBP
0x8ff3f9: MOV RBP, RSP
0x8ff3fc: NOP dword ptr [RAX]
0x8ff400: MOV RAX, RCX
0x8ff403: MOV RCX, qword ptr [RCX]
0x8ff406: TEST RCX, RCX
0x8ff409: JNZ 0x008ff400
0x8ff40b: NOP dword ptr [RAX + RAX*0x1]
0x8ff410: MOV byte ptr [RAX + 0x31], 0x0
0x8ff414: MOV RDX, qword ptr [RAX + 0x8]
0x8ff418: TEST RDX, RDX
0x8ff41b: JZ 0x008ff430
0x8ff41d: NOP dword ptr [RAX]
0x8ff420: MOV RAX, RDX
0x8ff423: MOV RDX, qword ptr [RDX]
0x8ff426: TEST RDX, RDX
0x8ff429: JNZ 0x008ff420
0x8ff42b: JMP 0x008ff410
0x8ff430: MOV RCX, RAX
0x8ff433: MOV RAX, qword ptr [RAX + 0x10]
0x8ff437: TEST RAX, RAX
0x8ff43a: JZ 0x008ff450
0x8ff43c: CMP RCX, qword ptr [RAX]

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

; ===== SUPPLEMENTAL FULL SHARED CARRIER TEXT GNU objdump: handlers_b_support.text_0x3af8e0.bin; not REA output =====

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handlers_b_support.text_0x3af8e0.bin:     file format binary


Disassembly of section .data:

00000000003af8e0 <.data>:
  3af8e0:	55                   	push   rbp
  3af8e1:	48 89 e5             	mov    rbp,rsp
  3af8e4:	31 f6                	xor    esi,esi
  3af8e6:	5d                   	pop    rbp
  3af8e7:	e9 74 5e eb ff       	jmp    0x265760
  3af8ec:	90                   	nop
  3af8ed:	90                   	nop
  3af8ee:	90                   	nop
  3af8ef:	90                   	nop
  3af8f0:	55                   	push   rbp
  3af8f1:	48 89 e5             	mov    rbp,rsp
  3af8f4:	31 f6                	xor    esi,esi
  3af8f6:	5d                   	pop    rbp
  3af8f7:	e9 64 5e eb ff       	jmp    0x265760
  3af8fc:	90                   	nop
  3af8fd:	90                   	nop
  3af8fe:	90                   	nop
  3af8ff:	90                   	nop
  3af900:	55                   	push   rbp
  3af901:	48 89 e5             	mov    rbp,rsp
  3af904:	48 8b 06             	mov    rax,QWORD PTR [rsi]
  3af907:	8b 56 08             	mov    edx,DWORD PTR [rsi+0x8]
  3af90a:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
  3af90e:	48 89 c6             	mov    rsi,rax
  3af911:	5d                   	pop    rbp
  3af912:	e9 09 00 00 00       	jmp    0x3af920
  3af917:	90                   	nop
  3af918:	90                   	nop
  3af919:	90                   	nop
  3af91a:	90                   	nop
  3af91b:	90                   	nop
  3af91c:	90                   	nop
  3af91d:	90                   	nop
  3af91e:	90                   	nop
  3af91f:	90                   	nop
  3af920:	55                   	push   rbp
  3af921:	48 89 e5             	mov    rbp,rsp
  3af924:	41 57                	push   r15
  3af926:	41 56                	push   r14
  3af928:	41 55                	push   r13
  3af92a:	41 54                	push   r12
  3af92c:	53                   	push   rbx
  3af92d:	48 83 e4 e0          	and    rsp,0xffffffffffffffe0
  3af931:	48 81 ec a0 00 00 00 	sub    rsp,0xa0
  3af938:	48 89 e3             	mov    rbx,rsp
  3af93b:	4c 8d 2d ce c9 56 03 	lea    r13,[rip+0x356c9ce]        # 0x391c310
  3af942:	48 89 4b 60          	mov    QWORD PTR [rbx+0x60],rcx
  3af946:	48 89 53 48          	mov    QWORD PTR [rbx+0x48],rdx
  3af94a:	49 89 f6             	mov    r14,rsi
  3af94d:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  3af951:	48 89 83 80 00 00 00 	mov    QWORD PTR [rbx+0x80],rax
  3af958:	48 89 7b 68          	mov    QWORD PTR [rbx+0x68],rdi
  3af95c:	4c 8b 67 08          	mov    r12,QWORD PTR [rdi+0x8]
  3af960:	49 8b 84 24 48 0c 00 	mov    rax,QWORD PTR [r12+0xc48]
  3af967:	00 
  3af968:	4c 89 e7             	mov    rdi,r12
  3af96b:	c7 43 74 00 00 00 00 	mov    DWORD PTR [rbx+0x74],0x0
  3af972:	c7 43 70 00 00 00 00 	mov    DWORD PTR [rbx+0x70],0x0
  3af979:	48 89 43 50          	mov    QWORD PTR [rbx+0x50],rax
  3af97d:	e8 fe 87 64 00       	call   0x9f8180
  3af982:	48 8d 73 78          	lea    rsi,[rbx+0x78]
  3af986:	4c 89 e7             	mov    rdi,r12
  3af989:	49 89 c7             	mov    r15,rax
  3af98c:	e8 2f 88 64 00       	call   0x9f81c0
  3af991:	85 c0                	test   eax,eax
  3af993:	75 2a                	jne    0x3af9bf
  3af995:	8b 43 78             	mov    eax,DWORD PTR [rbx+0x78]
  3af998:	3d ff ff ff 00       	cmp    eax,0xffffff
  3af99d:	77 20                	ja     0x3af9bf
  3af99f:	3d ff ff 00 00       	cmp    eax,0xffff
  3af9a4:	0f 86 7e 01 00 00    	jbe    0x3afb28
  3af9aa:	25 00 00 ff 00       	and    eax,0xff0000
  3af9af:	3d 00 00 01 00       	cmp    eax,0x10000
  3af9b4:	75 09                	jne    0x3af9bf
  3af9b6:	48 8d 35 b3 04 12 03 	lea    rsi,[rip+0x31204b3]        # 0x34cfe70
  3af9bd:	eb 07                	jmp    0x3af9c6
  3af9bf:	48 8d 35 02 ff 11 03 	lea    rsi,[rip+0x311ff02]        # 0x34cf8c8
  3af9c6:	83 be a0 04 00 00 01 	cmp    DWORD PTR [rsi+0x4a0],0x1
  3af9cd:	74 28                	je     0x3af9f7
  3af9cf:	bf 01 00 00 00       	mov    edi,0x1
  3af9d4:	e8 37 3a 00 00       	call   0x3b3410
  3af9d9:	85 c0                	test   eax,eax
  3af9db:	74 1a                	je     0x3af9f7
  3af9dd:	41 89 c7             	mov    r15d,eax
  3af9e0:	48 8d 3d 21 c5 f6 00 	lea    rdi,[rip+0xf6c521]        # 0x131bf08
  3af9e7:	48 8d 35 9e 4b fd 00 	lea    rsi,[rip+0xfd4b9e]        # 0x138458c
  3af9ee:	ba 9b 0e 00 00       	mov    edx,0xe9b
  3af9f3:	89 c1                	mov    ecx,eax
  3af9f5:	eb 30                	jmp    0x3afa27
  3af9f7:	4c 8b 7b 48          	mov    r15,QWORD PTR [rbx+0x48]
  3af9fb:	41 8d 87 7f ff ff ff 	lea    eax,[r15-0x81]
  3afa02:	3d 7f ff ff ff       	cmp    eax,0xffffff7f
  3afa07:	77 2a                	ja     0x3afa33
  3afa09:	48 8d 3d f8 c4 f6 00 	lea    rdi,[rip+0xf6c4f8]        # 0x131bf08
  3afa10:	48 8d 35 75 4b fd 00 	lea    rsi,[rip+0xfd4b75]        # 0x138458c
  3afa17:	41 bf 16 00 00 00    	mov    r15d,0x16
  3afa1d:	ba a1 0e 00 00       	mov    edx,0xea1
  3afa22:	b9 16 00 00 00       	mov    ecx,0x16
  3afa27:	31 c0                	xor    eax,eax
  3afa29:	e8 e2 d9 ea ff       	call   0x25d410
  3afa2e:	e9 77 07 00 00       	jmp    0x3b01aa
  3afa33:	4c 89 73 10          	mov    QWORD PTR [rbx+0x10],r14
  3afa37:	41 83 ff 02          	cmp    r15d,0x2
  3afa3b:	72 38                	jb     0x3afa75
  3afa3d:	42 8d 04 bd 0f 00 00 	lea    eax,[r15*4+0xf]
  3afa44:	00 
  3afa45:	49 89 e6             	mov    r14,rsp
  3afa48:	42 8d 34 bd 00 00 00 	lea    esi,[r15*4+0x0]
  3afa4f:	00 
  3afa50:	83 e0 f0             	and    eax,0xfffffff0
  3afa53:	49 29 c6             	sub    r14,rax
  3afa56:	49 83 e6 e0          	and    r14,0xffffffffffffffe0
  3afa5a:	4c 89 f4             	mov    rsp,r14
  3afa5d:	48 89 e7             	mov    rdi,rsp
  3afa60:	48 29 c7             	sub    rdi,rax
  3afa63:	48 83 e7 e0          	and    rdi,0xffffffffffffffe0
  3afa67:	48 89 fc             	mov    rsp,rdi
  3afa6a:	48 89 7b 08          	mov    QWORD PTR [rbx+0x8],rdi
  3afa6e:	e8 7d 95 ea ff       	call   0x258ff0
  3afa73:	eb 0c                	jmp    0x3afa81
  3afa75:	48 8d 43 70          	lea    rax,[rbx+0x70]
  3afa79:	4c 8d 73 74          	lea    r14,[rbx+0x74]
  3afa7d:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
  3afa81:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3afa88:	00 00 
  3afa8a:	45 89 fd             	mov    r13d,r15d
  3afa8d:	48 8d 35 a9 84 fe 00 	lea    rsi,[rip+0xfe84a9]        # 0x1397f3d
  3afa94:	31 d2                	xor    edx,edx
  3afa96:	4e 8d 24 ad 00 00 00 	lea    r12,[r13*4+0x0]
  3afa9d:	00 
  3afa9e:	e8 3d a9 86 00       	call   0xc1a3e0
  3afaa3:	48 8b 7b 10          	mov    rdi,QWORD PTR [rbx+0x10]
  3afaa7:	4c 89 f6             	mov    rsi,r14
  3afaaa:	4c 89 e2             	mov    rdx,r12
  3afaad:	e8 ce 97 ea ff       	call   0x259280
  3afab2:	85 c0                	test   eax,eax
  3afab4:	74 2b                	je     0x3afae1
  3afab6:	48 8d 3d 4b c4 f6 00 	lea    rdi,[rip+0xf6c44b]        # 0x131bf08
  3afabd:	48 8d 35 c8 4a fd 00 	lea    rsi,[rip+0xfd4ac8]        # 0x138458c
  3afac4:	ba b0 0e 00 00       	mov    edx,0xeb0
  3afac9:	89 c1                	mov    ecx,eax
  3afacb:	41 89 c7             	mov    r15d,eax
  3aface:	31 c0                	xor    eax,eax
  3afad0:	e8 3b d9 ea ff       	call   0x25d410
  3afad5:	4c 8d 2d 34 c8 56 03 	lea    r13,[rip+0x356c834]        # 0x391c310
  3afadc:	e9 c9 06 00 00       	jmp    0x3b01aa
  3afae1:	4c 89 6b 18          	mov    QWORD PTR [rbx+0x18],r13
  3afae5:	4c 89 73 10          	mov    QWORD PTR [rbx+0x10],r14
  3afae9:	e8 e2 7d 75 00       	call   0xb078d0
  3afaee:	4c 89 63 58          	mov    QWORD PTR [rbx+0x58],r12
  3afaf2:	85 c0                	test   eax,eax
  3afaf4:	74 6a                	je     0x3afb60
  3afaf6:	4c 8b 73 18          	mov    r14,QWORD PTR [rbx+0x18]
  3afafa:	48 8d 35 ff dc 6c 01 	lea    rsi,[rip+0x16cdcff]        # 0x1a7d800
  3afb01:	ba 02 01 00 00       	mov    edx,0x102
  3afb06:	4a 8d 04 f5 00 00 00 	lea    rax,[r14*8+0x0]
  3afb0d:	00 
  3afb0e:	48 8d 3c 40          	lea    rdi,[rax+rax*2]
  3afb12:	e8 39 90 85 00       	call   0xc08b50
  3afb17:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  3afb1b:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
  3afb1f:	4c 89 f7             	mov    rdi,r14
  3afb22:	48 89 43 40          	mov    QWORD PTR [rbx+0x40],rax
  3afb26:	eb 4c                	jmp    0x3afb74
  3afb28:	4c 39 3d 99 fc 11 03 	cmp    QWORD PTR [rip+0x311fc99],r15        # 0x34cf7c8
  3afb2f:	0f 84 94 06 00 00    	je     0x3b01c9
  3afb35:	4c 39 3d 84 0d 12 03 	cmp    QWORD PTR [rip+0x3120d84],r15        # 0x34d08c0
  3afb3c:	0f 84 93 06 00 00    	je     0x3b01d5
  3afb42:	83 3d 77 fc 11 03 00 	cmp    DWORD PTR [rip+0x311fc77],0x0        # 0x34cf7c0
  3afb49:	48 8d 05 d0 f7 11 03 	lea    rax,[rip+0x311f7d0]        # 0x34cf320
  3afb50:	48 8d 35 c1 08 12 03 	lea    rsi,[rip+0x31208c1]        # 0x34d0418
  3afb57:	48 0f 44 f0          	cmove  rsi,rax
  3afb5b:	e9 66 fe ff ff       	jmp    0x3af9c6
  3afb60:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  3afb64:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
  3afb68:	48 8b 7b 18          	mov    rdi,QWORD PTR [rbx+0x18]
  3afb6c:	48 c7 43 40 00 00 00 	mov    QWORD PTR [rbx+0x40],0x0
  3afb73:	00 
  3afb74:	45 31 ed             	xor    r13d,r13d
  3afb77:	45 31 e4             	xor    r12d,r12d
  3afb7a:	c7 43 28 00 00 00 00 	mov    DWORD PTR [rbx+0x28],0x0
  3afb81:	eb 27                	jmp    0x3afbaa
  3afb83:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3afb8a:	84 00 00 00 00 00 
  3afb90:	42 c7 04 aa 03 00 02 	mov    DWORD PTR [rdx+r13*4],0x80020003
  3afb97:	80 
  3afb98:	45 89 e7             	mov    r15d,r12d
  3afb9b:	49 ff c5             	inc    r13
  3afb9e:	45 89 fc             	mov    r12d,r15d
  3afba1:	49 39 fd             	cmp    r13,rdi
  3afba4:	0f 84 66 05 00 00    	je     0x3b0110
  3afbaa:	46 8b 3c ae          	mov    r15d,DWORD PTR [rsi+r13*4]
  3afbae:	42 c7 04 aa 00 00 00 	mov    DWORD PTR [rdx+r13*4],0x0
  3afbb5:	00 
  3afbb6:	45 89 fe             	mov    r14d,r15d
  3afbb9:	41 c1 fe 10          	sar    r14d,0x10
  3afbbd:	41 81 e7 ff ff 00 00 	and    r15d,0xffff
  3afbc4:	41 0f 95 c0          	setne  r8b
  3afbc8:	41 81 fe 80 00 00 00 	cmp    r14d,0x80
  3afbcf:	0f 92 c1             	setb   cl
  3afbd2:	41 84 c8             	test   r8b,cl
  3afbd5:	74 b9                	je     0x3afb90
  3afbd7:	45 39 e7             	cmp    r15d,r12d
  3afbda:	75 44                	jne    0x3afc20
  3afbdc:	48 85 c0             	test   rax,rax
  3afbdf:	75 77                	jne    0x3afc58
  3afbe1:	42 c7 04 aa 03 00 02 	mov    DWORD PTR [rdx+r13*4],0x80020003
  3afbe8:	80 
  3afbe9:	48 8d 3d 87 b7 fa 00 	lea    rdi,[rip+0xfab787]        # 0x135b377
  3afbf0:	48 8d 35 95 49 fd 00 	lea    rsi,[rip+0xfd4995]        # 0x138458c
  3afbf7:	ba da 0e 00 00       	mov    edx,0xeda
  3afbfc:	44 89 e9             	mov    ecx,r13d
  3afbff:	41 b8 03 00 00 00    	mov    r8d,0x3
  3afc05:	31 c0                	xor    eax,eax
  3afc07:	e8 04 d8 ea ff       	call   0x25d410
  3afc0c:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
  3afc10:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  3afc14:	45 89 e7             	mov    r15d,r12d
  3afc17:	31 c0                	xor    eax,eax
  3afc19:	e9 e5 00 00 00       	jmp    0x3afd03
  3afc1e:	66 90                	xchg   ax,ax
  3afc20:	83 7b 28 00          	cmp    DWORD PTR [rbx+0x28],0x0
  3afc24:	74 09                	je     0x3afc2f
  3afc26:	48 8b 7b 78          	mov    rdi,QWORD PTR [rbx+0x78]
  3afc2a:	e8 81 a2 fe ff       	call   0x399eb0
  3afc2f:	48 8b 7b 50          	mov    rdi,QWORD PTR [rbx+0x50]
  3afc33:	44 89 fe             	mov    esi,r15d
  3afc36:	ba 60 01 00 00       	mov    edx,0x160
  3afc3b:	48 8d 4b 78          	lea    rcx,[rbx+0x78]
  3afc3f:	e8 9c a2 fe ff       	call   0x399ee0
  3afc44:	48 85 c0             	test   rax,rax
  3afc47:	0f 84 9a 00 00 00    	je     0x3afce7
  3afc4d:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  3afc51:	c7 43 28 01 00 00 00 	mov    DWORD PTR [rbx+0x28],0x1
  3afc58:	49 89 c4             	mov    r12,rax
  3afc5b:	0f bf 00             	movsx  eax,WORD PTR [rax]
  3afc5e:	41 39 c6             	cmp    r14d,eax
  3afc61:	7d 45                	jge    0x3afca8
  3afc63:	48 8b 7b 78          	mov    rdi,QWORD PTR [rbx+0x78]
  3afc67:	e8 b4 a1 fe ff       	call   0x399e20
  3afc6c:	85 c0                	test   eax,eax
  3afc6e:	0f 84 98 00 00 00    	je     0x3afd0c
  3afc74:	4c 8b 73 08          	mov    r14,QWORD PTR [rbx+0x8]
  3afc78:	48 8d 3d f8 b6 fa 00 	lea    rdi,[rip+0xfab6f8]        # 0x135b377
  3afc7f:	48 8d 35 06 49 fd 00 	lea    rsi,[rip+0xfd4906]        # 0x138458c
  3afc86:	ba e9 0e 00 00       	mov    edx,0xee9
  3afc8b:	44 89 e9             	mov    ecx,r13d
  3afc8e:	41 b8 01 00 00 00    	mov    r8d,0x1
  3afc94:	43 c7 04 ae 01 00 02 	mov    DWORD PTR [r14+r13*4],0x80020001
  3afc9b:	80 
  3afc9c:	31 c0                	xor    eax,eax
  3afc9e:	e8 6d d7 ea ff       	call   0x25d410
  3afca3:	4c 89 f2             	mov    rdx,r14
  3afca6:	eb 2f                	jmp    0x3afcd7
  3afca8:	42 c7 04 aa 03 00 02 	mov    DWORD PTR [rdx+r13*4],0x80020003
  3afcaf:	80 
  3afcb0:	48 8d 3d c0 b6 fa 00 	lea    rdi,[rip+0xfab6c0]        # 0x135b377
  3afcb7:	48 8d 35 ce 48 fd 00 	lea    rsi,[rip+0xfd48ce]        # 0x138458c
  3afcbe:	ba e3 0e 00 00       	mov    edx,0xee3
  3afcc3:	44 89 e9             	mov    ecx,r13d
  3afcc6:	41 b8 03 00 00 00    	mov    r8d,0x3
  3afccc:	31 c0                	xor    eax,eax
  3afcce:	e8 3d d7 ea ff       	call   0x25d410
  3afcd3:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  3afcd7:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
  3afcdb:	48 8b 7b 18          	mov    rdi,QWORD PTR [rbx+0x18]
  3afcdf:	4c 89 e0             	mov    rax,r12
  3afce2:	e9 b4 fe ff ff       	jmp    0x3afb9b
  3afce7:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  3afceb:	42 c7 04 aa 03 00 02 	mov    DWORD PTR [rdx+r13*4],0x80020003
  3afcf2:	80 
  3afcf3:	45 31 ff             	xor    r15d,r15d
  3afcf6:	c7 43 28 00 00 00 00 	mov    DWORD PTR [rbx+0x28],0x0
  3afcfd:	31 c0                	xor    eax,eax
  3afcff:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
  3afd03:	48 8b 7b 18          	mov    rdi,QWORD PTR [rbx+0x18]
  3afd07:	e9 8f fe ff ff       	jmp    0x3afb9b
  3afd0c:	49 8b 44 24 28       	mov    rax,QWORD PTR [r12+0x28]
  3afd11:	44 89 f1             	mov    ecx,r14d
  3afd14:	4c 8b 34 c8          	mov    r14,QWORD PTR [rax+rcx*8]
  3afd18:	4d 85 f6             	test   r14,r14
  3afd1b:	0f 84 13 02 00 00    	je     0x3aff34
  3afd21:	48 83 7b 40 00       	cmp    QWORD PTR [rbx+0x40],0x0
  3afd26:	48 89 4b 30          	mov    QWORD PTR [rbx+0x30],rcx
  3afd2a:	0f 95 43 38          	setne  BYTE PTR [rbx+0x38]
  3afd2e:	e8 9d 7b 75 00       	call   0xb078d0
  3afd33:	85 c0                	test   eax,eax
  3afd35:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
  3afd39:	0f 95 c0             	setne  al
  3afd3c:	22 43 38             	and    al,BYTE PTR [rbx+0x38]
  3afd3f:	3c 01                	cmp    al,0x1
  3afd41:	75 2f                	jne    0x3afd72
  3afd43:	42 8b 04 ae          	mov    eax,DWORD PTR [rsi+r13*4]
  3afd47:	48 8b 7b 40          	mov    rdi,QWORD PTR [rbx+0x40]
  3afd4b:	4b 8d 4c 6d 00       	lea    rcx,[r13+r13*2+0x0]
  3afd50:	89 04 cf             	mov    DWORD PTR [rdi+rcx*8],eax
  3afd53:	49 8b 46 18          	mov    rax,QWORD PTR [r14+0x18]
  3afd57:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3afd5a:	48 89 44 cf 08       	mov    QWORD PTR [rdi+rcx*8+0x8],rax
  3afd5f:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
  3afd63:	48 89 c2             	mov    rdx,rax
  3afd66:	48 c1 fa 04          	sar    rdx,0x4
  3afd6a:	48 31 c2             	xor    rdx,rax
  3afd6d:	48 89 54 cf 10       	mov    QWORD PTR [rdi+rcx*8+0x10],rdx
  3afd72:	4d 8b 76 20          	mov    r14,QWORD PTR [r14+0x20]
  3afd76:	41 8b 46 08          	mov    eax,DWORD PTR [r14+0x8]
  3afd7a:	83 c0 fd             	add    eax,0xfffffffd
  3afd7d:	83 f8 02             	cmp    eax,0x2
  3afd80:	0f 83 db 01 00 00    	jae    0x3aff61
  3afd86:	49 8d 7e 20          	lea    rdi,[r14+0x20]
  3afd8a:	be 00 00 08 00       	mov    esi,0x80000
  3afd8f:	31 d2                	xor    edx,edx
  3afd91:	31 c9                	xor    ecx,ecx
  3afd93:	45 31 c0             	xor    r8d,r8d
  3afd96:	45 31 c9             	xor    r9d,r9d
  3afd99:	48 89 7b 38          	mov    QWORD PTR [rbx+0x38],rdi
  3afd9d:	6a 00                	push   0x0
  3afd9f:	6a 00                	push   0x0
  3afda1:	e8 ca 19 84 00       	call   0xbf1770
  3afda6:	48 83 c4 10          	add    rsp,0x10
  3afdaa:	41 80 7e 0c 00       	cmp    BYTE PTR [r14+0xc],0x0
  3afdaf:	75 2b                	jne    0x3afddc
  3afdb1:	48 8d 3d 50 c1 f6 00 	lea    rdi,[rip+0xf6c150]        # 0x131bf08
  3afdb8:	48 8d 35 cd 47 fd 00 	lea    rsi,[rip+0xfd47cd]        # 0x138458c
  3afdbf:	ba 0a 0f 00 00       	mov    edx,0xf0a
  3afdc4:	b9 10 00 00 00       	mov    ecx,0x10
  3afdc9:	31 c0                	xor    eax,eax
  3afdcb:	e8 40 d6 ea ff       	call   0x25d410
  3afdd0:	48 8b 43 08          	mov    rax,QWORD PTR [rbx+0x8]
  3afdd4:	42 c7 04 a8 10 00 02 	mov    DWORD PTR [rax+r13*4],0x80020010
  3afddb:	80 
  3afddc:	49 83 7e 50 00       	cmp    QWORD PTR [r14+0x50],0x0
  3afde1:	4c 89 73 20          	mov    QWORD PTR [rbx+0x20],r14
  3afde5:	4c 8b 73 08          	mov    r14,QWORD PTR [rbx+0x8]
  3afde9:	74 27                	je     0x3afe12
  3afdeb:	48 8d 3d 16 c1 f6 00 	lea    rdi,[rip+0xf6c116]        # 0x131bf08
  3afdf2:	48 8d 35 93 47 fd 00 	lea    rsi,[rip+0xfd4793]        # 0x138458c
  3afdf9:	ba 0f 0f 00 00       	mov    edx,0xf0f
  3afdfe:	b9 10 00 00 00       	mov    ecx,0x10
  3afe03:	31 c0                	xor    eax,eax
  3afe05:	e8 06 d6 ea ff       	call   0x25d410
  3afe0a:	43 c7 04 ae 10 00 02 	mov    DWORD PTR [r14+r13*4],0x80020010
  3afe11:	80 
  3afe12:	48 8b 7b 38          	mov    rdi,QWORD PTR [rbx+0x38]
  3afe16:	31 d2                	xor    edx,edx
  3afe18:	be 00 00 10 00       	mov    esi,0x100000
  3afe1d:	31 c9                	xor    ecx,ecx
  3afe1f:	45 31 c0             	xor    r8d,r8d
  3afe22:	45 31 c9             	xor    r9d,r9d
  3afe25:	6a 00                	push   0x0
  3afe27:	6a 00                	push   0x0
  3afe29:	e8 42 19 84 00       	call   0xbf1770
  3afe2e:	48 83 c4 10          	add    rsp,0x10
  3afe32:	43 83 3c ae 00       	cmp    DWORD PTR [r14+r13*4],0x0
  3afe37:	4c 89 f2             	mov    rdx,r14
  3afe3a:	0f 85 97 fe ff ff    	jne    0x3afcd7
  3afe40:	48 8b 4b 20          	mov    rcx,QWORD PTR [rbx+0x20]
  3afe44:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
  3afe48:	48 8b 7b 18          	mov    rdi,QWORD PTR [rbx+0x18]
  3afe4c:	4c 89 e0             	mov    rax,r12
  3afe4f:	83 79 04 00          	cmp    DWORD PTR [rcx+0x4],0x0
  3afe53:	0f 85 42 fd ff ff    	jne    0x3afb9b
  3afe59:	80 79 0c 00          	cmp    BYTE PTR [rcx+0xc],0x0
  3afe5d:	0f 84 38 fd ff ff    	je     0x3afb9b
  3afe63:	48 8b 7b 78          	mov    rdi,QWORD PTR [rbx+0x78]
  3afe67:	e8 44 a0 fe ff       	call   0x399eb0
  3afe6c:	48 8b 7b 50          	mov    rdi,QWORD PTR [rbx+0x50]
  3afe70:	44 89 fe             	mov    esi,r15d
  3afe73:	ba 60 01 00 00       	mov    edx,0x160
  3afe78:	48 8d 4b 78          	lea    rcx,[rbx+0x78]
  3afe7c:	e8 1f a4 fe ff       	call   0x39a2a0
  3afe81:	48 85 c0             	test   rax,rax
  3afe84:	0f 84 21 01 00 00    	je     0x3affab
  3afe8a:	48 8b 48 28          	mov    rcx,QWORD PTR [rax+0x28]
  3afe8e:	48 8b 53 30          	mov    rdx,QWORD PTR [rbx+0x30]
  3afe92:	44 0f b7 40 02       	movzx  r8d,WORD PTR [rax+0x2]
  3afe97:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
  3afe9b:	48 89 43 20          	mov    QWORD PTR [rbx+0x20],rax
  3afe9f:	4c 8b 24 d1          	mov    r12,QWORD PTR [rcx+rdx*8]
  3afea3:	66 41 83 f8 01       	cmp    r8w,0x1
  3afea8:	0f 85 0e 01 00 00    	jne    0x3affbc
  3afeae:	4d 85 e4             	test   r12,r12
  3afeb1:	0f 84 31 02 00 00    	je     0x3b00e8
  3afeb7:	4d 8b 74 24 18       	mov    r14,QWORD PTR [r12+0x18]
  3afebc:	4c 8b 43 20          	mov    r8,QWORD PTR [rbx+0x20]
  3afec0:	48 89 d1             	mov    rcx,rdx
  3afec3:	4d 85 f6             	test   r14,r14
  3afec6:	74 36                	je     0x3afefe
  3afec8:	49 8b 7e 10          	mov    rdi,QWORD PTR [r14+0x10]
  3afecc:	48 85 ff             	test   rdi,rdi
  3afecf:	74 0d                	je     0x3afede
  3afed1:	e8 9a 97 ef ff       	call   0x2a9670
  3afed6:	49 c7 46 10 00 00 00 	mov    QWORD PTR [r14+0x10],0x0
  3afedd:	00 
  3afede:	4c 89 f7             	mov    rdi,r14
  3afee1:	48 8d 35 f8 5a 70 01 	lea    rsi,[rip+0x1705af8]        # 0x1ab59e0
  3afee8:	e8 03 8f 85 00       	call   0xc08df0
  3afeed:	4c 8b 43 20          	mov    r8,QWORD PTR [rbx+0x20]
  3afef1:	48 8b 4b 30          	mov    rcx,QWORD PTR [rbx+0x30]
  3afef5:	49 c7 44 24 18 00 00 	mov    QWORD PTR [r12+0x18],0x0
  3afefc:	00 00 
  3afefe:	66 41 83 38 01       	cmp    WORD PTR [r8],0x1
  3aff03:	0f 85 0b 01 00 00    	jne    0x3b0014
  3aff09:	4d 8b 74 24 20       	mov    r14,QWORD PTR [r12+0x20]
  3aff0e:	4d 85 f6             	test   r14,r14
  3aff11:	0f 84 72 01 00 00    	je     0x3b0089
  3aff17:	49 c7 44 24 20 00 00 	mov    QWORD PTR [r12+0x20],0x0
  3aff1e:	00 00 
  3aff20:	41 8b 06             	mov    eax,DWORD PTR [r14]
  3aff23:	85 c0                	test   eax,eax
  3aff25:	0f 84 4a 01 00 00    	je     0x3b0075
  3aff2b:	4c 89 73 28          	mov    QWORD PTR [rbx+0x28],r14
  3aff2f:	45 31 f6             	xor    r14d,r14d
  3aff32:	eb 4a                	jmp    0x3aff7e
  3aff34:	4c 8b 73 08          	mov    r14,QWORD PTR [rbx+0x8]
  3aff38:	48 8d 3d 38 b4 fa 00 	lea    rdi,[rip+0xfab438]        # 0x135b377
  3aff3f:	48 8d 35 46 46 fd 00 	lea    rsi,[rip+0xfd4646]        # 0x138458c
  3aff46:	ba f0 0e 00 00       	mov    edx,0xef0
  3aff4b:	44 89 e9             	mov    ecx,r13d
  3aff4e:	41 b8 03 00 00 00    	mov    r8d,0x3
  3aff54:	43 c7 04 ae 03 00 02 	mov    DWORD PTR [r14+r13*4],0x80020003
  3aff5b:	80 
  3aff5c:	e9 3b fd ff ff       	jmp    0x3afc9c
  3aff61:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  3aff65:	42 c7 04 aa 10 00 02 	mov    DWORD PTR [rdx+r13*4],0x80020010
  3aff6c:	80 
  3aff6d:	e9 69 fd ff ff       	jmp    0x3afcdb
  3aff72:	41 ff c6             	inc    r14d
  3aff75:	41 39 c6             	cmp    r14d,eax
  3aff78:	0f 83 a8 00 00 00    	jae    0x3b0026
  3aff7e:	49 8b 48 28          	mov    rcx,QWORD PTR [r8+0x28]
  3aff82:	4d 63 e6             	movsxd r12,r14d
  3aff85:	4a 8b 3c e1          	mov    rdi,QWORD PTR [rcx+r12*8]
  3aff89:	48 85 ff             	test   rdi,rdi
  3aff8c:	74 e4                	je     0x3aff72
  3aff8e:	e8 fd 3e 00 00       	call   0x3b3e90
  3aff93:	4c 8b 43 20          	mov    r8,QWORD PTR [rbx+0x20]
  3aff97:	49 8b 40 28          	mov    rax,QWORD PTR [r8+0x28]
  3aff9b:	4a c7 04 e0 00 00 00 	mov    QWORD PTR [rax+r12*8],0x0
  3affa2:	00 
  3affa3:	48 8b 43 28          	mov    rax,QWORD PTR [rbx+0x28]
  3affa7:	8b 00                	mov    eax,DWORD PTR [rax]
  3affa9:	eb c7                	jmp    0x3aff72
  3affab:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  3affaf:	42 c7 04 aa 00 00 00 	mov    DWORD PTR [rdx+r13*4],0x0
  3affb6:	00 
  3affb7:	e9 37 fd ff ff       	jmp    0x3afcf3
  3affbc:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  3affc0:	48 8b 7b 18          	mov    rdi,QWORD PTR [rbx+0x18]
  3affc4:	4d 85 e4             	test   r12,r12
  3affc7:	0f 84 ce fb ff ff    	je     0x3afb9b
  3affcd:	41 ff c8             	dec    r8d
  3affd0:	66 44 89 40 02       	mov    WORD PTR [rax+0x2],r8w
  3affd5:	49 83 7c 24 20 00    	cmp    QWORD PTR [r12+0x20],0x0
  3affdb:	74 12                	je     0x3affef
  3affdd:	48 8b 7b 38          	mov    rdi,QWORD PTR [rbx+0x38]
  3affe1:	e8 7a 17 84 00       	call   0xbf1760
  3affe6:	49 c7 44 24 20 00 00 	mov    QWORD PTR [r12+0x20],0x0
  3affed:	00 00 
  3affef:	4c 89 e7             	mov    rdi,r12
  3afff2:	e8 99 3e 00 00       	call   0x3b3e90
  3afff7:	48 8b 43 20          	mov    rax,QWORD PTR [rbx+0x20]
  3afffb:	48 8b 53 30          	mov    rdx,QWORD PTR [rbx+0x30]
  3affff:	48 8b 48 28          	mov    rcx,QWORD PTR [rax+0x28]
  3b0003:	48 c7 04 d1 00 00 00 	mov    QWORD PTR [rcx+rdx*8],0x0
  3b000a:	00 
  3b000b:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  3b000f:	e9 eb fc ff ff       	jmp    0x3afcff
  3b0014:	4c 89 e7             	mov    rdi,r12
  3b0017:	e8 74 3e 00 00       	call   0x3b3e90
  3b001c:	48 8b 4b 30          	mov    rcx,QWORD PTR [rbx+0x30]
  3b0020:	4c 8b 43 20          	mov    r8,QWORD PTR [rbx+0x20]
  3b0024:	eb 63                	jmp    0x3b0089
  3b0026:	4c 8b 73 28          	mov    r14,QWORD PTR [rbx+0x28]
  3b002a:	83 f8 02             	cmp    eax,0x2
  3b002d:	72 46                	jb     0x3b0075
  3b002f:	45 31 e4             	xor    r12d,r12d
  3b0032:	eb 08                	jmp    0x3b003c
  3b0034:	41 ff c4             	inc    r12d
  3b0037:	41 39 c4             	cmp    r12d,eax
  3b003a:	73 39                	jae    0x3b0075
  3b003c:	49 8b 48 28          	mov    rcx,QWORD PTR [r8+0x28]
  3b0040:	49 63 d4             	movsxd rdx,r12d
  3b0043:	4c 8b 0c d1          	mov    r9,QWORD PTR [rcx+rdx*8]
  3b0047:	4d 85 c9             	test   r9,r9
  3b004a:	74 e8                	je     0x3b0034
  3b004c:	48 8d 3d d5 d7 f2 00 	lea    rdi,[rip+0xf2d7d5]        # 0x12dd828
  3b0053:	48 8d 35 32 45 fd 00 	lea    rsi,[rip+0xfd4532]        # 0x138458c
  3b005a:	ba 4d 0f 00 00       	mov    edx,0xf4d
  3b005f:	44 89 e1             	mov    ecx,r12d
  3b0062:	45 89 e0             	mov    r8d,r12d
  3b0065:	31 c0                	xor    eax,eax
  3b0067:	e8 a4 d3 ea ff       	call   0x25d410
  3b006c:	4c 8b 43 20          	mov    r8,QWORD PTR [rbx+0x20]
  3b0070:	41 8b 06             	mov    eax,DWORD PTR [r14]
  3b0073:	eb bf                	jmp    0x3b0034
  3b0075:	49 83 c6 20          	add    r14,0x20
  3b0079:	4c 89 f7             	mov    rdi,r14
  3b007c:	e8 df 16 84 00       	call   0xbf1760
  3b0081:	4c 8b 43 20          	mov    r8,QWORD PTR [rbx+0x20]
  3b0085:	48 8b 4b 30          	mov    rcx,QWORD PTR [rbx+0x30]
  3b0089:	49 8b 40 28          	mov    rax,QWORD PTR [r8+0x28]
  3b008d:	48 8d 35 dc 58 70 01 	lea    rsi,[rip+0x17058dc]        # 0x1ab5970
  3b0094:	4d 89 c4             	mov    r12,r8
  3b0097:	48 c7 04 c8 00 00 00 	mov    QWORD PTR [rax+rcx*8],0x0
  3b009e:	00 
  3b009f:	49 8b 78 10          	mov    rdi,QWORD PTR [r8+0x10]
  3b00a3:	e8 48 8d 85 00       	call   0xc08df0
  3b00a8:	49 8b 7c 24 20       	mov    rdi,QWORD PTR [r12+0x20]
  3b00ad:	48 8d 35 dc 57 70 01 	lea    rsi,[rip+0x17057dc]        # 0x1ab5890
  3b00b4:	e8 37 8d 85 00       	call   0xc08df0
  3b00b9:	49 8b 7c 24 28       	mov    rdi,QWORD PTR [r12+0x28]
  3b00be:	4c 8d 35 8b 59 70 01 	lea    r14,[rip+0x170598b]        # 0x1ab5a50
  3b00c5:	4c 89 f6             	mov    rsi,r14
  3b00c8:	e8 23 8d 85 00       	call   0xc08df0
  3b00cd:	4c 89 e7             	mov    rdi,r12
  3b00d0:	4c 89 f6             	mov    rsi,r14
  3b00d3:	e8 18 8d 85 00       	call   0xc08df0
  3b00d8:	48 8b 53 78          	mov    rdx,QWORD PTR [rbx+0x78]
  3b00dc:	48 8b 7b 50          	mov    rdi,QWORD PTR [rbx+0x50]
  3b00e0:	44 89 fe             	mov    esi,r15d
  3b00e3:	e8 48 9d fe ff       	call   0x399e30
  3b00e8:	48 8b 7b 78          	mov    rdi,QWORD PTR [rbx+0x78]
  3b00ec:	e8 bf 9d fe ff       	call   0x399eb0
  3b00f1:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  3b00f5:	48 8b 73 10          	mov    rsi,QWORD PTR [rbx+0x10]
  3b00f9:	48 8b 7b 18          	mov    rdi,QWORD PTR [rbx+0x18]
  3b00fd:	48 8b 43 20          	mov    rax,QWORD PTR [rbx+0x20]
  3b0101:	45 31 ff             	xor    r15d,r15d
  3b0104:	c7 43 28 00 00 00 00 	mov    DWORD PTR [rbx+0x28],0x0
  3b010b:	e9 8b fa ff ff       	jmp    0x3afb9b
  3b0110:	4c 8b 7b 40          	mov    r15,QWORD PTR [rbx+0x40]
  3b0114:	4d 85 ff             	test   r15,r15
  3b0117:	41 0f 95 c6          	setne  r14b
  3b011b:	e8 b0 77 75 00       	call   0xb078d0
  3b0120:	85 c0                	test   eax,eax
  3b0122:	4c 8d 2d e7 c1 56 03 	lea    r13,[rip+0x356c1e7]        # 0x391c310
  3b0129:	0f 95 c0             	setne  al
  3b012c:	44 20 f0             	and    al,r14b
  3b012f:	4c 8b 73 68          	mov    r14,QWORD PTR [rbx+0x68]
  3b0133:	3c 01                	cmp    al,0x1
  3b0135:	75 1e                	jne    0x3b0155
  3b0137:	4c 89 f7             	mov    rdi,r14
  3b013a:	4c 89 fa             	mov    rdx,r15
  3b013d:	48 8b 73 48          	mov    rsi,QWORD PTR [rbx+0x48]
  3b0141:	e8 1a 38 cf ff       	call   0xa3960
  3b0146:	48 8d 35 b3 d6 6c 01 	lea    rsi,[rip+0x16cd6b3]        # 0x1a7d800
  3b014d:	4c 89 ff             	mov    rdi,r15
  3b0150:	e8 9b 8c 85 00       	call   0xc08df0
  3b0155:	83 7b 28 00          	cmp    DWORD PTR [rbx+0x28],0x0
  3b0159:	74 09                	je     0x3b0164
  3b015b:	48 8b 7b 78          	mov    rdi,QWORD PTR [rbx+0x78]
  3b015f:	e8 4c 9d fe ff       	call   0x399eb0
  3b0164:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3b016b:	00 00 
  3b016d:	48 8d 35 23 f1 f9 00 	lea    rsi,[rip+0xf9f123]        # 0x134f297
  3b0174:	31 d2                	xor    edx,edx
  3b0176:	e8 65 a2 86 00       	call   0xc1a3e0
  3b017b:	4c 8b 63 08          	mov    r12,QWORD PTR [rbx+0x8]
  3b017f:	48 8b 73 60          	mov    rsi,QWORD PTR [rbx+0x60]
  3b0183:	48 8b 53 58          	mov    rdx,QWORD PTR [rbx+0x58]
  3b0187:	4c 89 e7             	mov    rdi,r12
  3b018a:	e8 41 90 ea ff       	call   0x2591d0
  3b018f:	41 89 c7             	mov    r15d,eax
  3b0192:	e8 39 77 75 00       	call   0xb078d0
  3b0197:	85 c0                	test   eax,eax
  3b0199:	74 0f                	je     0x3b01aa
  3b019b:	4c 89 e6             	mov    rsi,r12
  3b019e:	4c 89 f2             	mov    rdx,r14
  3b01a1:	48 8b 7b 48          	mov    rdi,QWORD PTR [rbx+0x48]
  3b01a5:	e8 46 38 cf ff       	call   0xa39f0
  3b01aa:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  3b01ae:	48 3b 83 80 00 00 00 	cmp    rax,QWORD PTR [rbx+0x80]
  3b01b5:	75 2a                	jne    0x3b01e1
  3b01b7:	44 89 f8             	mov    eax,r15d
  3b01ba:	48 8d 65 d8          	lea    rsp,[rbp-0x28]
  3b01be:	5b                   	pop    rbx
  3b01bf:	41 5c                	pop    r12
  3b01c1:	41 5d                	pop    r13
  3b01c3:	41 5e                	pop    r14
  3b01c5:	41 5f                	pop    r15
  3b01c7:	5d                   	pop    rbp
  3b01c8:	c3                   	ret
  3b01c9:	48 8d 35 50 f1 11 03 	lea    rsi,[rip+0x311f150]        # 0x34cf320
  3b01d0:	e9 f1 f7 ff ff       	jmp    0x3af9c6
  3b01d5:	48 8d 35 3c 02 12 03 	lea    rsi,[rip+0x312023c]        # 0x34d0418
  3b01dc:	e9 e5 f7 ff ff       	jmp    0x3af9c6
  3b01e1:	e8 ca d4 34 00       	call   0x6fd6b0
  3b01e6:	0f 0b                	ud2
  3b01e8:	90                   	nop
  3b01e9:	90                   	nop
  3b01ea:	90                   	nop
  3b01eb:	90                   	nop
  3b01ec:	90                   	nop
  3b01ed:	90                   	nop
  3b01ee:	90                   	nop
  3b01ef:	90                   	nop
  3b01f0:	55                   	push   rbp
  3b01f1:	48 89 e5             	mov    rbp,rsp
  3b01f4:	48 8b 06             	mov    rax,QWORD PTR [rsi]
  3b01f7:	8b 56 08             	mov    edx,DWORD PTR [rsi+0x8]
  3b01fa:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
  3b01fe:	44 8b 46 18          	mov    r8d,DWORD PTR [rsi+0x18]
  3b0202:	4c 8b 4e 20          	mov    r9,QWORD PTR [rsi+0x20]
  3b0206:	48 89 c6             	mov    rsi,rax
  3b0209:	5d                   	pop    rbp
  3b020a:	e9 01 00 00 00       	jmp    0x3b0210
  3b020f:	90                   	nop
  3b0210:	55                   	push   rbp
  3b0211:	48 89 e5             	mov    rbp,rsp
  3b0214:	41 57                	push   r15
  3b0216:	41 56                	push   r14
  3b0218:	41 55                	push   r13
  3b021a:	41 54                	push   r12
  3b021c:	53                   	push   rbx
  3b021d:	48 83 e4 e0          	and    rsp,0xffffffffffffffe0
  3b0221:	48 81 ec 40 01 00 00 	sub    rsp,0x140
  3b0228:	48 89 e3             	mov    rbx,rsp
  3b022b:	48 8d 05 de c0 56 03 	lea    rax,[rip+0x356c0de]        # 0x391c310
  3b0232:	4c 89 4b 60          	mov    QWORD PTR [rbx+0x60],r9
  3b0236:	48 89 8b 98 00 00 00 	mov    QWORD PTR [rbx+0x98],rcx
  3b023d:	48 89 53 70          	mov    QWORD PTR [rbx+0x70],rdx
  3b0241:	45 89 c5             	mov    r13d,r8d
  3b0244:	49 89 f7             	mov    r15,rsi
  3b0247:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b024a:	48 89 83 20 01 00 00 	mov    QWORD PTR [rbx+0x120],rax
  3b0251:	48 89 7b 68          	mov    QWORD PTR [rbx+0x68],rdi
  3b0255:	4c 8b 67 08          	mov    r12,QWORD PTR [rdi+0x8]
  3b0259:	49 8b 84 24 48 0c 00 	mov    rax,QWORD PTR [r12+0xc48]
  3b0260:	00 
  3b0261:	4c 89 e7             	mov    rdi,r12
  3b0264:	c7 83 14 01 00 00 00 	mov    DWORD PTR [rbx+0x114],0x0
  3b026b:	00 00 00 
  3b026e:	c7 83 10 01 00 00 00 	mov    DWORD PTR [rbx+0x110],0x0
  3b0275:	00 00 00 
  3b0278:	c7 83 08 01 00 00 00 	mov    DWORD PTR [rbx+0x108],0x0
  3b027f:	00 00 00 
  3b0282:	48 89 83 a0 00 00 00 	mov    QWORD PTR [rbx+0xa0],rax
  3b0289:	e8 f2 7e 64 00       	call   0x9f8180
  3b028e:	48 8d b3 e0 00 00 00 	lea    rsi,[rbx+0xe0]
  3b0295:	4c 89 e7             	mov    rdi,r12
  3b0298:	49 89 c6             	mov    r14,rax
  3b029b:	e8 20 7f 64 00       	call   0x9f81c0
  3b02a0:	48 8d 35 21 f6 11 03 	lea    rsi,[rip+0x311f621]        # 0x34cf8c8
  3b02a7:	45 31 e4             	xor    r12d,r12d
  3b02aa:	85 c0                	test   eax,eax
  3b02ac:	0f 85 87 00 00 00    	jne    0x3b0339
  3b02b2:	8b 83 e0 00 00 00    	mov    eax,DWORD PTR [rbx+0xe0]
  3b02b8:	3d ff ff ff 00       	cmp    eax,0xffffff
  3b02bd:	77 7a                	ja     0x3b0339
  3b02bf:	3d ff ff 00 00       	cmp    eax,0xffff
  3b02c4:	76 30                	jbe    0x3b02f6
  3b02c6:	25 00 00 ff 00       	and    eax,0xff0000
  3b02cb:	48 8d 0d 9e fb 11 03 	lea    rcx,[rip+0x311fb9e]        # 0x34cfe70
  3b02d2:	48 8d 35 ef f5 11 03 	lea    rsi,[rip+0x311f5ef]        # 0x34cf8c8
  3b02d9:	41 bc 01 00 00 00    	mov    r12d,0x1
  3b02df:	3d 00 00 01 00       	cmp    eax,0x10000
  3b02e4:	48 0f 44 f1          	cmove  rsi,rcx
  3b02e8:	83 be a0 04 00 00 01 	cmp    DWORD PTR [rsi+0x4a0],0x1
  3b02ef:	75 51                	jne    0x3b0342
  3b02f1:	e9 8e 00 00 00       	jmp    0x3b0384
  3b02f6:	41 bc 01 00 00 00    	mov    r12d,0x1
  3b02fc:	4c 39 35 c5 f4 11 03 	cmp    QWORD PTR [rip+0x311f4c5],r14        # 0x34cf7c8
  3b0303:	74 2d                	je     0x3b0332
  3b0305:	4c 39 35 b4 05 12 03 	cmp    QWORD PTR [rip+0x31205b4],r14        # 0x34d08c0
  3b030c:	74 66                	je     0x3b0374
  3b030e:	83 3d ab f4 11 03 00 	cmp    DWORD PTR [rip+0x311f4ab],0x0        # 0x34cf7c0
  3b0315:	48 8d 05 04 f0 11 03 	lea    rax,[rip+0x311f004]        # 0x34cf320
  3b031c:	48 8d 35 f5 00 12 03 	lea    rsi,[rip+0x31200f5]        # 0x34d0418
  3b0323:	48 0f 44 f0          	cmove  rsi,rax
  3b0327:	83 be a0 04 00 00 01 	cmp    DWORD PTR [rsi+0x4a0],0x1
  3b032e:	75 12                	jne    0x3b0342
  3b0330:	eb 52                	jmp    0x3b0384
  3b0332:	48 8d 35 e7 ef 11 03 	lea    rsi,[rip+0x311efe7]        # 0x34cf320
  3b0339:	83 be a0 04 00 00 01 	cmp    DWORD PTR [rsi+0x4a0],0x1
  3b0340:	74 42                	je     0x3b0384
  3b0342:	bf 01 00 00 00       	mov    edi,0x1
  3b0347:	49 89 f6             	mov    r14,rsi
  3b034a:	e8 c1 30 00 00       	call   0x3b3410
  3b034f:	4c 89 f6             	mov    rsi,r14
  3b0352:	85 c0                	test   eax,eax
  3b0354:	74 2e                	je     0x3b0384
  3b0356:	41 89 c6             	mov    r14d,eax
  3b0359:	48 8d 3d a8 bb f6 00 	lea    rdi,[rip+0xf6bba8]        # 0x131bf08
  3b0360:	48 8d 35 15 9a fc 00 	lea    rsi,[rip+0xfc9a15]        # 0x1379d7c
  3b0367:	ba fc 0f 00 00       	mov    edx,0xffc
  3b036c:	44 89 f1             	mov    ecx,r14d
  3b036f:	e9 15 01 00 00       	jmp    0x3b0489
  3b0374:	48 8d 35 9d 00 12 03 	lea    rsi,[rip+0x312009d]        # 0x34d0418
  3b037b:	83 be a0 04 00 00 01 	cmp    DWORD PTR [rsi+0x4a0],0x1
  3b0382:	75 be                	jne    0x3b0342
  3b0384:	48 8b 4b 70          	mov    rcx,QWORD PTR [rbx+0x70]
  3b0388:	8d 81 7f ff ff ff    	lea    eax,[rcx-0x81]
  3b038e:	3d 7f ff ff ff       	cmp    eax,0xffffff7f
  3b0393:	77 23                	ja     0x3b03b8
  3b0395:	48 8d 3d 6c bb f6 00 	lea    rdi,[rip+0xf6bb6c]        # 0x131bf08
  3b039c:	48 8d 35 d9 99 fc 00 	lea    rsi,[rip+0xfc99d9]        # 0x1379d7c
  3b03a3:	41 be 16 00 00 00    	mov    r14d,0x16
  3b03a9:	ba 02 10 00 00       	mov    edx,0x1002
  3b03ae:	b9 16 00 00 00       	mov    ecx,0x16
  3b03b3:	e9 d1 00 00 00       	jmp    0x3b0489
  3b03b8:	41 83 fd 03          	cmp    r13d,0x3
  3b03bc:	73 50                	jae    0x3b040e
  3b03be:	89 c8                	mov    eax,ecx
  3b03c0:	44 89 6b 2c          	mov    DWORD PTR [rbx+0x2c],r13d
  3b03c4:	48 89 b3 90 00 00 00 	mov    QWORD PTR [rbx+0x90],rsi
  3b03cb:	48 89 43 20          	mov    QWORD PTR [rbx+0x20],rax
  3b03cf:	83 f9 02             	cmp    ecx,0x2
  3b03d2:	72 5a                	jb     0x3b042e
  3b03d4:	8d 04 8d 0f 00 00 00 	lea    eax,[rcx*4+0xf]
  3b03db:	49 89 e6             	mov    r14,rsp
  3b03de:	8d 34 8d 00 00 00 00 	lea    esi,[rcx*4+0x0]
  3b03e5:	83 e0 f0             	and    eax,0xfffffff0
  3b03e8:	49 29 c6             	sub    r14,rax
  3b03eb:	49 83 e6 e0          	and    r14,0xffffffffffffffe0
  3b03ef:	4c 89 f4             	mov    rsp,r14
  3b03f2:	48 89 e7             	mov    rdi,rsp
  3b03f5:	48 29 c7             	sub    rdi,rax
  3b03f8:	48 83 e7 e0          	and    rdi,0xffffffffffffffe0
  3b03fc:	48 89 fc             	mov    rsp,rdi
  3b03ff:	48 89 7b 38          	mov    QWORD PTR [rbx+0x38],rdi
  3b0403:	e8 e8 8b ea ff       	call   0x258ff0
  3b0408:	48 8b 43 20          	mov    rax,QWORD PTR [rbx+0x20]
  3b040c:	eb 32                	jmp    0x3b0440
  3b040e:	48 8d 3d f3 ba f6 00 	lea    rdi,[rip+0xf6baf3]        # 0x131bf08
  3b0415:	48 8d 35 60 99 fc 00 	lea    rsi,[rip+0xfc9960]        # 0x1379d7c
  3b041c:	41 be 16 00 00 00    	mov    r14d,0x16
  3b0422:	ba 0c 10 00 00       	mov    edx,0x100c
  3b0427:	b9 16 00 00 00       	mov    ecx,0x16
  3b042c:	eb 5b                	jmp    0x3b0489
  3b042e:	48 8d 8b 10 01 00 00 	lea    rcx,[rbx+0x110]
  3b0435:	4c 8d b3 14 01 00 00 	lea    r14,[rbx+0x114]
  3b043c:	48 89 4b 38          	mov    QWORD PTR [rbx+0x38],rcx
  3b0440:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3b0447:	00 00 
  3b0449:	48 8d 35 ed 7a fe 00 	lea    rsi,[rip+0xfe7aed]        # 0x1397f3d
  3b0450:	31 d2                	xor    edx,edx
  3b0452:	4c 8d 2c 85 00 00 00 	lea    r13,[rax*4+0x0]
  3b0459:	00 
  3b045a:	e8 81 9f 86 00       	call   0xc1a3e0
  3b045f:	4c 89 ff             	mov    rdi,r15
  3b0462:	4c 89 f6             	mov    rsi,r14
  3b0465:	4c 89 ea             	mov    rdx,r13
  3b0468:	e8 13 8e ea ff       	call   0x259280
  3b046d:	85 c0                	test   eax,eax
  3b046f:	74 48                	je     0x3b04b9
  3b0471:	48 8d 3d 90 ba f6 00 	lea    rdi,[rip+0xf6ba90]        # 0x131bf08
  3b0478:	48 8d 35 fd 98 fc 00 	lea    rsi,[rip+0xfc98fd]        # 0x1379d7c
  3b047f:	ba 1b 10 00 00       	mov    edx,0x101b
  3b0484:	89 c1                	mov    ecx,eax
  3b0486:	41 89 c6             	mov    r14d,eax
  3b0489:	31 c0                	xor    eax,eax
  3b048b:	e8 80 cf ea ff       	call   0x25d410
  3b0490:	48 8d 05 79 be 56 03 	lea    rax,[rip+0x356be79]        # 0x391c310
  3b0497:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b049a:	48 3b 83 20 01 00 00 	cmp    rax,QWORD PTR [rbx+0x120]
  3b04a1:	0f 85 01 0b 00 00    	jne    0x3b0fa8
  3b04a7:	44 89 f0             	mov    eax,r14d
  3b04aa:	48 8d 65 d8          	lea    rsp,[rbp-0x28]
  3b04ae:	5b                   	pop    rbx
  3b04af:	41 5c                	pop    r12
  3b04b1:	41 5d                	pop    r13
  3b04b3:	41 5e                	pop    r14
  3b04b5:	41 5f                	pop    r15
  3b04b7:	5d                   	pop    rbp
  3b04b8:	c3                   	ret
  3b04b9:	4c 89 73 30          	mov    QWORD PTR [rbx+0x30],r14
  3b04bd:	4c 8b 73 60          	mov    r14,QWORD PTR [rbx+0x60]
  3b04c1:	4c 89 ab 80 00 00 00 	mov    QWORD PTR [rbx+0x80],r13
  3b04c8:	4d 85 f6             	test   r14,r14
  3b04cb:	74 4a                	je     0x3b0517
  3b04cd:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3b04d4:	00 00 
  3b04d6:	48 8d 35 60 7a fe 00 	lea    rsi,[rip+0xfe7a60]        # 0x1397f3d
  3b04dd:	31 d2                	xor    edx,edx
  3b04df:	e8 fc 9e 86 00       	call   0xc1a3e0
  3b04e4:	48 8d b3 08 01 00 00 	lea    rsi,[rbx+0x108]
  3b04eb:	ba 04 00 00 00       	mov    edx,0x4
  3b04f0:	4c 89 f7             	mov    rdi,r14
  3b04f3:	e8 88 8d ea ff       	call   0x259280
  3b04f8:	85 c0                	test   eax,eax
  3b04fa:	74 1b                	je     0x3b0517
  3b04fc:	41 89 c6             	mov    r14d,eax
  3b04ff:	48 8d 3d 02 ba f6 00 	lea    rdi,[rip+0xf6ba02]        # 0x131bf08
  3b0506:	48 8d 35 6f 98 fc 00 	lea    rsi,[rip+0xfc986f]        # 0x1379d7c
  3b050d:	ba 22 10 00 00       	mov    edx,0x1022
  3b0512:	e9 55 fe ff ff       	jmp    0x3b036c
  3b0517:	e8 b4 73 75 00       	call   0xb078d0
  3b051c:	44 89 63 7c          	mov    DWORD PTR [rbx+0x7c],r12d
  3b0520:	85 c0                	test   eax,eax
  3b0522:	74 26                	je     0x3b054a
  3b0524:	4c 8b 73 20          	mov    r14,QWORD PTR [rbx+0x20]
  3b0528:	48 8d 35 d1 d2 6c 01 	lea    rsi,[rip+0x16cd2d1]        # 0x1a7d800
  3b052f:	ba 02 01 00 00       	mov    edx,0x102
  3b0534:	4a 8d 04 f5 00 00 00 	lea    rax,[r14*8+0x0]
  3b053b:	00 
  3b053c:	48 8d 3c 40          	lea    rdi,[rax+rax*2]
  3b0540:	e8 0b 86 85 00       	call   0xc08b50
  3b0545:	49 89 c4             	mov    r12,rax
  3b0548:	eb 07                	jmp    0x3b0551
  3b054a:	4c 8b 73 20          	mov    r14,QWORD PTR [rbx+0x20]
  3b054e:	45 31 e4             	xor    r12d,r12d
  3b0551:	44 8b 7b 2c          	mov    r15d,DWORD PTR [rbx+0x2c]
  3b0555:	48 8d bb f8 00 00 00 	lea    rdi,[rbx+0xf8]
  3b055c:	48 8d 35 7b 73 f3 00 	lea    rsi,[rip+0xf3737b]        # 0x12e78de
  3b0563:	c7 83 04 01 00 00 00 	mov    DWORD PTR [rbx+0x104],0x0
  3b056a:	00 00 00 
  3b056d:	31 d2                	xor    edx,edx
  3b056f:	31 c9                	xor    ecx,ecx
  3b0571:	e8 5a 78 11 00       	call   0x4c7dd0
  3b0576:	49 6b fe 38          	imul   rdi,r14,0x38
  3b057a:	48 8d 35 cf 54 70 01 	lea    rsi,[rip+0x17054cf]        # 0x1ab5a50
  3b0581:	ba 02 01 00 00       	mov    edx,0x102
  3b0586:	e8 c5 85 85 00       	call   0xc08b50
  3b058b:	49 89 c6             	mov    r14,rax
  3b058e:	41 83 ff 02          	cmp    r15d,0x2
  3b0592:	75 14                	jne    0x3b05a8
  3b0594:	c7 83 04 01 00 00 01 	mov    DWORD PTR [rbx+0x104],0x1
  3b059b:	00 00 00 
  3b059e:	c7 83 0c 01 00 00 00 	mov    DWORD PTR [rbx+0x10c],0x0
  3b05a5:	00 00 00 
  3b05a8:	48 8b 73 20          	mov    rsi,QWORD PTR [rbx+0x20]
  3b05ac:	48 8b 7b 30          	mov    rdi,QWORD PTR [rbx+0x30]
  3b05b0:	4d 8d 44 24 10       	lea    r8,[r12+0x10]
  3b05b5:	4c 89 a3 88 00 00 00 	mov    QWORD PTR [rbx+0x88],r12
  3b05bc:	4c 89 73 40          	mov    QWORD PTR [rbx+0x40],r14
  3b05c0:	45 31 ff             	xor    r15d,r15d
  3b05c3:	31 c0                	xor    eax,eax
  3b05c5:	c7 43 14 00 00 00 00 	mov    DWORD PTR [rbx+0x14],0x0
  3b05cc:	eb 24                	jmp    0x3b05f2
  3b05ce:	66 90                	xchg   ax,ax
  3b05d0:	41 c7 46 20 03 00 02 	mov    DWORD PTR [r14+0x20],0x80020003
  3b05d7:	80 
  3b05d8:	41 89 c4             	mov    r12d,eax
  3b05db:	49 ff c7             	inc    r15
  3b05de:	49 83 c6 38          	add    r14,0x38
  3b05e2:	49 83 c0 18          	add    r8,0x18
  3b05e6:	44 89 e0             	mov    eax,r12d
  3b05e9:	4c 39 fe             	cmp    rsi,r15
  3b05ec:	0f 84 4f 04 00 00    	je     0x3b0a41
  3b05f2:	46 8b 24 bf          	mov    r12d,DWORD PTR [rdi+r15*4]
  3b05f6:	45 89 e5             	mov    r13d,r12d
  3b05f9:	41 c1 fd 10          	sar    r13d,0x10
  3b05fd:	41 81 e4 ff ff 00 00 	and    r12d,0xffff
  3b0604:	0f 95 c1             	setne  cl
  3b0607:	41 81 fd 80 00 00 00 	cmp    r13d,0x80
  3b060e:	0f 92 c2             	setb   dl
  3b0611:	84 d1                	test   cl,dl
  3b0613:	74 bb                	je     0x3b05d0
  3b0615:	4c 89 43 48          	mov    QWORD PTR [rbx+0x48],r8
  3b0619:	41 39 c4             	cmp    r12d,eax
  3b061c:	74 2f                	je     0x3b064d
  3b061e:	48 8b bb a0 00 00 00 	mov    rdi,QWORD PTR [rbx+0xa0]
  3b0625:	44 89 e6             	mov    esi,r12d
  3b0628:	ba 60 01 00 00       	mov    edx,0x160
  3b062d:	48 8d 8b 18 01 00 00 	lea    rcx,[rbx+0x118]
  3b0634:	e8 a7 98 fe ff       	call   0x399ee0
  3b0639:	48 89 43 58          	mov    QWORD PTR [rbx+0x58],rax
  3b063d:	48 85 c0             	test   rax,rax
  3b0640:	74 7e                	je     0x3b06c0
  3b0642:	48 8b 83 18 01 00 00 	mov    rax,QWORD PTR [rbx+0x118]
  3b0649:	49 89 46 28          	mov    QWORD PTR [r14+0x28],rax
  3b064d:	48 8b 43 58          	mov    rax,QWORD PTR [rbx+0x58]
  3b0651:	0f bf 00             	movsx  eax,WORD PTR [rax]
  3b0654:	41 39 c5             	cmp    r13d,eax
  3b0657:	7d 37                	jge    0x3b0690
  3b0659:	48 8b bb 18 01 00 00 	mov    rdi,QWORD PTR [rbx+0x118]
  3b0660:	e8 bb 97 fe ff       	call   0x399e20
  3b0665:	85 c0                	test   eax,eax
  3b0667:	74 6f                	je     0x3b06d8
  3b0669:	41 c7 46 20 01 00 02 	mov    DWORD PTR [r14+0x20],0x80020001
  3b0670:	80 
  3b0671:	48 8d 3d ff ac fa 00 	lea    rdi,[rip+0xfaacff]        # 0x135b377
  3b0678:	48 8d 35 fd 96 fc 00 	lea    rsi,[rip+0xfc96fd]        # 0x1379d7c
  3b067f:	ba 6a 10 00 00       	mov    edx,0x106a
  3b0684:	44 89 f9             	mov    ecx,r15d
  3b0687:	41 b8 01 00 00 00    	mov    r8d,0x1
  3b068d:	eb 25                	jmp    0x3b06b4
  3b068f:	90                   	nop
  3b0690:	48 8d 3d e0 ac fa 00 	lea    rdi,[rip+0xfaace0]        # 0x135b377
  3b0697:	48 8d 35 de 96 fc 00 	lea    rsi,[rip+0xfc96de]        # 0x1379d7c
  3b069e:	ba 64 10 00 00       	mov    edx,0x1064
  3b06a3:	41 c7 46 20 03 00 02 	mov    DWORD PTR [r14+0x20],0x80020003
  3b06aa:	80 
  3b06ab:	44 89 f9             	mov    ecx,r15d
  3b06ae:	41 b8 03 00 00 00    	mov    r8d,0x3
  3b06b4:	31 c0                	xor    eax,eax
  3b06b6:	e8 55 cd ea ff       	call   0x25d410
  3b06bb:	e9 70 03 00 00       	jmp    0x3b0a30
  3b06c0:	41 c7 46 20 03 00 02 	mov    DWORD PTR [r14+0x20],0x80020003
  3b06c7:	80 
  3b06c8:	45 31 e4             	xor    r12d,r12d
  3b06cb:	48 c7 43 58 00 00 00 	mov    QWORD PTR [rbx+0x58],0x0
  3b06d2:	00 
  3b06d3:	e9 58 03 00 00       	jmp    0x3b0a30
  3b06d8:	48 8b 43 58          	mov    rax,QWORD PTR [rbx+0x58]
  3b06dc:	44 89 e9             	mov    ecx,r13d
  3b06df:	48 8b 40 28          	mov    rax,QWORD PTR [rax+0x28]
  3b06e3:	4c 8b 2c c8          	mov    r13,QWORD PTR [rax+rcx*8]
  3b06e7:	4d 85 ed             	test   r13,r13
  3b06ea:	0f 84 29 01 00 00    	je     0x3b0819
  3b06f0:	48 83 bb 88 00 00 00 	cmp    QWORD PTR [rbx+0x88],0x0
  3b06f7:	00 
  3b06f8:	48 89 8b a8 00 00 00 	mov    QWORD PTR [rbx+0xa8],rcx
  3b06ff:	0f 95 43 18          	setne  BYTE PTR [rbx+0x18]
  3b0703:	e8 c8 71 75 00       	call   0xb078d0
  3b0708:	85 c0                	test   eax,eax
  3b070a:	0f 95 c0             	setne  al
  3b070d:	22 43 18             	and    al,BYTE PTR [rbx+0x18]
  3b0710:	3c 01                	cmp    al,0x1
  3b0712:	75 2b                	jne    0x3b073f
  3b0714:	48 8b 43 30          	mov    rax,QWORD PTR [rbx+0x30]
  3b0718:	48 8b 53 48          	mov    rdx,QWORD PTR [rbx+0x48]
  3b071c:	42 8b 04 b8          	mov    eax,DWORD PTR [rax+r15*4]
  3b0720:	89 42 f0             	mov    DWORD PTR [rdx-0x10],eax
  3b0723:	49 8b 45 18          	mov    rax,QWORD PTR [r13+0x18]
  3b0727:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b072a:	48 89 42 f8          	mov    QWORD PTR [rdx-0x8],rax
  3b072e:	49 8b 45 10          	mov    rax,QWORD PTR [r13+0x10]
  3b0732:	48 89 c1             	mov    rcx,rax
  3b0735:	48 c1 f9 04          	sar    rcx,0x4
  3b0739:	48 31 c1             	xor    rcx,rax
  3b073c:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  3b073f:	4d 8b 6d 20          	mov    r13,QWORD PTR [r13+0x20]
  3b0743:	4d 85 ed             	test   r13,r13
  3b0746:	75 20                	jne    0x3b0768
  3b0748:	48 8d 3d 3d 96 fc 00 	lea    rdi,[rip+0xfc963d]        # 0x1379d8c
  3b074f:	48 8d 35 26 96 fc 00 	lea    rsi,[rip+0xfc9626]        # 0x1379d7c
  3b0756:	ba 7f 10 00 00       	mov    edx,0x107f
  3b075b:	44 89 f9             	mov    ecx,r15d
  3b075e:	45 31 c0             	xor    r8d,r8d
  3b0761:	31 c0                	xor    eax,eax
  3b0763:	e8 a8 cc ea ff       	call   0x25d410
  3b0768:	49 8d 7d 20          	lea    rdi,[r13+0x20]
  3b076c:	be 00 00 08 00       	mov    esi,0x80000
  3b0771:	31 d2                	xor    edx,edx
  3b0773:	31 c9                	xor    ecx,ecx
  3b0775:	45 31 c0             	xor    r8d,r8d
  3b0778:	45 31 c9             	xor    r9d,r9d
  3b077b:	48 89 7b 18          	mov    QWORD PTR [rbx+0x18],rdi
  3b077f:	6a 00                	push   0x0
  3b0781:	6a 00                	push   0x0
  3b0783:	e8 e8 0f 84 00       	call   0xbf1770
  3b0788:	48 83 c4 10          	add    rsp,0x10
  3b078c:	8b 43 2c             	mov    eax,DWORD PTR [rbx+0x2c]
  3b078f:	83 f8 01             	cmp    eax,0x1
  3b0792:	0f 85 a1 00 00 00    	jne    0x3b0839
  3b0798:	41 8b 45 08          	mov    eax,DWORD PTR [r13+0x8]
  3b079c:	4c 89 e9             	mov    rcx,r13
  3b079f:	41 89 46 20          	mov    DWORD PTR [r14+0x20],eax
  3b07a3:	83 f8 02             	cmp    eax,0x2
  3b07a6:	0f 8f 21 01 00 00    	jg     0x3b08cd
  3b07ac:	4c 8d ab f8 00 00 00 	lea    r13,[rbx+0xf8]
  3b07b3:	48 89 4b 50          	mov    QWORD PTR [rbx+0x50],rcx
  3b07b7:	31 f6                	xor    esi,esi
  3b07b9:	31 d2                	xor    edx,edx
  3b07bb:	31 c9                	xor    ecx,ecx
  3b07bd:	4c 89 ef             	mov    rdi,r13
  3b07c0:	e8 3b 62 11 00       	call   0x4c6a00
  3b07c5:	ff 83 04 01 00 00    	inc    DWORD PTR [rbx+0x104]
  3b07cb:	48 8d 83 04 01 00 00 	lea    rax,[rbx+0x104]
  3b07d2:	4c 89 ef             	mov    rdi,r13
  3b07d5:	31 f6                	xor    esi,esi
  3b07d7:	31 d2                	xor    edx,edx
  3b07d9:	31 c9                	xor    ecx,ecx
  3b07db:	49 89 06             	mov    QWORD PTR [r14],rax
  3b07de:	48 8d 83 e0 00 00 00 	lea    rax,[rbx+0xe0]
  3b07e5:	49 89 46 10          	mov    QWORD PTR [r14+0x10],rax
  3b07e9:	e8 b2 67 11 00       	call   0x4c6fa0
  3b07ee:	4c 8b 6b 50          	mov    r13,QWORD PTR [rbx+0x50]
  3b07f2:	41 83 7d 08 02       	cmp    DWORD PTR [r13+0x8],0x2
  3b07f7:	0f 8f 79 01 00 00    	jg     0x3b0976
  3b07fd:	49 8b 45 50          	mov    rax,QWORD PTR [r13+0x50]
  3b0801:	c7 43 14 00 00 00 00 	mov    DWORD PTR [rbx+0x14],0x0
  3b0808:	49 89 46 30          	mov    QWORD PTR [r14+0x30],rax
  3b080c:	4d 89 75 50          	mov    QWORD PTR [r13+0x50],r14
  3b0810:	4d 89 6e 18          	mov    QWORD PTR [r14+0x18],r13
  3b0814:	e9 e8 01 00 00       	jmp    0x3b0a01
  3b0819:	41 c7 46 20 03 00 02 	mov    DWORD PTR [r14+0x20],0x80020003
  3b0820:	80 
  3b0821:	48 8d 3d 4f ab fa 00 	lea    rdi,[rip+0xfaab4f]        # 0x135b377
  3b0828:	48 8d 35 4d 95 fc 00 	lea    rsi,[rip+0xfc954d]        # 0x1379d7c
  3b082f:	ba 71 10 00 00       	mov    edx,0x1071
  3b0834:	e9 72 fe ff ff       	jmp    0x3b06ab
  3b0839:	48 8b 4b 40          	mov    rcx,QWORD PTR [rbx+0x40]
  3b083d:	4c 89 6b 50          	mov    QWORD PTR [rbx+0x50],r13
  3b0841:	83 f8 02             	cmp    eax,0x2
  3b0844:	0f 85 9b 00 00 00    	jne    0x3b08e5
  3b084a:	48 8b 4b 50          	mov    rcx,QWORD PTR [rbx+0x50]
  3b084e:	8b 41 08             	mov    eax,DWORD PTR [rcx+0x8]
  3b0851:	41 89 46 20          	mov    DWORD PTR [r14+0x20],eax
  3b0855:	83 f8 02             	cmp    eax,0x2
  3b0858:	7f 73                	jg     0x3b08cd
  3b085a:	4c 8d ab f8 00 00 00 	lea    r13,[rbx+0xf8]
  3b0861:	31 f6                	xor    esi,esi
  3b0863:	31 d2                	xor    edx,edx
  3b0865:	31 c9                	xor    ecx,ecx
  3b0867:	4c 89 ef             	mov    rdi,r13
  3b086a:	e8 91 61 11 00       	call   0x4c6a00
  3b086f:	ff 83 0c 01 00 00    	inc    DWORD PTR [rbx+0x10c]
  3b0875:	48 8d 83 04 01 00 00 	lea    rax,[rbx+0x104]
  3b087c:	4c 89 ef             	mov    rdi,r13
  3b087f:	31 f6                	xor    esi,esi
  3b0881:	31 d2                	xor    edx,edx
  3b0883:	31 c9                	xor    ecx,ecx
  3b0885:	49 89 06             	mov    QWORD PTR [r14],rax
  3b0888:	48 8d 83 e0 00 00 00 	lea    rax,[rbx+0xe0]
  3b088f:	49 89 46 10          	mov    QWORD PTR [r14+0x10],rax
  3b0893:	48 8d 83 0c 01 00 00 	lea    rax,[rbx+0x10c]
  3b089a:	49 89 46 08          	mov    QWORD PTR [r14+0x8],rax
  3b089e:	e8 fd 66 11 00       	call   0x4c6fa0
  3b08a3:	48 8b 4b 50          	mov    rcx,QWORD PTR [rbx+0x50]
  3b08a7:	83 79 08 02          	cmp    DWORD PTR [rcx+0x8],0x2
  3b08ab:	0f 8f 28 01 00 00    	jg     0x3b09d9
  3b08b1:	48 8b 41 50          	mov    rax,QWORD PTR [rcx+0x50]
  3b08b5:	c7 43 14 00 00 00 00 	mov    DWORD PTR [rbx+0x14],0x0
  3b08bc:	49 89 46 30          	mov    QWORD PTR [r14+0x30],rax
  3b08c0:	4c 89 71 50          	mov    QWORD PTR [rcx+0x50],r14
  3b08c4:	49 89 4e 18          	mov    QWORD PTR [r14+0x18],rcx
  3b08c8:	e9 34 01 00 00       	jmp    0x3b0a01
  3b08cd:	80 79 0c 00          	cmp    BYTE PTR [rcx+0xc],0x0
  3b08d1:	0f 84 eb 00 00 00    	je     0x3b09c2
  3b08d7:	0d 00 00 01 00       	or     eax,0x10000
  3b08dc:	41 89 46 20          	mov    DWORD PTR [r14+0x20],eax
  3b08e0:	e9 1c 01 00 00       	jmp    0x3b0a01
  3b08e5:	48 8b 43 58          	mov    rax,QWORD PTR [rbx+0x58]
  3b08e9:	48 8b 93 a8 00 00 00 	mov    rdx,QWORD PTR [rbx+0xa8]
  3b08f0:	48 8b 40 28          	mov    rax,QWORD PTR [rax+0x28]
  3b08f4:	48 8b 04 d0          	mov    rax,QWORD PTR [rax+rdx*8]
  3b08f8:	4c 8b 68 20          	mov    r13,QWORD PTR [rax+0x20]
  3b08fc:	41 8b 45 08          	mov    eax,DWORD PTR [r13+0x8]
  3b0900:	89 41 20             	mov    DWORD PTR [rcx+0x20],eax
  3b0903:	83 f8 02             	cmp    eax,0x2
  3b0906:	0f 8f bc 00 00 00    	jg     0x3b09c8
  3b090c:	48 8d bb f8 00 00 00 	lea    rdi,[rbx+0xf8]
  3b0913:	31 f6                	xor    esi,esi
  3b0915:	31 d2                	xor    edx,edx
  3b0917:	31 c9                	xor    ecx,ecx
  3b0919:	e8 e2 60 11 00       	call   0x4c6a00
  3b091e:	ff 83 04 01 00 00    	inc    DWORD PTR [rbx+0x104]
  3b0924:	48 8b 4b 40          	mov    rcx,QWORD PTR [rbx+0x40]
  3b0928:	48 8d 83 04 01 00 00 	lea    rax,[rbx+0x104]
  3b092f:	48 8d bb f8 00 00 00 	lea    rdi,[rbx+0xf8]
  3b0936:	31 f6                	xor    esi,esi
  3b0938:	31 d2                	xor    edx,edx
  3b093a:	48 89 01             	mov    QWORD PTR [rcx],rax
  3b093d:	48 8d 83 e0 00 00 00 	lea    rax,[rbx+0xe0]
  3b0944:	48 89 41 10          	mov    QWORD PTR [rcx+0x10],rax
  3b0948:	31 c9                	xor    ecx,ecx
  3b094a:	e8 51 66 11 00       	call   0x4c6fa0
  3b094f:	41 83 7d 08 02       	cmp    DWORD PTR [r13+0x8],0x2
  3b0954:	7f 20                	jg     0x3b0976
  3b0956:	49 8b 45 50          	mov    rax,QWORD PTR [r13+0x50]
  3b095a:	48 8b 4b 40          	mov    rcx,QWORD PTR [rbx+0x40]
  3b095e:	c7 43 14 00 00 00 00 	mov    DWORD PTR [rbx+0x14],0x0
  3b0965:	48 89 41 30          	mov    QWORD PTR [rcx+0x30],rax
  3b0969:	49 89 4d 50          	mov    QWORD PTR [r13+0x50],rcx
  3b096d:	4c 89 69 18          	mov    QWORD PTR [rcx+0x18],r13
  3b0971:	e9 8b 00 00 00       	jmp    0x3b0a01
  3b0976:	48 8d 3d 1f 50 fb 00 	lea    rdi,[rip+0xfb501f]        # 0x136599c
  3b097d:	48 8d 35 3c d1 f0 00 	lea    rsi,[rip+0xf0d13c]        # 0x12bdac0
  3b0984:	ba a9 0f 00 00       	mov    edx,0xfa9
  3b0989:	31 c0                	xor    eax,eax
  3b098b:	e8 80 ca ea ff       	call   0x25d410
  3b0990:	4c 8d ab f8 00 00 00 	lea    r13,[rbx+0xf8]
  3b0997:	31 f6                	xor    esi,esi
  3b0999:	31 d2                	xor    edx,edx
  3b099b:	31 c9                	xor    ecx,ecx
  3b099d:	4c 89 ef             	mov    rdi,r13
  3b09a0:	e8 5b 60 11 00       	call   0x4c6a00
  3b09a5:	ff 8b 04 01 00 00    	dec    DWORD PTR [rbx+0x104]
  3b09ab:	4c 89 ef             	mov    rdi,r13
  3b09ae:	31 f6                	xor    esi,esi
  3b09b0:	31 d2                	xor    edx,edx
  3b09b2:	31 c9                	xor    ecx,ecx
  3b09b4:	e8 e7 65 11 00       	call   0x4c6fa0
  3b09b9:	c7 43 14 10 00 00 00 	mov    DWORD PTR [rbx+0x14],0x10
  3b09c0:	eb 3f                	jmp    0x3b0a01
  3b09c2:	c6 41 0c 01          	mov    BYTE PTR [rcx+0xc],0x1
  3b09c6:	eb 39                	jmp    0x3b0a01
  3b09c8:	41 80 7d 0c 00       	cmp    BYTE PTR [r13+0xc],0x0
  3b09cd:	74 2d                	je     0x3b09fc
  3b09cf:	0d 00 00 01 00       	or     eax,0x10000
  3b09d4:	89 41 20             	mov    DWORD PTR [rcx+0x20],eax
  3b09d7:	eb 28                	jmp    0x3b0a01
  3b09d9:	48 8d 3d bc 4f fb 00 	lea    rdi,[rip+0xfb4fbc]        # 0x136599c
  3b09e0:	48 8d 35 d9 d0 f0 00 	lea    rsi,[rip+0xf0d0d9]        # 0x12bdac0
  3b09e7:	ba a9 0f 00 00       	mov    edx,0xfa9
  3b09ec:	31 c0                	xor    eax,eax
  3b09ee:	e8 1d ca ea ff       	call   0x25d410
  3b09f3:	c7 43 14 10 00 00 00 	mov    DWORD PTR [rbx+0x14],0x10
  3b09fa:	eb 05                	jmp    0x3b0a01
  3b09fc:	41 c6 45 0c 01       	mov    BYTE PTR [r13+0xc],0x1
  3b0a01:	48 8b 7b 18          	mov    rdi,QWORD PTR [rbx+0x18]
  3b0a05:	be 00 00 10 00       	mov    esi,0x100000
  3b0a0a:	31 d2                	xor    edx,edx
  3b0a0c:	31 c9                	xor    ecx,ecx
  3b0a0e:	45 31 c0             	xor    r8d,r8d
  3b0a11:	45 31 c9             	xor    r9d,r9d
  3b0a14:	6a 00                	push   0x0
  3b0a16:	6a 00                	push   0x0
  3b0a18:	e8 53 0d 84 00       	call   0xbf1770
  3b0a1d:	48 83 c4 10          	add    rsp,0x10
  3b0a21:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b0a28:	0f 1f 84 00 00 00 00 
  3b0a2f:	00 
  3b0a30:	48 8b 73 20          	mov    rsi,QWORD PTR [rbx+0x20]
  3b0a34:	48 8b 7b 30          	mov    rdi,QWORD PTR [rbx+0x30]
  3b0a38:	4c 8b 43 48          	mov    r8,QWORD PTR [rbx+0x48]
  3b0a3c:	e9 9a fb ff ff       	jmp    0x3b05db
  3b0a41:	4c 8b bb 88 00 00 00 	mov    r15,QWORD PTR [rbx+0x88]
  3b0a48:	4d 85 ff             	test   r15,r15
  3b0a4b:	41 0f 95 c6          	setne  r14b
  3b0a4f:	e8 7c 6e 75 00       	call   0xb078d0
  3b0a54:	48 8b 73 70          	mov    rsi,QWORD PTR [rbx+0x70]
  3b0a58:	44 8b 63 2c          	mov    r12d,DWORD PTR [rbx+0x2c]
  3b0a5c:	85 c0                	test   eax,eax
  3b0a5e:	0f 95 c0             	setne  al
  3b0a61:	44 20 f0             	and    al,r14b
  3b0a64:	3c 01                	cmp    al,0x1
  3b0a66:	75 24                	jne    0x3b0a8c
  3b0a68:	8b 8b 08 01 00 00    	mov    ecx,DWORD PTR [rbx+0x108]
  3b0a6e:	48 8b 7b 68          	mov    rdi,QWORD PTR [rbx+0x68]
  3b0a72:	44 89 e2             	mov    edx,r12d
  3b0a75:	4d 89 f8             	mov    r8,r15
  3b0a78:	e8 73 30 cf ff       	call   0xa3af0
  3b0a7d:	48 8d 35 7c cd 6c 01 	lea    rsi,[rip+0x16ccd7c]        # 0x1a7d800
  3b0a84:	4c 89 ff             	mov    rdi,r15
  3b0a87:	e8 64 83 85 00       	call   0xc08df0
  3b0a8c:	4c 8d b3 f8 00 00 00 	lea    r14,[rbx+0xf8]
  3b0a93:	31 f6                	xor    esi,esi
  3b0a95:	31 d2                	xor    edx,edx
  3b0a97:	31 c9                	xor    ecx,ecx
  3b0a99:	4c 89 f7             	mov    rdi,r14
  3b0a9c:	e8 5f 5f 11 00       	call   0x4c6a00
  3b0aa1:	83 bb 04 01 00 00 00 	cmp    DWORD PTR [rbx+0x104],0x0
  3b0aa8:	4c 8b 7b 60          	mov    r15,QWORD PTR [rbx+0x60]
  3b0aac:	0f 8e b1 02 00 00    	jle    0x3b0d63
  3b0ab2:	41 83 fc 02          	cmp    r12d,0x2
  3b0ab6:	75 0d                	jne    0x3b0ac5
  3b0ab8:	83 bb 0c 01 00 00 00 	cmp    DWORD PTR [rbx+0x10c],0x0
  3b0abf:	0f 84 9e 02 00 00    	je     0x3b0d63
  3b0ac5:	48 8d 3d 1c e8 11 03 	lea    rdi,[rip+0x311e81c]        # 0x34cf2e8
  3b0acc:	31 f6                	xor    esi,esi
  3b0ace:	31 d2                	xor    edx,edx
  3b0ad0:	31 c9                	xor    ecx,ecx
  3b0ad2:	e8 29 5f 11 00       	call   0x4c6a00
  3b0ad7:	48 8b 83 90 00 00 00 	mov    rax,QWORD PTR [rbx+0x90]
  3b0ade:	48 8b b0 b0 04 00 00 	mov    rsi,QWORD PTR [rax+0x4b0]
  3b0ae5:	48 85 f6             	test   rsi,rsi
  3b0ae8:	74 19                	je     0x3b0b03
  3b0aea:	48 8d 3d ff e7 11 03 	lea    rdi,[rip+0x311e7ff]        # 0x34cf2f0
  3b0af1:	49 89 c6             	mov    r14,rax
  3b0af4:	e8 87 e4 38 00       	call   0x73ef80
  3b0af9:	4c 89 f0             	mov    rax,r14
  3b0afc:	4c 8d b3 f8 00 00 00 	lea    r14,[rbx+0xf8]
  3b0b03:	48 8b b0 28 05 00 00 	mov    rsi,QWORD PTR [rax+0x528]
  3b0b0a:	48 85 f6             	test   rsi,rsi
  3b0b0d:	74 0c                	je     0x3b0b1b
  3b0b0f:	48 8d 3d da e7 11 03 	lea    rdi,[rip+0x311e7da]        # 0x34cf2f0
  3b0b16:	e8 65 e4 38 00       	call   0x73ef80
  3b0b1b:	48 8d 3d c6 e7 11 03 	lea    rdi,[rip+0x311e7c6]        # 0x34cf2e8
  3b0b22:	31 f6                	xor    esi,esi
  3b0b24:	31 d2                	xor    edx,edx
  3b0b26:	31 c9                	xor    ecx,ecx
  3b0b28:	e8 73 64 11 00       	call   0x4c6fa0
  3b0b2d:	8b 83 08 01 00 00    	mov    eax,DWORD PTR [rbx+0x108]
  3b0b33:	85 c0                	test   eax,eax
  3b0b35:	0f 84 61 01 00 00    	je     0x3b0c9c
  3b0b3b:	89 c1                	mov    ecx,eax
  3b0b3d:	4c 69 e9 83 de 1b 43 	imul   r13,rcx,0x431bde83
  3b0b44:	49 c1 ed 32          	shr    r13,0x32
  3b0b48:	41 69 cd 40 42 0f 00 	imul   ecx,r13d,0xf4240
  3b0b4f:	29 c8                	sub    eax,ecx
  3b0b51:	44 69 f0 e8 03 00 00 	imul   r14d,eax,0x3e8
  3b0b58:	eb 24                	jmp    0x3b0b7e
  3b0b5a:	0f 8e 9a 01 00 00    	jle    0x3b0cfa
  3b0b60:	49 29 c6             	sub    r14,rax
  3b0b63:	49 8d 86 00 ca 9a 3b 	lea    rax,[r14+0x3b9aca00]
  3b0b6a:	4d 85 f6             	test   r14,r14
  3b0b6d:	49 0f 49 c6          	cmovns rax,r14
  3b0b71:	49 c1 fe 3f          	sar    r14,0x3f
  3b0b75:	4c 01 f2             	add    rdx,r14
  3b0b78:	49 89 c6             	mov    r14,rax
  3b0b7b:	49 89 d5             	mov    r13,rdx
  3b0b7e:	4c 89 f0             	mov    rax,r14
  3b0b81:	48 b9 cf f7 53 e3 a5 	movabs rcx,0x20c49ba5e353f7cf
  3b0b88:	9b c4 20 
  3b0b8b:	4c 89 ab b0 00 00 00 	mov    QWORD PTR [rbx+0xb0],r13
  3b0b92:	48 8d b3 d0 00 00 00 	lea    rsi,[rbx+0xd0]
  3b0b99:	48 f7 e9             	imul   rcx
  3b0b9c:	48 89 d0             	mov    rax,rdx
  3b0b9f:	48 c1 fa 07          	sar    rdx,0x7
  3b0ba3:	48 c1 e8 3f          	shr    rax,0x3f
  3b0ba7:	48 01 c2             	add    rdx,rax
  3b0baa:	48 89 93 b8 00 00 00 	mov    QWORD PTR [rbx+0xb8],rdx
  3b0bb1:	65 4c 8b 24 25 00 00 	mov    r12,QWORD PTR gs:0x0
  3b0bb8:	00 00 
  3b0bba:	4c 89 e7             	mov    rdi,r12
  3b0bbd:	e8 de b6 30 00       	call   0x6bc2a0
  3b0bc2:	4c 8b 3d 07 f8 56 03 	mov    r15,QWORD PTR [rip+0x356f807]        # 0x39203d0
  3b0bc9:	48 8d bb b0 00 00 00 	lea    rdi,[rbx+0xb0]
  3b0bd0:	e8 ab 60 8b 00       	call   0xc66c80
  3b0bd5:	4c 63 c0             	movsxd r8,eax
  3b0bd8:	4d 0f af c7          	imul   r8,r15
  3b0bdc:	48 83 ec 08          	sub    rsp,0x8
  3b0be0:	48 8d 0d e1 13 f4 00 	lea    rcx,[rip+0xf413e1]        # 0x12f1fc8
  3b0be7:	48 8d bb 04 01 00 00 	lea    rdi,[rbx+0x104]
  3b0bee:	48 8d b3 e0 00 00 00 	lea    rsi,[rbx+0xe0]
  3b0bf5:	ba 4c 10 00 00       	mov    edx,0x104c
  3b0bfa:	45 31 c9             	xor    r9d,r9d
  3b0bfd:	68 00 01 00 00       	push   0x100
  3b0c02:	e8 59 56 85 00       	call   0xc06260
  3b0c07:	48 83 c4 10          	add    rsp,0x10
  3b0c0b:	4c 89 e7             	mov    rdi,r12
  3b0c0e:	48 8d b3 c0 00 00 00 	lea    rsi,[rbx+0xc0]
  3b0c15:	41 89 c7             	mov    r15d,eax
  3b0c18:	e8 83 b6 30 00       	call   0x6bc2a0
  3b0c1d:	41 83 ff 23          	cmp    r15d,0x23
  3b0c21:	48 8b 8b c0 00 00 00 	mov    rcx,QWORD PTR [rbx+0xc0]
  3b0c28:	0f 95 c0             	setne  al
  3b0c2b:	45 85 ff             	test   r15d,r15d
  3b0c2e:	0f 95 c2             	setne  dl
  3b0c31:	48 2b 8b d0 00 00 00 	sub    rcx,QWORD PTR [rbx+0xd0]
  3b0c38:	84 d0                	test   al,dl
  3b0c3a:	0f 85 a1 00 00 00    	jne    0x3b0ce1
  3b0c40:	83 bb 04 01 00 00 00 	cmp    DWORD PTR [rbx+0x104],0x0
  3b0c47:	0f 8e 94 00 00 00    	jle    0x3b0ce1
  3b0c4d:	48 89 8b c0 00 00 00 	mov    QWORD PTR [rbx+0xc0],rcx
  3b0c54:	48 8b 83 c8 00 00 00 	mov    rax,QWORD PTR [rbx+0xc8]
  3b0c5b:	48 2b 83 d8 00 00 00 	sub    rax,QWORD PTR [rbx+0xd8]
  3b0c62:	48 89 83 c8 00 00 00 	mov    QWORD PTR [rbx+0xc8],rax
  3b0c69:	79 17                	jns    0x3b0c82
  3b0c6b:	48 ff c9             	dec    rcx
  3b0c6e:	48 05 00 ca 9a 3b    	add    rax,0x3b9aca00
  3b0c74:	48 89 8b c0 00 00 00 	mov    QWORD PTR [rbx+0xc0],rcx
  3b0c7b:	48 89 83 c8 00 00 00 	mov    QWORD PTR [rbx+0xc8],rax
  3b0c82:	4c 89 ea             	mov    rdx,r13
  3b0c85:	48 29 ca             	sub    rdx,rcx
  3b0c88:	0f 85 cc fe ff ff    	jne    0x3b0b5a
  3b0c8e:	49 39 c6             	cmp    r14,rax
  3b0c91:	0f 8f c9 fe ff ff    	jg     0x3b0b60
  3b0c97:	4c 89 e9             	mov    rcx,r13
  3b0c9a:	eb 5e                	jmp    0x3b0cfa
  3b0c9c:	48 83 ec 08          	sub    rsp,0x8
  3b0ca0:	48 8d 0d 21 13 f4 00 	lea    rcx,[rip+0xf41321]        # 0x12f1fc8
  3b0ca7:	48 8d bb 04 01 00 00 	lea    rdi,[rbx+0x104]
  3b0cae:	48 8d b3 e0 00 00 00 	lea    rsi,[rbx+0xe0]
  3b0cb5:	ba 4c 10 00 00       	mov    edx,0x104c
  3b0cba:	45 31 c0             	xor    r8d,r8d
  3b0cbd:	45 31 c9             	xor    r9d,r9d
  3b0cc0:	68 00 01 00 00       	push   0x100
  3b0cc5:	e8 96 55 85 00       	call   0xc06260
  3b0cca:	48 83 c4 10          	add    rsp,0x10
  3b0cce:	83 f8 ff             	cmp    eax,0xffffffff
  3b0cd1:	b9 04 00 00 00       	mov    ecx,0x4
  3b0cd6:	0f 45 c8             	cmovne ecx,eax
  3b0cd9:	89 4b 14             	mov    DWORD PTR [rbx+0x14],ecx
  3b0cdc:	e9 82 00 00 00       	jmp    0x3b0d63
  3b0ce1:	48 8b 83 c8 00 00 00 	mov    rax,QWORD PTR [rbx+0xc8]
  3b0ce8:	48 2b 83 d8 00 00 00 	sub    rax,QWORD PTR [rbx+0xd8]
  3b0cef:	79 09                	jns    0x3b0cfa
  3b0cf1:	48 ff c9             	dec    rcx
  3b0cf4:	48 05 00 ca 9a 3b    	add    rax,0x3b9aca00
  3b0cfa:	41 83 ff 23          	cmp    r15d,0x23
  3b0cfe:	ba 3c 00 00 00       	mov    edx,0x3c
  3b0d03:	be 04 00 00 00       	mov    esi,0x4
  3b0d08:	4c 8d b3 f8 00 00 00 	lea    r14,[rbx+0xf8]
  3b0d0f:	41 0f 45 d7          	cmovne edx,r15d
  3b0d13:	41 83 ff ff          	cmp    r15d,0xffffffff
  3b0d17:	0f 45 f2             	cmovne esi,edx
  3b0d1a:	48 ba cf f7 53 e3 a5 	movabs rdx,0x20c49ba5e353f7cf
  3b0d21:	9b c4 20 
  3b0d24:	69 c9 40 42 0f 00    	imul   ecx,ecx,0xf4240
  3b0d2a:	48 f7 ea             	imul   rdx
  3b0d2d:	89 73 14             	mov    DWORD PTR [rbx+0x14],esi
  3b0d30:	48 89 d0             	mov    rax,rdx
  3b0d33:	48 c1 ea 07          	shr    rdx,0x7
  3b0d37:	48 c1 e8 3f          	shr    rax,0x3f
  3b0d3b:	01 c2                	add    edx,eax
  3b0d3d:	8b 83 08 01 00 00    	mov    eax,DWORD PTR [rbx+0x108]
  3b0d43:	01 ca                	add    edx,ecx
  3b0d45:	29 d0                	sub    eax,edx
  3b0d47:	76 0c                	jbe    0x3b0d55
  3b0d49:	4c 8b 7b 60          	mov    r15,QWORD PTR [rbx+0x60]
  3b0d4d:	89 83 08 01 00 00    	mov    DWORD PTR [rbx+0x108],eax
  3b0d53:	eb 0e                	jmp    0x3b0d63
  3b0d55:	4c 8b 7b 60          	mov    r15,QWORD PTR [rbx+0x60]
  3b0d59:	c7 83 08 01 00 00 00 	mov    DWORD PTR [rbx+0x108],0x0
  3b0d60:	00 00 00 
  3b0d63:	4c 89 f7             	mov    rdi,r14
  3b0d66:	31 f6                	xor    esi,esi
  3b0d68:	31 d2                	xor    edx,edx
  3b0d6a:	31 c9                	xor    ecx,ecx
  3b0d6c:	e8 2f 62 11 00       	call   0x4c6fa0
  3b0d71:	4d 85 ff             	test   r15,r15
  3b0d74:	74 2b                	je     0x3b0da1
  3b0d76:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3b0d7d:	00 00 
  3b0d7f:	48 8d 35 11 e5 f9 00 	lea    rsi,[rip+0xf9e511]        # 0x134f297
  3b0d86:	31 d2                	xor    edx,edx
  3b0d88:	e8 53 96 86 00       	call   0xc1a3e0
  3b0d8d:	48 8d bb 08 01 00 00 	lea    rdi,[rbx+0x108]
  3b0d94:	ba 04 00 00 00       	mov    edx,0x4
  3b0d99:	4c 89 fe             	mov    rsi,r15
  3b0d9c:	e8 2f 84 ea ff       	call   0x2591d0
  3b0da1:	4c 8b 7b 20          	mov    r15,QWORD PTR [rbx+0x20]
  3b0da5:	48 8b 53 40          	mov    rdx,QWORD PTR [rbx+0x40]
  3b0da9:	45 31 f6             	xor    r14d,r14d
  3b0dac:	eb 35                	jmp    0x3b0de3
  3b0dae:	66 90                	xchg   ax,ax
  3b0db0:	31 d2                	xor    edx,edx
  3b0db2:	4c 89 ff             	mov    rdi,r15
  3b0db5:	be 00 00 10 00       	mov    esi,0x100000
  3b0dba:	31 c9                	xor    ecx,ecx
  3b0dbc:	45 31 c0             	xor    r8d,r8d
  3b0dbf:	45 31 c9             	xor    r9d,r9d
  3b0dc2:	6a 00                	push   0x0
  3b0dc4:	6a 00                	push   0x0
  3b0dc6:	e8 a5 09 84 00       	call   0xbf1770
  3b0dcb:	48 83 c4 10          	add    rsp,0x10
  3b0dcf:	4c 8b 7b 20          	mov    r15,QWORD PTR [rbx+0x20]
  3b0dd3:	48 8b 53 40          	mov    rdx,QWORD PTR [rbx+0x40]
  3b0dd7:	49 ff c6             	inc    r14
  3b0dda:	4d 39 fe             	cmp    r14,r15
  3b0ddd:	0f 84 cc 00 00 00    	je     0x3b0eaf
  3b0de3:	49 6b c6 38          	imul   rax,r14,0x38
  3b0de7:	4c 8b 64 02 18       	mov    r12,QWORD PTR [rdx+rax*1+0x18]
  3b0dec:	4c 8d 2c 02          	lea    r13,[rdx+rax*1]
  3b0df0:	4d 85 e4             	test   r12,r12
  3b0df3:	74 6b                	je     0x3b0e60
  3b0df5:	4d 8d 7c 24 20       	lea    r15,[r12+0x20]
  3b0dfa:	be 00 00 08 00       	mov    esi,0x80000
  3b0dff:	31 d2                	xor    edx,edx
  3b0e01:	31 c9                	xor    ecx,ecx
  3b0e03:	45 31 c0             	xor    r8d,r8d
  3b0e06:	45 31 c9             	xor    r9d,r9d
  3b0e09:	4c 89 ff             	mov    rdi,r15
  3b0e0c:	6a 00                	push   0x0
  3b0e0e:	6a 00                	push   0x0
  3b0e10:	e8 5b 09 84 00       	call   0xbf1770
  3b0e15:	48 83 c4 10          	add    rsp,0x10
  3b0e19:	41 8b 45 20          	mov    eax,DWORD PTR [r13+0x20]
  3b0e1d:	48 8b 4b 38          	mov    rcx,QWORD PTR [rbx+0x38]
  3b0e21:	42 89 04 b1          	mov    DWORD PTR [rcx+r14*4],eax
  3b0e25:	49 83 7c 24 50 00    	cmp    QWORD PTR [r12+0x50],0x0
  3b0e2b:	74 54                	je     0x3b0e81
  3b0e2d:	49 8b 4d 18          	mov    rcx,QWORD PTR [r13+0x18]
  3b0e31:	48 8b 41 50          	mov    rax,QWORD PTR [rcx+0x50]
  3b0e35:	4c 39 e8             	cmp    rax,r13
  3b0e38:	74 37                	je     0x3b0e71
  3b0e3a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  3b0e40:	48 89 c1             	mov    rcx,rax
  3b0e43:	48 8b 40 30          	mov    rax,QWORD PTR [rax+0x30]
  3b0e47:	4c 39 e8             	cmp    rax,r13
  3b0e4a:	75 f4                	jne    0x3b0e40
  3b0e4c:	48 8b 40 30          	mov    rax,QWORD PTR [rax+0x30]
  3b0e50:	48 89 41 30          	mov    QWORD PTR [rcx+0x30],rax
  3b0e54:	eb 23                	jmp    0x3b0e79
  3b0e56:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  3b0e5d:	00 00 00 
  3b0e60:	41 8b 45 20          	mov    eax,DWORD PTR [r13+0x20]
  3b0e64:	48 8b 4b 38          	mov    rcx,QWORD PTR [rbx+0x38]
  3b0e68:	42 89 04 b1          	mov    DWORD PTR [rcx+r14*4],eax
  3b0e6c:	e9 66 ff ff ff       	jmp    0x3b0dd7
  3b0e71:	48 8b 40 30          	mov    rax,QWORD PTR [rax+0x30]
  3b0e75:	48 89 41 50          	mov    QWORD PTR [rcx+0x50],rax
  3b0e79:	49 c7 45 18 00 00 00 	mov    QWORD PTR [r13+0x18],0x0
  3b0e80:	00 
  3b0e81:	41 80 7c 24 0c 00    	cmp    BYTE PTR [r12+0xc],0x0
  3b0e87:	74 0a                	je     0x3b0e93
  3b0e89:	48 8b 43 38          	mov    rax,QWORD PTR [rbx+0x38]
  3b0e8d:	42 80 4c b0 02 01    	or     BYTE PTR [rax+r14*4+0x2],0x1
  3b0e93:	41 8b 44 24 08       	mov    eax,DWORD PTR [r12+0x8]
  3b0e98:	83 c0 fd             	add    eax,0xfffffffd
  3b0e9b:	83 f8 01             	cmp    eax,0x1
  3b0e9e:	0f 87 0c ff ff ff    	ja     0x3b0db0
  3b0ea4:	41 c6 44 24 0c 01    	mov    BYTE PTR [r12+0xc],0x1
  3b0eaa:	e9 01 ff ff ff       	jmp    0x3b0db0
  3b0eaf:	44 8b 63 7c          	mov    r12d,DWORD PTR [rbx+0x7c]
  3b0eb3:	49 89 d6             	mov    r14,rdx
  3b0eb6:	49 83 c6 28          	add    r14,0x28
  3b0eba:	eb 0d                	jmp    0x3b0ec9
  3b0ebc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  3b0ec0:	49 83 c6 38          	add    r14,0x38
  3b0ec4:	49 ff cf             	dec    r15
  3b0ec7:	74 0f                	je     0x3b0ed8
  3b0ec9:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
  3b0ecc:	48 85 ff             	test   rdi,rdi
  3b0ecf:	74 ef                	je     0x3b0ec0
  3b0ed1:	e8 da 8f fe ff       	call   0x399eb0
  3b0ed6:	eb e8                	jmp    0x3b0ec0
  3b0ed8:	48 8d bb f8 00 00 00 	lea    rdi,[rbx+0xf8]
  3b0edf:	e8 6c 6f 11 00       	call   0x4c7e50
  3b0ee4:	48 8b 7b 68          	mov    rdi,QWORD PTR [rbx+0x68]
  3b0ee8:	48 8b b3 90 00 00 00 	mov    rsi,QWORD PTR [rbx+0x90]
  3b0eef:	48 8b 93 a0 00 00 00 	mov    rdx,QWORD PTR [rbx+0xa0]
  3b0ef6:	48 8b 4b 30          	mov    rcx,QWORD PTR [rbx+0x30]
  3b0efa:	45 89 e1             	mov    r9d,r12d
  3b0efd:	4c 8b 43 70          	mov    r8,QWORD PTR [rbx+0x70]
  3b0f01:	e8 4a 30 00 00       	call   0x3b3f50
  3b0f06:	44 8b 73 14          	mov    r14d,DWORD PTR [rbx+0x14]
  3b0f0a:	41 83 fe 04          	cmp    r14d,0x4
  3b0f0e:	74 41                	je     0x3b0f51
  3b0f10:	48 8b 93 80 00 00 00 	mov    rdx,QWORD PTR [rbx+0x80]
  3b0f17:	45 85 f6             	test   r14d,r14d
  3b0f1a:	75 57                	jne    0x3b0f73
  3b0f1c:	48 8b 7b 38          	mov    rdi,QWORD PTR [rbx+0x38]
  3b0f20:	48 8b b3 98 00 00 00 	mov    rsi,QWORD PTR [rbx+0x98]
  3b0f27:	e8 14 2b 00 00       	call   0x3b3a40
  3b0f2c:	85 c0                	test   eax,eax
  3b0f2e:	74 40                	je     0x3b0f70
  3b0f30:	48 8d 3d d1 af f6 00 	lea    rdi,[rip+0xf6afd1]        # 0x131bf08
  3b0f37:	48 8d 35 3e 8e fc 00 	lea    rsi,[rip+0xfc8e3e]        # 0x1379d7c
  3b0f3e:	ba 8f 11 00 00       	mov    edx,0x118f
  3b0f43:	89 c1                	mov    ecx,eax
  3b0f45:	41 89 c6             	mov    r14d,eax
  3b0f48:	31 c0                	xor    eax,eax
  3b0f4a:	e8 c1 c4 ea ff       	call   0x25d410
  3b0f4f:	eb 22                	jmp    0x3b0f73
  3b0f51:	48 8b 7b 38          	mov    rdi,QWORD PTR [rbx+0x38]
  3b0f55:	48 8b b3 98 00 00 00 	mov    rsi,QWORD PTR [rbx+0x98]
  3b0f5c:	48 8b 93 80 00 00 00 	mov    rdx,QWORD PTR [rbx+0x80]
  3b0f63:	e8 d8 2a 00 00       	call   0x3b3a40
  3b0f68:	41 be 04 00 00 00    	mov    r14d,0x4
  3b0f6e:	eb 03                	jmp    0x3b0f73
  3b0f70:	45 31 f6             	xor    r14d,r14d
  3b0f73:	e8 58 69 75 00       	call   0xb078d0
  3b0f78:	85 c0                	test   eax,eax
  3b0f7a:	74 17                	je     0x3b0f93
  3b0f7c:	8b 8b 08 01 00 00    	mov    ecx,DWORD PTR [rbx+0x108]
  3b0f82:	48 8b 7b 68          	mov    rdi,QWORD PTR [rbx+0x68]
  3b0f86:	48 8b 53 38          	mov    rdx,QWORD PTR [rbx+0x38]
  3b0f8a:	48 8b 73 20          	mov    rsi,QWORD PTR [rbx+0x20]
  3b0f8e:	e8 fd 2b cf ff       	call   0xa3b90
  3b0f93:	48 8b 7b 40          	mov    rdi,QWORD PTR [rbx+0x40]
  3b0f97:	48 8d 35 b2 4a 70 01 	lea    rsi,[rip+0x1704ab2]        # 0x1ab5a50
  3b0f9e:	e8 4d 7e 85 00       	call   0xc08df0
  3b0fa3:	e9 e8 f4 ff ff       	jmp    0x3b0490
  3b0fa8:	e8 03 c7 34 00       	call   0x6fd6b0
  3b0fad:	0f 0b                	ud2
  3b0faf:	90                   	nop
  3b0fb0:	55                   	push   rbp
  3b0fb1:	48 89 e5             	mov    rbp,rsp
  3b0fb4:	48 8b 06             	mov    rax,QWORD PTR [rsi]
  3b0fb7:	8b 56 08             	mov    edx,DWORD PTR [rsi+0x8]
  3b0fba:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
  3b0fbe:	48 89 c6             	mov    rsi,rax
  3b0fc1:	5d                   	pop    rbp
  3b0fc2:	e9 09 00 00 00       	jmp    0x3b0fd0
  3b0fc7:	90                   	nop
  3b0fc8:	90                   	nop
  3b0fc9:	90                   	nop
  3b0fca:	90                   	nop
  3b0fcb:	90                   	nop
  3b0fcc:	90                   	nop
  3b0fcd:	90                   	nop
  3b0fce:	90                   	nop
  3b0fcf:	90                   	nop
  3b0fd0:	55                   	push   rbp
  3b0fd1:	48 89 e5             	mov    rbp,rsp
  3b0fd4:	41 57                	push   r15
  3b0fd6:	41 56                	push   r14
  3b0fd8:	41 55                	push   r13
  3b0fda:	41 54                	push   r12
  3b0fdc:	53                   	push   rbx
  3b0fdd:	48 83 e4 e0          	and    rsp,0xffffffffffffffe0
  3b0fe1:	48 81 ec c0 00 00 00 	sub    rsp,0xc0
  3b0fe8:	48 89 e3             	mov    rbx,rsp
  3b0feb:	48 8d 05 1e b3 56 03 	lea    rax,[rip+0x356b31e]        # 0x391c310
  3b0ff2:	48 89 4b 78          	mov    QWORD PTR [rbx+0x78],rcx
  3b0ff6:	48 89 53 50          	mov    QWORD PTR [rbx+0x50],rdx
  3b0ffa:	49 89 f6             	mov    r14,rsi
  3b0ffd:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b1000:	48 89 83 a0 00 00 00 	mov    QWORD PTR [rbx+0xa0],rax
  3b1007:	48 89 bb 80 00 00 00 	mov    QWORD PTR [rbx+0x80],rdi
  3b100e:	4c 8b 67 08          	mov    r12,QWORD PTR [rdi+0x8]
  3b1012:	49 8b 84 24 48 0c 00 	mov    rax,QWORD PTR [r12+0xc48]
  3b1019:	00 
  3b101a:	4c 89 e7             	mov    rdi,r12
  3b101d:	48 c7 83 90 00 00 00 	mov    QWORD PTR [rbx+0x90],0x0
  3b1024:	00 00 00 00 
  3b1028:	c7 83 8c 00 00 00 00 	mov    DWORD PTR [rbx+0x8c],0x0
  3b102f:	00 00 00 
  3b1032:	c7 83 88 00 00 00 00 	mov    DWORD PTR [rbx+0x88],0x0
  3b1039:	00 00 00 
  3b103c:	48 89 43 58          	mov    QWORD PTR [rbx+0x58],rax
  3b1040:	e8 3b 71 64 00       	call   0x9f8180
  3b1045:	48 8d b3 9c 00 00 00 	lea    rsi,[rbx+0x9c]
  3b104c:	4c 89 e7             	mov    rdi,r12
  3b104f:	49 89 c7             	mov    r15,rax
  3b1052:	e8 69 71 64 00       	call   0x9f81c0
  3b1057:	48 8d 15 6a e8 11 03 	lea    rdx,[rip+0x311e86a]        # 0x34cf8c8
  3b105e:	45 31 e4             	xor    r12d,r12d
  3b1061:	85 c0                	test   eax,eax
  3b1063:	0f 85 87 00 00 00    	jne    0x3b10f0
  3b1069:	8b 83 9c 00 00 00    	mov    eax,DWORD PTR [rbx+0x9c]
  3b106f:	3d ff ff ff 00       	cmp    eax,0xffffff
  3b1074:	77 7a                	ja     0x3b10f0
  3b1076:	3d ff ff 00 00       	cmp    eax,0xffff
  3b107b:	76 30                	jbe    0x3b10ad
  3b107d:	25 00 00 ff 00       	and    eax,0xff0000
  3b1082:	48 8d 0d e7 ed 11 03 	lea    rcx,[rip+0x311ede7]        # 0x34cfe70
  3b1089:	48 8d 15 38 e8 11 03 	lea    rdx,[rip+0x311e838]        # 0x34cf8c8
  3b1090:	41 bc 01 00 00 00    	mov    r12d,0x1
  3b1096:	3d 00 00 01 00       	cmp    eax,0x10000
  3b109b:	48 0f 44 d1          	cmove  rdx,rcx
  3b109f:	83 ba a0 04 00 00 01 	cmp    DWORD PTR [rdx+0x4a0],0x1
  3b10a6:	75 51                	jne    0x3b10f9
  3b10a8:	e9 8e 00 00 00       	jmp    0x3b113b
  3b10ad:	41 bc 01 00 00 00    	mov    r12d,0x1
  3b10b3:	4c 39 3d 0e e7 11 03 	cmp    QWORD PTR [rip+0x311e70e],r15        # 0x34cf7c8
  3b10ba:	74 2d                	je     0x3b10e9
  3b10bc:	4c 39 3d fd f7 11 03 	cmp    QWORD PTR [rip+0x311f7fd],r15        # 0x34d08c0
  3b10c3:	74 66                	je     0x3b112b
  3b10c5:	83 3d f4 e6 11 03 00 	cmp    DWORD PTR [rip+0x311e6f4],0x0        # 0x34cf7c0
  3b10cc:	48 8d 05 4d e2 11 03 	lea    rax,[rip+0x311e24d]        # 0x34cf320
  3b10d3:	48 8d 15 3e f3 11 03 	lea    rdx,[rip+0x311f33e]        # 0x34d0418
  3b10da:	48 0f 44 d0          	cmove  rdx,rax
  3b10de:	83 ba a0 04 00 00 01 	cmp    DWORD PTR [rdx+0x4a0],0x1
  3b10e5:	75 12                	jne    0x3b10f9
  3b10e7:	eb 52                	jmp    0x3b113b
  3b10e9:	48 8d 15 30 e2 11 03 	lea    rdx,[rip+0x311e230]        # 0x34cf320
  3b10f0:	83 ba a0 04 00 00 01 	cmp    DWORD PTR [rdx+0x4a0],0x1
  3b10f7:	74 42                	je     0x3b113b
  3b10f9:	bf 01 00 00 00       	mov    edi,0x1
  3b10fe:	48 89 d6             	mov    rsi,rdx
  3b1101:	49 89 d7             	mov    r15,rdx
  3b1104:	e8 07 23 00 00       	call   0x3b3410
  3b1109:	4c 89 fa             	mov    rdx,r15
  3b110c:	85 c0                	test   eax,eax
  3b110e:	74 2b                	je     0x3b113b
  3b1110:	41 89 c7             	mov    r15d,eax
  3b1113:	48 8d 3d ee ad f6 00 	lea    rdi,[rip+0xf6adee]        # 0x131bf08
  3b111a:	48 8d 35 9a 8c fc 00 	lea    rsi,[rip+0xfc8c9a]        # 0x1379dbb
  3b1121:	ba c1 13 00 00       	mov    edx,0x13c1
  3b1126:	e9 e6 00 00 00       	jmp    0x3b1211
  3b112b:	48 8d 15 e6 f2 11 03 	lea    rdx,[rip+0x311f2e6]        # 0x34d0418
  3b1132:	83 ba a0 04 00 00 01 	cmp    DWORD PTR [rdx+0x4a0],0x1
  3b1139:	75 be                	jne    0x3b10f9
  3b113b:	48 8b 4b 50          	mov    rcx,QWORD PTR [rbx+0x50]
  3b113f:	8d 81 7f ff ff ff    	lea    eax,[rcx-0x81]
  3b1145:	3d 7f ff ff ff       	cmp    eax,0xffffff7f
  3b114a:	77 23                	ja     0x3b116f
  3b114c:	48 8d 3d b5 ad f6 00 	lea    rdi,[rip+0xf6adb5]        # 0x131bf08
  3b1153:	48 8d 35 61 8c fc 00 	lea    rsi,[rip+0xfc8c61]        # 0x1379dbb
  3b115a:	41 bf 16 00 00 00    	mov    r15d,0x16
  3b1160:	ba c7 13 00 00       	mov    edx,0x13c7
  3b1165:	b9 16 00 00 00       	mov    ecx,0x16
  3b116a:	e9 a5 00 00 00       	jmp    0x3b1214
  3b116f:	44 89 63 3c          	mov    DWORD PTR [rbx+0x3c],r12d
  3b1173:	41 89 cd             	mov    r13d,ecx
  3b1176:	4d 89 f4             	mov    r12,r14
  3b1179:	48 89 53 70          	mov    QWORD PTR [rbx+0x70],rdx
  3b117d:	83 f9 02             	cmp    ecx,0x2
  3b1180:	72 36                	jb     0x3b11b8
  3b1182:	8d 04 8d 0f 00 00 00 	lea    eax,[rcx*4+0xf]
  3b1189:	49 89 e7             	mov    r15,rsp
  3b118c:	8d 34 8d 00 00 00 00 	lea    esi,[rcx*4+0x0]
  3b1193:	83 e0 f0             	and    eax,0xfffffff0
  3b1196:	49 29 c7             	sub    r15,rax
  3b1199:	49 83 e7 e0          	and    r15,0xffffffffffffffe0
  3b119d:	4c 89 fc             	mov    rsp,r15
  3b11a0:	48 89 e7             	mov    rdi,rsp
  3b11a3:	48 29 c7             	sub    rdi,rax
  3b11a6:	48 83 e7 e0          	and    rdi,0xffffffffffffffe0
  3b11aa:	48 89 fc             	mov    rsp,rdi
  3b11ad:	48 89 7b 10          	mov    QWORD PTR [rbx+0x10],rdi
  3b11b1:	e8 3a 7e ea ff       	call   0x258ff0
  3b11b6:	eb 12                	jmp    0x3b11ca
  3b11b8:	48 8d 83 88 00 00 00 	lea    rax,[rbx+0x88]
  3b11bf:	4c 8d bb 8c 00 00 00 	lea    r15,[rbx+0x8c]
  3b11c6:	48 89 43 10          	mov    QWORD PTR [rbx+0x10],rax
  3b11ca:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3b11d1:	00 00 
  3b11d3:	48 8d 35 63 6d fe 00 	lea    rsi,[rip+0xfe6d63]        # 0x1397f3d
  3b11da:	31 d2                	xor    edx,edx
  3b11dc:	4e 8d 34 ad 00 00 00 	lea    r14,[r13*4+0x0]
  3b11e3:	00 
  3b11e4:	e8 f7 91 86 00       	call   0xc1a3e0
  3b11e9:	4c 89 e7             	mov    rdi,r12
  3b11ec:	4c 89 fe             	mov    rsi,r15
  3b11ef:	4c 89 f2             	mov    rdx,r14
  3b11f2:	e8 89 80 ea ff       	call   0x259280
  3b11f7:	85 c0                	test   eax,eax
  3b11f9:	74 49                	je     0x3b1244
  3b11fb:	41 89 c7             	mov    r15d,eax
  3b11fe:	48 8d 3d 03 ad f6 00 	lea    rdi,[rip+0xf6ad03]        # 0x131bf08
  3b1205:	48 8d 35 af 8b fc 00 	lea    rsi,[rip+0xfc8baf]        # 0x1379dbb
  3b120c:	ba d6 13 00 00       	mov    edx,0x13d6
  3b1211:	44 89 f9             	mov    ecx,r15d
  3b1214:	31 c0                	xor    eax,eax
  3b1216:	e8 f5 c1 ea ff       	call   0x25d410
  3b121b:	48 8d 05 ee b0 56 03 	lea    rax,[rip+0x356b0ee]        # 0x391c310
  3b1222:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b1225:	48 3b 83 a0 00 00 00 	cmp    rax,QWORD PTR [rbx+0xa0]
  3b122c:	0f 85 2a 04 00 00    	jne    0x3b165c
  3b1232:	44 89 f8             	mov    eax,r15d
  3b1235:	48 8d 65 d8          	lea    rsp,[rbp-0x28]
  3b1239:	5b                   	pop    rbx
  3b123a:	41 5c                	pop    r12
  3b123c:	41 5d                	pop    r13
  3b123e:	41 5e                	pop    r14
  3b1240:	41 5f                	pop    r15
  3b1242:	5d                   	pop    rbp
  3b1243:	c3                   	ret
  3b1244:	4c 89 7b 30          	mov    QWORD PTR [rbx+0x30],r15
  3b1248:	e8 83 66 75 00       	call   0xb078d0
  3b124d:	4c 89 73 68          	mov    QWORD PTR [rbx+0x68],r14
  3b1251:	85 c0                	test   eax,eax
  3b1253:	74 1f                	je     0x3b1274
  3b1255:	4a 8d 04 ed 00 00 00 	lea    rax,[r13*8+0x0]
  3b125c:	00 
  3b125d:	48 8d 35 9c c5 6c 01 	lea    rsi,[rip+0x16cc59c]        # 0x1a7d800
  3b1264:	ba 02 01 00 00       	mov    edx,0x102
  3b1269:	48 8d 3c 40          	lea    rdi,[rax+rax*2]
  3b126d:	e8 de 78 85 00       	call   0xc08b50
  3b1272:	eb 02                	jmp    0x3b1276
  3b1274:	31 c0                	xor    eax,eax
  3b1276:	48 89 43 40          	mov    QWORD PTR [rbx+0x40],rax
  3b127a:	48 83 c0 10          	add    rax,0x10
  3b127e:	45 31 ff             	xor    r15d,r15d
  3b1281:	45 31 f6             	xor    r14d,r14d
  3b1284:	c7 43 1c 00 00 00 00 	mov    DWORD PTR [rbx+0x1c],0x0
  3b128b:	4c 89 6b 20          	mov    QWORD PTR [rbx+0x20],r13
  3b128f:	eb 56                	jmp    0x3b12e7
  3b1291:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b1298:	0f 1f 84 00 00 00 00 
  3b129f:	00 
  3b12a0:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  3b12a4:	48 8d 3d cc a0 fa 00 	lea    rdi,[rip+0xfaa0cc]        # 0x135b377
  3b12ab:	48 8d 35 09 8b fc 00 	lea    rsi,[rip+0xfc8b09]        # 0x1379dbb
  3b12b2:	ba e6 13 00 00       	mov    edx,0x13e6
  3b12b7:	44 89 f9             	mov    ecx,r15d
  3b12ba:	41 b8 03 00 00 00    	mov    r8d,0x3
  3b12c0:	42 c7 04 b8 03 00 02 	mov    DWORD PTR [rax+r15*4],0x80020003
  3b12c7:	80 
  3b12c8:	31 c0                	xor    eax,eax
  3b12ca:	e8 41 c1 ea ff       	call   0x25d410
  3b12cf:	4c 8b 6b 20          	mov    r13,QWORD PTR [rbx+0x20]
  3b12d3:	48 8b 43 60          	mov    rax,QWORD PTR [rbx+0x60]
  3b12d7:	49 ff c7             	inc    r15
  3b12da:	48 83 c0 18          	add    rax,0x18
  3b12de:	4d 39 fd             	cmp    r13,r15
  3b12e1:	0f 84 94 02 00 00    	je     0x3b157b
  3b12e7:	48 89 43 60          	mov    QWORD PTR [rbx+0x60],rax
  3b12eb:	48 8b 43 30          	mov    rax,QWORD PTR [rbx+0x30]
  3b12ef:	46 8b 2c b8          	mov    r13d,DWORD PTR [rax+r15*4]
  3b12f3:	45 89 ec             	mov    r12d,r13d
  3b12f6:	44 89 ea             	mov    edx,r13d
  3b12f9:	41 c1 fc 10          	sar    r12d,0x10
  3b12fd:	81 e2 ff ff 00 00    	and    edx,0xffff
  3b1303:	0f 95 c0             	setne  al
  3b1306:	41 81 fc 80 00 00 00 	cmp    r12d,0x80
  3b130d:	0f 92 c1             	setb   cl
  3b1310:	84 c8                	test   al,cl
  3b1312:	74 8c                	je     0x3b12a0
  3b1314:	44 39 f2             	cmp    edx,r14d
  3b1317:	49 89 d6             	mov    r14,rdx
  3b131a:	74 3e                	je     0x3b135a
  3b131c:	83 7b 1c 00          	cmp    DWORD PTR [rbx+0x1c],0x0
  3b1320:	74 0c                	je     0x3b132e
  3b1322:	48 8b bb 90 00 00 00 	mov    rdi,QWORD PTR [rbx+0x90]
  3b1329:	e8 82 8b fe ff       	call   0x399eb0
  3b132e:	48 8b 7b 58          	mov    rdi,QWORD PTR [rbx+0x58]
  3b1332:	44 89 f6             	mov    esi,r14d
  3b1335:	ba 60 01 00 00       	mov    edx,0x160
  3b133a:	48 8d 8b 90 00 00 00 	lea    rcx,[rbx+0x90]
  3b1341:	e8 9a 8b fe ff       	call   0x399ee0
  3b1346:	48 89 43 28          	mov    QWORD PTR [rbx+0x28],rax
  3b134a:	48 85 c0             	test   rax,rax
  3b134d:	0f 84 95 00 00 00    	je     0x3b13e8
  3b1353:	c7 43 1c 01 00 00 00 	mov    DWORD PTR [rbx+0x1c],0x1
  3b135a:	48 8b 43 28          	mov    rax,QWORD PTR [rbx+0x28]
  3b135e:	0f bf 00             	movsx  eax,WORD PTR [rax]
  3b1361:	41 39 c4             	cmp    r12d,eax
  3b1364:	7d 4a                	jge    0x3b13b0
  3b1366:	48 8b bb 90 00 00 00 	mov    rdi,QWORD PTR [rbx+0x90]
  3b136d:	e8 ae 8a fe ff       	call   0x399e20
  3b1372:	85 c0                	test   eax,eax
  3b1374:	0f 84 b8 00 00 00    	je     0x3b1432
  3b137a:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  3b137e:	48 8d 3d f2 9f fa 00 	lea    rdi,[rip+0xfa9ff2]        # 0x135b377
  3b1385:	48 8d 35 2f 8a fc 00 	lea    rsi,[rip+0xfc8a2f]        # 0x1379dbb
  3b138c:	ba 08 14 00 00       	mov    edx,0x1408
  3b1391:	44 89 f9             	mov    ecx,r15d
  3b1394:	41 b8 01 00 00 00    	mov    r8d,0x1
  3b139a:	42 c7 04 b8 01 00 02 	mov    DWORD PTR [rax+r15*4],0x80020001
  3b13a1:	80 
  3b13a2:	eb 34                	jmp    0x3b13d8
  3b13a4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b13ab:	00 00 00 00 00 
  3b13b0:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  3b13b4:	48 8d 3d bc 9f fa 00 	lea    rdi,[rip+0xfa9fbc]        # 0x135b377
  3b13bb:	48 8d 35 f9 89 fc 00 	lea    rsi,[rip+0xfc89f9]        # 0x1379dbb
  3b13c2:	ba 02 14 00 00       	mov    edx,0x1402
  3b13c7:	44 89 f9             	mov    ecx,r15d
  3b13ca:	41 b8 03 00 00 00    	mov    r8d,0x3
  3b13d0:	42 c7 04 b8 03 00 02 	mov    DWORD PTR [rax+r15*4],0x80020003
  3b13d7:	80 
  3b13d8:	31 c0                	xor    eax,eax
  3b13da:	e8 31 c0 ea ff       	call   0x25d410
  3b13df:	4c 8b 6b 20          	mov    r13,QWORD PTR [rbx+0x20]
  3b13e3:	e9 eb fe ff ff       	jmp    0x3b12d3
  3b13e8:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  3b13ec:	48 8d 3d 84 9f fa 00 	lea    rdi,[rip+0xfa9f84]        # 0x135b377
  3b13f3:	48 8d 35 c1 89 fc 00 	lea    rsi,[rip+0xfc89c1]        # 0x1379dbb
  3b13fa:	ba f4 13 00 00       	mov    edx,0x13f4
  3b13ff:	44 89 f9             	mov    ecx,r15d
  3b1402:	41 b8 03 00 00 00    	mov    r8d,0x3
  3b1408:	45 31 f6             	xor    r14d,r14d
  3b140b:	42 c7 04 b8 03 00 02 	mov    DWORD PTR [rax+r15*4],0x80020003
  3b1412:	80 
  3b1413:	31 c0                	xor    eax,eax
  3b1415:	e8 f6 bf ea ff       	call   0x25d410
  3b141a:	4c 8b 6b 20          	mov    r13,QWORD PTR [rbx+0x20]
  3b141e:	c7 43 1c 00 00 00 00 	mov    DWORD PTR [rbx+0x1c],0x0
  3b1425:	48 c7 43 28 00 00 00 	mov    QWORD PTR [rbx+0x28],0x0
  3b142c:	00 
  3b142d:	e9 a1 fe ff ff       	jmp    0x3b12d3
  3b1432:	48 8b 43 28          	mov    rax,QWORD PTR [rbx+0x28]
  3b1436:	44 89 e1             	mov    ecx,r12d
  3b1439:	4c 89 73 48          	mov    QWORD PTR [rbx+0x48],r14
  3b143d:	48 8b 40 28          	mov    rax,QWORD PTR [rax+0x28]
  3b1441:	4c 8b 34 c8          	mov    r14,QWORD PTR [rax+rcx*8]
  3b1445:	4d 85 f6             	test   r14,r14
  3b1448:	0f 84 c9 00 00 00    	je     0x3b1517
  3b144e:	48 83 7b 40 00       	cmp    QWORD PTR [rbx+0x40],0x0
  3b1453:	0f 95 43 0f          	setne  BYTE PTR [rbx+0xf]
  3b1457:	e8 74 64 75 00       	call   0xb078d0
  3b145c:	85 c0                	test   eax,eax
  3b145e:	0f 95 c0             	setne  al
  3b1461:	22 43 0f             	and    al,BYTE PTR [rbx+0xf]
  3b1464:	3c 01                	cmp    al,0x1
  3b1466:	75 2b                	jne    0x3b1493
  3b1468:	48 8b 43 30          	mov    rax,QWORD PTR [rbx+0x30]
  3b146c:	48 8b 53 60          	mov    rdx,QWORD PTR [rbx+0x60]
  3b1470:	42 8b 04 b8          	mov    eax,DWORD PTR [rax+r15*4]
  3b1474:	89 42 f0             	mov    DWORD PTR [rdx-0x10],eax
  3b1477:	49 8b 46 18          	mov    rax,QWORD PTR [r14+0x18]
  3b147b:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b147e:	48 89 42 f8          	mov    QWORD PTR [rdx-0x8],rax
  3b1482:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
  3b1486:	48 89 c1             	mov    rcx,rax
  3b1489:	48 c1 f9 04          	sar    rcx,0x4
  3b148d:	48 31 c1             	xor    rcx,rax
  3b1490:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  3b1493:	4d 8b 76 20          	mov    r14,QWORD PTR [r14+0x20]
  3b1497:	41 81 fd 00 00 01 00 	cmp    r13d,0x10000
  3b149e:	72 23                	jb     0x3b14c3
  3b14a0:	41 83 3e 02          	cmp    DWORD PTR [r14],0x2
  3b14a4:	72 1d                	jb     0x3b14c3
  3b14a6:	48 8d 3d ae 44 fb 00 	lea    rdi,[rip+0xfb44ae]        # 0x136595b
  3b14ad:	48 8d 35 07 89 fc 00 	lea    rsi,[rip+0xfc8907]        # 0x1379dbb
  3b14b4:	ba 1f 14 00 00       	mov    edx,0x141f
  3b14b9:	44 89 e1             	mov    ecx,r12d
  3b14bc:	31 c0                	xor    eax,eax
  3b14be:	e8 4d bf ea ff       	call   0x25d410
  3b14c3:	4d 8d 66 20          	lea    r12,[r14+0x20]
  3b14c7:	31 c9                	xor    ecx,ecx
  3b14c9:	be 00 00 08 00       	mov    esi,0x80000
  3b14ce:	31 d2                	xor    edx,edx
  3b14d0:	45 31 c0             	xor    r8d,r8d
  3b14d3:	45 31 c9             	xor    r9d,r9d
  3b14d6:	4c 89 e7             	mov    rdi,r12
  3b14d9:	6a 00                	push   0x0
  3b14db:	6a 00                	push   0x0
  3b14dd:	e8 8e 02 84 00       	call   0xbf1770
  3b14e2:	48 83 c4 10          	add    rsp,0x10
  3b14e6:	41 8b 46 08          	mov    eax,DWORD PTR [r14+0x8]
  3b14ea:	48 8b 4b 10          	mov    rcx,QWORD PTR [rbx+0x10]
  3b14ee:	4c 8b 6b 20          	mov    r13,QWORD PTR [rbx+0x20]
  3b14f2:	42 89 04 b9          	mov    DWORD PTR [rcx+r15*4],eax
  3b14f6:	4c 89 f1             	mov    rcx,r14
  3b14f9:	4c 8b 73 48          	mov    r14,QWORD PTR [rbx+0x48]
  3b14fd:	83 f8 03             	cmp    eax,0x3
  3b1500:	7c 55                	jl     0x3b1557
  3b1502:	80 79 0c 00          	cmp    BYTE PTR [rcx+0xc],0x0
  3b1506:	74 4b                	je     0x3b1553
  3b1508:	48 8b 4b 10          	mov    rcx,QWORD PTR [rbx+0x10]
  3b150c:	0d 00 00 01 00       	or     eax,0x10000
  3b1511:	42 89 04 b9          	mov    DWORD PTR [rcx+r15*4],eax
  3b1515:	eb 40                	jmp    0x3b1557
  3b1517:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  3b151b:	48 8d 3d 55 9e fa 00 	lea    rdi,[rip+0xfa9e55]        # 0x135b377
  3b1522:	48 8d 35 92 88 fc 00 	lea    rsi,[rip+0xfc8892]        # 0x1379dbb
  3b1529:	ba 0f 14 00 00       	mov    edx,0x140f
  3b152e:	44 89 f9             	mov    ecx,r15d
  3b1531:	41 b8 03 00 00 00    	mov    r8d,0x3
  3b1537:	42 c7 04 b8 03 00 02 	mov    DWORD PTR [rax+r15*4],0x80020003
  3b153e:	80 
  3b153f:	31 c0                	xor    eax,eax
  3b1541:	e8 ca be ea ff       	call   0x25d410
  3b1546:	4c 8b 6b 20          	mov    r13,QWORD PTR [rbx+0x20]
  3b154a:	4c 8b 73 48          	mov    r14,QWORD PTR [rbx+0x48]
  3b154e:	e9 80 fd ff ff       	jmp    0x3b12d3
  3b1553:	c6 41 0c 01          	mov    BYTE PTR [rcx+0xc],0x1
  3b1557:	4c 89 e7             	mov    rdi,r12
  3b155a:	be 00 00 10 00       	mov    esi,0x100000
  3b155f:	31 d2                	xor    edx,edx
  3b1561:	31 c9                	xor    ecx,ecx
  3b1563:	45 31 c0             	xor    r8d,r8d
  3b1566:	45 31 c9             	xor    r9d,r9d
  3b1569:	6a 00                	push   0x0
  3b156b:	6a 00                	push   0x0
  3b156d:	e8 fe 01 84 00       	call   0xbf1770
  3b1572:	48 83 c4 10          	add    rsp,0x10
  3b1576:	e9 58 fd ff ff       	jmp    0x3b12d3
  3b157b:	4c 8b 63 40          	mov    r12,QWORD PTR [rbx+0x40]
  3b157f:	4d 85 e4             	test   r12,r12
  3b1582:	41 0f 95 c6          	setne  r14b
  3b1586:	e8 45 63 75 00       	call   0xb078d0
  3b158b:	85 c0                	test   eax,eax
  3b158d:	4c 8b 7b 50          	mov    r15,QWORD PTR [rbx+0x50]
  3b1591:	0f 95 c0             	setne  al
  3b1594:	44 20 f0             	and    al,r14b
  3b1597:	4c 8b b3 80 00 00 00 	mov    r14,QWORD PTR [rbx+0x80]
  3b159e:	3c 01                	cmp    al,0x1
  3b15a0:	75 1d                	jne    0x3b15bf
  3b15a2:	4c 89 f7             	mov    rdi,r14
  3b15a5:	44 89 fe             	mov    esi,r15d
  3b15a8:	4c 89 e2             	mov    rdx,r12
  3b15ab:	e8 00 2a cf ff       	call   0xa3fb0
  3b15b0:	48 8d 35 49 c2 6c 01 	lea    rsi,[rip+0x16cc249]        # 0x1a7d800
  3b15b7:	4c 89 e7             	mov    rdi,r12
  3b15ba:	e8 31 78 85 00       	call   0xc08df0
  3b15bf:	83 7b 1c 00          	cmp    DWORD PTR [rbx+0x1c],0x0
  3b15c3:	44 8b 63 3c          	mov    r12d,DWORD PTR [rbx+0x3c]
  3b15c7:	74 0c                	je     0x3b15d5
  3b15c9:	48 8b bb 90 00 00 00 	mov    rdi,QWORD PTR [rbx+0x90]
  3b15d0:	e8 db 88 fe ff       	call   0x399eb0
  3b15d5:	48 8b 73 70          	mov    rsi,QWORD PTR [rbx+0x70]
  3b15d9:	48 8b 53 58          	mov    rdx,QWORD PTR [rbx+0x58]
  3b15dd:	48 8b 4b 30          	mov    rcx,QWORD PTR [rbx+0x30]
  3b15e1:	4c 89 f7             	mov    rdi,r14
  3b15e4:	45 89 f8             	mov    r8d,r15d
  3b15e7:	45 89 e1             	mov    r9d,r12d
  3b15ea:	e8 61 29 00 00       	call   0x3b3f50
  3b15ef:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3b15f6:	00 00 
  3b15f8:	48 8d 35 98 dc f9 00 	lea    rsi,[rip+0xf9dc98]        # 0x134f297
  3b15ff:	31 d2                	xor    edx,edx
  3b1601:	e8 da 8d 86 00       	call   0xc1a3e0
  3b1606:	48 8b 7b 10          	mov    rdi,QWORD PTR [rbx+0x10]
  3b160a:	48 8b 73 78          	mov    rsi,QWORD PTR [rbx+0x78]
  3b160e:	48 8b 53 68          	mov    rdx,QWORD PTR [rbx+0x68]
  3b1612:	e8 b9 7b ea ff       	call   0x2591d0
  3b1617:	41 89 c7             	mov    r15d,eax
  3b161a:	85 c0                	test   eax,eax
  3b161c:	74 1d                	je     0x3b163b
  3b161e:	48 8d 3d 9b f3 ec 00 	lea    rdi,[rip+0xecf39b]        # 0x12809c0
  3b1625:	48 8d 35 8f 87 fc 00 	lea    rsi,[rip+0xfc878f]        # 0x1379dbb
  3b162c:	ba 44 14 00 00       	mov    edx,0x1444
  3b1631:	44 89 f9             	mov    ecx,r15d
  3b1634:	31 c0                	xor    eax,eax
  3b1636:	e8 d5 bd ea ff       	call   0x25d410
  3b163b:	e8 90 62 75 00       	call   0xb078d0
  3b1640:	85 c0                	test   eax,eax
  3b1642:	0f 84 d3 fb ff ff    	je     0x3b121b
  3b1648:	48 8b 53 10          	mov    rdx,QWORD PTR [rbx+0x10]
  3b164c:	4c 89 f7             	mov    rdi,r14
  3b164f:	44 89 ee             	mov    esi,r13d
  3b1652:	e8 e9 29 cf ff       	call   0xa4040
  3b1657:	e9 bf fb ff ff       	jmp    0x3b121b
  3b165c:	e8 4f c0 34 00       	call   0x6fd6b0
  3b1661:	0f 0b                	ud2
  3b1663:	90                   	nop
  3b1664:	90                   	nop
  3b1665:	90                   	nop
  3b1666:	90                   	nop
  3b1667:	90                   	nop
  3b1668:	90                   	nop
  3b1669:	90                   	nop
  3b166a:	90                   	nop
  3b166b:	90                   	nop
  3b166c:	90                   	nop
  3b166d:	90                   	nop
  3b166e:	90                   	nop
  3b166f:	90                   	nop
  3b1670:	55                   	push   rbp
  3b1671:	48 89 e5             	mov    rbp,rsp
  3b1674:	31 f6                	xor    esi,esi
  3b1676:	5d                   	pop    rbp
  3b1677:	e9 e4 40 eb ff       	jmp    0x265760
  3b167c:	90                   	nop
  3b167d:	90                   	nop
  3b167e:	90                   	nop
  3b167f:	90                   	nop
  3b1680:	55                   	push   rbp
  3b1681:	48 89 e5             	mov    rbp,rsp
  3b1684:	48 8b 06             	mov    rax,QWORD PTR [rsi]
  3b1687:	8b 56 08             	mov    edx,DWORD PTR [rsi+0x8]
  3b168a:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
  3b168e:	48 89 c6             	mov    rsi,rax
  3b1691:	5d                   	pop    rbp
  3b1692:	e9 09 00 00 00       	jmp    0x3b16a0
  3b1697:	90                   	nop
  3b1698:	90                   	nop
  3b1699:	90                   	nop
  3b169a:	90                   	nop
  3b169b:	90                   	nop
  3b169c:	90                   	nop
  3b169d:	90                   	nop
  3b169e:	90                   	nop
  3b169f:	90                   	nop
  3b16a0:	55                   	push   rbp
  3b16a1:	48 89 e5             	mov    rbp,rsp
  3b16a4:	41 57                	push   r15
  3b16a6:	41 56                	push   r14
  3b16a8:	41 55                	push   r13
  3b16aa:	41 54                	push   r12
  3b16ac:	53                   	push   rbx
  3b16ad:	48 83 e4 e0          	and    rsp,0xffffffffffffffe0
  3b16b1:	48 81 ec e0 00 00 00 	sub    rsp,0xe0
  3b16b8:	48 89 e3             	mov    rbx,rsp
  3b16bb:	4c 8d 2d 4e ac 56 03 	lea    r13,[rip+0x356ac4e]        # 0x391c310
  3b16c2:	48 89 8b 90 00 00 00 	mov    QWORD PTR [rbx+0x90],rcx
  3b16c9:	48 89 53 60          	mov    QWORD PTR [rbx+0x60],rdx
  3b16cd:	49 89 f6             	mov    r14,rsi
  3b16d0:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  3b16d4:	48 89 83 c0 00 00 00 	mov    QWORD PTR [rbx+0xc0],rax
  3b16db:	48 89 7b 78          	mov    QWORD PTR [rbx+0x78],rdi
  3b16df:	4c 8b 67 08          	mov    r12,QWORD PTR [rdi+0x8]
  3b16e3:	49 8b 84 24 48 0c 00 	mov    rax,QWORD PTR [r12+0xc48]
  3b16ea:	00 
  3b16eb:	4c 89 e7             	mov    rdi,r12
  3b16ee:	48 c7 83 b8 00 00 00 	mov    QWORD PTR [rbx+0xb8],0x0
  3b16f5:	00 00 00 00 
  3b16f9:	c7 83 b4 00 00 00 00 	mov    DWORD PTR [rbx+0xb4],0x0
  3b1700:	00 00 00 
  3b1703:	c7 83 b0 00 00 00 00 	mov    DWORD PTR [rbx+0xb0],0x0
  3b170a:	00 00 00 
  3b170d:	48 89 83 98 00 00 00 	mov    QWORD PTR [rbx+0x98],rax
  3b1714:	e8 67 6a 64 00       	call   0x9f8180
  3b1719:	48 8d b3 a0 00 00 00 	lea    rsi,[rbx+0xa0]
  3b1720:	4c 89 e7             	mov    rdi,r12
  3b1723:	49 89 c7             	mov    r15,rax
  3b1726:	e8 95 6a 64 00       	call   0x9f81c0
  3b172b:	85 c0                	test   eax,eax
  3b172d:	75 2d                	jne    0x3b175c
  3b172f:	8b 83 a0 00 00 00    	mov    eax,DWORD PTR [rbx+0xa0]
  3b1735:	3d ff ff ff 00       	cmp    eax,0xffffff
  3b173a:	77 20                	ja     0x3b175c
  3b173c:	3d ff ff 00 00       	cmp    eax,0xffff
  3b1741:	0f 86 7d 01 00 00    	jbe    0x3b18c4
  3b1747:	25 00 00 ff 00       	and    eax,0xff0000
  3b174c:	3d 00 00 01 00       	cmp    eax,0x10000
  3b1751:	75 09                	jne    0x3b175c
  3b1753:	48 8d 35 16 e7 11 03 	lea    rsi,[rip+0x311e716]        # 0x34cfe70
  3b175a:	eb 07                	jmp    0x3b1763
  3b175c:	48 8d 35 65 e1 11 03 	lea    rsi,[rip+0x311e165]        # 0x34cf8c8
  3b1763:	83 be a0 04 00 00 01 	cmp    DWORD PTR [rsi+0x4a0],0x1
  3b176a:	48 89 73 68          	mov    QWORD PTR [rbx+0x68],rsi
  3b176e:	74 28                	je     0x3b1798
  3b1770:	bf 01 00 00 00       	mov    edi,0x1
  3b1775:	e8 96 1c 00 00       	call   0x3b3410
  3b177a:	85 c0                	test   eax,eax
  3b177c:	74 1a                	je     0x3b1798
  3b177e:	41 89 c7             	mov    r15d,eax
  3b1781:	48 8d 3d 80 a7 f6 00 	lea    rdi,[rip+0xf6a780]        # 0x131bf08
  3b1788:	48 8d 35 f8 ef f9 00 	lea    rsi,[rip+0xf9eff8]        # 0x1350787
  3b178f:	ba ec 11 00 00       	mov    edx,0x11ec
  3b1794:	89 c1                	mov    ecx,eax
  3b1796:	eb 30                	jmp    0x3b17c8
  3b1798:	4c 8b 7b 60          	mov    r15,QWORD PTR [rbx+0x60]
  3b179c:	41 8d 87 7f ff ff ff 	lea    eax,[r15-0x81]
  3b17a3:	3d 7f ff ff ff       	cmp    eax,0xffffff7f
  3b17a8:	77 2a                	ja     0x3b17d4
  3b17aa:	48 8d 3d 57 a7 f6 00 	lea    rdi,[rip+0xf6a757]        # 0x131bf08
  3b17b1:	48 8d 35 cf ef f9 00 	lea    rsi,[rip+0xf9efcf]        # 0x1350787
  3b17b8:	41 bf 16 00 00 00    	mov    r15d,0x16
  3b17be:	ba f4 11 00 00       	mov    edx,0x11f4
  3b17c3:	b9 16 00 00 00       	mov    ecx,0x16
  3b17c8:	31 c0                	xor    eax,eax
  3b17ca:	e8 41 bc ea ff       	call   0x25d410
  3b17cf:	e9 c1 07 00 00       	jmp    0x3b1f95
  3b17d4:	4c 89 73 28          	mov    QWORD PTR [rbx+0x28],r14
  3b17d8:	41 83 ff 02          	cmp    r15d,0x2
  3b17dc:	72 38                	jb     0x3b1816
  3b17de:	42 8d 04 bd 0f 00 00 	lea    eax,[r15*4+0xf]
  3b17e5:	00 
  3b17e6:	49 89 e6             	mov    r14,rsp
  3b17e9:	42 8d 34 bd 00 00 00 	lea    esi,[r15*4+0x0]
  3b17f0:	00 
  3b17f1:	83 e0 f0             	and    eax,0xfffffff0
  3b17f4:	49 29 c6             	sub    r14,rax
  3b17f7:	49 83 e6 e0          	and    r14,0xffffffffffffffe0
  3b17fb:	4c 89 f4             	mov    rsp,r14
  3b17fe:	48 89 e7             	mov    rdi,rsp
  3b1801:	48 29 c7             	sub    rdi,rax
  3b1804:	48 83 e7 e0          	and    rdi,0xffffffffffffffe0
  3b1808:	48 89 fc             	mov    rsp,rdi
  3b180b:	48 89 7b 18          	mov    QWORD PTR [rbx+0x18],rdi
  3b180f:	e8 dc 77 ea ff       	call   0x258ff0
  3b1814:	eb 12                	jmp    0x3b1828
  3b1816:	48 8d 83 b0 00 00 00 	lea    rax,[rbx+0xb0]
  3b181d:	4c 8d b3 b4 00 00 00 	lea    r14,[rbx+0xb4]
  3b1824:	48 89 43 18          	mov    QWORD PTR [rbx+0x18],rax
  3b1828:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3b182f:	00 00 
  3b1831:	45 89 fd             	mov    r13d,r15d
  3b1834:	48 8d 35 02 67 fe 00 	lea    rsi,[rip+0xfe6702]        # 0x1397f3d
  3b183b:	31 d2                	xor    edx,edx
  3b183d:	4e 8d 24 ad 00 00 00 	lea    r12,[r13*4+0x0]
  3b1844:	00 
  3b1845:	e8 96 8b 86 00       	call   0xc1a3e0
  3b184a:	48 8b 7b 28          	mov    rdi,QWORD PTR [rbx+0x28]
  3b184e:	4c 89 f6             	mov    rsi,r14
  3b1851:	4c 89 e2             	mov    rdx,r12
  3b1854:	e8 27 7a ea ff       	call   0x259280
  3b1859:	85 c0                	test   eax,eax
  3b185b:	74 24                	je     0x3b1881
  3b185d:	48 8d 3d a4 a6 f6 00 	lea    rdi,[rip+0xf6a6a4]        # 0x131bf08
  3b1864:	48 8d 35 1c ef f9 00 	lea    rsi,[rip+0xf9ef1c]        # 0x1350787
  3b186b:	ba 03 12 00 00       	mov    edx,0x1203
  3b1870:	89 c1                	mov    ecx,eax
  3b1872:	41 89 c7             	mov    r15d,eax
  3b1875:	31 c0                	xor    eax,eax
  3b1877:	e8 94 bb ea ff       	call   0x25d410
  3b187c:	e9 0d 07 00 00       	jmp    0x3b1f8e
  3b1881:	4c 89 6b 38          	mov    QWORD PTR [rbx+0x38],r13
  3b1885:	4c 89 73 20          	mov    QWORD PTR [rbx+0x20],r14
  3b1889:	e8 42 60 75 00       	call   0xb078d0
  3b188e:	85 c0                	test   eax,eax
  3b1890:	74 6a                	je     0x3b18fc
  3b1892:	4c 8b 73 38          	mov    r14,QWORD PTR [rbx+0x38]
  3b1896:	48 8d 35 63 bf 6c 01 	lea    rsi,[rip+0x16cbf63]        # 0x1a7d800
  3b189d:	ba 02 01 00 00       	mov    edx,0x102
  3b18a2:	4a 8d 04 f5 00 00 00 	lea    rax,[r14*8+0x0]
  3b18a9:	00 
  3b18aa:	48 8d 3c 40          	lea    rdi,[rax+rax*2]
  3b18ae:	e8 9d 72 85 00       	call   0xc08b50
  3b18b3:	4c 8b 6b 18          	mov    r13,QWORD PTR [rbx+0x18]
  3b18b7:	4c 8b 43 20          	mov    r8,QWORD PTR [rbx+0x20]
  3b18bb:	4c 89 f7             	mov    rdi,r14
  3b18be:	48 89 43 58          	mov    QWORD PTR [rbx+0x58],rax
  3b18c2:	eb 4c                	jmp    0x3b1910
  3b18c4:	4c 39 3d fd de 11 03 	cmp    QWORD PTR [rip+0x311defd],r15        # 0x34cf7c8
  3b18cb:	0f 84 e7 06 00 00    	je     0x3b1fb8
  3b18d1:	4c 39 3d e8 ef 11 03 	cmp    QWORD PTR [rip+0x311efe8],r15        # 0x34d08c0
  3b18d8:	0f 84 e6 06 00 00    	je     0x3b1fc4
  3b18de:	83 3d db de 11 03 00 	cmp    DWORD PTR [rip+0x311dedb],0x0        # 0x34cf7c0
  3b18e5:	48 8d 05 34 da 11 03 	lea    rax,[rip+0x311da34]        # 0x34cf320
  3b18ec:	48 8d 35 25 eb 11 03 	lea    rsi,[rip+0x311eb25]        # 0x34d0418
  3b18f3:	48 0f 44 f0          	cmove  rsi,rax
  3b18f7:	e9 67 fe ff ff       	jmp    0x3b1763
  3b18fc:	4c 8b 6b 18          	mov    r13,QWORD PTR [rbx+0x18]
  3b1900:	4c 8b 43 20          	mov    r8,QWORD PTR [rbx+0x20]
  3b1904:	48 8b 7b 38          	mov    rdi,QWORD PTR [rbx+0x38]
  3b1908:	48 c7 43 58 00 00 00 	mov    QWORD PTR [rbx+0x58],0x0
  3b190f:	00 
  3b1910:	4c 89 a3 88 00 00 00 	mov    QWORD PTR [rbx+0x88],r12
  3b1917:	45 31 f6             	xor    r14d,r14d
  3b191a:	31 c0                	xor    eax,eax
  3b191c:	c7 43 34 00 00 00 00 	mov    DWORD PTR [rbx+0x34],0x0
  3b1923:	eb 20                	jmp    0x3b1945
  3b1925:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b192c:	00 00 00 00 
  3b1930:	43 c7 44 b5 00 03 00 	mov    DWORD PTR [r13+r14*4+0x0],0x80020003
  3b1937:	02 80 
  3b1939:	49 ff c6             	inc    r14
  3b193c:	49 39 fe             	cmp    r14,rdi
  3b193f:	0f 84 51 04 00 00    	je     0x3b1d96
  3b1945:	47 8b 3c b0          	mov    r15d,DWORD PTR [r8+r14*4]
  3b1949:	45 89 fc             	mov    r12d,r15d
  3b194c:	44 89 fe             	mov    esi,r15d
  3b194f:	41 c1 fc 10          	sar    r12d,0x10
  3b1953:	81 e6 ff ff 00 00    	and    esi,0xffff
  3b1959:	0f 95 c1             	setne  cl
  3b195c:	41 81 fc 80 00 00 00 	cmp    r12d,0x80
  3b1963:	0f 92 c2             	setb   dl
  3b1966:	84 d1                	test   cl,dl
  3b1968:	74 c6                	je     0x3b1930
  3b196a:	89 73 40             	mov    DWORD PTR [rbx+0x40],esi
  3b196d:	39 c6                	cmp    esi,eax
  3b196f:	74 41                	je     0x3b19b2
  3b1971:	83 7b 34 00          	cmp    DWORD PTR [rbx+0x34],0x0
  3b1975:	74 0f                	je     0x3b1986
  3b1977:	48 8b bb b8 00 00 00 	mov    rdi,QWORD PTR [rbx+0xb8]
  3b197e:	e8 2d 85 fe ff       	call   0x399eb0
  3b1983:	8b 73 40             	mov    esi,DWORD PTR [rbx+0x40]
  3b1986:	48 8b bb 98 00 00 00 	mov    rdi,QWORD PTR [rbx+0x98]
  3b198d:	ba 60 01 00 00       	mov    edx,0x160
  3b1992:	48 8d 8b b8 00 00 00 	lea    rcx,[rbx+0xb8]
  3b1999:	e8 42 85 fe ff       	call   0x399ee0
  3b199e:	48 89 43 28          	mov    QWORD PTR [rbx+0x28],rax
  3b19a2:	48 85 c0             	test   rax,rax
  3b19a5:	0f 84 91 00 00 00    	je     0x3b1a3c
  3b19ab:	c7 43 34 01 00 00 00 	mov    DWORD PTR [rbx+0x34],0x1
  3b19b2:	48 8b 43 28          	mov    rax,QWORD PTR [rbx+0x28]
  3b19b6:	0f bf 00             	movsx  eax,WORD PTR [rax]
  3b19b9:	41 39 c4             	cmp    r12d,eax
  3b19bc:	7d 42                	jge    0x3b1a00
  3b19be:	48 8b bb b8 00 00 00 	mov    rdi,QWORD PTR [rbx+0xb8]
  3b19c5:	e8 56 84 fe ff       	call   0x399e20
  3b19ca:	85 c0                	test   eax,eax
  3b19cc:	0f 84 c3 00 00 00    	je     0x3b1a95
  3b19d2:	43 c7 44 b5 00 01 00 	mov    DWORD PTR [r13+r14*4+0x0],0x80020001
  3b19d9:	02 80 
  3b19db:	48 8d 3d 95 99 fa 00 	lea    rdi,[rip+0xfa9995]        # 0x135b377
  3b19e2:	48 8d 35 9e ed f9 00 	lea    rsi,[rip+0xf9ed9e]        # 0x1350787
  3b19e9:	ba 36 12 00 00       	mov    edx,0x1236
  3b19ee:	44 89 f1             	mov    ecx,r14d
  3b19f1:	41 b8 01 00 00 00    	mov    r8d,0x1
  3b19f7:	eb 2c                	jmp    0x3b1a25
  3b19f9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  3b1a00:	48 8d 3d 70 99 fa 00 	lea    rdi,[rip+0xfa9970]        # 0x135b377
  3b1a07:	48 8d 35 79 ed f9 00 	lea    rsi,[rip+0xf9ed79]        # 0x1350787
  3b1a0e:	ba 30 12 00 00       	mov    edx,0x1230
  3b1a13:	43 c7 44 b5 00 03 00 	mov    DWORD PTR [r13+r14*4+0x0],0x80020003
  3b1a1a:	02 80 
  3b1a1c:	44 89 f1             	mov    ecx,r14d
  3b1a1f:	41 b8 03 00 00 00    	mov    r8d,0x3
  3b1a25:	31 c0                	xor    eax,eax
  3b1a27:	e8 e4 b9 ea ff       	call   0x25d410
  3b1a2c:	4c 8b 43 20          	mov    r8,QWORD PTR [rbx+0x20]
  3b1a30:	48 8b 7b 38          	mov    rdi,QWORD PTR [rbx+0x38]
  3b1a34:	8b 43 40             	mov    eax,DWORD PTR [rbx+0x40]
  3b1a37:	e9 fd fe ff ff       	jmp    0x3b1939
  3b1a3c:	48 8d 3d 34 99 fa 00 	lea    rdi,[rip+0xfa9934]        # 0x135b377
  3b1a43:	48 8d 35 3d ed f9 00 	lea    rsi,[rip+0xf9ed3d]        # 0x1350787
  3b1a4a:	ba 22 12 00 00       	mov    edx,0x1222
  3b1a4f:	44 89 f1             	mov    ecx,r14d
  3b1a52:	41 b8 03 00 00 00    	mov    r8d,0x3
  3b1a58:	31 c0                	xor    eax,eax
  3b1a5a:	43 c7 44 b5 00 03 00 	mov    DWORD PTR [r13+r14*4+0x0],0x80020003
  3b1a61:	02 80 
  3b1a63:	48 c7 43 28 00 00 00 	mov    QWORD PTR [rbx+0x28],0x0
  3b1a6a:	00 
  3b1a6b:	e8 a0 b9 ea ff       	call   0x25d410
  3b1a70:	48 8b 7b 38          	mov    rdi,QWORD PTR [rbx+0x38]
  3b1a74:	4c 8b 43 20          	mov    r8,QWORD PTR [rbx+0x20]
  3b1a78:	49 ff c6             	inc    r14
  3b1a7b:	b8 00 00 00 00       	mov    eax,0x0
  3b1a80:	c7 43 34 00 00 00 00 	mov    DWORD PTR [rbx+0x34],0x0
  3b1a87:	49 39 fe             	cmp    r14,rdi
  3b1a8a:	0f 85 b5 fe ff ff    	jne    0x3b1945
  3b1a90:	e9 13 03 00 00       	jmp    0x3b1da8
  3b1a95:	48 8b 53 28          	mov    rdx,QWORD PTR [rbx+0x28]
  3b1a99:	44 89 e1             	mov    ecx,r12d
  3b1a9c:	48 8b 42 28          	mov    rax,QWORD PTR [rdx+0x28]
  3b1aa0:	66 83 3a 02          	cmp    WORD PTR [rdx],0x2
  3b1aa4:	4c 8b 2c c8          	mov    r13,QWORD PTR [rax+rcx*8]
  3b1aa8:	7c 21                	jl     0x3b1acb
  3b1aaa:	4d 85 ed             	test   r13,r13
  3b1aad:	75 1c                	jne    0x3b1acb
  3b1aaf:	4c 8b 6b 18          	mov    r13,QWORD PTR [rbx+0x18]
  3b1ab3:	48 8d 3d bd 98 fa 00 	lea    rdi,[rip+0xfa98bd]        # 0x135b377
  3b1aba:	48 8d 35 c6 ec f9 00 	lea    rsi,[rip+0xf9ecc6]        # 0x1350787
  3b1ac1:	ba 3f 12 00 00       	mov    edx,0x123f
  3b1ac6:	e9 48 ff ff ff       	jmp    0x3b1a13
  3b1acb:	48 83 7b 58 00       	cmp    QWORD PTR [rbx+0x58],0x0
  3b1ad0:	0f 95 43 50          	setne  BYTE PTR [rbx+0x50]
  3b1ad4:	e8 f7 5d 75 00       	call   0xb078d0
  3b1ad9:	85 c0                	test   eax,eax
  3b1adb:	0f 95 c0             	setne  al
  3b1ade:	22 43 50             	and    al,BYTE PTR [rbx+0x50]
  3b1ae1:	3c 01                	cmp    al,0x1
  3b1ae3:	75 32                	jne    0x3b1b17
  3b1ae5:	48 8b 43 20          	mov    rax,QWORD PTR [rbx+0x20]
  3b1ae9:	48 8b 73 58          	mov    rsi,QWORD PTR [rbx+0x58]
  3b1aed:	4b 8d 0c 76          	lea    rcx,[r14+r14*2]
  3b1af1:	42 8b 04 b0          	mov    eax,DWORD PTR [rax+r14*4]
  3b1af5:	89 04 ce             	mov    DWORD PTR [rsi+rcx*8],eax
  3b1af8:	49 8b 45 18          	mov    rax,QWORD PTR [r13+0x18]
  3b1afc:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b1aff:	48 89 44 ce 08       	mov    QWORD PTR [rsi+rcx*8+0x8],rax
  3b1b04:	49 8b 45 10          	mov    rax,QWORD PTR [r13+0x10]
  3b1b08:	48 89 c2             	mov    rdx,rax
  3b1b0b:	48 c1 fa 04          	sar    rdx,0x4
  3b1b0f:	48 31 c2             	xor    rdx,rax
  3b1b12:	48 89 54 ce 10       	mov    QWORD PTR [rsi+rcx*8+0x10],rdx
  3b1b17:	4d 8b 6d 20          	mov    r13,QWORD PTR [r13+0x20]
  3b1b1b:	41 81 ff 00 00 01 00 	cmp    r15d,0x10000
  3b1b22:	72 24                	jb     0x3b1b48
  3b1b24:	41 83 7d 00 02       	cmp    DWORD PTR [r13+0x0],0x2
  3b1b29:	72 1d                	jb     0x3b1b48
  3b1b2b:	48 8d 3d 29 3e fb 00 	lea    rdi,[rip+0xfb3e29]        # 0x136595b
  3b1b32:	48 8d 35 4e ec f9 00 	lea    rsi,[rip+0xf9ec4e]        # 0x1350787
  3b1b39:	ba 50 12 00 00       	mov    edx,0x1250
  3b1b3e:	44 89 e1             	mov    ecx,r12d
  3b1b41:	31 c0                	xor    eax,eax
  3b1b43:	e8 c8 b8 ea ff       	call   0x25d410
  3b1b48:	49 8d 7d 20          	lea    rdi,[r13+0x20]
  3b1b4c:	be 00 00 08 00       	mov    esi,0x80000
  3b1b51:	31 d2                	xor    edx,edx
  3b1b53:	31 c9                	xor    ecx,ecx
  3b1b55:	45 31 c0             	xor    r8d,r8d
  3b1b58:	45 31 c9             	xor    r9d,r9d
  3b1b5b:	48 89 7b 70          	mov    QWORD PTR [rbx+0x70],rdi
  3b1b5f:	6a 00                	push   0x0
  3b1b61:	6a 00                	push   0x0
  3b1b63:	e8 08 fc 83 00       	call   0xbf1770
  3b1b68:	48 83 c4 10          	add    rsp,0x10
  3b1b6c:	41 8b 45 08          	mov    eax,DWORD PTR [r13+0x8]
  3b1b70:	4c 8b 7b 18          	mov    r15,QWORD PTR [rbx+0x18]
  3b1b74:	8d 48 fd             	lea    ecx,[rax-0x3]
  3b1b77:	83 f9 01             	cmp    ecx,0x1
  3b1b7a:	77 37                	ja     0x3b1bb3
  3b1b7c:	48 8b 7b 70          	mov    rdi,QWORD PTR [rbx+0x70]
  3b1b80:	45 31 c0             	xor    r8d,r8d
  3b1b83:	43 89 04 b7          	mov    DWORD PTR [r15+r14*4],eax
  3b1b87:	be 00 00 10 00       	mov    esi,0x100000
  3b1b8c:	31 d2                	xor    edx,edx
  3b1b8e:	31 c9                	xor    ecx,ecx
  3b1b90:	45 31 c9             	xor    r9d,r9d
  3b1b93:	6a 00                	push   0x0
  3b1b95:	6a 00                	push   0x0
  3b1b97:	e8 d4 fb 83 00       	call   0xbf1770
  3b1b9c:	48 83 c4 10          	add    rsp,0x10
  3b1ba0:	4c 8b 43 20          	mov    r8,QWORD PTR [rbx+0x20]
  3b1ba4:	48 8b 7b 38          	mov    rdi,QWORD PTR [rbx+0x38]
  3b1ba8:	8b 43 40             	mov    eax,DWORD PTR [rbx+0x40]
  3b1bab:	4d 89 fd             	mov    r13,r15
  3b1bae:	e9 86 fd ff ff       	jmp    0x3b1939
  3b1bb3:	41 8b 4d 00          	mov    ecx,DWORD PTR [r13+0x0]
  3b1bb7:	43 89 04 b7          	mov    DWORD PTR [r15+r14*4],eax
  3b1bbb:	4c 89 7b 18          	mov    QWORD PTR [rbx+0x18],r15
  3b1bbf:	41 83 7d 00 00       	cmp    DWORD PTR [r13+0x0],0x0
  3b1bc4:	0f 84 93 01 00 00    	je     0x3b1d5d
  3b1bca:	31 c0                	xor    eax,eax
  3b1bcc:	83 f9 02             	cmp    ecx,0x2
  3b1bcf:	4c 89 ab 80 00 00 00 	mov    QWORD PTR [rbx+0x80],r13
  3b1bd6:	44 0f 4d e0          	cmovge r12d,eax
  3b1bda:	eb 2d                	jmp    0x3b1c09
  3b1bdc:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
  3b1be0:	42 c7 04 b0 02 00 00 	mov    DWORD PTR [rax+r14*4],0x2
  3b1be7:	00 
  3b1be8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  3b1bef:	00 
  3b1bf0:	8b 43 50             	mov    eax,DWORD PTR [rbx+0x50]
  3b1bf3:	4c 8b ab 80 00 00 00 	mov    r13,QWORD PTR [rbx+0x80]
  3b1bfa:	41 ff c4             	inc    r12d
  3b1bfd:	ff c0                	inc    eax
  3b1bff:	41 3b 45 00          	cmp    eax,DWORD PTR [r13+0x0]
  3b1c03:	0f 83 54 01 00 00    	jae    0x3b1d5d
  3b1c09:	48 8b 4b 28          	mov    rcx,QWORD PTR [rbx+0x28]
  3b1c0d:	89 43 50             	mov    DWORD PTR [rbx+0x50],eax
  3b1c10:	48 8b 41 28          	mov    rax,QWORD PTR [rcx+0x28]
  3b1c14:	49 63 cc             	movsxd rcx,r12d
  3b1c17:	4c 8b 2c c8          	mov    r13,QWORD PTR [rax+rcx*8]
  3b1c1b:	4d 85 ed             	test   r13,r13
  3b1c1e:	74 d0                	je     0x3b1bf0
  3b1c20:	41 83 7d 38 01       	cmp    DWORD PTR [r13+0x38],0x1
  3b1c25:	75 c9                	jne    0x3b1bf0
  3b1c27:	48 8b 43 28          	mov    rax,QWORD PTR [rbx+0x28]
  3b1c2b:	48 8b 4b 68          	mov    rcx,QWORD PTR [rbx+0x68]
  3b1c2f:	4c 89 ef             	mov    rdi,r13
  3b1c32:	ba 01 00 00 00       	mov    edx,0x1
  3b1c37:	8b 70 04             	mov    esi,DWORD PTR [rax+0x4]
  3b1c3a:	e8 51 25 00 00       	call   0x3b4190
  3b1c3f:	85 c0                	test   eax,eax
  3b1c41:	75 ad                	jne    0x3b1bf0
  3b1c43:	49 8b 45 10          	mov    rax,QWORD PTR [r13+0x10]
  3b1c47:	4c 89 ea             	mov    rdx,r13
  3b1c4a:	48 83 78 18 00       	cmp    QWORD PTR [rax+0x18],0x0
  3b1c4f:	74 51                	je     0x3b1ca2
  3b1c51:	48 c7 83 a8 00 00 00 	mov    QWORD PTR [rbx+0xa8],0x0
  3b1c58:	00 00 00 00 
  3b1c5c:	48 c7 83 a0 00 00 00 	mov    QWORD PTR [rbx+0xa0],0xffffffff80020055
  3b1c63:	55 00 02 80 
  3b1c67:	48 8d 35 29 d6 f9 00 	lea    rsi,[rip+0xf9d629]        # 0x134f297
  3b1c6e:	8b 4a 38             	mov    ecx,DWORD PTR [rdx+0x38]
  3b1c71:	31 d2                	xor    edx,edx
  3b1c73:	89 8b a8 00 00 00    	mov    DWORD PTR [rbx+0xa8],ecx
  3b1c79:	4c 8b 78 18          	mov    r15,QWORD PTR [rax+0x18]
  3b1c7d:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3b1c84:	00 00 
  3b1c86:	e8 55 87 86 00       	call   0xc1a3e0
  3b1c8b:	ba 10 00 00 00       	mov    edx,0x10
  3b1c90:	48 8d bb a0 00 00 00 	lea    rdi,[rbx+0xa0]
  3b1c97:	4c 89 fe             	mov    rsi,r15
  3b1c9a:	e8 31 75 ea ff       	call   0x2591d0
  3b1c9f:	4c 89 ea             	mov    rdx,r13
  3b1ca2:	48 8b 8b 80 00 00 00 	mov    rcx,QWORD PTR [rbx+0x80]
  3b1ca9:	8b 41 04             	mov    eax,DWORD PTR [rcx+0x4]
  3b1cac:	85 c0                	test   eax,eax
  3b1cae:	74 11                	je     0x3b1cc1
  3b1cb0:	ff c8                	dec    eax
  3b1cb2:	89 41 04             	mov    DWORD PTR [rcx+0x4],eax
  3b1cb5:	c6 41 0d 01          	mov    BYTE PTR [rcx+0xd],0x1
  3b1cb9:	0f 85 1d ff ff ff    	jne    0x3b1bdc
  3b1cbf:	eb 04                	jmp    0x3b1cc5
  3b1cc1:	c6 41 0d 01          	mov    BYTE PTR [rcx+0xd],0x1
  3b1cc5:	8b 42 38             	mov    eax,DWORD PTR [rdx+0x38]
  3b1cc8:	89 41 08             	mov    DWORD PTR [rcx+0x8],eax
  3b1ccb:	4c 8b 79 50          	mov    r15,QWORD PTR [rcx+0x50]
  3b1ccf:	4d 85 ff             	test   r15,r15
  3b1cd2:	0f 84 18 ff ff ff    	je     0x3b1bf0
  3b1cd8:	c7 43 4c 00 00 00 00 	mov    DWORD PTR [rbx+0x4c],0x0
  3b1cdf:	eb 32                	jmp    0x3b1d13
  3b1ce1:	49 8b 3f             	mov    rdi,QWORD PTR [r15]
  3b1ce4:	c7 43 4c 01 00 00 00 	mov    DWORD PTR [rbx+0x4c],0x1
  3b1ceb:	e8 20 4c 85 00       	call   0xc06910
  3b1cf0:	49 8b 7f 10          	mov    rdi,QWORD PTR [r15+0x10]
  3b1cf4:	31 f6                	xor    esi,esi
  3b1cf6:	31 d2                	xor    edx,edx
  3b1cf8:	31 c9                	xor    ecx,ecx
  3b1cfa:	48 83 c7 18          	add    rdi,0x18
  3b1cfe:	e8 9d 52 11 00       	call   0x4c6fa0
  3b1d03:	4d 8b 7f 30          	mov    r15,QWORD PTR [r15+0x30]
  3b1d07:	4c 89 ea             	mov    rdx,r13
  3b1d0a:	4d 85 ff             	test   r15,r15
  3b1d0d:	0f 84 dd fe ff ff    	je     0x3b1bf0
  3b1d13:	8b 42 38             	mov    eax,DWORD PTR [rdx+0x38]
  3b1d16:	31 f6                	xor    esi,esi
  3b1d18:	31 d2                	xor    edx,edx
  3b1d1a:	31 c9                	xor    ecx,ecx
  3b1d1c:	41 89 47 20          	mov    DWORD PTR [r15+0x20],eax
  3b1d20:	49 8b 7f 10          	mov    rdi,QWORD PTR [r15+0x10]
  3b1d24:	48 83 c7 18          	add    rdi,0x18
  3b1d28:	e8 d3 4c 11 00       	call   0x4c6a00
  3b1d2d:	49 8b 07             	mov    rax,QWORD PTR [r15]
  3b1d30:	ff 08                	dec    DWORD PTR [rax]
  3b1d32:	49 8b 3f             	mov    rdi,QWORD PTR [r15]
  3b1d35:	83 3f 00             	cmp    DWORD PTR [rdi],0x0
  3b1d38:	7f b6                	jg     0x3b1cf0
  3b1d3a:	49 8b 47 08          	mov    rax,QWORD PTR [r15+0x8]
  3b1d3e:	48 85 c0             	test   rax,rax
  3b1d41:	74 a8                	je     0x3b1ceb
  3b1d43:	ff 08                	dec    DWORD PTR [rax]
  3b1d45:	83 7b 4c 00          	cmp    DWORD PTR [rbx+0x4c],0x0
  3b1d49:	74 96                	je     0x3b1ce1
  3b1d4b:	49 8b 47 08          	mov    rax,QWORD PTR [r15+0x8]
  3b1d4f:	c7 43 4c 01 00 00 00 	mov    DWORD PTR [rbx+0x4c],0x1
  3b1d56:	83 38 00             	cmp    DWORD PTR [rax],0x0
  3b1d59:	75 95                	jne    0x3b1cf0
  3b1d5b:	eb 84                	jmp    0x3b1ce1
  3b1d5d:	41 80 7d 0d 00       	cmp    BYTE PTR [r13+0xd],0x0
  3b1d62:	4c 8b 6b 18          	mov    r13,QWORD PTR [rbx+0x18]
  3b1d66:	74 09                	je     0x3b1d71
  3b1d68:	43 c7 44 b5 00 04 00 	mov    DWORD PTR [r13+r14*4+0x0],0x4
  3b1d6f:	00 00 
  3b1d71:	48 8b 7b 70          	mov    rdi,QWORD PTR [rbx+0x70]
  3b1d75:	be 00 00 10 00       	mov    esi,0x100000
  3b1d7a:	31 d2                	xor    edx,edx
  3b1d7c:	31 c9                	xor    ecx,ecx
  3b1d7e:	45 31 c0             	xor    r8d,r8d
  3b1d81:	45 31 c9             	xor    r9d,r9d
  3b1d84:	6a 00                	push   0x0
  3b1d86:	6a 00                	push   0x0
  3b1d88:	e8 e3 f9 83 00       	call   0xbf1770
  3b1d8d:	48 83 c4 10          	add    rsp,0x10
  3b1d91:	e9 96 fc ff ff       	jmp    0x3b1a2c
  3b1d96:	83 7b 34 00          	cmp    DWORD PTR [rbx+0x34],0x0
  3b1d9a:	74 0c                	je     0x3b1da8
  3b1d9c:	48 8b bb b8 00 00 00 	mov    rdi,QWORD PTR [rbx+0xb8]
  3b1da3:	e8 08 81 fe ff       	call   0x399eb0
  3b1da8:	4c 8b 7b 58          	mov    r15,QWORD PTR [rbx+0x58]
  3b1dac:	4d 85 ff             	test   r15,r15
  3b1daf:	41 0f 95 c6          	setne  r14b
  3b1db3:	e8 18 5b 75 00       	call   0xb078d0
  3b1db8:	85 c0                	test   eax,eax
  3b1dba:	0f 95 c0             	setne  al
  3b1dbd:	44 20 f0             	and    al,r14b
  3b1dc0:	3c 01                	cmp    al,0x1
  3b1dc2:	75 1f                	jne    0x3b1de3
  3b1dc4:	48 8b 7b 78          	mov    rdi,QWORD PTR [rbx+0x78]
  3b1dc8:	4c 89 fa             	mov    rdx,r15
  3b1dcb:	48 8b 73 60          	mov    rsi,QWORD PTR [rbx+0x60]
  3b1dcf:	e8 cc 1e cf ff       	call   0xa3ca0
  3b1dd4:	48 8d 35 25 ba 6c 01 	lea    rsi,[rip+0x16cba25]        # 0x1a7d800
  3b1ddb:	4c 89 ff             	mov    rdi,r15
  3b1dde:	e8 0d 70 85 00       	call   0xc08df0
  3b1de3:	4c 8b 7b 68          	mov    r15,QWORD PTR [rbx+0x68]
  3b1de7:	41 be 03 00 00 00    	mov    r14d,0x3
  3b1ded:	49 8d 87 d8 00 00 00 	lea    rax,[r15+0xd8]
  3b1df4:	49 8d 8f 80 00 00 00 	lea    rcx,[r15+0x80]
  3b1dfb:	48 89 43 40          	mov    QWORD PTR [rbx+0x40],rax
  3b1dff:	48 89 4b 50          	mov    QWORD PTR [rbx+0x50],rcx
  3b1e03:	eb 37                	jmp    0x3b1e3c
  3b1e05:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b1e0c:	00 00 00 00 
  3b1e10:	48 8b 7b 28          	mov    rdi,QWORD PTR [rbx+0x28]
  3b1e14:	43 c7 84 b0 60 01 00 	mov    DWORD PTR [r8+r14*4+0x160],0x0
  3b1e1b:	00 00 00 00 00 
  3b1e20:	31 f6                	xor    esi,esi
  3b1e22:	31 d2                	xor    edx,edx
  3b1e24:	31 c9                	xor    ecx,ecx
  3b1e26:	4d 89 c7             	mov    r15,r8
  3b1e29:	e8 72 51 11 00       	call   0x4c6fa0
  3b1e2e:	49 83 fe 01          	cmp    r14,0x1
  3b1e32:	4d 8d 76 ff          	lea    r14,[r14-0x1]
  3b1e36:	0f 86 05 01 00 00    	jbe    0x3b1f41
  3b1e3c:	4c 89 f7             	mov    rdi,r14
  3b1e3f:	31 f6                	xor    esi,esi
  3b1e41:	31 d2                	xor    edx,edx
  3b1e43:	31 c9                	xor    ecx,ecx
  3b1e45:	48 c1 e7 05          	shl    rdi,0x5
  3b1e49:	48 03 7b 40          	add    rdi,QWORD PTR [rbx+0x40]
  3b1e4d:	48 89 7b 28          	mov    QWORD PTR [rbx+0x28],rdi
  3b1e51:	e8 aa 4b 11 00       	call   0x4c6a00
  3b1e56:	43 83 bc b7 60 01 00 	cmp    DWORD PTR [r15+r14*4+0x160],0x0
  3b1e5d:	00 00 
  3b1e5f:	4d 89 f8             	mov    r8,r15
  3b1e62:	74 ac                	je     0x3b1e10
  3b1e64:	43 83 bc b0 c0 01 00 	cmp    DWORD PTR [r8+r14*4+0x1c0],0x0
  3b1e6b:	00 00 
  3b1e6d:	74 a1                	je     0x3b1e10
  3b1e6f:	48 8b 43 50          	mov    rax,QWORD PTR [rbx+0x50]
  3b1e73:	4d 89 f5             	mov    r13,r14
  3b1e76:	49 c1 e5 04          	shl    r13,0x4
  3b1e7a:	4e 8d 3c 28          	lea    r15,[rax+r13*1]
  3b1e7e:	eb 27                	jmp    0x3b1ea7
  3b1e80:	48 c7 47 48 00 00 00 	mov    QWORD PTR [rdi+0x48],0x0
  3b1e87:	00 
  3b1e88:	4b 8b 44 28 48       	mov    rax,QWORD PTR [r8+r13*1+0x48]
  3b1e8d:	48 89 47 50          	mov    QWORD PTR [rdi+0x50],rax
  3b1e91:	48 89 38             	mov    QWORD PTR [rax],rdi
  3b1e94:	4f 89 64 28 48       	mov    QWORD PTR [r8+r13*1+0x48],r12
  3b1e99:	43 ff 8c b0 60 01 00 	dec    DWORD PTR [r8+r14*4+0x160]
  3b1ea0:	00 
  3b1ea1:	0f 84 69 ff ff ff    	je     0x3b1e10
  3b1ea7:	49 8b 3f             	mov    rdi,QWORD PTR [r15]
  3b1eaa:	48 85 ff             	test   rdi,rdi
  3b1ead:	0f 84 5d ff ff ff    	je     0x3b1e10
  3b1eb3:	48 8b 47 48          	mov    rax,QWORD PTR [rdi+0x48]
  3b1eb7:	4c 8d 67 48          	lea    r12,[rdi+0x48]
  3b1ebb:	48 85 c0             	test   rax,rax
  3b1ebe:	74 20                	je     0x3b1ee0
  3b1ec0:	4c 39 60 50          	cmp    QWORD PTR [rax+0x50],r12
  3b1ec4:	0f 85 43 01 00 00    	jne    0x3b200d
  3b1eca:	48 8b 4f 50          	mov    rcx,QWORD PTR [rdi+0x50]
  3b1ece:	48 39 39             	cmp    QWORD PTR [rcx],rdi
  3b1ed1:	0f 85 f9 00 00 00    	jne    0x3b1fd0
  3b1ed7:	48 89 48 50          	mov    QWORD PTR [rax+0x50],rcx
  3b1edb:	eb 14                	jmp    0x3b1ef1
  3b1edd:	0f 1f 00             	nop    DWORD PTR [rax]
  3b1ee0:	48 8b 47 50          	mov    rax,QWORD PTR [rdi+0x50]
  3b1ee4:	48 39 38             	cmp    QWORD PTR [rax],rdi
  3b1ee7:	0f 85 e3 00 00 00    	jne    0x3b1fd0
  3b1eed:	49 89 47 08          	mov    QWORD PTR [r15+0x8],rax
  3b1ef1:	48 8b 47 48          	mov    rax,QWORD PTR [rdi+0x48]
  3b1ef5:	48 8b 4f 50          	mov    rcx,QWORD PTR [rdi+0x50]
  3b1ef9:	48 89 01             	mov    QWORD PTR [rcx],rax
  3b1efc:	43 8b 84 b0 d0 01 00 	mov    eax,DWORD PTR [r8+r14*4+0x1d0]
  3b1f03:	00 
  3b1f04:	8d 48 01             	lea    ecx,[rax+0x1]
  3b1f07:	43 89 8c b0 d0 01 00 	mov    DWORD PTR [r8+r14*4+0x1d0],ecx
  3b1f0e:	00 
  3b1f0f:	89 47 04             	mov    DWORD PTR [rdi+0x4],eax
  3b1f12:	48 8b 57 08          	mov    rdx,QWORD PTR [rdi+0x8]
  3b1f16:	48 85 d2             	test   rdx,rdx
  3b1f19:	0f 84 61 ff ff ff    	je     0x3b1e80
  3b1f1f:	44 89 f6             	mov    esi,r14d
  3b1f22:	4c 89 c1             	mov    rcx,r8
  3b1f25:	e8 16 25 00 00       	call   0x3b4440
  3b1f2a:	4c 8b 43 68          	mov    r8,QWORD PTR [rbx+0x68]
  3b1f2e:	43 ff 8c b0 60 01 00 	dec    DWORD PTR [r8+r14*4+0x160]
  3b1f35:	00 
  3b1f36:	0f 85 6b ff ff ff    	jne    0x3b1ea7
  3b1f3c:	e9 cf fe ff ff       	jmp    0x3b1e10
  3b1f41:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3b1f48:	00 00 
  3b1f4a:	48 8d 35 46 d3 f9 00 	lea    rsi,[rip+0xf9d346]        # 0x134f297
  3b1f51:	31 d2                	xor    edx,edx
  3b1f53:	e8 88 84 86 00       	call   0xc1a3e0
  3b1f58:	4c 8b 73 18          	mov    r14,QWORD PTR [rbx+0x18]
  3b1f5c:	48 8b b3 90 00 00 00 	mov    rsi,QWORD PTR [rbx+0x90]
  3b1f63:	48 8b 93 88 00 00 00 	mov    rdx,QWORD PTR [rbx+0x88]
  3b1f6a:	4c 89 f7             	mov    rdi,r14
  3b1f6d:	e8 5e 72 ea ff       	call   0x2591d0
  3b1f72:	41 89 c7             	mov    r15d,eax
  3b1f75:	e8 56 59 75 00       	call   0xb078d0
  3b1f7a:	85 c0                	test   eax,eax
  3b1f7c:	74 10                	je     0x3b1f8e
  3b1f7e:	48 8b 7b 78          	mov    rdi,QWORD PTR [rbx+0x78]
  3b1f82:	4c 89 f2             	mov    rdx,r14
  3b1f85:	48 8b 73 60          	mov    rsi,QWORD PTR [rbx+0x60]
  3b1f89:	e8 a2 1d cf ff       	call   0xa3d30
  3b1f8e:	4c 8d 2d 7b a3 56 03 	lea    r13,[rip+0x356a37b]        # 0x391c310
  3b1f95:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  3b1f99:	48 3b 83 c0 00 00 00 	cmp    rax,QWORD PTR [rbx+0xc0]
  3b1fa0:	0f 85 ac 00 00 00    	jne    0x3b2052
  3b1fa6:	44 89 f8             	mov    eax,r15d
  3b1fa9:	48 8d 65 d8          	lea    rsp,[rbp-0x28]
  3b1fad:	5b                   	pop    rbx
  3b1fae:	41 5c                	pop    r12
  3b1fb0:	41 5d                	pop    r13
  3b1fb2:	41 5e                	pop    r14
  3b1fb4:	41 5f                	pop    r15
  3b1fb6:	5d                   	pop    rbp
  3b1fb7:	c3                   	ret
  3b1fb8:	48 8d 35 61 d3 11 03 	lea    rsi,[rip+0x311d361]        # 0x34cf320
  3b1fbf:	e9 9f f7 ff ff       	jmp    0x3b1763
  3b1fc4:	48 8d 35 4d e4 11 03 	lea    rsi,[rip+0x311e44d]        # 0x34d0418
  3b1fcb:	e9 93 f7 ff ff       	jmp    0x3b1763
  3b1fd0:	49 89 fe             	mov    r14,rdi
  3b1fd3:	e8 78 f9 43 00       	call   0x7f1950
  3b1fd8:	49 8b 56 50          	mov    rdx,QWORD PTR [r14+0x50]
  3b1fdc:	48 8d 3d ed ff ff ff 	lea    rdi,[rip+0xffffffffffffffed]        # 0x3b1fd0
  3b1fe3:	4c 89 f6             	mov    rsi,r14
  3b1fe6:	48 8b 0a             	mov    rcx,QWORD PTR [rdx]
  3b1fe9:	e8 d2 00 44 00       	call   0x7f20c0
  3b1fee:	49 8b 4e 50          	mov    rcx,QWORD PTR [r14+0x50]
  3b1ff2:	48 8d 35 6b 9b f6 00 	lea    rsi,[rip+0xf69b6b]        # 0x131bb64
  3b1ff9:	bf 4b 00 00 00       	mov    edi,0x4b
  3b1ffe:	4c 89 f2             	mov    rdx,r14
  3b2001:	31 c0                	xor    eax,eax
  3b2003:	4c 8b 01             	mov    r8,QWORD PTR [rcx]
  3b2006:	e8 05 8a 8e 00       	call   0xc9aa10
  3b200b:	0f 0b                	ud2
  3b200d:	49 89 fe             	mov    r14,rdi
  3b2010:	e8 3b f9 43 00       	call   0x7f1950
  3b2015:	49 8b 56 48          	mov    rdx,QWORD PTR [r14+0x48]
  3b2019:	48 8d 3d ed ff ff ff 	lea    rdi,[rip+0xffffffffffffffed]        # 0x3b200d
  3b2020:	4c 89 f6             	mov    rsi,r14
  3b2023:	4d 89 e0             	mov    r8,r12
  3b2026:	48 8b 4a 50          	mov    rcx,QWORD PTR [rdx+0x50]
  3b202a:	e8 51 01 44 00       	call   0x7f2180
  3b202f:	49 8b 4e 48          	mov    rcx,QWORD PTR [r14+0x48]
  3b2033:	48 8d 35 b9 d6 fb 00 	lea    rsi,[rip+0xfbd6b9]        # 0x136f6f3
  3b203a:	bf 47 00 00 00       	mov    edi,0x47
  3b203f:	4c 89 f2             	mov    rdx,r14
  3b2042:	4d 89 e1             	mov    r9,r12
  3b2045:	31 c0                	xor    eax,eax
  3b2047:	4c 8b 41 50          	mov    r8,QWORD PTR [rcx+0x50]
  3b204b:	e8 c0 89 8e 00       	call   0xc9aa10
  3b2050:	0f 0b                	ud2
  3b2052:	e8 59 b6 34 00       	call   0x6fd6b0
  3b2057:	0f 0b                	ud2
  3b2059:	90                   	nop
  3b205a:	90                   	nop
  3b205b:	90                   	nop
  3b205c:	90                   	nop
  3b205d:	90                   	nop
  3b205e:	90                   	nop
  3b205f:	90                   	nop
  3b2060:	55                   	push   rbp
  3b2061:	48 89 e5             	mov    rbp,rsp
  3b2064:	8b 06                	mov    eax,DWORD PTR [rsi]
  3b2066:	48 8b 56 08          	mov    rdx,QWORD PTR [rsi+0x8]
  3b206a:	8b 4e 10             	mov    ecx,DWORD PTR [rsi+0x10]
  3b206d:	44 8b 46 18          	mov    r8d,DWORD PTR [rsi+0x18]
  3b2071:	4c 8b 4e 20          	mov    r9,QWORD PTR [rsi+0x20]
  3b2075:	89 c6                	mov    esi,eax
  3b2077:	5d                   	pop    rbp
  3b2078:	e9 03 00 00 00       	jmp    0x3b2080
  3b207d:	90                   	nop
  3b207e:	90                   	nop
  3b207f:	90                   	nop
  3b2080:	55                   	push   rbp
  3b2081:	48 89 e5             	mov    rbp,rsp
  3b2084:	41 57                	push   r15
  3b2086:	41 56                	push   r14
  3b2088:	41 55                	push   r13
  3b208a:	41 54                	push   r12
  3b208c:	53                   	push   rbx
  3b208d:	48 83 e4 e0          	and    rsp,0xffffffffffffffe0
  3b2091:	48 81 ec a0 00 00 00 	sub    rsp,0xa0
  3b2098:	48 89 e3             	mov    rbx,rsp
  3b209b:	48 8d 05 6e a2 56 03 	lea    rax,[rip+0x356a26e]        # 0x391c310
  3b20a2:	4c 89 4b 68          	mov    QWORD PTR [rbx+0x68],r9
  3b20a6:	4c 89 43 38          	mov    QWORD PTR [rbx+0x38],r8
  3b20aa:	48 89 4b 10          	mov    QWORD PTR [rbx+0x10],rcx
  3b20ae:	49 89 d4             	mov    r12,rdx
  3b20b1:	41 89 f7             	mov    r15d,esi
  3b20b4:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b20b7:	48 89 83 80 00 00 00 	mov    QWORD PTR [rbx+0x80],rax
  3b20be:	48 89 7b 60          	mov    QWORD PTR [rbx+0x60],rdi
  3b20c2:	4c 8b 6f 08          	mov    r13,QWORD PTR [rdi+0x8]
  3b20c6:	49 8b 85 48 0c 00 00 	mov    rax,QWORD PTR [r13+0xc48]
  3b20cd:	4c 89 ef             	mov    rdi,r13
  3b20d0:	48 89 43 30          	mov    QWORD PTR [rbx+0x30],rax
  3b20d4:	e8 a7 60 64 00       	call   0x9f8180
  3b20d9:	48 8d 73 70          	lea    rsi,[rbx+0x70]
  3b20dd:	4c 89 ef             	mov    rdi,r13
  3b20e0:	49 89 c6             	mov    r14,rax
  3b20e3:	e8 d8 60 64 00       	call   0x9f81c0
  3b20e8:	85 c0                	test   eax,eax
  3b20ea:	75 2a                	jne    0x3b2116
  3b20ec:	8b 43 70             	mov    eax,DWORD PTR [rbx+0x70]
  3b20ef:	3d ff ff ff 00       	cmp    eax,0xffffff
  3b20f4:	77 20                	ja     0x3b2116
  3b20f6:	3d ff ff 00 00       	cmp    eax,0xffff
  3b20fb:	0f 86 8d 01 00 00    	jbe    0x3b228e
  3b2101:	25 00 00 ff 00       	and    eax,0xff0000
  3b2106:	3d 00 00 01 00       	cmp    eax,0x10000
  3b210b:	75 09                	jne    0x3b2116
  3b210d:	4c 8d 35 5c dd 11 03 	lea    r14,[rip+0x311dd5c]        # 0x34cfe70
  3b2114:	eb 07                	jmp    0x3b211d
  3b2116:	4c 8d 35 ab d7 11 03 	lea    r14,[rip+0x311d7ab]        # 0x34cf8c8
  3b211d:	44 89 f9             	mov    ecx,r15d
  3b2120:	41 bd 16 00 00 00    	mov    r13d,0x16
  3b2126:	81 e1 ff 0f 00 00    	and    ecx,0xfff
  3b212c:	8d 41 ff             	lea    eax,[rcx-0x1]
  3b212f:	83 f8 01             	cmp    eax,0x1
  3b2132:	0f 87 af 01 00 00    	ja     0x3b22e7
  3b2138:	41 83 be a0 04 00 00 	cmp    DWORD PTR [r14+0x4a0],0x1
  3b213f:	01 
  3b2140:	74 34                	je     0x3b2176
  3b2142:	bf 01 00 00 00       	mov    edi,0x1
  3b2147:	4c 89 f6             	mov    rsi,r14
  3b214a:	49 89 cd             	mov    r13,rcx
  3b214d:	e8 be 12 00 00       	call   0x3b3410
  3b2152:	4c 89 e9             	mov    rcx,r13
  3b2155:	85 c0                	test   eax,eax
  3b2157:	74 1d                	je     0x3b2176
  3b2159:	41 89 c5             	mov    r13d,eax
  3b215c:	48 8d 3d a5 9d f6 00 	lea    rdi,[rip+0xf69da5]        # 0x131bf08
  3b2163:	48 8d 35 02 7c fc 00 	lea    rsi,[rip+0xfc7c02]        # 0x1379d6c
  3b216a:	ba b7 0d 00 00       	mov    edx,0xdb7
  3b216f:	89 c1                	mov    ecx,eax
  3b2171:	e9 6a 01 00 00       	jmp    0x3b22e0
  3b2176:	4c 89 73 50          	mov    QWORD PTR [rbx+0x50],r14
  3b217a:	4c 8b 73 10          	mov    r14,QWORD PTR [rbx+0x10]
  3b217e:	41 8d 86 7f ff ff ff 	lea    eax,[r14-0x81]
  3b2185:	3d 7f ff ff ff       	cmp    eax,0xffffff7f
  3b218a:	77 1e                	ja     0x3b21aa
  3b218c:	48 8d 3d 75 9d f6 00 	lea    rdi,[rip+0xf69d75]        # 0x131bf08
  3b2193:	48 8d 35 d2 7b fc 00 	lea    rsi,[rip+0xfc7bd2]        # 0x1379d6c
  3b219a:	41 bd 16 00 00 00    	mov    r13d,0x16
  3b21a0:	ba bd 0d 00 00       	mov    edx,0xdbd
  3b21a5:	e9 31 01 00 00       	jmp    0x3b22db
  3b21aa:	48 8b 43 38          	mov    rax,QWORD PTR [rbx+0x38]
  3b21ae:	ff c8                	dec    eax
  3b21b0:	83 f8 03             	cmp    eax,0x3
  3b21b3:	0f 83 09 01 00 00    	jae    0x3b22c2
  3b21b9:	48 8b 7b 30          	mov    rdi,QWORD PTR [rbx+0x30]
  3b21bd:	48 8d 73 70          	lea    rsi,[rbx+0x70]
  3b21c1:	48 89 4b 28          	mov    QWORD PTR [rbx+0x28],rcx
  3b21c5:	e8 16 77 fe ff       	call   0x3998e0
  3b21ca:	89 43 7c             	mov    DWORD PTR [rbx+0x7c],eax
  3b21cd:	83 f8 ff             	cmp    eax,0xffffffff
  3b21d0:	0f 84 46 01 00 00    	je     0x3b231c
  3b21d6:	89 43 1c             	mov    DWORD PTR [rbx+0x1c],eax
  3b21d9:	42 8d 04 f5 00 00 00 	lea    eax,[r14*8+0x0]
  3b21e0:	00 
  3b21e1:	48 8d 35 a8 36 70 01 	lea    rsi,[rip+0x17036a8]        # 0x1ab5890
  3b21e8:	ba 02 01 00 00       	mov    edx,0x102
  3b21ed:	44 8d 2c 80          	lea    r13d,[rax+rax*4]
  3b21f1:	4c 89 ef             	mov    rdi,r13
  3b21f4:	e8 57 69 85 00       	call   0xc08b50
  3b21f9:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3b2200:	00 00 
  3b2202:	48 8d 35 34 5d fe 00 	lea    rsi,[rip+0xfe5d34]        # 0x1397f3d
  3b2209:	31 d2                	xor    edx,edx
  3b220b:	49 89 c6             	mov    r14,rax
  3b220e:	e8 cd 81 86 00       	call   0xc1a3e0
  3b2213:	4c 89 e7             	mov    rdi,r12
  3b2216:	4c 89 f6             	mov    rsi,r14
  3b2219:	4c 89 ea             	mov    rdx,r13
  3b221c:	e8 5f 70 ea ff       	call   0x259280
  3b2221:	85 c0                	test   eax,eax
  3b2223:	0f 84 1f 01 00 00    	je     0x3b2348
  3b2229:	4c 8d 3d d8 9c f6 00 	lea    r15,[rip+0xf69cd8]        # 0x131bf08
  3b2230:	48 8d 35 e5 a1 f4 00 	lea    rsi,[rip+0xf4a1e5]        # 0x12fc41c
  3b2237:	ba 13 0b 00 00       	mov    edx,0xb13
  3b223c:	89 c1                	mov    ecx,eax
  3b223e:	41 89 c5             	mov    r13d,eax
  3b2241:	31 c0                	xor    eax,eax
  3b2243:	4c 89 ff             	mov    rdi,r15
  3b2246:	e8 c5 b1 ea ff       	call   0x25d410
  3b224b:	48 8d 35 3e 36 70 01 	lea    rsi,[rip+0x170363e]        # 0x1ab5890
  3b2252:	4c 89 f7             	mov    rdi,r14
  3b2255:	e8 96 6b 85 00       	call   0xc08df0
  3b225a:	48 8d 35 0b 7b fc 00 	lea    rsi,[rip+0xfc7b0b]        # 0x1379d6c
  3b2261:	4c 89 ff             	mov    rdi,r15
  3b2264:	ba d6 0d 00 00       	mov    edx,0xdd6
  3b2269:	44 89 e9             	mov    ecx,r13d
  3b226c:	31 c0                	xor    eax,eax
  3b226e:	e8 9d b1 ea ff       	call   0x25d410
  3b2273:	48 8b 53 70          	mov    rdx,QWORD PTR [rbx+0x70]
  3b2277:	48 8b 7b 30          	mov    rdi,QWORD PTR [rbx+0x30]
  3b227b:	8b 73 1c             	mov    esi,DWORD PTR [rbx+0x1c]
  3b227e:	e8 ad 7b fe ff       	call   0x399e30
  3b2283:	48 8b 7b 70          	mov    rdi,QWORD PTR [rbx+0x70]
  3b2287:	e8 24 7c fe ff       	call   0x399eb0
  3b228c:	eb 59                	jmp    0x3b22e7
  3b228e:	4c 39 35 33 d5 11 03 	cmp    QWORD PTR [rip+0x311d533],r14        # 0x34cf7c8
  3b2295:	74 79                	je     0x3b2310
  3b2297:	4c 39 35 22 e6 11 03 	cmp    QWORD PTR [rip+0x311e622],r14        # 0x34d08c0
  3b229e:	0f 84 98 00 00 00    	je     0x3b233c
  3b22a4:	83 3d 15 d5 11 03 00 	cmp    DWORD PTR [rip+0x311d515],0x0        # 0x34cf7c0
  3b22ab:	48 8d 05 6e d0 11 03 	lea    rax,[rip+0x311d06e]        # 0x34cf320
  3b22b2:	4c 8d 35 5f e1 11 03 	lea    r14,[rip+0x311e15f]        # 0x34d0418
  3b22b9:	4c 0f 44 f0          	cmove  r14,rax
  3b22bd:	e9 5b fe ff ff       	jmp    0x3b211d
  3b22c2:	48 8d 3d 3f 9c f6 00 	lea    rdi,[rip+0xf69c3f]        # 0x131bf08
  3b22c9:	48 8d 35 9c 7a fc 00 	lea    rsi,[rip+0xfc7a9c]        # 0x1379d6c
  3b22d0:	41 bd 16 00 00 00    	mov    r13d,0x16
  3b22d6:	ba c7 0d 00 00       	mov    edx,0xdc7
  3b22db:	b9 16 00 00 00       	mov    ecx,0x16
  3b22e0:	31 c0                	xor    eax,eax
  3b22e2:	e8 29 b1 ea ff       	call   0x25d410
  3b22e7:	48 8d 05 22 a0 56 03 	lea    rax,[rip+0x356a022]        # 0x391c310
  3b22ee:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b22f1:	48 3b 83 80 00 00 00 	cmp    rax,QWORD PTR [rbx+0x80]
  3b22f8:	0f 85 be 05 00 00    	jne    0x3b28bc
  3b22fe:	44 89 e8             	mov    eax,r13d
  3b2301:	48 8d 65 d8          	lea    rsp,[rbp-0x28]
  3b2305:	5b                   	pop    rbx
  3b2306:	41 5c                	pop    r12
  3b2308:	41 5d                	pop    r13
  3b230a:	41 5e                	pop    r14
  3b230c:	41 5f                	pop    r15
  3b230e:	5d                   	pop    rbp
  3b230f:	c3                   	ret
  3b2310:	4c 8d 35 09 d0 11 03 	lea    r14,[rip+0x311d009]        # 0x34cf320
  3b2317:	e9 01 fe ff ff       	jmp    0x3b211d
  3b231c:	48 8d 3d e5 9b f6 00 	lea    rdi,[rip+0xf69be5]        # 0x131bf08
  3b2323:	48 8d 35 42 7a fc 00 	lea    rsi,[rip+0xfc7a42]        # 0x1379d6c
  3b232a:	41 bd 23 00 00 00    	mov    r13d,0x23
  3b2330:	ba cf 0d 00 00       	mov    edx,0xdcf
  3b2335:	b9 23 00 00 00       	mov    ecx,0x23
  3b233a:	eb a4                	jmp    0x3b22e0
  3b233c:	4c 8d 35 d5 e0 11 03 	lea    r14,[rip+0x311e0d5]        # 0x34d0418
  3b2343:	e9 d5 fd ff ff       	jmp    0x3b211d
  3b2348:	44 89 f8             	mov    eax,r15d
  3b234b:	4c 89 73 40          	mov    QWORD PTR [rbx+0x40],r14
  3b234f:	25 00 10 00 00       	and    eax,0x1000
  3b2354:	89 43 0c             	mov    DWORD PTR [rbx+0xc],eax
  3b2357:	75 54                	jne    0x3b23ad
  3b2359:	48 8d 35 10 36 70 01 	lea    rsi,[rip+0x1703610]        # 0x1ab5970
  3b2360:	bf 58 00 00 00       	mov    edi,0x58
  3b2365:	ba 02 01 00 00       	mov    edx,0x102
  3b236a:	e8 e1 67 85 00       	call   0xc08b50
  3b236f:	49 89 c6             	mov    r14,rax
  3b2372:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  3b2376:	48 8d 15 22 e7 f7 00 	lea    rdx,[rip+0xf7e722]        # 0x1330a9f
  3b237d:	41 b8 01 00 00 00    	mov    r8d,0x1
  3b2383:	31 f6                	xor    esi,esi
  3b2385:	31 c9                	xor    ecx,ecx
  3b2387:	49 8d 7e 20          	lea    rdi,[r14+0x20]
  3b238b:	41 89 06             	mov    DWORD PTR [r14],eax
  3b238e:	41 89 46 04          	mov    DWORD PTR [r14+0x4],eax
  3b2392:	41 c7 46 08 01 00 00 	mov    DWORD PTR [r14+0x8],0x1
  3b2399:	00 
  3b239a:	49 c7 46 50 00 00 00 	mov    QWORD PTR [r14+0x50],0x0
  3b23a1:	00 
  3b23a2:	e8 e9 f2 83 00       	call   0xbf1690
  3b23a7:	44 8b 6b 1c          	mov    r13d,DWORD PTR [rbx+0x1c]
  3b23ab:	eb 68                	jmp    0x3b2415
  3b23ad:	4c 8b 63 10          	mov    r12,QWORD PTR [rbx+0x10]
  3b23b1:	48 8d 35 b8 35 70 01 	lea    rsi,[rip+0x17035b8]        # 0x1ab5970
  3b23b8:	ba 02 01 00 00       	mov    edx,0x102
  3b23bd:	41 6b fc 58          	imul   edi,r12d,0x58
  3b23c1:	e8 8a 67 85 00       	call   0xc08b50
  3b23c6:	49 89 c6             	mov    r14,rax
  3b23c9:	49 89 c5             	mov    r13,rax
  3b23cc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  3b23d0:	48 b8 01 00 00 00 01 	movabs rax,0x100000001
  3b23d7:	00 00 00 
  3b23da:	49 8d 7d 20          	lea    rdi,[r13+0x20]
  3b23de:	48 8d 15 ba e6 f7 00 	lea    rdx,[rip+0xf7e6ba]        # 0x1330a9f
  3b23e5:	41 b8 01 00 00 00    	mov    r8d,0x1
  3b23eb:	31 f6                	xor    esi,esi
  3b23ed:	31 c9                	xor    ecx,ecx
  3b23ef:	49 89 45 00          	mov    QWORD PTR [r13+0x0],rax
  3b23f3:	41 c7 45 08 01 00 00 	mov    DWORD PTR [r13+0x8],0x1
  3b23fa:	00 
  3b23fb:	49 c7 45 50 00 00 00 	mov    QWORD PTR [r13+0x50],0x0
  3b2402:	00 
  3b2403:	e8 88 f2 83 00       	call   0xbf1690
  3b2408:	49 83 c5 58          	add    r13,0x58
  3b240c:	41 ff cc             	dec    r12d
  3b240f:	75 bf                	jne    0x3b23d0
  3b2411:	44 8b 6b 7c          	mov    r13d,DWORD PTR [rbx+0x7c]
  3b2415:	48 8d 35 34 36 70 01 	lea    rsi,[rip+0x1703634]        # 0x1ab5a50
  3b241c:	bf 30 00 00 00       	mov    edi,0x30
  3b2421:	ba 02 01 00 00       	mov    edx,0x102
  3b2426:	e8 25 67 85 00       	call   0xc08b50
  3b242b:	49 89 c4             	mov    r12,rax
  3b242e:	8b 43 10             	mov    eax,DWORD PTR [rbx+0x10]
  3b2431:	48 8d 35 18 36 70 01 	lea    rsi,[rip+0x1703618]        # 0x1ab5a50
  3b2438:	ba 02 01 00 00       	mov    edx,0x102
  3b243d:	48 8d 3c c5 00 00 00 	lea    rdi,[rax*8+0x0]
  3b2444:	00 
  3b2445:	48 89 43 20          	mov    QWORD PTR [rbx+0x20],rax
  3b2449:	e8 02 67 85 00       	call   0xc08b50
  3b244e:	83 7b 0c 00          	cmp    DWORD PTR [rbx+0xc],0x0
  3b2452:	49 89 44 24 28       	mov    QWORD PTR [r12+0x28],rax
  3b2457:	4d 89 74 24 10       	mov    QWORD PTR [r12+0x10],r14
  3b245c:	4c 89 63 48          	mov    QWORD PTR [rbx+0x48],r12
  3b2460:	45 89 6c 24 08       	mov    DWORD PTR [r12+0x8],r13d
  3b2465:	4c 8b 63 40          	mov    r12,QWORD PTR [rbx+0x40]
  3b2469:	44 89 6b 1c          	mov    DWORD PTR [rbx+0x1c],r13d
  3b246d:	75 0a                	jne    0x3b2479
  3b246f:	49 89 46 18          	mov    QWORD PTR [r14+0x18],rax
  3b2473:	66 b8 01 00          	mov    ax,0x1
  3b2477:	eb 04                	jmp    0x3b247d
  3b2479:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  3b247d:	48 8b 4b 48          	mov    rcx,QWORD PTR [rbx+0x48]
  3b2481:	4c 8b 6b 38          	mov    r13,QWORD PTR [rbx+0x38]
  3b2485:	66 89 41 02          	mov    WORD PTR [rcx+0x2],ax
  3b2489:	66 89 01             	mov    WORD PTR [rcx],ax
  3b248c:	48 8b 43 50          	mov    rax,QWORD PTR [rbx+0x50]
  3b2490:	44 89 69 04          	mov    DWORD PTR [rcx+0x4],r13d
  3b2494:	4c 89 61 20          	mov    QWORD PTR [rcx+0x20],r12
  3b2498:	48 89 41 18          	mov    QWORD PTR [rcx+0x18],rax
  3b249c:	e8 2f 54 75 00       	call   0xb078d0
  3b24a1:	85 c0                	test   eax,eax
  3b24a3:	74 16                	je     0x3b24bb
  3b24a5:	48 8b 4b 60          	mov    rcx,QWORD PTR [rbx+0x60]
  3b24a9:	44 89 fe             	mov    esi,r15d
  3b24ac:	4c 89 e2             	mov    rdx,r12
  3b24af:	45 89 e8             	mov    r8d,r13d
  3b24b2:	48 8b 7b 10          	mov    rdi,QWORD PTR [rbx+0x10]
  3b24b6:	e8 15 12 cf ff       	call   0xa36d0
  3b24bb:	48 8d 35 1e 35 70 01 	lea    rsi,[rip+0x170351e]        # 0x1ab59e0
  3b24c2:	bf 30 00 00 00       	mov    edi,0x30
  3b24c7:	ba 02 01 00 00       	mov    edx,0x102
  3b24cc:	e8 7f 66 85 00       	call   0xc08b50
  3b24d1:	49 89 c7             	mov    r15,rax
  3b24d4:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  3b24db:	00 00 
  3b24dd:	48 8b 88 90 03 00 00 	mov    rcx,QWORD PTR [rax+0x390]
  3b24e4:	49 89 0f             	mov    QWORD PTR [r15],rcx
  3b24e7:	48 8b 48 08          	mov    rcx,QWORD PTR [rax+0x8]
  3b24eb:	49 89 4f 08          	mov    QWORD PTR [r15+0x8],rcx
  3b24ef:	48 8b b8 40 01 00 00 	mov    rdi,QWORD PTR [rax+0x140]
  3b24f6:	e8 a5 8e ef ff       	call   0x2ab3a0
  3b24fb:	4c 8b 6b 48          	mov    r13,QWORD PTR [rbx+0x48]
  3b24ff:	49 89 47 10          	mov    QWORD PTR [r15+0x10],rax
  3b2503:	4d 89 6f 28          	mov    QWORD PTR [r15+0x28],r13
  3b2507:	e8 44 ea 23 00       	call   0x5f0f50
  3b250c:	83 7b 0c 00          	cmp    DWORD PTR [rbx+0xc],0x0
  3b2510:	4c 89 7b 58          	mov    QWORD PTR [rbx+0x58],r15
  3b2514:	41 89 47 20          	mov    DWORD PTR [r15+0x20],eax
  3b2518:	75 59                	jne    0x3b2573
  3b251a:	45 31 ff             	xor    r15d,r15d
  3b251d:	4d 89 6e 10          	mov    QWORD PTR [r14+0x10],r13
  3b2521:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b2528:	0f 1f 84 00 00 00 00 
  3b252f:	00 
  3b2530:	bf 58 00 00 00       	mov    edi,0x58
  3b2535:	48 8d 35 c4 33 70 01 	lea    rsi,[rip+0x17033c4]        # 0x1ab5900
  3b253c:	ba 02 01 00 00       	mov    edx,0x102
  3b2541:	e8 0a 66 85 00       	call   0xc08b50
  3b2546:	48 8b 4b 28          	mov    rcx,QWORD PTR [rbx+0x28]
  3b254a:	48 8b 73 58          	mov    rsi,QWORD PTR [rbx+0x58]
  3b254e:	49 8b 55 28          	mov    rdx,QWORD PTR [r13+0x28]
  3b2552:	89 08                	mov    DWORD PTR [rax],ecx
  3b2554:	4c 89 60 10          	mov    QWORD PTR [rax+0x10],r12
  3b2558:	48 89 70 18          	mov    QWORD PTR [rax+0x18],rsi
  3b255c:	4c 89 70 20          	mov    QWORD PTR [rax+0x20],r14
  3b2560:	4a 89 04 fa          	mov    QWORD PTR [rdx+r15*8],rax
  3b2564:	49 ff c7             	inc    r15
  3b2567:	49 83 c4 28          	add    r12,0x28
  3b256b:	4c 39 7b 20          	cmp    QWORD PTR [rbx+0x20],r15
  3b256f:	75 bf                	jne    0x3b2530
  3b2571:	eb 56                	jmp    0x3b25c9
  3b2573:	4d 89 e7             	mov    r15,r12
  3b2576:	45 31 e4             	xor    r12d,r12d
  3b2579:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  3b2580:	bf 58 00 00 00       	mov    edi,0x58
  3b2585:	48 8d 35 74 33 70 01 	lea    rsi,[rip+0x1703374]        # 0x1ab5900
  3b258c:	ba 02 01 00 00       	mov    edx,0x102
  3b2591:	e8 ba 65 85 00       	call   0xc08b50
  3b2596:	48 8b 4b 28          	mov    rcx,QWORD PTR [rbx+0x28]
  3b259a:	48 8b 73 58          	mov    rsi,QWORD PTR [rbx+0x58]
  3b259e:	49 8b 55 28          	mov    rdx,QWORD PTR [r13+0x28]
  3b25a2:	4d 89 6e 10          	mov    QWORD PTR [r14+0x10],r13
  3b25a6:	89 08                	mov    DWORD PTR [rax],ecx
  3b25a8:	4c 89 78 10          	mov    QWORD PTR [rax+0x10],r15
  3b25ac:	48 89 70 18          	mov    QWORD PTR [rax+0x18],rsi
  3b25b0:	4c 89 70 20          	mov    QWORD PTR [rax+0x20],r14
  3b25b4:	4a 89 04 e2          	mov    QWORD PTR [rdx+r12*8],rax
  3b25b8:	49 ff c4             	inc    r12
  3b25bb:	49 83 c6 58          	add    r14,0x58
  3b25bf:	49 83 c7 28          	add    r15,0x28
  3b25c3:	4c 39 63 20          	cmp    QWORD PTR [rbx+0x20],r12
  3b25c7:	75 b7                	jne    0x3b2580
  3b25c9:	48 8b 7b 70          	mov    rdi,QWORD PTR [rbx+0x70]
  3b25cd:	4c 8b 73 20          	mov    r14,QWORD PTR [rbx+0x20]
  3b25d1:	be 60 01 00 00       	mov    esi,0x160
  3b25d6:	4c 89 ea             	mov    rdx,r13
  3b25d9:	31 c9                	xor    ecx,ecx
  3b25db:	45 31 ff             	xor    r15d,r15d
  3b25de:	e8 fd 77 fe ff       	call   0x399de0
  3b25e3:	48 8b 7b 70          	mov    rdi,QWORD PTR [rbx+0x70]
  3b25e7:	e8 c4 78 fe ff       	call   0x399eb0
  3b25ec:	83 7b 0c 00          	cmp    DWORD PTR [rbx+0xc],0x0
  3b25f0:	4d 89 ec             	mov    r12,r13
  3b25f3:	75 0f                	jne    0x3b2604
  3b25f5:	4c 8b 73 68          	mov    r14,QWORD PTR [rbx+0x68]
  3b25f9:	48 8d 7b 7c          	lea    rdi,[rbx+0x7c]
  3b25fd:	ba 04 00 00 00       	mov    edx,0x4
  3b2602:	eb 53                	jmp    0x3b2657
  3b2604:	4a 8d 04 b5 0f 00 00 	lea    rax,[r14*4+0xf]
  3b260b:	00 
  3b260c:	48 89 e7             	mov    rdi,rsp
  3b260f:	4a 8d 14 b5 00 00 00 	lea    rdx,[r14*4+0x0]
  3b2616:	00 
  3b2617:	4d 89 f0             	mov    r8,r14
  3b261a:	48 83 e0 f0          	and    rax,0xfffffffffffffff0
  3b261e:	48 29 c7             	sub    rdi,rax
  3b2621:	48 83 e7 e0          	and    rdi,0xffffffffffffffe0
  3b2625:	48 89 fc             	mov    rsp,rdi
  3b2628:	4c 8b 73 68          	mov    r14,QWORD PTR [rbx+0x68]
  3b262c:	8b 73 1c             	mov    esi,DWORD PTR [rbx+0x1c]
  3b262f:	31 c0                	xor    eax,eax
  3b2631:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b2638:	0f 1f 84 00 00 00 00 
  3b263f:	00 
  3b2640:	44 89 f9             	mov    ecx,r15d
  3b2643:	41 81 c7 00 00 01 00 	add    r15d,0x10000
  3b264a:	09 f1                	or     ecx,esi
  3b264c:	89 0c 87             	mov    DWORD PTR [rdi+rax*4],ecx
  3b264f:	48 ff c0             	inc    rax
  3b2652:	49 39 c0             	cmp    r8,rax
  3b2655:	75 e9                	jne    0x3b2640
  3b2657:	4c 89 f6             	mov    rsi,r14
  3b265a:	e8 e1 13 00 00       	call   0x3b3a40
  3b265f:	41 89 c5             	mov    r13d,eax
  3b2662:	85 c0                	test   eax,eax
  3b2664:	74 15                	je     0x3b267b
  3b2666:	48 8d 3d 9b 98 f6 00 	lea    rdi,[rip+0xf6989b]        # 0x131bf08
  3b266d:	48 8d 35 f8 76 fc 00 	lea    rsi,[rip+0xfc76f8]        # 0x1379d6c
  3b2674:	ba 1a 0e 00 00       	mov    edx,0xe1a
  3b2679:	eb 39                	jmp    0x3b26b4
  3b267b:	4c 8b 7b 50          	mov    r15,QWORD PTR [rbx+0x50]
  3b267f:	4c 89 e1             	mov    rcx,r12
  3b2682:	48 8b 7b 10          	mov    rdi,QWORD PTR [rbx+0x10]
  3b2686:	48 8b 73 38          	mov    rsi,QWORD PTR [rbx+0x38]
  3b268a:	48 8b 53 28          	mov    rdx,QWORD PTR [rbx+0x28]
  3b268e:	4d 89 f8             	mov    r8,r15
  3b2691:	e8 fa 13 00 00       	call   0x3b3a90
  3b2696:	85 c0                	test   eax,eax
  3b2698:	0f 84 ab 01 00 00    	je     0x3b2849
  3b269e:	41 89 c5             	mov    r13d,eax
  3b26a1:	48 8d 3d 60 98 f6 00 	lea    rdi,[rip+0xf69860]        # 0x131bf08
  3b26a8:	48 8d 35 bd 76 fc 00 	lea    rsi,[rip+0xfc76bd]        # 0x1379d6c
  3b26af:	ba 21 0e 00 00       	mov    edx,0xe21
  3b26b4:	44 89 e9             	mov    ecx,r13d
  3b26b7:	31 c0                	xor    eax,eax
  3b26b9:	e8 52 ad ea ff       	call   0x25d410
  3b26be:	4c 8b 7b 30          	mov    r15,QWORD PTR [rbx+0x30]
  3b26c2:	8b 73 7c             	mov    esi,DWORD PTR [rbx+0x7c]
  3b26c5:	48 8d 4b 70          	lea    rcx,[rbx+0x70]
  3b26c9:	ba 60 01 00 00       	mov    edx,0x160
  3b26ce:	4c 89 ff             	mov    rdi,r15
  3b26d1:	e8 ca 7b fe ff       	call   0x39a2a0
  3b26d6:	8b 73 7c             	mov    esi,DWORD PTR [rbx+0x7c]
  3b26d9:	48 8b 53 70          	mov    rdx,QWORD PTR [rbx+0x70]
  3b26dd:	4c 89 ff             	mov    rdi,r15
  3b26e0:	49 89 c6             	mov    r14,rax
  3b26e3:	e8 48 77 fe ff       	call   0x399e30
  3b26e8:	48 8b 7b 70          	mov    rdi,QWORD PTR [rbx+0x70]
  3b26ec:	e8 bf 77 fe ff       	call   0x399eb0
  3b26f1:	83 7b 0c 00          	cmp    DWORD PTR [rbx+0xc],0x0
  3b26f5:	0f 85 1e 01 00 00    	jne    0x3b2819
  3b26fb:	49 8b 46 28          	mov    rax,QWORD PTR [r14+0x28]
  3b26ff:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b2702:	48 8b 78 20          	mov    rdi,QWORD PTR [rax+0x20]
  3b2706:	48 83 c7 20          	add    rdi,0x20
  3b270a:	e8 51 f0 83 00       	call   0xbf1760
  3b270f:	49 8b 46 28          	mov    rax,QWORD PTR [r14+0x28]
  3b2713:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b2716:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
  3b271a:	48 8b 78 10          	mov    rdi,QWORD PTR [rax+0x10]
  3b271e:	e8 4d 6f ef ff       	call   0x2a9670
  3b2723:	49 8b 46 28          	mov    rax,QWORD PTR [r14+0x28]
  3b2727:	48 8d 35 b2 32 70 01 	lea    rsi,[rip+0x17032b2]        # 0x1ab59e0
  3b272e:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b2731:	48 8b 78 18          	mov    rdi,QWORD PTR [rax+0x18]
  3b2735:	e8 b6 66 85 00       	call   0xc08df0
  3b273a:	83 7b 10 00          	cmp    DWORD PTR [rbx+0x10],0x0
  3b273e:	0f 8e 92 00 00 00    	jle    0x3b27d6
  3b2744:	45 31 ff             	xor    r15d,r15d
  3b2747:	eb 2d                	jmp    0x3b2776
  3b2749:	49 c7 44 24 40 00 00 	mov    QWORD PTR [r12+0x40],0x0
  3b2750:	00 00 
  3b2752:	4c 89 e7             	mov    rdi,r12
  3b2755:	48 8d 35 a4 31 70 01 	lea    rsi,[rip+0x17031a4]        # 0x1ab5900
  3b275c:	e8 8f 66 85 00       	call   0xc08df0
  3b2761:	49 8b 46 28          	mov    rax,QWORD PTR [r14+0x28]
  3b2765:	4a c7 04 f8 00 00 00 	mov    QWORD PTR [rax+r15*8],0x0
  3b276c:	00 
  3b276d:	49 ff c7             	inc    r15
  3b2770:	4c 39 7b 20          	cmp    QWORD PTR [rbx+0x20],r15
  3b2774:	74 60                	je     0x3b27d6
  3b2776:	49 8b 46 28          	mov    rax,QWORD PTR [r14+0x28]
  3b277a:	4e 8b 24 f8          	mov    r12,QWORD PTR [rax+r15*8]
  3b277e:	4d 85 e4             	test   r12,r12
  3b2781:	74 ea                	je     0x3b276d
  3b2783:	49 83 7c 24 28 00    	cmp    QWORD PTR [r12+0x28],0x0
  3b2789:	74 1a                	je     0x3b27a5
  3b278b:	48 8d 3d 65 42 f5 00 	lea    rdi,[rip+0xf54265]        # 0x13069f7
  3b2792:	48 8d 35 e5 d3 fb 00 	lea    rsi,[rip+0xfbd3e5]        # 0x136fb7e
  3b2799:	ba 35 0b 00 00       	mov    edx,0xb35
  3b279e:	31 c0                	xor    eax,eax
  3b27a0:	e8 6b ac ea ff       	call   0x25d410
  3b27a5:	49 8b 44 24 40       	mov    rax,QWORD PTR [r12+0x40]
  3b27aa:	48 85 c0             	test   rax,rax
  3b27ad:	74 a3                	je     0x3b2752
  3b27af:	b9 ff ff ff ff       	mov    ecx,0xffffffff
  3b27b4:	f0 0f c1 48 28       	lock xadd DWORD PTR [rax+0x28],ecx
  3b27b9:	83 f9 01             	cmp    ecx,0x1
  3b27bc:	75 8b                	jne    0x3b2749
  3b27be:	49 8b 7c 24 40       	mov    rdi,QWORD PTR [r12+0x40]
  3b27c3:	65 48 8b 34 25 00 00 	mov    rsi,QWORD PTR gs:0x0
  3b27ca:	00 00 
  3b27cc:	e8 af 8b 37 00       	call   0x72b380
  3b27d1:	e9 73 ff ff ff       	jmp    0x3b2749
  3b27d6:	49 8b 7e 10          	mov    rdi,QWORD PTR [r14+0x10]
  3b27da:	48 8d 35 8f 31 70 01 	lea    rsi,[rip+0x170318f]        # 0x1ab5970
  3b27e1:	e8 0a 66 85 00       	call   0xc08df0
  3b27e6:	49 8b 7e 28          	mov    rdi,QWORD PTR [r14+0x28]
  3b27ea:	4c 8d 3d 5f 32 70 01 	lea    r15,[rip+0x170325f]        # 0x1ab5a50
  3b27f1:	4c 89 fe             	mov    rsi,r15
  3b27f4:	e8 f7 65 85 00       	call   0xc08df0
  3b27f9:	4c 89 f7             	mov    rdi,r14
  3b27fc:	4c 89 fe             	mov    rsi,r15
  3b27ff:	e8 ec 65 85 00       	call   0xc08df0
  3b2804:	48 8b 7b 40          	mov    rdi,QWORD PTR [rbx+0x40]
  3b2808:	48 8d 35 81 30 70 01 	lea    rsi,[rip+0x1703081]        # 0x1ab5890
  3b280f:	e8 dc 65 85 00       	call   0xc08df0
  3b2814:	e9 ce fa ff ff       	jmp    0x3b22e7
  3b2819:	45 31 ff             	xor    r15d,r15d
  3b281c:	eb 0f                	jmp    0x3b282d
  3b281e:	66 90                	xchg   ax,ax
  3b2820:	49 ff c7             	inc    r15
  3b2823:	4c 39 7b 20          	cmp    QWORD PTR [rbx+0x20],r15
  3b2827:	0f 84 e2 fe ff ff    	je     0x3b270f
  3b282d:	49 8b 46 28          	mov    rax,QWORD PTR [r14+0x28]
  3b2831:	4a 8b 04 f8          	mov    rax,QWORD PTR [rax+r15*8]
  3b2835:	48 85 c0             	test   rax,rax
  3b2838:	74 e6                	je     0x3b2820
  3b283a:	48 8b 78 20          	mov    rdi,QWORD PTR [rax+0x20]
  3b283e:	48 83 c7 20          	add    rdi,0x20
  3b2842:	e8 19 ef 83 00       	call   0xbf1760
  3b2847:	eb d7                	jmp    0x3b2820
  3b2849:	48 8d 3d 98 ca 11 03 	lea    rdi,[rip+0x311ca98]        # 0x34cf2e8
  3b2850:	31 f6                	xor    esi,esi
  3b2852:	31 d2                	xor    edx,edx
  3b2854:	31 c9                	xor    ecx,ecx
  3b2856:	e8 a5 41 11 00       	call   0x4c6a00
  3b285b:	49 8b b7 b0 04 00 00 	mov    rsi,QWORD PTR [r15+0x4b0]
  3b2862:	48 85 f6             	test   rsi,rsi
  3b2865:	75 0c                	jne    0x3b2873
  3b2867:	49 8b b7 28 05 00 00 	mov    rsi,QWORD PTR [r15+0x528]
  3b286e:	48 85 f6             	test   rsi,rsi
  3b2871:	74 0c                	je     0x3b287f
  3b2873:	48 8d 3d 76 ca 11 03 	lea    rdi,[rip+0x311ca76]        # 0x34cf2f0
  3b287a:	e8 01 c7 38 00       	call   0x73ef80
  3b287f:	48 8d 3d 62 ca 11 03 	lea    rdi,[rip+0x311ca62]        # 0x34cf2e8
  3b2886:	45 31 ed             	xor    r13d,r13d
  3b2889:	31 f6                	xor    esi,esi
  3b288b:	31 d2                	xor    edx,edx
  3b288d:	31 c9                	xor    ecx,ecx
  3b288f:	e8 0c 47 11 00       	call   0x4c6fa0
  3b2894:	e8 37 50 75 00       	call   0xb078d0
  3b2899:	85 c0                	test   eax,eax
  3b289b:	0f 84 46 fa ff ff    	je     0x3b22e7
  3b28a1:	8b 73 0c             	mov    esi,DWORD PTR [rbx+0xc]
  3b28a4:	48 8b 53 60          	mov    rdx,QWORD PTR [rbx+0x60]
  3b28a8:	4c 89 f1             	mov    rcx,r14
  3b28ab:	48 8b 7b 10          	mov    rdi,QWORD PTR [rbx+0x10]
  3b28af:	c1 ee 0c             	shr    esi,0xc
  3b28b2:	e8 99 0f cf ff       	call   0xa3850
  3b28b7:	e9 2b fa ff ff       	jmp    0x3b22e7
  3b28bc:	e8 ef ad 34 00       	call   0x6fd6b0
  3b28c1:	0f 0b                	ud2
  3b28c3:	90                   	nop
  3b28c4:	90                   	nop
  3b28c5:	90                   	nop
  3b28c6:	90                   	nop
  3b28c7:	90                   	nop
  3b28c8:	90                   	nop
  3b28c9:	90                   	nop
  3b28ca:	90                   	nop
  3b28cb:	90                   	nop
  3b28cc:	90                   	nop
  3b28cd:	90                   	nop
  3b28ce:	90                   	nop
  3b28cf:	90                   	nop
  3b28d0:	55                   	push   rbp
  3b28d1:	48 89 e5             	mov    rbp,rsp
  3b28d4:	41 57                	push   r15
  3b28d6:	41 56                	push   r14
  3b28d8:	41 55                	push   r13
  3b28da:	41 54                	push   r12
  3b28dc:	53                   	push   rbx
  3b28dd:	48 83 ec 58          	sub    rsp,0x58
  3b28e1:	48 8d 05 28 9a 56 03 	lea    rax,[rip+0x3569a28]        # 0x391c310
  3b28e8:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b28eb:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  3b28ef:	48 89 7d 88          	mov    QWORD PTR [rbp-0x78],rdi
  3b28f3:	4c 8b 7f 08          	mov    r15,QWORD PTR [rdi+0x8]
  3b28f7:	8b 46 08             	mov    eax,DWORD PTR [rsi+0x8]
  3b28fa:	4c 8b 26             	mov    r12,QWORD PTR [rsi]
  3b28fd:	4c 8b 6e 10          	mov    r13,QWORD PTR [rsi+0x10]
  3b2901:	44 8b 76 18          	mov    r14d,DWORD PTR [rsi+0x18]
  3b2905:	4c 89 ff             	mov    rdi,r15
  3b2908:	89 45 90             	mov    DWORD PTR [rbp-0x70],eax
  3b290b:	e8 70 58 64 00       	call   0x9f8180
  3b2910:	48 8d 75 94          	lea    rsi,[rbp-0x6c]
  3b2914:	4c 89 ff             	mov    rdi,r15
  3b2917:	48 89 c3             	mov    rbx,rax
  3b291a:	e8 a1 58 64 00       	call   0x9f81c0
  3b291f:	48 8d 0d a2 cf 11 03 	lea    rcx,[rip+0x311cfa2]        # 0x34cf8c8
  3b2926:	85 c0                	test   eax,eax
  3b2928:	75 36                	jne    0x3b2960
  3b292a:	8b 45 94             	mov    eax,DWORD PTR [rbp-0x6c]
  3b292d:	3d ff ff ff 00       	cmp    eax,0xffffff
  3b2932:	77 2c                	ja     0x3b2960
  3b2934:	3d ff ff 00 00       	cmp    eax,0xffff
  3b2939:	0f 86 0d 01 00 00    	jbe    0x3b2a4c
  3b293f:	25 00 00 ff 00       	and    eax,0xff0000
  3b2944:	48 8d 15 25 d5 11 03 	lea    rdx,[rip+0x311d525]        # 0x34cfe70
  3b294b:	48 8d 0d 76 cf 11 03 	lea    rcx,[rip+0x311cf76]        # 0x34cf8c8
  3b2952:	41 b7 01             	mov    r15b,0x1
  3b2955:	3d 00 00 01 00       	cmp    eax,0x10000
  3b295a:	48 0f 44 ca          	cmove  rcx,rdx
  3b295e:	eb 03                	jmp    0x3b2963
  3b2960:	45 31 ff             	xor    r15d,r15d
  3b2963:	4d 85 ed             	test   r13,r13
  3b2966:	74 1a                	je     0x3b2982
  3b2968:	48 8d 3d 99 95 f6 00 	lea    rdi,[rip+0xf69599]        # 0x131bf08
  3b296f:	48 8d 35 3a 74 fc 00 	lea    rsi,[rip+0xfc743a]        # 0x1379db0
  3b2976:	bb 16 00 00 00       	mov    ebx,0x16
  3b297b:	ba 1f 13 00 00       	mov    edx,0x131f
  3b2980:	eb 1d                	jmp    0x3b299f
  3b2982:	45 85 f6             	test   r14d,r14d
  3b2985:	74 49                	je     0x3b29d0
  3b2987:	48 8d 3d 7a 95 f6 00 	lea    rdi,[rip+0xf6957a]        # 0x131bf08
  3b298e:	48 8d 35 1b 74 fc 00 	lea    rsi,[rip+0xfc741b]        # 0x1379db0
  3b2995:	bb 16 00 00 00       	mov    ebx,0x16
  3b299a:	ba 24 13 00 00       	mov    edx,0x1324
  3b299f:	b9 16 00 00 00       	mov    ecx,0x16
  3b29a4:	31 c0                	xor    eax,eax
  3b29a6:	e8 65 aa ea ff       	call   0x25d410
  3b29ab:	48 8d 05 5e 99 56 03 	lea    rax,[rip+0x356995e]        # 0x391c310
  3b29b2:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b29b5:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  3b29b9:	0f 85 89 03 00 00    	jne    0x3b2d48
  3b29bf:	89 d8                	mov    eax,ebx
  3b29c1:	48 83 c4 58          	add    rsp,0x58
  3b29c5:	5b                   	pop    rbx
  3b29c6:	41 5c                	pop    r12
  3b29c8:	41 5d                	pop    r13
  3b29ca:	41 5e                	pop    r14
  3b29cc:	41 5f                	pop    r15
  3b29ce:	5d                   	pop    rbp
  3b29cf:	c3                   	ret
  3b29d0:	48 8d 3d 29 c9 11 03 	lea    rdi,[rip+0x311c929]        # 0x34cf300
  3b29d7:	49 89 ce             	mov    r14,rcx
  3b29da:	31 db                	xor    ebx,ebx
  3b29dc:	31 f6                	xor    esi,esi
  3b29de:	31 d2                	xor    edx,edx
  3b29e0:	31 c9                	xor    ecx,ecx
  3b29e2:	e8 39 91 89 00       	call   0xc4bb20
  3b29e7:	4d 85 e4             	test   r12,r12
  3b29ea:	41 bd 01 00 00 00    	mov    r13d,0x1
  3b29f0:	0f 94 c0             	sete   al
  3b29f3:	41 80 f7 01          	xor    r15b,0x1
  3b29f7:	41 08 c7             	or     r15b,al
  3b29fa:	75 0e                	jne    0x3b2a0a
  3b29fc:	41 83 be a0 04 00 00 	cmp    DWORD PTR [r14+0x4a0],0x0
  3b2a03:	00 
  3b2a04:	0f 84 81 00 00 00    	je     0x3b2a8b
  3b2a0a:	48 8d 3d ef c8 11 03 	lea    rdi,[rip+0x311c8ef]        # 0x34cf300
  3b2a11:	31 f6                	xor    esi,esi
  3b2a13:	31 d2                	xor    edx,edx
  3b2a15:	e8 96 9a 89 00       	call   0xc4c4b0
  3b2a1a:	44 89 ef             	mov    edi,r13d
  3b2a1d:	4c 89 f6             	mov    rsi,r14
  3b2a20:	e8 eb 09 00 00       	call   0x3b3410
  3b2a25:	85 c0                	test   eax,eax
  3b2a27:	74 82                	je     0x3b29ab
  3b2a29:	48 8d 3d d8 94 f6 00 	lea    rdi,[rip+0xf694d8]        # 0x131bf08
  3b2a30:	48 8d 35 79 73 fc 00 	lea    rsi,[rip+0xfc7379]        # 0x1379db0
  3b2a37:	ba 83 13 00 00       	mov    edx,0x1383
  3b2a3c:	89 c1                	mov    ecx,eax
  3b2a3e:	89 c3                	mov    ebx,eax
  3b2a40:	31 c0                	xor    eax,eax
  3b2a42:	e8 c9 a9 ea ff       	call   0x25d410
  3b2a47:	e9 5f ff ff ff       	jmp    0x3b29ab
  3b2a4c:	41 b7 01             	mov    r15b,0x1
  3b2a4f:	48 39 1d 72 cd 11 03 	cmp    QWORD PTR [rip+0x311cd72],rbx        # 0x34cf7c8
  3b2a56:	74 27                	je     0x3b2a7f
  3b2a58:	48 39 1d 61 de 11 03 	cmp    QWORD PTR [rip+0x311de61],rbx        # 0x34d08c0
  3b2a5f:	74 73                	je     0x3b2ad4
  3b2a61:	83 3d 58 cd 11 03 00 	cmp    DWORD PTR [rip+0x311cd58],0x0        # 0x34cf7c0
  3b2a68:	48 8d 05 b1 c8 11 03 	lea    rax,[rip+0x311c8b1]        # 0x34cf320
  3b2a6f:	48 8d 0d a2 d9 11 03 	lea    rcx,[rip+0x311d9a2]        # 0x34d0418
  3b2a76:	48 0f 44 c8          	cmove  rcx,rax
  3b2a7a:	e9 e4 fe ff ff       	jmp    0x3b2963
  3b2a7f:	48 8d 0d 9a c8 11 03 	lea    rcx,[rip+0x311c89a]        # 0x34cf320
  3b2a86:	e9 d8 fe ff ff       	jmp    0x3b2963
  3b2a8b:	83 7d 90 3c          	cmp    DWORD PTR [rbp-0x70],0x3c
  3b2a8f:	75 4f                	jne    0x3b2ae0
  3b2a91:	48 8d 75 94          	lea    rsi,[rbp-0x6c]
  3b2a95:	4c 89 e7             	mov    rdi,r12
  3b2a98:	e8 73 14 00 00       	call   0x3b3f10
  3b2a9d:	85 c0                	test   eax,eax
  3b2a9f:	74 78                	je     0x3b2b19
  3b2aa1:	48 8d 3d 60 94 f6 00 	lea    rdi,[rip+0xf69460]        # 0x131bf08
  3b2aa8:	48 8d 35 01 73 fc 00 	lea    rsi,[rip+0xfc7301]        # 0x1379db0
  3b2aaf:	ba 3a 13 00 00       	mov    edx,0x133a
  3b2ab4:	89 c1                	mov    ecx,eax
  3b2ab6:	89 c3                	mov    ebx,eax
  3b2ab8:	31 c0                	xor    eax,eax
  3b2aba:	e8 51 a9 ea ff       	call   0x25d410
  3b2abf:	48 8d 3d 3a c8 11 03 	lea    rdi,[rip+0x311c83a]        # 0x34cf300
  3b2ac6:	31 f6                	xor    esi,esi
  3b2ac8:	31 d2                	xor    edx,edx
  3b2aca:	e8 e1 99 89 00       	call   0xc4c4b0
  3b2acf:	e9 73 ff ff ff       	jmp    0x3b2a47
  3b2ad4:	48 8d 0d 3d d9 11 03 	lea    rcx,[rip+0x311d93d]        # 0x34d0418
  3b2adb:	e9 83 fe ff ff       	jmp    0x3b2963
  3b2ae0:	48 8d 3d 21 94 f6 00 	lea    rdi,[rip+0xf69421]        # 0x131bf08
  3b2ae7:	48 8d 35 c2 72 fc 00 	lea    rsi,[rip+0xfc72c2]        # 0x1379db0
  3b2aee:	bb 16 00 00 00       	mov    ebx,0x16
  3b2af3:	ba 31 13 00 00       	mov    edx,0x1331
  3b2af8:	b9 16 00 00 00       	mov    ecx,0x16
  3b2afd:	31 c0                	xor    eax,eax
  3b2aff:	e8 0c a9 ea ff       	call   0x25d410
  3b2b04:	48 8d 3d f5 c7 11 03 	lea    rdi,[rip+0x311c7f5]        # 0x34cf300
  3b2b0b:	31 f6                	xor    esi,esi
  3b2b0d:	31 d2                	xor    edx,edx
  3b2b0f:	e8 9c 99 89 00       	call   0xc4c4b0
  3b2b14:	e9 92 fe ff ff       	jmp    0x3b29ab
  3b2b19:	8b 45 94             	mov    eax,DWORD PTR [rbp-0x6c]
  3b2b1c:	3d 80 00 00 00       	cmp    eax,0x80
  3b2b21:	76 1a                	jbe    0x3b2b3d
  3b2b23:	48 8d 3d de 93 f6 00 	lea    rdi,[rip+0xf693de]        # 0x131bf08
  3b2b2a:	48 8d 35 7f 72 fc 00 	lea    rsi,[rip+0xfc727f]        # 0x1379db0
  3b2b31:	bb 16 00 00 00       	mov    ebx,0x16
  3b2b36:	ba 43 13 00 00       	mov    edx,0x1343
  3b2b3b:	eb bb                	jmp    0x3b2af8
  3b2b3d:	8b 4d 98             	mov    ecx,DWORD PTR [rbp-0x68]
  3b2b40:	81 f9 81 00 00 00    	cmp    ecx,0x81
  3b2b46:	72 1a                	jb     0x3b2b62
  3b2b48:	48 8d 3d b9 93 f6 00 	lea    rdi,[rip+0xf693b9]        # 0x131bf08
  3b2b4f:	48 8d 35 5a 72 fc 00 	lea    rsi,[rip+0xfc725a]        # 0x1379db0
  3b2b56:	bb 16 00 00 00       	mov    ebx,0x16
  3b2b5b:	ba 4a 13 00 00       	mov    edx,0x134a
  3b2b60:	eb 96                	jmp    0x3b2af8
  3b2b62:	8b 55 9c             	mov    edx,DWORD PTR [rbp-0x64]
  3b2b65:	89 d6                	mov    esi,edx
  3b2b67:	89 d7                	mov    edi,edx
  3b2b69:	85 d2                	test   edx,edx
  3b2b6b:	74 67                	je     0x3b2bd4
  3b2b6d:	83 fa 01             	cmp    edx,0x1
  3b2b70:	0f 85 b5 01 00 00    	jne    0x3b2d2b
  3b2b76:	8b 75 a0             	mov    esi,DWORD PTR [rbp-0x60]
  3b2b79:	8d be ff ff ff fe    	lea    edi,[rsi-0x1000001]
  3b2b7f:	81 ff ff ff ff fe    	cmp    edi,0xfeffffff
  3b2b85:	77 1d                	ja     0x3b2ba4
  3b2b87:	48 8d 3d 7a 93 f6 00 	lea    rdi,[rip+0xf6937a]        # 0x131bf08
  3b2b8e:	48 8d 35 1b 72 fc 00 	lea    rsi,[rip+0xfc721b]        # 0x1379db0
  3b2b95:	bb 16 00 00 00       	mov    ebx,0x16
  3b2b9a:	ba 59 13 00 00       	mov    edx,0x1359
  3b2b9f:	e9 54 ff ff ff       	jmp    0x3b2af8
  3b2ba4:	8b 7d a4             	mov    edi,DWORD PTR [rbp-0x5c]
  3b2ba7:	44 8d 87 ff ff ff fe 	lea    r8d,[rdi-0x1000001]
  3b2bae:	41 81 f8 ff ff ff fe 	cmp    r8d,0xfeffffff
  3b2bb5:	77 1d                	ja     0x3b2bd4
  3b2bb7:	48 8d 3d 4a 93 f6 00 	lea    rdi,[rip+0xf6934a]        # 0x131bf08
  3b2bbe:	48 8d 35 eb 71 fc 00 	lea    rsi,[rip+0xfc71eb]        # 0x1379db0
  3b2bc5:	bb 16 00 00 00       	mov    ebx,0x16
  3b2bca:	ba 61 13 00 00       	mov    edx,0x1361
  3b2bcf:	e9 24 ff ff ff       	jmp    0x3b2af8
  3b2bd4:	41 89 b6 b4 01 00 00 	mov    DWORD PTR [r14+0x1b4],esi
  3b2bdb:	41 89 be 94 01 00 00 	mov    DWORD PTR [r14+0x194],edi
  3b2be2:	41 89 96 a4 01 00 00 	mov    DWORD PTR [r14+0x1a4],edx
  3b2be9:	41 89 86 74 01 00 00 	mov    DWORD PTR [r14+0x174],eax
  3b2bf0:	8b 45 a8             	mov    eax,DWORD PTR [rbp-0x58]
  3b2bf3:	41 89 8e 84 01 00 00 	mov    DWORD PTR [r14+0x184],ecx
  3b2bfa:	3d 80 00 00 00       	cmp    eax,0x80
  3b2bff:	0f 87 1e ff ff ff    	ja     0x3b2b23
  3b2c05:	8b 4d ac             	mov    ecx,DWORD PTR [rbp-0x54]
  3b2c08:	81 f9 80 00 00 00    	cmp    ecx,0x80
  3b2c0e:	0f 87 34 ff ff ff    	ja     0x3b2b48
  3b2c14:	8b 55 b0             	mov    edx,DWORD PTR [rbp-0x50]
  3b2c17:	89 d6                	mov    esi,edx
  3b2c19:	89 d7                	mov    edi,edx
  3b2c1b:	85 d2                	test   edx,edx
  3b2c1d:	74 35                	je     0x3b2c54
  3b2c1f:	83 fa 01             	cmp    edx,0x1
  3b2c22:	0f 85 03 01 00 00    	jne    0x3b2d2b
  3b2c28:	8b 75 b4             	mov    esi,DWORD PTR [rbp-0x4c]
  3b2c2b:	8d be ff ff ff fe    	lea    edi,[rsi-0x1000001]
  3b2c31:	81 ff 00 00 00 ff    	cmp    edi,0xff000000
  3b2c37:	0f 82 4a ff ff ff    	jb     0x3b2b87
  3b2c3d:	8b 7d b8             	mov    edi,DWORD PTR [rbp-0x48]
  3b2c40:	44 8d 87 ff ff ff fe 	lea    r8d,[rdi-0x1000001]
  3b2c47:	41 81 f8 00 00 00 ff 	cmp    r8d,0xff000000
  3b2c4e:	0f 82 63 ff ff ff    	jb     0x3b2bb7
  3b2c54:	41 89 b6 b8 01 00 00 	mov    DWORD PTR [r14+0x1b8],esi
  3b2c5b:	41 89 be 98 01 00 00 	mov    DWORD PTR [r14+0x198],edi
  3b2c62:	41 89 96 a8 01 00 00 	mov    DWORD PTR [r14+0x1a8],edx
  3b2c69:	41 89 86 78 01 00 00 	mov    DWORD PTR [r14+0x178],eax
  3b2c70:	8b 45 bc             	mov    eax,DWORD PTR [rbp-0x44]
  3b2c73:	41 89 8e 88 01 00 00 	mov    DWORD PTR [r14+0x188],ecx
  3b2c7a:	3d 80 00 00 00       	cmp    eax,0x80
  3b2c7f:	0f 87 9e fe ff ff    	ja     0x3b2b23
  3b2c85:	8b 4d c0             	mov    ecx,DWORD PTR [rbp-0x40]
  3b2c88:	81 f9 80 00 00 00    	cmp    ecx,0x80
  3b2c8e:	0f 87 b4 fe ff ff    	ja     0x3b2b48
  3b2c94:	8b 55 c4             	mov    edx,DWORD PTR [rbp-0x3c]
  3b2c97:	89 d6                	mov    esi,edx
  3b2c99:	89 d7                	mov    edi,edx
  3b2c9b:	85 d2                	test   edx,edx
  3b2c9d:	74 35                	je     0x3b2cd4
  3b2c9f:	83 fa 01             	cmp    edx,0x1
  3b2ca2:	0f 85 83 00 00 00    	jne    0x3b2d2b
  3b2ca8:	8b 75 c8             	mov    esi,DWORD PTR [rbp-0x38]
  3b2cab:	8d be ff ff ff fe    	lea    edi,[rsi-0x1000001]
  3b2cb1:	81 ff 00 00 00 ff    	cmp    edi,0xff000000
  3b2cb7:	0f 82 ca fe ff ff    	jb     0x3b2b87
  3b2cbd:	8b 7d cc             	mov    edi,DWORD PTR [rbp-0x34]
  3b2cc0:	44 8d 87 ff ff ff fe 	lea    r8d,[rdi-0x1000001]
  3b2cc7:	41 81 f8 00 00 00 ff 	cmp    r8d,0xff000000
  3b2cce:	0f 82 e3 fe ff ff    	jb     0x3b2bb7
  3b2cd4:	41 89 b6 bc 01 00 00 	mov    DWORD PTR [r14+0x1bc],esi
  3b2cdb:	41 89 be 9c 01 00 00 	mov    DWORD PTR [r14+0x19c],edi
  3b2ce2:	41 89 96 ac 01 00 00 	mov    DWORD PTR [r14+0x1ac],edx
  3b2ce9:	41 89 86 7c 01 00 00 	mov    DWORD PTR [r14+0x17c],eax
  3b2cf0:	41 89 8e 8c 01 00 00 	mov    DWORD PTR [r14+0x18c],ecx
  3b2cf7:	e8 d4 4b 75 00       	call   0xb078d0
  3b2cfc:	85 c0                	test   eax,eax
  3b2cfe:	74 0c                	je     0x3b2d0c
  3b2d00:	48 8b 7d 88          	mov    rdi,QWORD PTR [rbp-0x78]
  3b2d04:	4c 89 f6             	mov    rsi,r14
  3b2d07:	e8 24 11 cf ff       	call   0xa3e30
  3b2d0c:	45 31 ed             	xor    r13d,r13d
  3b2d0f:	41 83 be a0 04 00 00 	cmp    DWORD PTR [r14+0x4a0],0x1
  3b2d16:	01 
  3b2d17:	0f 85 ed fc ff ff    	jne    0x3b2a0a
  3b2d1d:	48 8d 3d dc c5 11 03 	lea    rdi,[rip+0x311c5dc]        # 0x34cf300
  3b2d24:	31 db                	xor    ebx,ebx
  3b2d26:	e9 e0 fd ff ff       	jmp    0x3b2b0b
  3b2d2b:	48 8d 3d d6 91 f6 00 	lea    rdi,[rip+0xf691d6]        # 0x131bf08
  3b2d32:	48 8d 35 77 70 fc 00 	lea    rsi,[rip+0xfc7077]        # 0x1379db0
  3b2d39:	bb 16 00 00 00       	mov    ebx,0x16
  3b2d3e:	ba 52 13 00 00       	mov    edx,0x1352
  3b2d43:	e9 b0 fd ff ff       	jmp    0x3b2af8
  3b2d48:	e8 63 a9 34 00       	call   0x6fd6b0
  3b2d4d:	0f 0b                	ud2
  3b2d4f:	90                   	nop
  3b2d50:	55                   	push   rbp
  3b2d51:	48 89 e5             	mov    rbp,rsp
  3b2d54:	41 57                	push   r15
  3b2d56:	41 56                	push   r14
  3b2d58:	41 55                	push   r13
  3b2d5a:	41 54                	push   r12
  3b2d5c:	53                   	push   rbx
  3b2d5d:	48 83 ec 38          	sub    rsp,0x38
  3b2d61:	4c 8d 2d a8 95 56 03 	lea    r13,[rip+0x35695a8]        # 0x391c310
  3b2d68:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  3b2d6c:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  3b2d70:	48 8b 56 08          	mov    rdx,QWORD PTR [rsi+0x8]
  3b2d74:	4c 8b 66 18          	mov    r12,QWORD PTR [rsi+0x18]
  3b2d78:	44 8b 3e             	mov    r15d,DWORD PTR [rsi]
  3b2d7b:	44 8b 76 10          	mov    r14d,DWORD PTR [rsi+0x10]
  3b2d7f:	c7 45 cc 00 00 00 00 	mov    DWORD PTR [rbp-0x34],0x0
  3b2d86:	48 85 d2             	test   rdx,rdx
  3b2d89:	0f 95 c0             	setne  al
  3b2d8c:	4d 85 e4             	test   r12,r12
  3b2d8f:	0f 95 c1             	setne  cl
  3b2d92:	84 c8                	test   al,cl
  3b2d94:	75 1f                	jne    0x3b2db5
  3b2d96:	48 8d 3d 6b 91 f6 00 	lea    rdi,[rip+0xf6916b]        # 0x131bf08
  3b2d9d:	48 8d 35 25 da f9 00 	lea    rsi,[rip+0xf9da25]        # 0x13507c9
  3b2da4:	bb 0e 00 00 00       	mov    ebx,0xe
  3b2da9:	ba fe 14 00 00       	mov    edx,0x14fe
  3b2dae:	b9 0e 00 00 00       	mov    ecx,0xe
  3b2db3:	eb 30                	jmp    0x3b2de5
  3b2db5:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
  3b2db9:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
  3b2dbd:	44 89 ff             	mov    edi,r15d
  3b2dc0:	be 15 00 00 00       	mov    esi,0x15
  3b2dc5:	e8 96 94 18 00       	call   0x53c260
  3b2dca:	85 c0                	test   eax,eax
  3b2dcc:	74 3d                	je     0x3b2e0b
  3b2dce:	89 c3                	mov    ebx,eax
  3b2dd0:	48 8d 3d 31 91 f6 00 	lea    rdi,[rip+0xf69131]        # 0x131bf08
  3b2dd7:	48 8d 35 eb d9 f9 00 	lea    rsi,[rip+0xf9d9eb]        # 0x13507c9
  3b2dde:	ba 06 15 00 00       	mov    edx,0x1506
  3b2de3:	89 c1                	mov    ecx,eax
  3b2de5:	31 c0                	xor    eax,eax
  3b2de7:	e8 24 a6 ea ff       	call   0x25d410
  3b2dec:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  3b2df0:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  3b2df4:	0f 85 80 02 00 00    	jne    0x3b307a
  3b2dfa:	89 d8                	mov    eax,ebx
  3b2dfc:	48 83 c4 38          	add    rsp,0x38
  3b2e00:	5b                   	pop    rbx
  3b2e01:	41 5c                	pop    r12
  3b2e03:	41 5d                	pop    r13
  3b2e05:	41 5e                	pop    r14
  3b2e07:	41 5f                	pop    r15
  3b2e09:	5d                   	pop    rbp
  3b2e0a:	c3                   	ret
  3b2e0b:	44 89 ff             	mov    edi,r15d
  3b2e0e:	e8 fd 52 1f 00       	call   0x5a8110
  3b2e13:	83 f8 ff             	cmp    eax,0xffffffff
  3b2e16:	74 41                	je     0x3b2e59
  3b2e18:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  3b2e1c:	48 8b 80 48 0c 00 00 	mov    rax,QWORD PTR [rax+0xc48]
  3b2e23:	48 85 c0             	test   rax,rax
  3b2e26:	74 4b                	je     0x3b2e73
  3b2e28:	45 85 f6             	test   r14d,r14d
  3b2e2b:	7e 0d                	jle    0x3b2e3a
  3b2e2d:	44 3b b0 28 02 00 00 	cmp    r14d,DWORD PTR [rax+0x228]
  3b2e34:	0f 8e b8 00 00 00    	jle    0x3b2ef2
  3b2e3a:	48 8d 3d c7 90 f6 00 	lea    rdi,[rip+0xf690c7]        # 0x131bf08
  3b2e41:	48 8d 35 81 d9 f9 00 	lea    rsi,[rip+0xf9d981]        # 0x13507c9
  3b2e48:	bb 16 00 00 00       	mov    ebx,0x16
  3b2e4d:	ba 1c 15 00 00       	mov    edx,0x151c
  3b2e52:	b9 16 00 00 00       	mov    ecx,0x16
  3b2e57:	eb 37                	jmp    0x3b2e90
  3b2e59:	48 8d 3d a8 90 f6 00 	lea    rdi,[rip+0xf690a8]        # 0x131bf08
  3b2e60:	48 8d 35 62 d9 f9 00 	lea    rsi,[rip+0xf9d962]        # 0x13507c9
  3b2e67:	bb 03 00 00 00       	mov    ebx,0x3
  3b2e6c:	ba 0d 15 00 00       	mov    edx,0x150d
  3b2e71:	eb 18                	jmp    0x3b2e8b
  3b2e73:	48 8d 3d 8e 90 f6 00 	lea    rdi,[rip+0xf6908e]        # 0x131bf08
  3b2e7a:	48 8d 35 48 d9 f9 00 	lea    rsi,[rip+0xf9d948]        # 0x13507c9
  3b2e81:	bb 03 00 00 00       	mov    ebx,0x3
  3b2e86:	ba 15 15 00 00       	mov    edx,0x1515
  3b2e8b:	b9 03 00 00 00       	mov    ecx,0x3
  3b2e90:	31 c0                	xor    eax,eax
  3b2e92:	e8 79 a5 ea ff       	call   0x25d410
  3b2e97:	bf 48 01 00 00       	mov    edi,0x148
  3b2e9c:	48 03 7d b8          	add    rdi,QWORD PTR [rbp-0x48]
  3b2ea0:	31 f6                	xor    esi,esi
  3b2ea2:	31 d2                	xor    edx,edx
  3b2ea4:	31 c9                	xor    ecx,ecx
  3b2ea6:	e8 55 3b 11 00       	call   0x4c6a00
  3b2eab:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  3b2eaf:	ff 88 58 03 00 00    	dec    DWORD PTR [rax+0x358]
  3b2eb5:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  3b2eb9:	f6 87 b1 00 00 00 20 	test   BYTE PTR [rdi+0xb1],0x20
  3b2ec0:	74 19                	je     0x3b2edb
  3b2ec2:	83 bf 58 03 00 00 00 	cmp    DWORD PTR [rdi+0x358],0x0
  3b2ec9:	75 10                	jne    0x3b2edb
  3b2ecb:	48 81 c7 58 03 00 00 	add    rdi,0x358
  3b2ed2:	e8 39 3a 85 00       	call   0xc06910
  3b2ed7:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  3b2edb:	48 81 c7 48 01 00 00 	add    rdi,0x148
  3b2ee2:	31 f6                	xor    esi,esi
  3b2ee4:	31 d2                	xor    edx,edx
  3b2ee6:	31 c9                	xor    ecx,ecx
  3b2ee8:	e8 b3 40 11 00       	call   0x4c6fa0
  3b2eed:	e9 fa fe ff ff       	jmp    0x3b2dec
  3b2ef2:	4c 89 f7             	mov    rdi,r14
  3b2ef5:	48 8d 35 c4 2b 70 01 	lea    rsi,[rip+0x1702bc4]        # 0x1ab5ac0
  3b2efc:	ba 02 01 00 00       	mov    edx,0x102
  3b2f01:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  3b2f05:	48 c1 e7 04          	shl    rdi,0x4
  3b2f09:	e8 42 5c 85 00       	call   0xc08b50
  3b2f0e:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  3b2f12:	49 89 c7             	mov    r15,rax
  3b2f15:	8b 87 20 02 00 00    	mov    eax,DWORD PTR [rdi+0x220]
  3b2f1b:	c1 e0 07             	shl    eax,0x7
  3b2f1e:	85 c0                	test   eax,eax
  3b2f20:	0f 8e a9 00 00 00    	jle    0x3b2fcf
  3b2f26:	31 db                	xor    ebx,ebx
  3b2f28:	45 31 ed             	xor    r13d,r13d
  3b2f2b:	eb 25                	jmp    0x3b2f52
  3b2f2d:	0f 1f 00             	nop    DWORD PTR [rax]
  3b2f30:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  3b2f34:	e8 77 6f fe ff       	call   0x399eb0
  3b2f39:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  3b2f3d:	41 ff c5             	inc    r13d
  3b2f40:	8b 87 20 02 00 00    	mov    eax,DWORD PTR [rdi+0x220]
  3b2f46:	c1 e0 07             	shl    eax,0x7
  3b2f49:	41 39 c5             	cmp    r13d,eax
  3b2f4c:	0f 8d 7d 00 00 00    	jge    0x3b2fcf
  3b2f52:	44 89 ee             	mov    esi,r13d
  3b2f55:	ba 60 01 00 00       	mov    edx,0x160
  3b2f5a:	48 8d 4d c0          	lea    rcx,[rbp-0x40]
  3b2f5e:	e8 8d 71 fe ff       	call   0x39a0f0
  3b2f63:	48 85 c0             	test   rax,rax
  3b2f66:	74 d1                	je     0x3b2f39
  3b2f68:	48 0f bf 08          	movsx  rcx,WORD PTR [rax]
  3b2f6c:	48 85 c9             	test   rcx,rcx
  3b2f6f:	7e bf                	jle    0x3b2f30
  3b2f71:	48 8b 50 28          	mov    rdx,QWORD PTR [rax+0x28]
  3b2f75:	48 c1 e1 10          	shl    rcx,0x10
  3b2f79:	31 f6                	xor    esi,esi
  3b2f7b:	eb 18                	jmp    0x3b2f95
  3b2f7d:	0f 1f 00             	nop    DWORD PTR [rax]
  3b2f80:	ff c3                	inc    ebx
  3b2f82:	89 5d cc             	mov    DWORD PTR [rbp-0x34],ebx
  3b2f85:	48 81 c6 00 00 01 00 	add    rsi,0x10000
  3b2f8c:	48 83 c2 08          	add    rdx,0x8
  3b2f90:	48 39 f1             	cmp    rcx,rsi
  3b2f93:	74 9b                	je     0x3b2f30
  3b2f95:	48 8b 3a             	mov    rdi,QWORD PTR [rdx]
  3b2f98:	48 85 ff             	test   rdi,rdi
  3b2f9b:	74 e8                	je     0x3b2f85
  3b2f9d:	44 39 f3             	cmp    ebx,r14d
  3b2fa0:	7d de                	jge    0x3b2f80
  3b2fa2:	44 8b 40 08          	mov    r8d,DWORD PTR [rax+0x8]
  3b2fa6:	4c 63 cb             	movsxd r9,ebx
  3b2fa9:	49 c1 e1 04          	shl    r9,0x4
  3b2fad:	41 09 f0             	or     r8d,esi
  3b2fb0:	47 89 04 0f          	mov    DWORD PTR [r15+r9*1],r8d
  3b2fb4:	44 8b 47 38          	mov    r8d,DWORD PTR [rdi+0x38]
  3b2fb8:	47 89 44 0f 04       	mov    DWORD PTR [r15+r9*1+0x4],r8d
  3b2fbd:	44 8b 40 04          	mov    r8d,DWORD PTR [rax+0x4]
  3b2fc1:	47 89 44 0f 08       	mov    DWORD PTR [r15+r9*1+0x8],r8d
  3b2fc6:	8b 3f                	mov    edi,DWORD PTR [rdi]
  3b2fc8:	43 89 7c 0f 0c       	mov    DWORD PTR [r15+r9*1+0xc],edi
  3b2fcd:	eb b1                	jmp    0x3b2f80
  3b2fcf:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  3b2fd6:	00 00 
  3b2fd8:	48 8d 35 b8 c2 f9 00 	lea    rsi,[rip+0xf9c2b8]        # 0x134f297
  3b2fdf:	31 d2                	xor    edx,edx
  3b2fe1:	31 db                	xor    ebx,ebx
  3b2fe3:	e8 f8 73 86 00       	call   0xc1a3e0
  3b2fe8:	48 8d 7d cc          	lea    rdi,[rbp-0x34]
  3b2fec:	ba 04 00 00 00       	mov    edx,0x4
  3b2ff1:	4c 89 e6             	mov    rsi,r12
  3b2ff4:	e8 d7 61 ea ff       	call   0x2591d0
  3b2ff9:	85 c0                	test   eax,eax
  3b2ffb:	74 27                	je     0x3b3024
  3b2ffd:	48 8d 3d 04 8f f6 00 	lea    rdi,[rip+0xf68f04]        # 0x131bf08
  3b3004:	48 8d 35 be d7 f9 00 	lea    rsi,[rip+0xf9d7be]        # 0x13507c9
  3b300b:	ba 53 15 00 00       	mov    edx,0x1553
  3b3010:	89 c1                	mov    ecx,eax
  3b3012:	89 c3                	mov    ebx,eax
  3b3014:	31 c0                	xor    eax,eax
  3b3016:	e8 f5 a3 ea ff       	call   0x25d410
  3b301b:	4c 8d 2d ee 92 56 03 	lea    r13,[rip+0x35692ee]        # 0x391c310
  3b3022:	eb 42                	jmp    0x3b3066
  3b3024:	48 63 55 cc          	movsxd rdx,DWORD PTR [rbp-0x34]
  3b3028:	4c 8d 2d e1 92 56 03 	lea    r13,[rip+0x35692e1]        # 0x391c310
  3b302f:	44 39 f2             	cmp    edx,r14d
  3b3032:	7f 32                	jg     0x3b3066
  3b3034:	48 8b 75 a8          	mov    rsi,QWORD PTR [rbp-0x58]
  3b3038:	48 c1 e2 04          	shl    rdx,0x4
  3b303c:	4c 89 ff             	mov    rdi,r15
  3b303f:	e8 fc 09 00 00       	call   0x3b3a40
  3b3044:	85 c0                	test   eax,eax
  3b3046:	74 1e                	je     0x3b3066
  3b3048:	48 8d 3d b9 8e f6 00 	lea    rdi,[rip+0xf68eb9]        # 0x131bf08
  3b304f:	48 8d 35 73 d7 f9 00 	lea    rsi,[rip+0xf9d773]        # 0x13507c9
  3b3056:	ba 62 15 00 00       	mov    edx,0x1562
  3b305b:	89 c1                	mov    ecx,eax
  3b305d:	89 c3                	mov    ebx,eax
  3b305f:	31 c0                	xor    eax,eax
  3b3061:	e8 aa a3 ea ff       	call   0x25d410
  3b3066:	48 8d 35 53 2a 70 01 	lea    rsi,[rip+0x1702a53]        # 0x1ab5ac0
  3b306d:	4c 89 ff             	mov    rdi,r15
  3b3070:	e8 7b 5d 85 00       	call   0xc08df0
  3b3075:	e9 1d fe ff ff       	jmp    0x3b2e97
  3b307a:	e8 31 a6 34 00       	call   0x6fd6b0
  3b307f:	0f 0b                	ud2
  3b3081:	90                   	nop
  3b3082:	90                   	nop
  3b3083:	90                   	nop
  3b3084:	90                   	nop
  3b3085:	90                   	nop
  3b3086:	90                   	nop
  3b3087:	90                   	nop
  3b3088:	90                   	nop
  3b3089:	90                   	nop
  3b308a:	90                   	nop
  3b308b:	90                   	nop
  3b308c:	90                   	nop
  3b308d:	90                   	nop
  3b308e:	90                   	nop
  3b308f:	90                   	nop
  3b3090:	55                   	push   rbp
  3b3091:	48 89 e5             	mov    rbp,rsp
  3b3094:	41 57                	push   r15
  3b3096:	41 56                	push   r14
  3b3098:	41 55                	push   r13
  3b309a:	41 54                	push   r12
  3b309c:	53                   	push   rbx
  3b309d:	48 83 ec 48          	sub    rsp,0x48
  3b30a1:	4c 8d 2d 68 92 56 03 	lea    r13,[rip+0x3569268]        # 0x391c310
  3b30a8:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  3b30ac:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  3b30b0:	4c 8b 76 10          	mov    r14,QWORD PTR [rsi+0x10]
  3b30b4:	4c 8b 66 20          	mov    r12,QWORD PTR [rsi+0x20]
  3b30b8:	44 8b 3e             	mov    r15d,DWORD PTR [rsi]
  3b30bb:	8b 7e 08             	mov    edi,DWORD PTR [rsi+0x8]
  3b30be:	8b 56 18             	mov    edx,DWORD PTR [rsi+0x18]
  3b30c1:	c7 45 cc 00 00 00 00 	mov    DWORD PTR [rbp-0x34],0x0
  3b30c8:	4d 85 f6             	test   r14,r14
  3b30cb:	0f 95 c0             	setne  al
  3b30ce:	4d 85 e4             	test   r12,r12
  3b30d1:	0f 95 c1             	setne  cl
  3b30d4:	84 c8                	test   al,cl
  3b30d6:	75 1f                	jne    0x3b30f7
  3b30d8:	48 8d 3d 29 8e f6 00 	lea    rdi,[rip+0xf68e29]        # 0x131bf08
  3b30df:	48 8d 35 e5 63 ef 00 	lea    rsi,[rip+0xef63e5]        # 0x12a94cb
  3b30e6:	bb 0e 00 00 00       	mov    ebx,0xe
  3b30eb:	ba 66 14 00 00       	mov    edx,0x1466
  3b30f0:	b9 0e 00 00 00       	mov    ecx,0xe
  3b30f5:	eb 33                	jmp    0x3b312a
  3b30f7:	89 7d b4             	mov    DWORD PTR [rbp-0x4c],edi
  3b30fa:	48 89 55 a0          	mov    QWORD PTR [rbp-0x60],rdx
  3b30fe:	48 8d 55 b8          	lea    rdx,[rbp-0x48]
  3b3102:	44 89 ff             	mov    edi,r15d
  3b3105:	be 15 00 00 00       	mov    esi,0x15
  3b310a:	e8 51 91 18 00       	call   0x53c260
  3b310f:	85 c0                	test   eax,eax
  3b3111:	74 3d                	je     0x3b3150
  3b3113:	89 c3                	mov    ebx,eax
  3b3115:	48 8d 3d ec 8d f6 00 	lea    rdi,[rip+0xf68dec]        # 0x131bf08
  3b311c:	48 8d 35 a8 63 ef 00 	lea    rsi,[rip+0xef63a8]        # 0x12a94cb
  3b3123:	ba 6e 14 00 00       	mov    edx,0x146e
  3b3128:	89 c1                	mov    ecx,eax
  3b312a:	31 c0                	xor    eax,eax
  3b312c:	e8 df a2 ea ff       	call   0x25d410
  3b3131:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  3b3135:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  3b3139:	0f 85 c4 02 00 00    	jne    0x3b3403
  3b313f:	89 d8                	mov    eax,ebx
  3b3141:	48 83 c4 48          	add    rsp,0x48
  3b3145:	5b                   	pop    rbx
  3b3146:	41 5c                	pop    r12
  3b3148:	41 5d                	pop    r13
  3b314a:	41 5e                	pop    r14
  3b314c:	41 5f                	pop    r15
  3b314e:	5d                   	pop    rbp
  3b314f:	c3                   	ret
  3b3150:	44 89 ff             	mov    edi,r15d
  3b3153:	e8 b8 4f 1f 00       	call   0x5a8110
  3b3158:	83 f8 ff             	cmp    eax,0xffffffff
  3b315b:	74 3f                	je     0x3b319c
  3b315d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  3b3161:	48 8b 98 48 0c 00 00 	mov    rbx,QWORD PTR [rax+0xc48]
  3b3168:	48 85 db             	test   rbx,rbx
  3b316b:	74 49                	je     0x3b31b6
  3b316d:	48 8b 45 a0          	mov    rax,QWORD PTR [rbp-0x60]
  3b3171:	85 c0                	test   eax,eax
  3b3173:	7e 08                	jle    0x3b317d
  3b3175:	3b 83 28 02 00 00    	cmp    eax,DWORD PTR [rbx+0x228]
  3b317b:	7e 53                	jle    0x3b31d0
  3b317d:	48 8d 3d 84 8d f6 00 	lea    rdi,[rip+0xf68d84]        # 0x131bf08
  3b3184:	48 8d 35 40 63 ef 00 	lea    rsi,[rip+0xef6340]        # 0x12a94cb
  3b318b:	bb 16 00 00 00       	mov    ebx,0x16
  3b3190:	ba 84 14 00 00       	mov    edx,0x1484
  3b3195:	b9 16 00 00 00       	mov    ecx,0x16
  3b319a:	eb 5f                	jmp    0x3b31fb
  3b319c:	48 8d 3d 65 8d f6 00 	lea    rdi,[rip+0xf68d65]        # 0x131bf08
  3b31a3:	48 8d 35 21 63 ef 00 	lea    rsi,[rip+0xef6321]        # 0x12a94cb
  3b31aa:	bb 03 00 00 00       	mov    ebx,0x3
  3b31af:	ba 75 14 00 00       	mov    edx,0x1475
  3b31b4:	eb 40                	jmp    0x3b31f6
  3b31b6:	48 8d 3d 4b 8d f6 00 	lea    rdi,[rip+0xf68d4b]        # 0x131bf08
  3b31bd:	48 8d 35 07 63 ef 00 	lea    rsi,[rip+0xef6307]        # 0x12a94cb
  3b31c4:	bb 03 00 00 00       	mov    ebx,0x3
  3b31c9:	ba 7d 14 00 00       	mov    edx,0x147d
  3b31ce:	eb 26                	jmp    0x3b31f6
  3b31d0:	8b 4d b4             	mov    ecx,DWORD PTR [rbp-0x4c]
  3b31d3:	c1 f9 10             	sar    ecx,0x10
  3b31d6:	81 f9 80 00 00 00    	cmp    ecx,0x80
  3b31dc:	72 7f                	jb     0x3b325d
  3b31de:	48 8d 3d 23 8d f6 00 	lea    rdi,[rip+0xf68d23]        # 0x131bf08
  3b31e5:	48 8d 35 df 62 ef 00 	lea    rsi,[rip+0xef62df]        # 0x12a94cb
  3b31ec:	bb 03 00 00 00       	mov    ebx,0x3
  3b31f1:	ba 8d 14 00 00       	mov    edx,0x148d
  3b31f6:	b9 03 00 00 00       	mov    ecx,0x3
  3b31fb:	31 c0                	xor    eax,eax
  3b31fd:	e8 0e a2 ea ff       	call   0x25d410
  3b3202:	bf 48 01 00 00       	mov    edi,0x148
  3b3207:	48 03 7d b8          	add    rdi,QWORD PTR [rbp-0x48]
  3b320b:	31 f6                	xor    esi,esi
  3b320d:	31 d2                	xor    edx,edx
  3b320f:	31 c9                	xor    ecx,ecx
  3b3211:	e8 ea 37 11 00       	call   0x4c6a00
  3b3216:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  3b321a:	ff 88 58 03 00 00    	dec    DWORD PTR [rax+0x358]
  3b3220:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  3b3224:	f6 87 b1 00 00 00 20 	test   BYTE PTR [rdi+0xb1],0x20
  3b322b:	74 19                	je     0x3b3246
  3b322d:	83 bf 58 03 00 00 00 	cmp    DWORD PTR [rdi+0x358],0x0
  3b3234:	75 10                	jne    0x3b3246
  3b3236:	48 81 c7 58 03 00 00 	add    rdi,0x358
  3b323d:	e8 ce 36 85 00       	call   0xc06910
  3b3242:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  3b3246:	48 81 c7 48 01 00 00 	add    rdi,0x148
  3b324d:	31 f6                	xor    esi,esi
  3b324f:	31 d2                	xor    edx,edx
  3b3251:	31 c9                	xor    ecx,ecx
  3b3253:	e8 48 3d 11 00       	call   0x4c6fa0
  3b3258:	e9 d4 fe ff ff       	jmp    0x3b3131
  3b325d:	48 8d 04 c5 00 00 00 	lea    rax,[rax*8+0x0]
  3b3264:	00 
  3b3265:	48 8d 35 54 28 70 01 	lea    rsi,[rip+0x1702854]        # 0x1ab5ac0
  3b326c:	ba 02 01 00 00       	mov    edx,0x102
  3b3271:	48 89 4d 98          	mov    QWORD PTR [rbp-0x68],rcx
  3b3275:	48 8d 3c 40          	lea    rdi,[rax+rax*2]
  3b3279:	e8 d2 58 85 00       	call   0xc08b50
  3b327e:	8b 8b 20 02 00 00    	mov    ecx,DWORD PTR [rbx+0x220]
  3b3284:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
  3b3288:	c1 e1 07             	shl    ecx,0x7
  3b328b:	85 c9                	test   ecx,ecx
  3b328d:	0f 8e ce 00 00 00    	jle    0x3b3361
  3b3293:	44 8b 7d b4          	mov    r15d,DWORD PTR [rbp-0x4c]
  3b3297:	8b 45 98             	mov    eax,DWORD PTR [rbp-0x68]
  3b329a:	45 31 ed             	xor    r13d,r13d
  3b329d:	41 81 e7 00 00 ff ff 	and    r15d,0xffff0000
  3b32a4:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
  3b32a8:	eb 1e                	jmp    0x3b32c8
  3b32aa:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  3b32ae:	e8 fd 6b fe ff       	call   0x399eb0
  3b32b3:	8b 83 20 02 00 00    	mov    eax,DWORD PTR [rbx+0x220]
  3b32b9:	41 ff c5             	inc    r13d
  3b32bc:	c1 e0 07             	shl    eax,0x7
  3b32bf:	41 39 c5             	cmp    r13d,eax
  3b32c2:	0f 8d 99 00 00 00    	jge    0x3b3361
  3b32c8:	48 89 df             	mov    rdi,rbx
  3b32cb:	44 89 ee             	mov    esi,r13d
  3b32ce:	ba 60 01 00 00       	mov    edx,0x160
  3b32d3:	48 8d 4d c0          	lea    rcx,[rbp-0x40]
  3b32d7:	e8 14 6e fe ff       	call   0x39a0f0
  3b32dc:	48 85 c0             	test   rax,rax
  3b32df:	74 d2                	je     0x3b32b3
  3b32e1:	8b 48 08             	mov    ecx,DWORD PTR [rax+0x8]
  3b32e4:	44 09 f9             	or     ecx,r15d
  3b32e7:	39 4d b4             	cmp    DWORD PTR [rbp-0x4c],ecx
  3b32ea:	75 be                	jne    0x3b32aa
  3b32ec:	48 8b 48 28          	mov    rcx,QWORD PTR [rax+0x28]
  3b32f0:	48 8b 55 90          	mov    rdx,QWORD PTR [rbp-0x70]
  3b32f4:	48 8b 0c d1          	mov    rcx,QWORD PTR [rcx+rdx*8]
  3b32f8:	48 85 c9             	test   rcx,rcx
  3b32fb:	74 ad                	je     0x3b32aa
  3b32fd:	48 8b 49 20          	mov    rcx,QWORD PTR [rcx+0x20]
  3b3301:	4c 8b 55 a0          	mov    r10,QWORD PTR [rbp-0x60]
  3b3305:	4c 8b 5d a8          	mov    r11,QWORD PTR [rbp-0x58]
  3b3309:	48 8b 5d 98          	mov    rbx,QWORD PTR [rbp-0x68]
  3b330d:	8b 09                	mov    ecx,DWORD PTR [rcx]
  3b330f:	85 c9                	test   ecx,ecx
  3b3311:	74 45                	je     0x3b3358
  3b3313:	31 d2                	xor    edx,edx
  3b3315:	eb 09                	jmp    0x3b3320
  3b3317:	ff c2                	inc    edx
  3b3319:	89 55 cc             	mov    DWORD PTR [rbp-0x34],edx
  3b331c:	39 d1                	cmp    ecx,edx
  3b331e:	74 38                	je     0x3b3358
  3b3320:	44 39 d2             	cmp    edx,r10d
  3b3323:	7d f2                	jge    0x3b3317
  3b3325:	8d 3c 13             	lea    edi,[rbx+rdx*1]
  3b3328:	48 8b 70 20          	mov    rsi,QWORD PTR [rax+0x20]
  3b332c:	4c 63 ca             	movsxd r9,edx
  3b332f:	48 63 ff             	movsxd rdi,edi
  3b3332:	4f 8d 0c 49          	lea    r9,[r9+r9*2]
  3b3336:	48 8d 3c bf          	lea    rdi,[rdi+rdi*4]
  3b333a:	44 8b 44 fe 20       	mov    r8d,DWORD PTR [rsi+rdi*8+0x20]
  3b333f:	47 89 04 cb          	mov    DWORD PTR [r11+r9*8],r8d
  3b3343:	4c 8b 44 fe 08       	mov    r8,QWORD PTR [rsi+rdi*8+0x8]
  3b3348:	4f 89 44 cb 08       	mov    QWORD PTR [r11+r9*8+0x8],r8
  3b334d:	48 8b 34 fe          	mov    rsi,QWORD PTR [rsi+rdi*8]
  3b3351:	4b 89 74 cb 10       	mov    QWORD PTR [r11+r9*8+0x10],rsi
  3b3356:	eb bf                	jmp    0x3b3317
  3b3358:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  3b335c:	e8 4f 6b fe ff       	call   0x399eb0
  3b3361:	48 8d 7d cc          	lea    rdi,[rbp-0x34]
  3b3365:	ba 04 00 00 00       	mov    edx,0x4
  3b336a:	4c 89 e6             	mov    rsi,r12
  3b336d:	e8 ce 06 00 00       	call   0x3b3a40
  3b3372:	85 c0                	test   eax,eax
  3b3374:	74 2b                	je     0x3b33a1
  3b3376:	48 8d 3d 8b 8b f6 00 	lea    rdi,[rip+0xf68b8b]        # 0x131bf08
  3b337d:	48 8d 35 47 61 ef 00 	lea    rsi,[rip+0xef6147]        # 0x12a94cb
  3b3384:	ba d1 14 00 00       	mov    edx,0x14d1
  3b3389:	89 c1                	mov    ecx,eax
  3b338b:	89 c3                	mov    ebx,eax
  3b338d:	31 c0                	xor    eax,eax
  3b338f:	e8 7c a0 ea ff       	call   0x25d410
  3b3394:	4c 8d 2d 75 8f 56 03 	lea    r13,[rip+0x3568f75]        # 0x391c310
  3b339b:	48 8b 7d a8          	mov    rdi,QWORD PTR [rbp-0x58]
  3b339f:	eb 51                	jmp    0x3b33f2
  3b33a1:	48 63 45 cc          	movsxd rax,DWORD PTR [rbp-0x34]
  3b33a5:	4c 8d 2d 64 8f 56 03 	lea    r13,[rip+0x3568f64]        # 0x391c310
  3b33ac:	48 8b 7d a8          	mov    rdi,QWORD PTR [rbp-0x58]
  3b33b0:	31 db                	xor    ebx,ebx
  3b33b2:	3b 45 a0             	cmp    eax,DWORD PTR [rbp-0x60]
  3b33b5:	7f 3b                	jg     0x3b33f2
  3b33b7:	48 c1 e0 03          	shl    rax,0x3
  3b33bb:	4c 89 f6             	mov    rsi,r14
  3b33be:	49 89 ff             	mov    r15,rdi
  3b33c1:	48 8d 14 40          	lea    rdx,[rax+rax*2]
  3b33c5:	e8 76 06 00 00       	call   0x3b3a40
  3b33ca:	4c 89 ff             	mov    rdi,r15
  3b33cd:	85 c0                	test   eax,eax
  3b33cf:	74 21                	je     0x3b33f2
  3b33d1:	48 8d 3d 30 8b f6 00 	lea    rdi,[rip+0xf68b30]        # 0x131bf08
  3b33d8:	48 8d 35 ec 60 ef 00 	lea    rsi,[rip+0xef60ec]        # 0x12a94cb
  3b33df:	ba e0 14 00 00       	mov    edx,0x14e0
  3b33e4:	89 c1                	mov    ecx,eax
  3b33e6:	89 c3                	mov    ebx,eax
  3b33e8:	31 c0                	xor    eax,eax
  3b33ea:	e8 21 a0 ea ff       	call   0x25d410
  3b33ef:	4c 89 ff             	mov    rdi,r15
  3b33f2:	48 8d 35 c7 26 70 01 	lea    rsi,[rip+0x17026c7]        # 0x1ab5ac0
  3b33f9:	e8 f2 59 85 00       	call   0xc08df0
  3b33fe:	e9 ff fd ff ff       	jmp    0x3b3202
  3b3403:	e8 a8 a2 34 00       	call   0x6fd6b0
  3b3408:	0f 0b                	ud2
  3b340a:	90                   	nop
  3b340b:	90                   	nop
  3b340c:	90                   	nop
  3b340d:	90                   	nop
  3b340e:	90                   	nop
  3b340f:	90                   	nop
  3b3410:	55                   	push   rbp
  3b3411:	48 89 e5             	mov    rbp,rsp
  3b3414:	41 57                	push   r15
  3b3416:	41 56                	push   r14
  3b3418:	41 55                	push   r13
  3b341a:	41 54                	push   r12
  3b341c:	53                   	push   rbx
  3b341d:	48 83 ec 38          	sub    rsp,0x38
  3b3421:	48 8d 05 e8 8e 56 03 	lea    rax,[rip+0x3568ee8]        # 0x391c310
  3b3428:	89 7d b8             	mov    DWORD PTR [rbp-0x48],edi
  3b342b:	48 89 f3             	mov    rbx,rsi
  3b342e:	48 8d 75 cc          	lea    rsi,[rbp-0x34]
  3b3432:	48 8b 00             	mov    rax,QWORD PTR [rax]
  3b3435:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  3b3439:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  3b3440:	00 00 
  3b3442:	48 8b 78 08          	mov    rdi,QWORD PTR [rax+0x8]
  3b3446:	48 89 7d a8          	mov    QWORD PTR [rbp-0x58],rdi
  3b344a:	e8 71 4d 64 00       	call   0x9f81c0
  3b344f:	85 c0                	test   eax,eax
  3b3451:	48 8d 3d 90 be 11 03 	lea    rdi,[rip+0x311be90]        # 0x34cf2e8
  3b3458:	0f 95 45 be          	setne  BYTE PTR [rbp-0x42]
  3b345c:	81 7d cc 00 00 00 01 	cmp    DWORD PTR [rbp-0x34],0x1000000
  3b3463:	0f 93 45 bf          	setae  BYTE PTR [rbp-0x41]
  3b3467:	31 f6                	xor    esi,esi
  3b3469:	31 d2                	xor    edx,edx
  3b346b:	31 c9                	xor    ecx,ecx
  3b346d:	e8 8e 35 11 00       	call   0x4c6a00
  3b3472:	83 bb a0 04 00 00 00 	cmp    DWORD PTR [rbx+0x4a0],0x0
  3b3479:	0f 84 83 00 00 00    	je     0x3b3502
  3b347f:	41 bc 10 00 00 00    	mov    r12d,0x10
  3b3485:	7e 23                	jle    0x3b34aa
  3b3487:	48 8d 05 3a c4 11 03 	lea    rax,[rip+0x311c43a]        # 0x34cf8c8
  3b348e:	31 c9                	xor    ecx,ecx
  3b3490:	48 39 c3             	cmp    rbx,rax
  3b3493:	44 0f 44 e1          	cmove  r12d,ecx
  3b3497:	4c 8d 3d 72 8e 56 03 	lea    r15,[rip+0x3568e72]        # 0x391c310
  3b349e:	48 8d 3d 43 be 11 03 	lea    rdi,[rip+0x311be43]        # 0x34cf2e8
  3b34a5:	e9 f7 02 00 00       	jmp    0x3b37a1
  3b34aa:	4c 8d 2d 3f be 11 03 	lea    r13,[rip+0x311be3f]        # 0x34cf2f0
  3b34b1:	4c 8d 35 18 be 11 03 	lea    r14,[rip+0x311be18]        # 0x34cf2d0
  3b34b8:	4c 8d 3d 29 be 11 03 	lea    r15,[rip+0x311be29]        # 0x34cf2e8
  3b34bf:	90                   	nop
  3b34c0:	4c 89 ef             	mov    rdi,r13
  3b34c3:	4c 89 f6             	mov    rsi,r14
  3b34c6:	31 d2                	xor    edx,edx
  3b34c8:	e8 b3 b2 38 00       	call   0x73e780
  3b34cd:	83 bb a0 04 00 00 00 	cmp    DWORD PTR [rbx+0x4a0],0x0
  3b34d4:	41 89 c4             	mov    r12d,eax
  3b34d7:	75 be                	jne    0x3b3497
  3b34d9:	4c 89 ff             	mov    rdi,r15
  3b34dc:	31 f6                	xor    esi,esi
  3b34de:	31 d2                	xor    edx,edx
  3b34e0:	31 c9                	xor    ecx,ecx
  3b34e2:	e8 b9 3a 11 00       	call   0x4c6fa0
  3b34e7:	4c 89 ff             	mov    rdi,r15
  3b34ea:	31 f6                	xor    esi,esi
  3b34ec:	31 d2                	xor    edx,edx
  3b34ee:	31 c9                	xor    ecx,ecx
  3b34f0:	e8 0b 35 11 00       	call   0x4c6a00
  3b34f5:	83 bb a0 04 00 00 00 	cmp    DWORD PTR [rbx+0x4a0],0x0
  3b34fc:	74 04                	je     0x3b3502
  3b34fe:	7e c0                	jle    0x3b34c0
  3b3500:	eb 85                	jmp    0x3b3487
  3b3502:	80 3d c7 d4 11 03 00 	cmp    BYTE PTR [rip+0x311d4c7],0x0        # 0x34d09d0
  3b3509:	75 1a                	jne    0x3b3525
  3b350b:	48 8d 3d de bd 11 03 	lea    rdi,[rip+0x311bdde]        # 0x34cf2f0
  3b3512:	48 8d 35 df b7 fd 00 	lea    rsi,[rip+0xfdb7df]        # 0x138ecf8
  3b3519:	e8 02 b0 38 00       	call   0x73e520
  3b351e:	c6 05 ab d4 11 03 01 	mov    BYTE PTR [rip+0x311d4ab],0x1        # 0x34d09d0
  3b3525:	4c 8d 25 d3 b7 fd 00 	lea    r12,[rip+0xfdb7d3]        # 0x138ecff
  3b352c:	48 8d bb d8 00 00 00 	lea    rdi,[rbx+0xd8]
  3b3533:	c7 83 a0 04 00 00 ff 	mov    DWORD PTR [rbx+0x4a0],0xffffffff
  3b353a:	ff ff ff 
  3b353d:	4c 8d 73 40          	lea    r14,[rbx+0x40]
  3b3541:	4c 8d bb 80 00 00 00 	lea    r15,[rbx+0x80]
  3b3548:	31 d2                	xor    edx,edx
  3b354a:	31 c9                	xor    ecx,ecx
  3b354c:	4c 89 e6             	mov    rsi,r12
  3b354f:	e8 7c 48 11 00       	call   0x4c7dd0
  3b3554:	48 8d bb f8 00 00 00 	lea    rdi,[rbx+0xf8]
  3b355b:	4c 89 e6             	mov    rsi,r12
  3b355e:	48 c7 03 00 00 00 00 	mov    QWORD PTR [rbx],0x0
  3b3565:	48 89 5b 08          	mov    QWORD PTR [rbx+0x8],rbx
  3b3569:	48 c7 43 40 00 00 00 	mov    QWORD PTR [rbx+0x40],0x0
  3b3570:	00 
  3b3571:	4c 89 73 48          	mov    QWORD PTR [rbx+0x48],r14
  3b3575:	48 c7 83 80 00 00 00 	mov    QWORD PTR [rbx+0x80],0x0
  3b357c:	00 00 00 00 
  3b3580:	4c 89 bb 88 00 00 00 	mov    QWORD PTR [rbx+0x88],r15
  3b3587:	c7 83 c0 01 00 00 00 	mov    DWORD PTR [rbx+0x1c0],0x0
  3b358e:	00 00 00 
  3b3591:	c7 83 d0 01 00 00 00 	mov    DWORD PTR [rbx+0x1d0],0x0
  3b3598:	00 00 00 
  3b359b:	31 d2                	xor    edx,edx
  3b359d:	31 c9                	xor    ecx,ecx
  3b359f:	e8 2c 48 11 00       	call   0x4c7dd0
  3b35a4:	48 8d 43 10          	lea    rax,[rbx+0x10]
  3b35a8:	48 8d 7b 50          	lea    rdi,[rbx+0x50]
  3b35ac:	48 8d b3 90 00 00 00 	lea    rsi,[rbx+0x90]
  3b35b3:	48 c7 43 10 00 00 00 	mov    QWORD PTR [rbx+0x10],0x0
  3b35ba:	00 
  3b35bb:	31 d2                	xor    edx,edx
  3b35bd:	31 c9                	xor    ecx,ecx
  3b35bf:	48 89 43 18          	mov    QWORD PTR [rbx+0x18],rax
  3b35c3:	48 c7 43 50 00 00 00 	mov    QWORD PTR [rbx+0x50],0x0
  3b35ca:	00 
  3b35cb:	48 89 7b 58          	mov    QWORD PTR [rbx+0x58],rdi
  3b35cf:	48 c7 83 90 00 00 00 	mov    QWORD PTR [rbx+0x90],0x0
  3b35d6:	00 00 00 00 
  3b35da:	48 89 b3 98 00 00 00 	mov    QWORD PTR [rbx+0x98],rsi
  3b35e1:	48 8d bb 18 01 00 00 	lea    rdi,[rbx+0x118]
  3b35e8:	4c 89 e6             	mov    rsi,r12
  3b35eb:	c7 83 c4 01 00 00 00 	mov    DWORD PTR [rbx+0x1c4],0x0
  3b35f2:	00 00 00 
  3b35f5:	c7 83 d4 01 00 00 00 	mov    DWORD PTR [rbx+0x1d4],0x0
  3b35fc:	00 00 00 
  3b35ff:	e8 cc 47 11 00       	call   0x4c7dd0
  3b3604:	48 8d 43 20          	lea    rax,[rbx+0x20]
  3b3608:	48 8d 7b 60          	lea    rdi,[rbx+0x60]
  3b360c:	48 8d b3 a0 00 00 00 	lea    rsi,[rbx+0xa0]
  3b3613:	48 c7 43 20 00 00 00 	mov    QWORD PTR [rbx+0x20],0x0
  3b361a:	00 
  3b361b:	31 d2                	xor    edx,edx
  3b361d:	31 c9                	xor    ecx,ecx
  3b361f:	48 89 43 28          	mov    QWORD PTR [rbx+0x28],rax
  3b3623:	48 c7 43 60 00 00 00 	mov    QWORD PTR [rbx+0x60],0x0
  3b362a:	00 
  3b362b:	48 89 7b 68          	mov    QWORD PTR [rbx+0x68],rdi
  3b362f:	48 c7 83 a0 00 00 00 	mov    QWORD PTR [rbx+0xa0],0x0
  3b3636:	00 00 00 00 
  3b363a:	48 89 b3 a8 00 00 00 	mov    QWORD PTR [rbx+0xa8],rsi
  3b3641:	48 8d bb 38 01 00 00 	lea    rdi,[rbx+0x138]
  3b3648:	4c 89 e6             	mov    rsi,r12
  3b364b:	c7 83 c8 01 00 00 00 	mov    DWORD PTR [rbx+0x1c8],0x0
  3b3652:	00 00 00 
  3b3655:	c7 83 d8 01 00 00 00 	mov    DWORD PTR [rbx+0x1d8],0x0
  3b365c:	00 00 00 
  3b365f:	e8 6c 47 11 00       	call   0x4c7dd0
  3b3664:	48 8d 43 30          	lea    rax,[rbx+0x30]
  3b3668:	4c 8d 43 70          	lea    r8,[rbx+0x70]
  3b366c:	48 8d bb b0 00 00 00 	lea    rdi,[rbx+0xb0]
  3b3673:	48 c7 43 30 00 00 00 	mov    QWORD PTR [rbx+0x30],0x0
  3b367a:	00 
  3b367b:	31 f6                	xor    esi,esi
  3b367d:	31 d2                	xor    edx,edx
  3b367f:	31 c9                	xor    ecx,ecx
  3b3681:	48 89 43 38          	mov    QWORD PTR [rbx+0x38],rax
  3b3685:	48 c7 43 70 00 00 00 	mov    QWORD PTR [rbx+0x70],0x0
  3b368c:	00 
  3b368d:	4c 89 43 78          	mov    QWORD PTR [rbx+0x78],r8
  3b3691:	48 c7 83 b0 00 00 00 	mov    QWORD PTR [rbx+0xb0],0x0
  3b3698:	00 00 00 00 
  3b369c:	48 89 bb b8 00 00 00 	mov    QWORD PTR [rbx+0xb8],rdi
  3b36a3:	48 8d 3d 3e bc 11 03 	lea    rdi,[rip+0x311bc3e]        # 0x34cf2e8
  3b36aa:	c7 83 cc 01 00 00 00 	mov    DWORD PTR [rbx+0x1cc],0x0
  3b36b1:	00 00 00 
  3b36b4:	c7 83 dc 01 00 00 00 	mov    DWORD PTR [rbx+0x1dc],0x0
  3b36bb:	00 00 00 
  3b36be:	e8 dd 38 11 00       	call   0x4c6fa0
  3b36c3:	4c 8d 3d 24 42 f3 00 	lea    r15,[rip+0xf34224]        # 0x12e78ee
  3b36ca:	4c 8d 2d d0 a3 f0 00 	lea    r13,[rip+0xf0a3d0]        # 0x12bdaa1
  3b36d1:	4c 8d 35 ea a1 eb 00 	lea    r14,[rip+0xeba1ea]        # 0x126d8c2
  3b36d8:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  3b36df:	00 
  3b36e0:	31 c0                	xor    eax,eax
  3b36e2:	48 8d b3 b0 04 00 00 	lea    rsi,[rbx+0x4b0]
  3b36e9:	48 89 9b c8 04 00 00 	mov    QWORD PTR [rbx+0x4c8],rbx
  3b36f0:	48 8d 8b b8 04 00 00 	lea    rcx,[rbx+0x4b8]
  3b36f7:	48 8d 3d 92 e0 ea ff 	lea    rdi,[rip+0xffffffffffeae092]        # 0x261790
  3b36fe:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
  3b3702:	45 31 c0             	xor    r8d,r8d
  3b3705:	45 31 c9             	xor    r9d,r9d
  3b3708:	6a 00                	push   0x0
  3b370a:	41 57                	push   r15
  3b370c:	41 55                	push   r13
  3b370e:	41 56                	push   r14
  3b3710:	e8 bb 2b 57 00       	call   0x9262d0
  3b3715:	48 83 c4 20          	add    rsp,0x20
  3b3719:	85 c0                	test   eax,eax
  3b371b:	75 54                	jne    0x3b3771
  3b371d:	48 8d b3 28 05 00 00 	lea    rsi,[rbx+0x528]
  3b3724:	48 c7 83 b0 04 00 00 	mov    QWORD PTR [rbx+0x4b0],0x0
  3b372b:	00 00 00 00 
  3b372f:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  3b3736:	00 
  3b3737:	31 c0                	xor    eax,eax
  3b3739:	48 89 9b 40 05 00 00 	mov    QWORD PTR [rbx+0x540],rbx
  3b3740:	48 8d 8b 30 05 00 00 	lea    rcx,[rbx+0x530]
  3b3747:	48 8d 3d 42 e0 ea ff 	lea    rdi,[rip+0xffffffffffeae042]        # 0x261790
  3b374e:	48 8d 55 c0          	lea    rdx,[rbp-0x40]
  3b3752:	45 31 c0             	xor    r8d,r8d
  3b3755:	45 31 c9             	xor    r9d,r9d
  3b3758:	48 89 75 b0          	mov    QWORD PTR [rbp-0x50],rsi
  3b375c:	6a 01                	push   0x1
  3b375e:	41 57                	push   r15
  3b3760:	41 55                	push   r13
  3b3762:	41 56                	push   r14
  3b3764:	e8 67 2b 57 00       	call   0x9262d0
  3b3769:	48 83 c4 20          	add    rsp,0x20
  3b376d:	85 c0                	test   eax,eax
  3b376f:	74 5a                	je     0x3b37cb
  3b3771:	4c 8d 3d 98 8b 56 03 	lea    r15,[rip+0x3568b98]        # 0x391c310
  3b3778:	48 8d 1d 69 bb 11 03 	lea    rbx,[rip+0x311bb69]        # 0x34cf2e8
  3b377f:	41 89 c4             	mov    r12d,eax
  3b3782:	31 f6                	xor    esi,esi
  3b3784:	31 d2                	xor    edx,edx
  3b3786:	31 c9                	xor    ecx,ecx
  3b3788:	48 89 df             	mov    rdi,rbx
  3b378b:	e8 70 32 11 00       	call   0x4c6a00
  3b3790:	48 8d 3d 59 bb 11 03 	lea    rdi,[rip+0x311bb59]        # 0x34cf2f0
  3b3797:	31 f6                	xor    esi,esi
  3b3799:	e8 72 b8 38 00       	call   0x73f010
  3b379e:	48 89 df             	mov    rdi,rbx
  3b37a1:	31 f6                	xor    esi,esi
  3b37a3:	31 d2                	xor    edx,edx
  3b37a5:	31 c9                	xor    ecx,ecx
  3b37a7:	e8 f4 37 11 00       	call   0x4c6fa0
  3b37ac:	49 8b 07             	mov    rax,QWORD PTR [r15]
  3b37af:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  3b37b3:	0f 85 74 02 00 00    	jne    0x3b3a2d
  3b37b9:	44 89 e0             	mov    eax,r12d
  3b37bc:	48 83 c4 38          	add    rsp,0x38
  3b37c0:	5b                   	pop    rbx
  3b37c1:	41 5c                	pop    r12
  3b37c3:	41 5d                	pop    r13
  3b37c5:	41 5e                	pop    r14
  3b37c7:	41 5f                	pop    r15
  3b37c9:	5d                   	pop    rbp
  3b37ca:	c3                   	ret
  3b37cb:	44 0f b6 65 be       	movzx  r12d,BYTE PTR [rbp-0x42]
  3b37d0:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
  3b37d4:	44 0a 65 bf          	or     r12b,BYTE PTR [rbp-0x41]
  3b37d8:	48 8d 3d 21 bb 11 03 	lea    rdi,[rip+0x311bb21]        # 0x34cf300
  3b37df:	31 f6                	xor    esi,esi
  3b37e1:	31 d2                	xor    edx,edx
  3b37e3:	31 c9                	xor    ecx,ecx
  3b37e5:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
  3b37ec:	e8 2f 83 89 00       	call   0xc4bb20
  3b37f1:	48 83 3d df d1 11 03 	cmp    QWORD PTR [rip+0x311d1df],0x0        # 0x34d09d8
  3b37f8:	00 
  3b37f9:	4c 8d 3d 10 8b 56 03 	lea    r15,[rip+0x3568b10]        # 0x391c310
  3b3800:	0f 85 57 01 00 00    	jne    0x3b395d
  3b3806:	48 8d 35 a7 12 fb 00 	lea    rsi,[rip+0xfb12a7]        # 0x1364ab4
  3b380d:	48 8d 15 0c 3b eb ff 	lea    rdx,[rip+0xffffffffffeb3b0c]        # 0x267320
  3b3814:	48 8d 0d 8c a2 f0 00 	lea    rcx,[rip+0xf0a28c]        # 0x12bdaa7
  3b381b:	41 b9 20 4e 00 00    	mov    r9d,0x4e20
  3b3821:	45 31 f6             	xor    r14d,r14d
  3b3824:	31 ff                	xor    edi,edi
  3b3826:	45 31 c0             	xor    r8d,r8d
  3b3829:	e8 12 a5 38 00       	call   0x73dd40
  3b382e:	48 8d 35 da d9 f3 00 	lea    rsi,[rip+0xf3d9da]        # 0x12f120f
  3b3835:	48 8d 15 ec 3a eb ff 	lea    rdx,[rip+0xffffffffffeb3aec]        # 0x267328
  3b383c:	48 8d 0d 54 72 ed 00 	lea    rcx,[rip+0xed7254]        # 0x128aa97
  3b3843:	41 b9 20 4e 00 00    	mov    r9d,0x4e20
  3b3849:	48 89 05 88 d1 11 03 	mov    QWORD PTR [rip+0x311d188],rax        # 0x34d09d8
  3b3850:	31 ff                	xor    edi,edi
  3b3852:	45 31 c0             	xor    r8d,r8d
  3b3855:	e8 e6 a4 38 00       	call   0x73dd40
  3b385a:	48 8d 35 0c f7 fe 00 	lea    rsi,[rip+0xfef70c]        # 0x13a2f6d
  3b3861:	48 8d 15 c8 3a eb ff 	lea    rdx,[rip+0xffffffffffeb3ac8]        # 0x267330
  3b3868:	48 8d 0d dd da f5 00 	lea    rcx,[rip+0xf5dadd]        # 0x131134c
  3b386f:	41 b9 20 4e 00 00    	mov    r9d,0x4e20
  3b3875:	48 89 05 64 d1 11 03 	mov    QWORD PTR [rip+0x311d164],rax        # 0x34d09e0
  3b387c:	31 ff                	xor    edi,edi
  3b387e:	45 31 c0             	xor    r8d,r8d
  3b3881:	e8 ba a4 38 00       	call   0x73dd40
  3b3886:	48 8d 35 11 3e f3 00 	lea    rsi,[rip+0xf33e11]        # 0x12e769e
  3b388d:	48 8d 15 d4 1e eb ff 	lea    rdx,[rip+0xffffffffffeb1ed4]        # 0x265768
  3b3894:	48 8d 0d 10 1d ee 00 	lea    rcx,[rip+0xee1d10]        # 0x12955ab
  3b389b:	41 b9 20 4e 00 00    	mov    r9d,0x4e20
  3b38a1:	48 89 05 40 d1 11 03 	mov    QWORD PTR [rip+0x311d140],rax        # 0x34d09e8
  3b38a8:	31 ff                	xor    edi,edi
  3b38aa:	45 31 c0             	xor    r8d,r8d
  3b38ad:	e8 8e a4 38 00       	call   0x73dd40
  3b38b2:	48 8d 35 6c 31 ec 00 	lea    rsi,[rip+0xec316c]        # 0x1276a25
  3b38b9:	48 8d 15 b0 1e eb ff 	lea    rdx,[rip+0xffffffffffeb1eb0]        # 0x265770
  3b38c0:	48 8d 0d bf 73 f8 00 	lea    rcx,[rip+0xf873bf]        # 0x133ac86
  3b38c7:	41 b9 20 4e 00 00    	mov    r9d,0x4e20
  3b38cd:	48 89 05 1c d1 11 03 	mov    QWORD PTR [rip+0x311d11c],rax        # 0x34d09f0
  3b38d4:	31 ff                	xor    edi,edi
  3b38d6:	45 31 c0             	xor    r8d,r8d
  3b38d9:	e8 62 a4 38 00       	call   0x73dd40
  3b38de:	48                   	rex.W
  3b38df:	8d                   	.byte 0x8d

; ===== SUPPLEMENTAL FULL SHARED CARRIER TEXT GNU objdump: handlers_b_support.text_0x8fb210.bin; not REA output =====

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handlers_b_support.text_0x8fb210.bin:     file format binary


Disassembly of section .data:

00000000008fb210 <.data>:
  8fb210:	55                   	push   rbp
  8fb211:	48 89 e5             	mov    rbp,rsp
  8fb214:	41 57                	push   r15
  8fb216:	41 56                	push   r14
  8fb218:	41 55                	push   r13
  8fb21a:	41 54                	push   r12
  8fb21c:	53                   	push   rbx
  8fb21d:	48 83 ec 48          	sub    rsp,0x48
  8fb221:	4c 8d 2d e8 10 02 03 	lea    r13,[rip+0x30210e8]        # 0x391c310
  8fb228:	41 89 f6             	mov    r14d,esi
  8fb22b:	48 89 fb             	mov    rbx,rdi
  8fb22e:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  8fb232:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fb236:	65 4c 8b 24 25 00 00 	mov    r12,QWORD PTR gs:0x0
  8fb23d:	00 00 
  8fb23f:	41 f6 84 24 ef 00 00 	test   BYTE PTR [r12+0xef],0x1
  8fb246:	00 01 
  8fb248:	74 08                	je     0x8fb252
  8fb24a:	44 89 f7             	mov    edi,r14d
  8fb24d:	e8 7e 8e b4 ff       	call   0x4440d0
  8fb252:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
  8fb256:	48 ba 00 01 00 00 00 	movabs rdx,0x200000000000100
  8fb25d:	00 00 02 
  8fb260:	31 ff                	xor    edi,edi
  8fb262:	31 c9                	xor    ecx,ecx
  8fb264:	31 c0                	xor    eax,eax
  8fb266:	e8 b5 0f 9c ff       	call   0x2bc220
  8fb26b:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
  8fb26f:	44 89 f6             	mov    esi,r14d
  8fb272:	48 89 c2             	mov    rdx,rax
  8fb275:	45 31 c0             	xor    r8d,r8d
  8fb278:	48 8b 79 48          	mov    rdi,QWORD PTR [rcx+0x48]
  8fb27c:	48 8d 4d a0          	lea    rcx,[rbp-0x60]
  8fb280:	e8 3b 02 e3 ff       	call   0x72b4c0
  8fb285:	85 c0                	test   eax,eax
  8fb287:	74 1d                	je     0x8fb2a6
  8fb289:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  8fb28d:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  8fb291:	0f 85 87 01 00 00    	jne    0x8fb41e
  8fb297:	48 83 c4 48          	add    rsp,0x48
  8fb29b:	5b                   	pop    rbx
  8fb29c:	41 5c                	pop    r12
  8fb29e:	41 5d                	pop    r13
  8fb2a0:	41 5e                	pop    r14
  8fb2a2:	41 5f                	pop    r15
  8fb2a4:	5d                   	pop    rbp
  8fb2a5:	c3                   	ret
  8fb2a6:	4c 8b 75 a0          	mov    r14,QWORD PTR [rbp-0x60]
  8fb2aa:	49 83 7e 18 00       	cmp    QWORD PTR [r14+0x18],0x0
  8fb2af:	0f 84 3a 01 00 00    	je     0x8fb3ef
  8fb2b5:	49 8b 46 08          	mov    rax,QWORD PTR [r14+0x8]
  8fb2b9:	48 3b 05 e0 1e 16 01 	cmp    rax,QWORD PTR [rip+0x1161ee0]        # 0x1a5d1a0
  8fb2c0:	0f 84 29 01 00 00    	je     0x8fb3ef
  8fb2c6:	4d 8b 7e 18          	mov    r15,QWORD PTR [r14+0x18]
  8fb2ca:	48 8d 75 98          	lea    rsi,[rbp-0x68]
  8fb2ce:	ba 01 10 00 00       	mov    edx,0x1001
  8fb2d3:	4c 89 ff             	mov    rdi,r15
  8fb2d6:	e8 15 42 db ff       	call   0x6af4f0
  8fb2db:	85 c0                	test   eax,eax
  8fb2dd:	0f 85 e4 00 00 00    	jne    0x8fb3c7
  8fb2e3:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
  8fb2e7:	48 85 c0             	test   rax,rax
  8fb2ea:	75 09                	jne    0x8fb2f5
  8fb2ec:	49 8b 47 18          	mov    rax,QWORD PTR [r15+0x18]
  8fb2f0:	48 85 c0             	test   rax,rax
  8fb2f3:	74 0e                	je     0x8fb303
  8fb2f5:	f6 80 90 00 00 00 80 	test   BYTE PTR [rax+0x90],0x80
  8fb2fc:	be 00 04 20 00       	mov    esi,0x200400
  8fb301:	75 05                	jne    0x8fb308
  8fb303:	be 00 04 08 00       	mov    esi,0x80400
  8fb308:	48 8d 15 eb a0 a7 00 	lea    rdx,[rip+0xa7a0eb]        # 0x13753fa
  8fb30f:	4c 89 ff             	mov    rdi,r15
  8fb312:	b9 3e 0e 00 00       	mov    ecx,0xe3e
  8fb317:	e8 34 48 db ff       	call   0x6afb50
  8fb31c:	41 f6 84 24 ef 00 00 	test   BYTE PTR [r12+0xef],0x1
  8fb323:	00 01 
  8fb325:	74 08                	je     0x8fb32f
  8fb327:	4c 89 ff             	mov    rdi,r15
  8fb32a:	e8 81 96 b4 ff       	call   0x4449b0
  8fb32f:	49 8b bf f8 00 00 00 	mov    rdi,QWORD PTR [r15+0xf8]
  8fb336:	48 85 ff             	test   rdi,rdi
  8fb339:	74 33                	je     0x8fb36e
  8fb33b:	48 83 c7 18          	add    rdi,0x18
  8fb33f:	31 f6                	xor    esi,esi
  8fb341:	31 d2                	xor    edx,edx
  8fb343:	e8 58 93 ed ff       	call   0x7d46a0
  8fb348:	49 8b bf f8 00 00 00 	mov    rdi,QWORD PTR [r15+0xf8]
  8fb34f:	31 f6                	xor    esi,esi
  8fb351:	31 d2                	xor    edx,edx
  8fb353:	31 c9                	xor    ecx,ecx
  8fb355:	e8 26 7a b6 ff       	call   0x462d80
  8fb35a:	49 8b bf f8 00 00 00 	mov    rdi,QWORD PTR [r15+0xf8]
  8fb361:	31 f6                	xor    esi,esi
  8fb363:	31 d2                	xor    edx,edx
  8fb365:	48 83 c7 18          	add    rdi,0x18
  8fb369:	e8 42 9b ed ff       	call   0x7d4eb0
  8fb36e:	48 8d 05 83 07 1e 01 	lea    rax,[rip+0x11e0783]        # 0x1adbaf8
  8fb375:	48 8d 75 a0          	lea    rsi,[rbp-0x60]
  8fb379:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  8fb37d:	4c 89 7d a8          	mov    QWORD PTR [rbp-0x58],r15
  8fb381:	c7 45 b0 01 00 00 00 	mov    DWORD PTR [rbp-0x50],0x1
  8fb388:	48 89 5d b8          	mov    QWORD PTR [rbp-0x48],rbx
  8fb38c:	49 8b 7f 08          	mov    rdi,QWORD PTR [r15+0x8]
  8fb390:	e8 0b 20 c9 ff       	call   0x58d3a0
  8fb395:	41 89 c4             	mov    r12d,eax
  8fb398:	48 8d 05 29 1a 1e 01 	lea    rax,[rip+0x11e1a29]        # 0x1adcdc8
  8fb39f:	48 8d 75 a0          	lea    rsi,[rbp-0x60]
  8fb3a3:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  8fb3a7:	4c 89 7d a8          	mov    QWORD PTR [rbp-0x58],r15
  8fb3ab:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [rbp-0x50],0x0
  8fb3b2:	49 8b 7f 08          	mov    rdi,QWORD PTR [r15+0x8]
  8fb3b6:	e8 d5 36 c9 ff       	call   0x58ea90
  8fb3bb:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  8fb3bf:	e8 1c 42 db ff       	call   0x6af5e0
  8fb3c4:	44 89 e0             	mov    eax,r12d
  8fb3c7:	b9 ff ff ff ff       	mov    ecx,0xffffffff
  8fb3cc:	f0 41 0f c1 4e 28    	lock xadd DWORD PTR [r14+0x28],ecx
  8fb3d2:	83 f9 01             	cmp    ecx,0x1
  8fb3d5:	0f 85 ae fe ff ff    	jne    0x8fb289
  8fb3db:	48 89 de             	mov    rsi,rbx
  8fb3de:	4c 89 f7             	mov    rdi,r14
  8fb3e1:	89 c3                	mov    ebx,eax
  8fb3e3:	e8 98 ff e2 ff       	call   0x72b380
  8fb3e8:	89 d8                	mov    eax,ebx
  8fb3ea:	e9 9a fe ff ff       	jmp    0x8fb289
  8fb3ef:	b8 16 00 00 00       	mov    eax,0x16
  8fb3f4:	b9 ff ff ff ff       	mov    ecx,0xffffffff
  8fb3f9:	f0 41 0f c1 4e 28    	lock xadd DWORD PTR [r14+0x28],ecx
  8fb3ff:	83 f9 01             	cmp    ecx,0x1
  8fb402:	0f 85 81 fe ff ff    	jne    0x8fb289
  8fb408:	48 8b 7d a0          	mov    rdi,QWORD PTR [rbp-0x60]
  8fb40c:	48 89 de             	mov    rsi,rbx
  8fb40f:	e8 6c ff e2 ff       	call   0x72b380
  8fb414:	b8 16 00 00 00       	mov    eax,0x16
  8fb419:	e9 6b fe ff ff       	jmp    0x8fb289
  8fb41e:	e8 8d 22 e0 ff       	call   0x6fd6b0
  8fb423:	0f 0b                	ud2
  8fb425:	90                   	nop
  8fb426:	90                   	nop
  8fb427:	90                   	nop
  8fb428:	90                   	nop
  8fb429:	90                   	nop
  8fb42a:	90                   	nop
  8fb42b:	90                   	nop
  8fb42c:	90                   	nop
  8fb42d:	90                   	nop
  8fb42e:	90                   	nop
  8fb42f:	90                   	nop
  8fb430:	55                   	push   rbp
  8fb431:	48 89 e5             	mov    rbp,rsp
  8fb434:	8b 36                	mov    esi,DWORD PTR [rsi]
  8fb436:	5d                   	pop    rbp
  8fb437:	e9 d4 fd ff ff       	jmp    0x8fb210
  8fb43c:	90                   	nop
  8fb43d:	90                   	nop
  8fb43e:	90                   	nop
  8fb43f:	90                   	nop
  8fb440:	55                   	push   rbp
  8fb441:	48 89 e5             	mov    rbp,rsp
  8fb444:	8b 36                	mov    esi,DWORD PTR [rsi]
  8fb446:	5d                   	pop    rbp
  8fb447:	e9 c4 fd ff ff       	jmp    0x8fb210
  8fb44c:	90                   	nop
  8fb44d:	90                   	nop
  8fb44e:	90                   	nop
  8fb44f:	90                   	nop
  8fb450:	55                   	push   rbp
  8fb451:	48 89 e5             	mov    rbp,rsp
  8fb454:	48 8b 16             	mov    rdx,QWORD PTR [rsi]
  8fb457:	4c 8b 46 08          	mov    r8,QWORD PTR [rsi+0x8]
  8fb45b:	be 9c ff ff ff       	mov    esi,0xffffff9c
  8fb460:	b9 9c ff ff ff       	mov    ecx,0xffffff9c
  8fb465:	45 31 c9             	xor    r9d,r9d
  8fb468:	5d                   	pop    rbp
  8fb469:	e9 02 00 00 00       	jmp    0x8fb470
  8fb46e:	90                   	nop
  8fb46f:	90                   	nop
  8fb470:	55                   	push   rbp
  8fb471:	48 89 e5             	mov    rbp,rsp
  8fb474:	41 57                	push   r15
  8fb476:	41 56                	push   r14
  8fb478:	41 55                	push   r13
  8fb47a:	41 54                	push   r12
  8fb47c:	53                   	push   rbx
  8fb47d:	48 81 ec 48 02 00 00 	sub    rsp,0x248
  8fb484:	48 8d 05 85 0e 02 03 	lea    rax,[rip+0x3020e85]        # 0x391c310
  8fb48b:	4c 89 85 a0 fd ff ff 	mov    QWORD PTR [rbp-0x260],r8
  8fb492:	89 8d ac fd ff ff    	mov    DWORD PTR [rbp-0x254],ecx
  8fb498:	48 89 95 98 fd ff ff 	mov    QWORD PTR [rbp-0x268],rdx
  8fb49f:	89 b5 a8 fd ff ff    	mov    DWORD PTR [rbp-0x258],esi
  8fb4a5:	45 89 cd             	mov    r13d,r9d
  8fb4a8:	49 89 fc             	mov    r12,rdi
  8fb4ab:	4c 8d bd f0 fd ff ff 	lea    r15,[rbp-0x210]
  8fb4b2:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8fb4b5:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fb4b9:	48 c7 85 b0 fd ff ff 	mov    QWORD PTR [rbp-0x250],0x0
  8fb4c0:	00 00 00 00 
  8fb4c4:	eb 2c                	jmp    0x8fb4f2
  8fb4c6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  8fb4cd:	00 00 00 
  8fb4d0:	48 8d b5 b0 fd ff ff 	lea    rsi,[rbp-0x250]
  8fb4d7:	ba 04 10 00 00       	mov    edx,0x1004
  8fb4dc:	31 ff                	xor    edi,edi
  8fb4de:	e8 0d 40 db ff       	call   0x6af4f0
  8fb4e3:	4c 8d bd f0 fd ff ff 	lea    r15,[rbp-0x210]
  8fb4ea:	85 c0                	test   eax,eax
  8fb4ec:	0f 85 b0 01 00 00    	jne    0x8fb6a2
  8fb4f2:	31 ff                	xor    edi,edi
  8fb4f4:	e8 c7 35 1a 00       	call   0xa9eac0
  8fb4f9:	4c 89 fe             	mov    rsi,r15
  8fb4fc:	48 ba 00 04 00 04 00 	movabs rdx,0x200000004000400
  8fb503:	00 00 02 
  8fb506:	31 ff                	xor    edi,edi
  8fb508:	31 c9                	xor    ecx,ecx
  8fb50a:	31 c0                	xor    eax,eax
  8fb50c:	e8 0f 0d 9c ff       	call   0x2bc220
  8fb511:	48 83 ec 08          	sub    rsp,0x8
  8fb515:	4c 8b 85 98 fd ff ff 	mov    r8,QWORD PTR [rbp-0x268]
  8fb51c:	44 8b 8d a8 fd ff ff 	mov    r9d,DWORD PTR [rbp-0x258]
  8fb523:	48 8d 9d e8 fe ff ff 	lea    rbx,[rbp-0x118]
  8fb52a:	be 02 00 00 00       	mov    esi,0x2
  8fb52f:	ba 10 10 00 04       	mov    edx,0x4001010
  8fb534:	44 89 e9             	mov    ecx,r13d
  8fb537:	48 89 df             	mov    rdi,rbx
  8fb53a:	41 54                	push   r12
  8fb53c:	50                   	push   rax
  8fb53d:	6a 00                	push   0x0
  8fb53f:	e8 9c f1 cf ff       	call   0x5fa6e0
  8fb544:	48 83 c4 20          	add    rsp,0x20
  8fb548:	48 89 df             	mov    rdi,rbx
  8fb54b:	e8 d0 d6 cf ff       	call   0x5f8c20
  8fb550:	85 c0                	test   eax,eax
  8fb552:	0f 85 4a 01 00 00    	jne    0x8fb6a2
  8fb558:	48 8b 9d 48 ff ff ff 	mov    rbx,QWORD PTR [rbp-0xb8]
  8fb55f:	48 89 df             	mov    rdi,rbx
  8fb562:	e8 89 cb ff ff       	call   0x8f80f0
  8fb567:	49 89 c6             	mov    r14,rax
  8fb56a:	4c 89 fe             	mov    rsi,r15
  8fb56d:	48 ba 00 04 00 00 00 	movabs rdx,0x200040000000400
  8fb574:	04 00 02 
  8fb577:	31 ff                	xor    edi,edi
  8fb579:	31 c9                	xor    ecx,ecx
  8fb57b:	31 c0                	xor    eax,eax
  8fb57d:	49 81 ce 2c 10 00 08 	or     r14,0x800102c
  8fb584:	e8 97 0c 9c ff       	call   0x2bc220
  8fb589:	48 83 ec 08          	sub    rsp,0x8
  8fb58d:	4c 8b 85 a0 fd ff ff 	mov    r8,QWORD PTR [rbp-0x260]
  8fb594:	44 8b 8d ac fd ff ff 	mov    r9d,DWORD PTR [rbp-0x254]
  8fb59b:	be 03 00 00 00       	mov    esi,0x3
  8fb5a0:	48 8d bd 00 fe ff ff 	lea    rdi,[rbp-0x200]
  8fb5a7:	4c 89 f2             	mov    rdx,r14
  8fb5aa:	44 89 e9             	mov    ecx,r13d
  8fb5ad:	41 54                	push   r12
  8fb5af:	50                   	push   rax
  8fb5b0:	6a 00                	push   0x0
  8fb5b2:	e8 29 f1 cf ff       	call   0x5fa6e0
  8fb5b7:	48 83 c4 20          	add    rsp,0x20
  8fb5bb:	48 8b 85 48 ff ff ff 	mov    rax,QWORD PTR [rbp-0xb8]
  8fb5c2:	83 b8 d4 01 00 00 02 	cmp    DWORD PTR [rax+0x1d4],0x2
  8fb5c9:	75 07                	jne    0x8fb5d2
  8fb5cb:	80 8d 92 fe ff ff 08 	or     BYTE PTR [rbp-0x16e],0x8
  8fb5d2:	48 8d bd 00 fe ff ff 	lea    rdi,[rbp-0x200]
  8fb5d9:	e8 42 d6 cf ff       	call   0x5f8c20
  8fb5de:	85 c0                	test   eax,eax
  8fb5e0:	0f 85 c8 00 00 00    	jne    0x8fb6ae
  8fb5e6:	45 89 ef             	mov    r15d,r13d
  8fb5e9:	4c 8b b5 60 fe ff ff 	mov    r14,QWORD PTR [rbp-0x1a0]
  8fb5f0:	4c 8b ad 68 fe ff ff 	mov    r13,QWORD PTR [rbp-0x198]
  8fb5f7:	48 89 df             	mov    rdi,rbx
  8fb5fa:	48 8d b5 b0 fd ff ff 	lea    rsi,[rbp-0x250]
  8fb601:	ba 02 00 00 00       	mov    edx,0x2
  8fb606:	e8 e5 3e db ff       	call   0x6af4f0
  8fb60b:	85 c0                	test   eax,eax
  8fb60d:	0f 84 e6 00 00 00    	je     0x8fb6f9
  8fb613:	48 8d bd e8 fe ff ff 	lea    rdi,[rbp-0x118]
  8fb61a:	be df ff ff ff       	mov    esi,0xffffffdf
  8fb61f:	e8 5c f1 cf ff       	call   0x5fa780
  8fb624:	48 8d bd 00 fe ff ff 	lea    rdi,[rbp-0x200]
  8fb62b:	be df ff ff ff       	mov    esi,0xffffffdf
  8fb630:	e8 4b f1 cf ff       	call   0x5fa780
  8fb635:	4d 85 f6             	test   r14,r14
  8fb638:	74 08                	je     0x8fb642
  8fb63a:	4c 89 f7             	mov    rdi,r14
  8fb63d:	e8 fe ed c4 ff       	call   0x54a440
  8fb642:	4c 89 ef             	mov    rdi,r13
  8fb645:	4d 39 f5             	cmp    r13,r14
  8fb648:	74 16                	je     0x8fb660
  8fb64a:	e8 f1 ed c4 ff       	call   0x54a440
  8fb64f:	eb 14                	jmp    0x8fb665
  8fb651:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fb658:	0f 1f 84 00 00 00 00 
  8fb65f:	00 
  8fb660:	e8 bb ea c4 ff       	call   0x54a120
  8fb665:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  8fb66c:	e8 af ea c4 ff       	call   0x54a120
  8fb671:	48 89 df             	mov    rdi,rbx
  8fb674:	e8 a7 ea c4 ff       	call   0x54a120
  8fb679:	48 8b bd 20 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x1e0]
  8fb680:	e8 9b ea c4 ff       	call   0x54a120
  8fb685:	48 8b bd 08 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xf8]
  8fb68c:	45 89 fd             	mov    r13d,r15d
  8fb68f:	48 85 ff             	test   rdi,rdi
  8fb692:	0f 84 38 fe ff ff    	je     0x8fb4d0
  8fb698:	e8 83 ea c4 ff       	call   0x54a120
  8fb69d:	e9 2e fe ff ff       	jmp    0x8fb4d0
  8fb6a2:	4c 8d 25 67 0c 02 03 	lea    r12,[rip+0x3020c67]        # 0x391c310
  8fb6a9:	e9 c9 01 00 00       	jmp    0x8fb877
  8fb6ae:	41 89 c7             	mov    r15d,eax
  8fb6b1:	83 f8 15             	cmp    eax,0x15
  8fb6b4:	75 12                	jne    0x8fb6c8
  8fb6b6:	45 31 ff             	xor    r15d,r15d
  8fb6b9:	83 bb d4 01 00 00 02 	cmp    DWORD PTR [rbx+0x1d4],0x2
  8fb6c0:	41 0f 94 c7          	sete   r15b
  8fb6c4:	41 83 c7 15          	add    r15d,0x15
  8fb6c8:	4c 8d 25 41 0c 02 03 	lea    r12,[rip+0x3020c41]        # 0x391c310
  8fb6cf:	48 8d bd e8 fe ff ff 	lea    rdi,[rbp-0x118]
  8fb6d6:	be df ff ff ff       	mov    esi,0xffffffdf
  8fb6db:	e8 a0 f0 cf ff       	call   0x5fa780
  8fb6e0:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  8fb6e7:	e8 34 ea c4 ff       	call   0x54a120
  8fb6ec:	48 89 df             	mov    rdi,rbx
  8fb6ef:	e8 2c ea c4 ff       	call   0x54a120
  8fb6f4:	e9 63 01 00 00       	jmp    0x8fb85c
  8fb6f9:	4c 8d 25 10 0c 02 03 	lea    r12,[rip+0x3020c10]        # 0x391c310
  8fb700:	4d 85 f6             	test   r14,r14
  8fb703:	74 2f                	je     0x8fb734
  8fb705:	83 bb d4 01 00 00 02 	cmp    DWORD PTR [rbx+0x1d4],0x2
  8fb70c:	41 8b 86 d4 01 00 00 	mov    eax,DWORD PTR [r14+0x1d4]
  8fb713:	75 10                	jne    0x8fb725
  8fb715:	41 bf 14 00 00 00    	mov    r15d,0x14
  8fb71b:	83 f8 02             	cmp    eax,0x2
  8fb71e:	74 14                	je     0x8fb734
  8fb720:	e9 c8 00 00 00       	jmp    0x8fb7ed
  8fb725:	41 bf 15 00 00 00    	mov    r15d,0x15
  8fb72b:	83 f8 02             	cmp    eax,0x2
  8fb72e:	0f 84 b9 00 00 00    	je     0x8fb7ed
  8fb734:	4c 39 eb             	cmp    rbx,r13
  8fb737:	0f 84 a2 00 00 00    	je     0x8fb7df
  8fb73d:	4c 39 f3             	cmp    rbx,r14
  8fb740:	0f 84 a1 00 00 00    	je     0x8fb7e7
  8fb746:	4c 8d 0d fb 08 1e 01 	lea    r9,[rip+0x11e08fb]        # 0x1adc048
  8fb74d:	48 8b 85 48 ff ff ff 	mov    rax,QWORD PTR [rbp-0xb8]
  8fb754:	48 8b 8d 50 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xb0]
  8fb75b:	48 8b b5 60 fe ff ff 	mov    rsi,QWORD PTR [rbp-0x1a0]
  8fb762:	48 8b bd 68 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x198]
  8fb769:	48 8d 95 70 ff ff ff 	lea    rdx,[rbp-0x90]
  8fb770:	4c 8d 85 88 fe ff ff 	lea    r8,[rbp-0x178]
  8fb777:	4c 89 8d b8 fd ff ff 	mov    QWORD PTR [rbp-0x248],r9
  8fb77e:	48 89 8d c0 fd ff ff 	mov    QWORD PTR [rbp-0x240],rcx
  8fb785:	48 89 85 c8 fd ff ff 	mov    QWORD PTR [rbp-0x238],rax
  8fb78c:	48 89 95 d0 fd ff ff 	mov    QWORD PTR [rbp-0x230],rdx
  8fb793:	48 89 bd d8 fd ff ff 	mov    QWORD PTR [rbp-0x228],rdi
  8fb79a:	48 89 b5 e0 fd ff ff 	mov    QWORD PTR [rbp-0x220],rsi
  8fb7a1:	4c 89 85 e8 fd ff ff 	mov    QWORD PTR [rbp-0x218],r8
  8fb7a8:	48 8d b5 b8 fd ff ff 	lea    rsi,[rbp-0x248]
  8fb7af:	48 8b 79 08          	mov    rdi,QWORD PTR [rcx+0x8]
  8fb7b3:	e8 a8 21 c9 ff       	call   0x58d960
  8fb7b8:	48 8d bd e8 fe ff ff 	lea    rdi,[rbp-0x118]
  8fb7bf:	be df ff ff ff       	mov    esi,0xffffffdf
  8fb7c4:	41 89 c7             	mov    r15d,eax
  8fb7c7:	e8 b4 ef cf ff       	call   0x5fa780
  8fb7cc:	48 8d bd 00 fe ff ff 	lea    rdi,[rbp-0x200]
  8fb7d3:	be df ff ff ff       	mov    esi,0xffffffdf
  8fb7d8:	e8 a3 ef cf ff       	call   0x5fa780
  8fb7dd:	eb 65                	jmp    0x8fb844
  8fb7df:	41 bf 16 00 00 00    	mov    r15d,0x16
  8fb7e5:	eb 06                	jmp    0x8fb7ed
  8fb7e7:	41 bf ff ff ff ff    	mov    r15d,0xffffffff
  8fb7ed:	48 8d bd e8 fe ff ff 	lea    rdi,[rbp-0x118]
  8fb7f4:	be df ff ff ff       	mov    esi,0xffffffdf
  8fb7f9:	e8 82 ef cf ff       	call   0x5fa780
  8fb7fe:	48 8d bd 00 fe ff ff 	lea    rdi,[rbp-0x200]
  8fb805:	be df ff ff ff       	mov    esi,0xffffffdf
  8fb80a:	e8 71 ef cf ff       	call   0x5fa780
  8fb80f:	4d 85 f6             	test   r14,r14
  8fb812:	74 08                	je     0x8fb81c
  8fb814:	4c 89 f7             	mov    rdi,r14
  8fb817:	e8 24 ec c4 ff       	call   0x54a440
  8fb81c:	4c 89 ef             	mov    rdi,r13
  8fb81f:	4d 39 f5             	cmp    r13,r14
  8fb822:	74 07                	je     0x8fb82b
  8fb824:	e8 17 ec c4 ff       	call   0x54a440
  8fb829:	eb 05                	jmp    0x8fb830
  8fb82b:	e8 f0 e8 c4 ff       	call   0x54a120
  8fb830:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  8fb837:	e8 e4 e8 c4 ff       	call   0x54a120
  8fb83c:	48 89 df             	mov    rdi,rbx
  8fb83f:	e8 dc e8 c4 ff       	call   0x54a120
  8fb844:	48 8b bd 20 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x1e0]
  8fb84b:	e8 d0 e8 c4 ff       	call   0x54a120
  8fb850:	48 8b bd b0 fd ff ff 	mov    rdi,QWORD PTR [rbp-0x250]
  8fb857:	e8 84 3d db ff       	call   0x6af5e0
  8fb85c:	48 8b bd 08 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xf8]
  8fb863:	48 85 ff             	test   rdi,rdi
  8fb866:	74 05                	je     0x8fb86d
  8fb868:	e8 b3 e8 c4 ff       	call   0x54a120
  8fb86d:	31 c0                	xor    eax,eax
  8fb86f:	41 83 ff ff          	cmp    r15d,0xffffffff
  8fb873:	41 0f 45 c7          	cmovne eax,r15d
  8fb877:	49 8b 0c 24          	mov    rcx,QWORD PTR [r12]
  8fb87b:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  8fb87f:	75 12                	jne    0x8fb893
  8fb881:	48 81 c4 48 02 00 00 	add    rsp,0x248
  8fb888:	5b                   	pop    rbx
  8fb889:	41 5c                	pop    r12
  8fb88b:	41 5d                	pop    r13
  8fb88d:	41 5e                	pop    r14
  8fb88f:	41 5f                	pop    r15
  8fb891:	5d                   	pop    rbp
  8fb892:	c3                   	ret
  8fb893:	e8 18 1e e0 ff       	call   0x6fd6b0
  8fb898:	0f 0b                	ud2
  8fb89a:	90                   	nop
  8fb89b:	90                   	nop
  8fb89c:	90                   	nop
  8fb89d:	90                   	nop
  8fb89e:	90                   	nop
  8fb89f:	90                   	nop
  8fb8a0:	55                   	push   rbp
  8fb8a1:	48 89 e5             	mov    rbp,rsp
  8fb8a4:	41 56                	push   r14
  8fb8a6:	53                   	push   rbx
  8fb8a7:	49 89 f6             	mov    r14,rsi
  8fb8aa:	be ab 02 00 00       	mov    esi,0x2ab
  8fb8af:	48 89 fb             	mov    rbx,rdi
  8fb8b2:	e8 79 41 1e 00       	call   0xadfa30
  8fb8b7:	85 c0                	test   eax,eax
  8fb8b9:	74 05                	je     0x8fb8c0
  8fb8bb:	5b                   	pop    rbx
  8fb8bc:	41 5e                	pop    r14
  8fb8be:	5d                   	pop    rbp
  8fb8bf:	c3                   	ret
  8fb8c0:	41 8b 36             	mov    esi,DWORD PTR [r14]
  8fb8c3:	49 8b 56 08          	mov    rdx,QWORD PTR [r14+0x8]
  8fb8c7:	41 8b 4e 10          	mov    ecx,DWORD PTR [r14+0x10]
  8fb8cb:	4d 8b 46 18          	mov    r8,QWORD PTR [r14+0x18]
  8fb8cf:	48 89 df             	mov    rdi,rbx
  8fb8d2:	45 31 c9             	xor    r9d,r9d
  8fb8d5:	5b                   	pop    rbx
  8fb8d6:	41 5e                	pop    r14
  8fb8d8:	5d                   	pop    rbp
  8fb8d9:	e9 92 fb ff ff       	jmp    0x8fb470
  8fb8de:	90                   	nop
  8fb8df:	90                   	nop
  8fb8e0:	55                   	push   rbp
  8fb8e1:	48 89 e5             	mov    rbp,rsp
  8fb8e4:	48 8b 16             	mov    rdx,QWORD PTR [rsi]
  8fb8e7:	44 8b 46 08          	mov    r8d,DWORD PTR [rsi+0x8]
  8fb8eb:	be 9c ff ff ff       	mov    esi,0xffffff9c
  8fb8f0:	31 c9                	xor    ecx,ecx
  8fb8f2:	5d                   	pop    rbp
  8fb8f3:	e9 08 00 00 00       	jmp    0x8fb900
  8fb8f8:	90                   	nop
  8fb8f9:	90                   	nop
  8fb8fa:	90                   	nop
  8fb8fb:	90                   	nop
  8fb8fc:	90                   	nop
  8fb8fd:	90                   	nop
  8fb8fe:	90                   	nop
  8fb8ff:	90                   	nop
  8fb900:	55                   	push   rbp
  8fb901:	48 89 e5             	mov    rbp,rsp
  8fb904:	41 57                	push   r15
  8fb906:	41 56                	push   r14
  8fb908:	41 55                	push   r13
  8fb90a:	41 54                	push   r12
  8fb90c:	53                   	push   rbx
  8fb90d:	48 81 ec e8 01 00 00 	sub    rsp,0x1e8
  8fb914:	48 8d 05 f5 09 02 03 	lea    rax,[rip+0x30209f5]        # 0x391c310
  8fb91b:	89 8d f8 fd ff ff    	mov    DWORD PTR [rbp-0x208],ecx
  8fb921:	48 89 bd f0 fd ff ff 	mov    QWORD PTR [rbp-0x210],rdi
  8fb928:	44 89 c3             	mov    ebx,r8d
  8fb92b:	49 89 d4             	mov    r12,rdx
  8fb92e:	41 89 f5             	mov    r13d,esi
  8fb931:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8fb934:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fb938:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  8fb93f:	00 00 
  8fb941:	f6 80 ef 00 00 00 01 	test   BYTE PTR [rax+0xef],0x1
  8fb948:	74 08                	je     0x8fb952
  8fb94a:	0f b7 fb             	movzx  edi,bx
  8fb94d:	e8 ee 89 b4 ff       	call   0x444340
  8fb952:	89 9d fc fd ff ff    	mov    DWORD PTR [rbp-0x204],ebx
  8fb958:	48 8d 9d e8 fe ff ff 	lea    rbx,[rbp-0x118]
  8fb95f:	4c 8d b5 a8 fe ff ff 	lea    r14,[rbp-0x158]
  8fb966:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  8fb96d:	00 00 00 
  8fb970:	31 ff                	xor    edi,edi
  8fb972:	e8 49 31 1a 00       	call   0xa9eac0
  8fb977:	48 8d b5 d8 fe ff ff 	lea    rsi,[rbp-0x128]
  8fb97e:	48 ba 00 04 80 00 00 	movabs rdx,0x200000000800400
  8fb985:	00 00 02 
  8fb988:	31 ff                	xor    edi,edi
  8fb98a:	31 c9                	xor    ecx,ecx
  8fb98c:	31 c0                	xor    eax,eax
  8fb98e:	e8 8d 08 9c ff       	call   0x2bc220
  8fb993:	48 83 ec 08          	sub    rsp,0x8
  8fb997:	8b 8d f8 fd ff ff    	mov    ecx,DWORD PTR [rbp-0x208]
  8fb99d:	be 01 00 00 00       	mov    esi,0x1
  8fb9a2:	ba 28 08 00 04       	mov    edx,0x4000828
  8fb9a7:	48 89 df             	mov    rdi,rbx
  8fb9aa:	4d 89 e0             	mov    r8,r12
  8fb9ad:	45 89 e9             	mov    r9d,r13d
  8fb9b0:	ff b5 f0 fd ff ff    	push   QWORD PTR [rbp-0x210]
  8fb9b6:	50                   	push   rax
  8fb9b7:	6a 00                	push   0x0
  8fb9b9:	e8 22 ed cf ff       	call   0x5fa6e0
  8fb9be:	48 83 c4 20          	add    rsp,0x20
  8fb9c2:	80 8d 7a ff ff ff 08 	or     BYTE PTR [rbp-0x86],0x8
  8fb9c9:	48 89 df             	mov    rdi,rbx
  8fb9cc:	e8 4f d2 cf ff       	call   0x5f8c20
  8fb9d1:	85 c0                	test   eax,eax
  8fb9d3:	75 54                	jne    0x8fba29
  8fb9d5:	4c 8b bd 48 ff ff ff 	mov    r15,QWORD PTR [rbp-0xb8]
  8fb9dc:	4d 85 ff             	test   r15,r15
  8fb9df:	75 50                	jne    0x8fba31
  8fb9e1:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  8fb9e8:	4c 89 f6             	mov    rsi,r14
  8fb9eb:	ba 02 00 00 00       	mov    edx,0x2
  8fb9f0:	e8 fb 3a db ff       	call   0x6af4f0
  8fb9f5:	85 c0                	test   eax,eax
  8fb9f7:	74 63                	je     0x8fba5c
  8fb9f9:	48 89 df             	mov    rdi,rbx
  8fb9fc:	be df ff ff ff       	mov    esi,0xffffffdf
  8fba01:	e8 7a ed cf ff       	call   0x5fa780
  8fba06:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  8fba0d:	e8 2e ea c4 ff       	call   0x54a440
  8fba12:	4c 89 f6             	mov    rsi,r14
  8fba15:	ba 04 10 00 00       	mov    edx,0x1004
  8fba1a:	31 ff                	xor    edi,edi
  8fba1c:	e8 cf 3a db ff       	call   0x6af4f0
  8fba21:	85 c0                	test   eax,eax
  8fba23:	0f 84 47 ff ff ff    	je     0x8fb970
  8fba29:	41 89 c7             	mov    r15d,eax
  8fba2c:	e9 03 01 00 00       	jmp    0x8fbb34
  8fba31:	48 8d bd e8 fe ff ff 	lea    rdi,[rbp-0x118]
  8fba38:	be df ff ff ff       	mov    esi,0xffffffdf
  8fba3d:	e8 3e ed cf ff       	call   0x5fa780
  8fba42:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  8fba49:	49 39 ff             	cmp    r15,rdi
  8fba4c:	0f 84 eb 00 00 00    	je     0x8fbb3d
  8fba52:	e8 e9 e9 c4 ff       	call   0x54a440
  8fba57:	e9 e6 00 00 00       	jmp    0x8fbb42
  8fba5c:	48 8d 9d 00 fe ff ff 	lea    rbx,[rbp-0x200]
  8fba63:	48 8d 35 26 e0 f2 02 	lea    rsi,[rip+0x2f2e026]        # 0x3829a90
  8fba6a:	ba a8 00 00 00       	mov    edx,0xa8
  8fba6f:	4c 8d b5 70 ff ff ff 	lea    r14,[rbp-0x90]
  8fba76:	48 89 df             	mov    rdi,rbx
  8fba79:	e8 32 d6 95 ff       	call   0x2590b0
  8fba7e:	48 8b 85 f0 fd ff ff 	mov    rax,QWORD PTR [rbp-0x210]
  8fba85:	c7 85 00 fe ff ff 02 	mov    DWORD PTR [rbp-0x200],0x2
  8fba8c:	00 00 00 
  8fba8f:	48 8d 0d 32 07 1e 01 	lea    rcx,[rip+0x11e0732]        # 0x1adc1c8
  8fba96:	48 8d b5 b0 fe ff ff 	lea    rsi,[rbp-0x150]
  8fba9d:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  8fbaa1:	48 8b 40 48          	mov    rax,QWORD PTR [rax+0x48]
  8fbaa5:	8b 40 30             	mov    eax,DWORD PTR [rax+0x30]
  8fbaa8:	c4 e2 78 f2 85 fc fd 	andn   eax,eax,DWORD PTR [rbp-0x204]
  8fbaaf:	ff ff 
  8fbab1:	48 89 8d b0 fe ff ff 	mov    QWORD PTR [rbp-0x150],rcx
  8fbab8:	48 8d 8d 48 ff ff ff 	lea    rcx,[rbp-0xb8]
  8fbabf:	25 ff 01 00 00       	and    eax,0x1ff
  8fbac4:	66 89 85 04 fe ff ff 	mov    WORD PTR [rbp-0x1fc],ax
  8fbacb:	48 8b 85 50 ff ff ff 	mov    rax,QWORD PTR [rbp-0xb0]
  8fbad2:	48 89 85 b8 fe ff ff 	mov    QWORD PTR [rbp-0x148],rax
  8fbad9:	48 89 8d c0 fe ff ff 	mov    QWORD PTR [rbp-0x140],rcx
  8fbae0:	4c 89 b5 c8 fe ff ff 	mov    QWORD PTR [rbp-0x138],r14
  8fbae7:	48 89 9d d0 fe ff ff 	mov    QWORD PTR [rbp-0x130],rbx
  8fbaee:	48 8b 78 08          	mov    rdi,QWORD PTR [rax+0x8]
  8fbaf2:	e8 49 20 c9 ff       	call   0x58db40
  8fbaf7:	48 8d bd e8 fe ff ff 	lea    rdi,[rbp-0x118]
  8fbafe:	be df ff ff ff       	mov    esi,0xffffffdf
  8fbb03:	41 89 c7             	mov    r15d,eax
  8fbb06:	e8 75 ec cf ff       	call   0x5fa780
  8fbb0b:	48 8b bd 50 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb0]
  8fbb12:	e8 29 e9 c4 ff       	call   0x54a440
  8fbb17:	45 85 ff             	test   r15d,r15d
  8fbb1a:	75 0c                	jne    0x8fbb28
  8fbb1c:	48 8b bd 48 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xb8]
  8fbb23:	e8 18 e9 c4 ff       	call   0x54a440
  8fbb28:	48 8b bd a8 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x158]
  8fbb2f:	e8 ac 3a db ff       	call   0x6af5e0
  8fbb34:	48 8d 1d d5 07 02 03 	lea    rbx,[rip+0x30207d5]        # 0x391c310
  8fbb3b:	eb 1a                	jmp    0x8fbb57
  8fbb3d:	e8 de e5 c4 ff       	call   0x54a120
  8fbb42:	48 8d 1d c7 07 02 03 	lea    rbx,[rip+0x30207c7]        # 0x391c310
  8fbb49:	4c 89 ff             	mov    rdi,r15
  8fbb4c:	e8 cf e5 c4 ff       	call   0x54a120
  8fbb51:	41 bf 11 00 00 00    	mov    r15d,0x11
  8fbb57:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  8fbb5a:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  8fbb5e:	75 15                	jne    0x8fbb75
  8fbb60:	44 89 f8             	mov    eax,r15d
  8fbb63:	48 81 c4 e8 01 00 00 	add    rsp,0x1e8
  8fbb6a:	5b                   	pop    rbx
  8fbb6b:	41 5c                	pop    r12
  8fbb6d:	41 5d                	pop    r13
  8fbb6f:	41 5e                	pop    r14
  8fbb71:	41 5f                	pop    r15
  8fbb73:	5d                   	pop    rbp
  8fbb74:	c3                   	ret
  8fbb75:	e8 36 1b e0 ff       	call   0x6fd6b0
  8fbb7a:	0f 0b                	ud2
  8fbb7c:	90                   	nop
  8fbb7d:	90                   	nop
  8fbb7e:	90                   	nop
  8fbb7f:	90                   	nop
  8fbb80:	55                   	push   rbp
  8fbb81:	48 89 e5             	mov    rbp,rsp
  8fbb84:	41 56                	push   r14
  8fbb86:	53                   	push   rbx
  8fbb87:	49 89 f6             	mov    r14,rsi
  8fbb8a:	be ab 02 00 00       	mov    esi,0x2ab
  8fbb8f:	48 89 fb             	mov    rbx,rdi
  8fbb92:	e8 99 3e 1e 00       	call   0xadfa30
  8fbb97:	85 c0                	test   eax,eax
  8fbb99:	74 05                	je     0x8fbba0
  8fbb9b:	5b                   	pop    rbx
  8fbb9c:	41 5e                	pop    r14
  8fbb9e:	5d                   	pop    rbp
  8fbb9f:	c3                   	ret
  8fbba0:	41 8b 36             	mov    esi,DWORD PTR [r14]
  8fbba3:	49 8b 56 08          	mov    rdx,QWORD PTR [r14+0x8]
  8fbba7:	45 0f b7 46 10       	movzx  r8d,WORD PTR [r14+0x10]
  8fbbac:	48 89 df             	mov    rdi,rbx
  8fbbaf:	31 c9                	xor    ecx,ecx
  8fbbb1:	5b                   	pop    rbx
  8fbbb2:	41 5e                	pop    r14
  8fbbb4:	5d                   	pop    rbp
  8fbbb5:	e9 46 fd ff ff       	jmp    0x8fb900
  8fbbba:	90                   	nop
  8fbbbb:	90                   	nop
  8fbbbc:	90                   	nop
  8fbbbd:	90                   	nop
  8fbbbe:	90                   	nop
  8fbbbf:	90                   	nop
  8fbbc0:	55                   	push   rbp
  8fbbc1:	48 89 e5             	mov    rbp,rsp
  8fbbc4:	48 8b 16             	mov    rdx,QWORD PTR [rsi]
  8fbbc7:	be 9c ff ff ff       	mov    esi,0xffffff9c
  8fbbcc:	31 c9                	xor    ecx,ecx
  8fbbce:	5d                   	pop    rbp
  8fbbcf:	e9 9c cc ff ff       	jmp    0x8f8870
  8fbbd4:	90                   	nop
  8fbbd5:	90                   	nop
  8fbbd6:	90                   	nop
  8fbbd7:	90                   	nop
  8fbbd8:	90                   	nop
  8fbbd9:	90                   	nop
  8fbbda:	90                   	nop
  8fbbdb:	90                   	nop
  8fbbdc:	90                   	nop
  8fbbdd:	90                   	nop
  8fbbde:	90                   	nop
  8fbbdf:	90                   	nop
  8fbbe0:	55                   	push   rbp
  8fbbe1:	48 89 e5             	mov    rbp,rsp
  8fbbe4:	41 57                	push   r15
  8fbbe6:	41 56                	push   r14
  8fbbe8:	41 55                	push   r13
  8fbbea:	41 54                	push   r12
  8fbbec:	53                   	push   rbx
  8fbbed:	48 83 ec 48          	sub    rsp,0x48
  8fbbf1:	4c 8d 3d 18 07 02 03 	lea    r15,[rip+0x3020718]        # 0x391c310
  8fbbf8:	48 89 f3             	mov    rbx,rsi
  8fbbfb:	4c 8d 45 b0          	lea    r8,[rbp-0x50]
  8fbbff:	49 89 fe             	mov    r14,rdi
  8fbc02:	45 31 c9             	xor    r9d,r9d
  8fbc05:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fbc08:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fbc0c:	8b 36                	mov    esi,DWORD PTR [rsi]
  8fbc0e:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  8fbc12:	8b 4b 10             	mov    ecx,DWORD PTR [rbx+0x10]
  8fbc15:	c7 04 24 00 00 00 00 	mov    DWORD PTR [rsp],0x0
  8fbc1c:	e8 4f 02 00 00       	call   0x8fbe70
  8fbc21:	85 c0                	test   eax,eax
  8fbc23:	0f 84 32 01 00 00    	je     0x8fbd5b
  8fbc29:	49 8b 4e 08          	mov    rcx,QWORD PTR [r14+0x8]
  8fbc2d:	41 89 c4             	mov    r12d,eax
  8fbc30:	80 b9 81 0c 00 00 00 	cmp    BYTE PTR [rcx+0xc81],0x0
  8fbc37:	0f 85 58 01 00 00    	jne    0x8fbd95
  8fbc3d:	8b 43 10             	mov    eax,DWORD PTR [rbx+0x10]
  8fbc40:	3d ff ff 00 00       	cmp    eax,0xffff
  8fbc45:	0f 87 4a 01 00 00    	ja     0x8fbd95
  8fbc4b:	41 bc 16 00 00 00    	mov    r12d,0x16
  8fbc51:	3d 00 02 00 00       	cmp    eax,0x200
  8fbc56:	0f 82 39 01 00 00    	jb     0x8fbd95
  8fbc5c:	48 8d 35 1d 04 30 02 	lea    rsi,[rip+0x230041d]        # 0x2bfc080
  8fbc63:	bf 00 00 01 00       	mov    edi,0x10000
  8fbc68:	ba 02 00 00 00       	mov    edx,0x2
  8fbc6d:	e8 de ce 30 00       	call   0xc08b50
  8fbc72:	8b 33                	mov    esi,DWORD PTR [rbx]
  8fbc74:	4c 8d 45 b0          	lea    r8,[rbp-0x50]
  8fbc78:	4c 8d 4d a8          	lea    r9,[rbp-0x58]
  8fbc7c:	4c 89 f7             	mov    rdi,r14
  8fbc7f:	48 89 c2             	mov    rdx,rax
  8fbc82:	b9 00 00 01 00       	mov    ecx,0x10000
  8fbc87:	49 89 c5             	mov    r13,rax
  8fbc8a:	c7 04 24 01 00 00 00 	mov    DWORD PTR [rsp],0x1
  8fbc91:	e8 da 01 00 00       	call   0x8fbe70
  8fbc96:	85 c0                	test   eax,eax
  8fbc98:	74 17                	je     0x8fbcb1
  8fbc9a:	48 8d 35 df 03 30 02 	lea    rsi,[rip+0x23003df]        # 0x2bfc080
  8fbca1:	4c 89 ef             	mov    rdi,r13
  8fbca4:	41 89 c4             	mov    r12d,eax
  8fbca7:	e8 44 d1 30 00       	call   0xc08df0
  8fbcac:	e9 e4 00 00 00       	jmp    0x8fbd95
  8fbcb1:	41 0f b7 45 04       	movzx  eax,WORD PTR [r13+0x4]
  8fbcb6:	8b 7b 10             	mov    edi,DWORD PTR [rbx+0x10]
  8fbcb9:	4c 89 6d a0          	mov    QWORD PTR [rbp-0x60],r13
  8fbcbd:	66 83 f8 08          	cmp    ax,0x8
  8fbcc1:	0f b7 c8             	movzx  ecx,ax
  8fbcc4:	89 fe                	mov    esi,edi
  8fbcc6:	0f 92 c2             	setb   dl
  8fbcc9:	39 cf                	cmp    edi,ecx
  8fbccb:	40 0f 92 c7          	setb   dil
  8fbccf:	40 08 d7             	or     dil,dl
  8fbcd2:	75 16                	jne    0x8fbcea
  8fbcd4:	41 0f b6 55 07       	movzx  edx,BYTE PTR [r13+0x7]
  8fbcd9:	83 c2 04             	add    edx,0x4
  8fbcdc:	83 e2 fc             	and    edx,0xfffffffc
  8fbcdf:	83 c2 08             	add    edx,0x8
  8fbce2:	39 ca                	cmp    edx,ecx
  8fbce4:	0f 86 ca 00 00 00    	jbe    0x8fbdb4
  8fbcea:	39 ce                	cmp    esi,ecx
  8fbcec:	73 1c                	jae    0x8fbd0a
  8fbcee:	41 0f b6 45 07       	movzx  eax,BYTE PTR [r13+0x7]
  8fbcf3:	83 c0 04             	add    eax,0x4
  8fbcf6:	83 e0 fc             	and    eax,0xfffffffc
  8fbcf9:	83 c0 08             	add    eax,0x8
  8fbcfc:	39 f0                	cmp    eax,esi
  8fbcfe:	73 0a                	jae    0x8fbd0a
  8fbd00:	66 41 89 75 04       	mov    WORD PTR [r13+0x4],si
  8fbd05:	49 89 f5             	mov    r13,rsi
  8fbd08:	eb 03                	jmp    0x8fbd0d
  8fbd0a:	45 31 ed             	xor    r13d,r13d
  8fbd0d:	31 c9                	xor    ecx,ecx
  8fbd0f:	4c 8b 63 08          	mov    r12,QWORD PTR [rbx+0x8]
  8fbd13:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  8fbd1a:	00 00 
  8fbd1c:	48 8d 35 74 35 a5 00 	lea    rsi,[rip+0xa53574]        # 0x134f297
  8fbd23:	31 d2                	xor    edx,edx
  8fbd25:	49 01 cd             	add    r13,rcx
  8fbd28:	e8 b3 e6 31 00       	call   0xc1a3e0
  8fbd2d:	48 8b 7d a0          	mov    rdi,QWORD PTR [rbp-0x60]
  8fbd31:	4c 89 e6             	mov    rsi,r12
  8fbd34:	4c 89 ea             	mov    rdx,r13
  8fbd37:	e8 94 d4 95 ff       	call   0x2591d0
  8fbd3c:	48 8d 35 3d 03 30 02 	lea    rsi,[rip+0x230033d]        # 0x2bfc080
  8fbd43:	48 8b 7d a0          	mov    rdi,QWORD PTR [rbp-0x60]
  8fbd47:	41 89 c4             	mov    r12d,eax
  8fbd4a:	e8 a1 d0 30 00       	call   0xc08df0
  8fbd4f:	45 85 e4             	test   r12d,r12d
  8fbd52:	75 41                	jne    0x8fbd95
  8fbd54:	4d 89 ae 08 04 00 00 	mov    QWORD PTR [r14+0x408],r13
  8fbd5b:	48 8b 5b 18          	mov    rbx,QWORD PTR [rbx+0x18]
  8fbd5f:	41 bc 00 00 00 00    	mov    r12d,0x0
  8fbd65:	48 85 db             	test   rbx,rbx
  8fbd68:	74 2b                	je     0x8fbd95
  8fbd6a:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  8fbd71:	00 00 
  8fbd73:	48 8d 35 1d 35 a5 00 	lea    rsi,[rip+0xa5351d]        # 0x134f297
  8fbd7a:	31 d2                	xor    edx,edx
  8fbd7c:	e8 5f e6 31 00       	call   0xc1a3e0
  8fbd81:	48 8d 7d b0          	lea    rdi,[rbp-0x50]
  8fbd85:	ba 08 00 00 00       	mov    edx,0x8
  8fbd8a:	48 89 de             	mov    rsi,rbx
  8fbd8d:	e8 3e d4 95 ff       	call   0x2591d0
  8fbd92:	41 89 c4             	mov    r12d,eax
  8fbd95:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fbd98:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  8fbd9c:	0f 85 bb 00 00 00    	jne    0x8fbe5d
  8fbda2:	44 89 e0             	mov    eax,r12d
  8fbda5:	48 83 c4 48          	add    rsp,0x48
  8fbda9:	5b                   	pop    rbx
  8fbdaa:	41 5c                	pop    r12
  8fbdac:	41 5d                	pop    r13
  8fbdae:	41 5e                	pop    r14
  8fbdb0:	41 5f                	pop    r15
  8fbdb2:	5d                   	pop    rbp
  8fbdb3:	c3                   	ret
  8fbdb4:	48 8b 4d a8          	mov    rcx,QWORD PTR [rbp-0x58]
  8fbdb8:	4c 89 ef             	mov    rdi,r13
  8fbdbb:	48 f7 d9             	neg    rcx
  8fbdbe:	49 8d 8c 0d 00 00 01 	lea    rcx,[r13+rcx*1+0x10000]
  8fbdc5:	00 
  8fbdc6:	45 31 ed             	xor    r13d,r13d
  8fbdc9:	48 39 cf             	cmp    rdi,rcx
  8fbdcc:	0f 83 3b ff ff ff    	jae    0x8fbd0d
  8fbdd2:	41 89 c1             	mov    r9d,eax
  8fbdd5:	0f b7 c0             	movzx  eax,ax
  8fbdd8:	48 89 fa             	mov    rdx,rdi
  8fbddb:	48 01 c7             	add    rdi,rax
  8fbdde:	49 01 c5             	add    r13,rax
  8fbde1:	0f b7 44 02 04       	movzx  eax,WORD PTR [rdx+rax*1+0x4]
  8fbde6:	48 83 f8 08          	cmp    rax,0x8
  8fbdea:	72 20                	jb     0x8fbe0c
  8fbdec:	4d 8d 44 05 00       	lea    r8,[r13+rax*1+0x0]
  8fbdf1:	49 39 f0             	cmp    r8,rsi
  8fbdf4:	7f 16                	jg     0x8fbe0c
  8fbdf6:	44 0f b6 47 07       	movzx  r8d,BYTE PTR [rdi+0x7]
  8fbdfb:	41 83 c0 04          	add    r8d,0x4
  8fbdff:	41 83 e0 fc          	and    r8d,0xfffffffc
  8fbe03:	41 83 c0 08          	add    r8d,0x8
  8fbe07:	41 39 c0             	cmp    r8d,eax
  8fbe0a:	76 bd                	jbe    0x8fbdc9
  8fbe0c:	4c 29 ee             	sub    rsi,r13
  8fbe0f:	41 01 f1             	add    r9d,esi
  8fbe12:	49 89 f4             	mov    r12,rsi
  8fbe15:	66 44 89 4a 04       	mov    WORD PTR [rdx+0x4],r9w
  8fbe1a:	e8 d1 d1 95 ff       	call   0x258ff0
  8fbe1f:	8b 03                	mov    eax,DWORD PTR [rbx]
  8fbe21:	48 8d 75 b8          	lea    rsi,[rbp-0x48]
  8fbe25:	4c 89 f7             	mov    rdi,r14
  8fbe28:	89 45 b8             	mov    DWORD PTR [rbp-0x48],eax
  8fbe2b:	48 8b 45 b0          	mov    rax,QWORD PTR [rbp-0x50]
  8fbe2f:	4c 01 e8             	add    rax,r13
  8fbe32:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  8fbe36:	c7 45 c8 00 00 00 00 	mov    DWORD PTR [rbp-0x38],0x0
  8fbe3d:	e8 6e cc ff ff       	call   0x8f8ab0
  8fbe42:	4c 89 e1             	mov    rcx,r12
  8fbe45:	85 c0                	test   eax,eax
  8fbe47:	0f 84 c2 fe ff ff    	je     0x8fbd0f
  8fbe4d:	48 8d 35 2c 02 30 02 	lea    rsi,[rip+0x230022c]        # 0x2bfc080
  8fbe54:	48 8b 7d a0          	mov    rdi,QWORD PTR [rbp-0x60]
  8fbe58:	e9 47 fe ff ff       	jmp    0x8fbca4
  8fbe5d:	e8 4e 18 e0 ff       	call   0x6fd6b0
  8fbe62:	0f 0b                	ud2
  8fbe64:	90                   	nop
  8fbe65:	90                   	nop
  8fbe66:	90                   	nop
  8fbe67:	90                   	nop
  8fbe68:	90                   	nop
  8fbe69:	90                   	nop
  8fbe6a:	90                   	nop
  8fbe6b:	90                   	nop
  8fbe6c:	90                   	nop
  8fbe6d:	90                   	nop
  8fbe6e:	90                   	nop
  8fbe6f:	90                   	nop
  8fbe70:	55                   	push   rbp
  8fbe71:	48 89 e5             	mov    rbp,rsp
  8fbe74:	41 57                	push   r15
  8fbe76:	41 56                	push   r14
  8fbe78:	41 55                	push   r13
  8fbe7a:	41 54                	push   r12
  8fbe7c:	53                   	push   rbx
  8fbe7d:	48 81 ec c8 00 00 00 	sub    rsp,0xc8
  8fbe84:	48 8d 05 85 04 02 03 	lea    rax,[rip+0x3020485]        # 0x391c310
  8fbe8b:	4c 89 8d 18 ff ff ff 	mov    QWORD PTR [rbp-0xe8],r9
  8fbe92:	4c 89 85 20 ff ff ff 	mov    QWORD PTR [rbp-0xe0],r8
  8fbe99:	41 89 cf             	mov    r15d,ecx
  8fbe9c:	49 89 d5             	mov    r13,rdx
  8fbe9f:	41 89 f6             	mov    r14d,esi
  8fbea2:	48 89 fb             	mov    rbx,rdi
  8fbea5:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8fbea8:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fbeac:	65 4c 8b 24 25 00 00 	mov    r12,QWORD PTR gs:0x0
  8fbeb3:	00 00 
  8fbeb5:	41 f6 84 24 ef 00 00 	test   BYTE PTR [r12+0xef],0x1
  8fbebc:	00 01 
  8fbebe:	74 08                	je     0x8fbec8
  8fbec0:	44 89 f7             	mov    edi,r14d
  8fbec3:	e8 08 82 b4 ff       	call   0x4440d0
  8fbec8:	45 89 ff             	mov    r15d,r15d
  8fbecb:	e8 e0 00 bf ff       	call   0x4ebfb0
  8fbed0:	48 89 c1             	mov    rcx,rax
  8fbed3:	b8 16 00 00 00       	mov    eax,0x16
  8fbed8:	4c 39 f9             	cmp    rcx,r15
  8fbedb:	72 3e                	jb     0x8fbf1b
  8fbedd:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
  8fbee1:	48 ba 01 00 00 00 00 	movabs rdx,0x200000000000001
  8fbee8:	00 00 02 
  8fbeeb:	4c 89 bd 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],r15
  8fbef2:	31 ff                	xor    edi,edi
  8fbef4:	31 c9                	xor    ecx,ecx
  8fbef6:	31 c0                	xor    eax,eax
  8fbef8:	e8 23 03 9c ff       	call   0x2bc220
  8fbefd:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
  8fbf01:	44 89 f6             	mov    esi,r14d
  8fbf04:	48 89 c2             	mov    rdx,rax
  8fbf07:	45 31 c0             	xor    r8d,r8d
  8fbf0a:	48 8b 79 48          	mov    rdi,QWORD PTR [rcx+0x48]
  8fbf0e:	48 8d 4d 88          	lea    rcx,[rbp-0x78]
  8fbf12:	e8 a9 f5 e2 ff       	call   0x72b4c0
  8fbf17:	85 c0                	test   eax,eax
  8fbf19:	74 26                	je     0x8fbf41
  8fbf1b:	48 8d 0d ee 03 02 03 	lea    rcx,[rip+0x30203ee]        # 0x391c310
  8fbf22:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  8fbf25:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  8fbf29:	0f 85 58 04 00 00    	jne    0x8fc387
  8fbf2f:	48 81 c4 c8 00 00 00 	add    rsp,0xc8
  8fbf36:	5b                   	pop    rbx
  8fbf37:	41 5c                	pop    r12
  8fbf39:	41 5d                	pop    r13
  8fbf3b:	41 5e                	pop    r14
  8fbf3d:	41 5f                	pop    r15
  8fbf3f:	5d                   	pop    rbp
  8fbf40:	c3                   	ret
  8fbf41:	4c 8b 75 88          	mov    r14,QWORD PTR [rbp-0x78]
  8fbf45:	49 83 7e 18 00       	cmp    QWORD PTR [r14+0x18],0x0
  8fbf4a:	74 3c                	je     0x8fbf88
  8fbf4c:	49 8b 46 08          	mov    rax,QWORD PTR [r14+0x8]
  8fbf50:	48 3b 05 49 12 16 01 	cmp    rax,QWORD PTR [rip+0x1161249]        # 0x1a5d1a0
  8fbf57:	74 2f                	je     0x8fbf88
  8fbf59:	41 8b 46 24          	mov    eax,DWORD PTR [r14+0x24]
  8fbf5d:	a8 01                	test   al,0x1
  8fbf5f:	75 56                	jne    0x8fbfb7
  8fbf61:	b8 09 00 00 00       	mov    eax,0x9
  8fbf66:	b9 ff ff ff ff       	mov    ecx,0xffffffff
  8fbf6b:	f0 41 0f c1 4e 28    	lock xadd DWORD PTR [r14+0x28],ecx
  8fbf71:	83 f9 01             	cmp    ecx,0x1
  8fbf74:	75 a5                	jne    0x8fbf1b
  8fbf76:	4c 89 f7             	mov    rdi,r14
  8fbf79:	48 89 de             	mov    rsi,rbx
  8fbf7c:	e8 ff f3 e2 ff       	call   0x72b380
  8fbf81:	b8 09 00 00 00       	mov    eax,0x9
  8fbf86:	eb 93                	jmp    0x8fbf1b
  8fbf88:	b8 16 00 00 00       	mov    eax,0x16
  8fbf8d:	b9 ff ff ff ff       	mov    ecx,0xffffffff
  8fbf92:	f0 41 0f c1 4e 28    	lock xadd DWORD PTR [r14+0x28],ecx
  8fbf98:	83 f9 01             	cmp    ecx,0x1
  8fbf9b:	0f 85 7a ff ff ff    	jne    0x8fbf1b
  8fbfa1:	48 8b 7d 88          	mov    rdi,QWORD PTR [rbp-0x78]
  8fbfa5:	48 89 de             	mov    rsi,rbx
  8fbfa8:	e8 d3 f3 e2 ff       	call   0x72b380
  8fbfad:	b8 16 00 00 00       	mov    eax,0x16
  8fbfb2:	e9 64 ff ff ff       	jmp    0x8fbf1b
  8fbfb7:	49 8b 46 18          	mov    rax,QWORD PTR [r14+0x18]
  8fbfbb:	4c 89 f7             	mov    rdi,r14
  8fbfbe:	31 f6                	xor    esi,esi
  8fbfc0:	48 89 85 38 ff ff ff 	mov    QWORD PTR [rbp-0xc8],rax
  8fbfc7:	e8 f4 46 db ff       	call   0x6b06c0
  8fbfcc:	48 8b b5 38 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xc8]
  8fbfd3:	c7 85 40 ff ff ff 16 	mov    DWORD PTR [rbp-0xc0],0x16
  8fbfda:	00 00 00 
  8fbfdd:	83 be d4 01 00 00 02 	cmp    DWORD PTR [rsi+0x1d4],0x2
  8fbfe4:	0f 85 19 01 00 00    	jne    0x8fc103
  8fbfea:	48 89 85 28 ff ff ff 	mov    QWORD PTR [rbp-0xd8],rax
  8fbff1:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
  8fbff4:	48 8d 8d 48 ff ff ff 	lea    rcx,[rbp-0xb8]
  8fbffb:	48 89 f7             	mov    rdi,rsi
  8fbffe:	48 8d 15 f5 93 a7 00 	lea    rdx,[rip+0xa793f5]        # 0x13753fa
  8fc005:	be 00 04 20 00       	mov    esi,0x200400
  8fc00a:	4c 89 ad 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],r13
  8fc011:	4c 89 bd 50 ff ff ff 	mov    QWORD PTR [rbp-0xb0],r15
  8fc018:	48 89 8d 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],rcx
  8fc01f:	b9 f0 10 00 00       	mov    ecx,0x10f0
  8fc024:	c7 85 60 ff ff ff 01 	mov    DWORD PTR [rbp-0xa0],0x1
  8fc02b:	00 00 00 
  8fc02e:	c7 85 7c ff ff ff 00 	mov    DWORD PTR [rbp-0x84],0x0
  8fc035:	00 00 00 
  8fc038:	89 85 78 ff ff ff    	mov    DWORD PTR [rbp-0x88],eax
  8fc03e:	48 89 5d 80          	mov    QWORD PTR [rbp-0x80],rbx
  8fc042:	e8 09 3b db ff       	call   0x6afb50
  8fc047:	41 f6 84 24 ef 00 00 	test   BYTE PTR [r12+0xef],0x1
  8fc04e:	00 01 
  8fc050:	74 0c                	je     0x8fc05e
  8fc052:	48 8b bd 38 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xc8]
  8fc059:	e8 52 89 b4 ff       	call   0x4449b0
  8fc05e:	48 8b 85 28 ff ff ff 	mov    rax,QWORD PTR [rbp-0xd8]
  8fc065:	48 8d 0d dc 05 1e 01 	lea    rcx,[rip+0x11e05dc]        # 0x1adc648
  8fc06c:	48 8b 95 38 ff ff ff 	mov    rdx,QWORD PTR [rbp-0xc8]
  8fc073:	48 8d 75 88          	lea    rsi,[rbp-0x78]
  8fc077:	48 89 85 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],rax
  8fc07e:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
  8fc082:	48 89 4d 88          	mov    QWORD PTR [rbp-0x78],rcx
  8fc086:	48 8d 8d 58 ff ff ff 	lea    rcx,[rbp-0xa8]
  8fc08d:	48 89 55 90          	mov    QWORD PTR [rbp-0x70],rdx
  8fc091:	48 89 4d 98          	mov    QWORD PTR [rbp-0x68],rcx
  8fc095:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  8fc099:	48 8d 85 44 ff ff ff 	lea    rax,[rbp-0xbc]
  8fc0a0:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
  8fc0a4:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
  8fc0ab:	00 
  8fc0ac:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
  8fc0b3:	00 
  8fc0b4:	48 8b 7a 08          	mov    rdi,QWORD PTR [rdx+0x8]
  8fc0b8:	e8 53 20 c9 ff       	call   0x58e110
  8fc0bd:	48 8b 8d 68 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x98]
  8fc0c4:	85 c0                	test   eax,eax
  8fc0c6:	74 43                	je     0x8fc10b
  8fc0c8:	49 89 cf             	mov    r15,rcx
  8fc0cb:	48 8b 8d 38 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xc8]
  8fc0d2:	89 85 40 ff ff ff    	mov    DWORD PTR [rbp-0xc0],eax
  8fc0d8:	48 8d 05 e9 0c 1e 01 	lea    rax,[rip+0x11e0ce9]        # 0x1adcdc8
  8fc0df:	48 8d 75 88          	lea    rsi,[rbp-0x78]
  8fc0e3:	48 89 45 88          	mov    QWORD PTR [rbp-0x78],rax
  8fc0e7:	48 89 4d 90          	mov    QWORD PTR [rbp-0x70],rcx
  8fc0eb:	c7 45 98 00 00 00 00 	mov    DWORD PTR [rbp-0x68],0x0
  8fc0f2:	48 8b 79 08          	mov    rdi,QWORD PTR [rcx+0x8]
  8fc0f6:	e8 95 29 c9 ff       	call   0x58ea90
  8fc0fb:	4c 89 fe             	mov    rsi,r15
  8fc0fe:	e9 39 02 00 00       	jmp    0x8fc33c
  8fc103:	48 89 c6             	mov    rsi,rax
  8fc106:	e9 31 02 00 00       	jmp    0x8fc33c
  8fc10b:	4c 39 bd 70 ff ff ff 	cmp    QWORD PTR [rbp-0x90],r15
  8fc112:	0f 85 b9 01 00 00    	jne    0x8fc2d1
  8fc118:	48 8b 95 38 ff ff ff 	mov    rdx,QWORD PTR [rbp-0xc8]
  8fc11f:	f6 82 c8 01 00 00 01 	test   BYTE PTR [rdx+0x1c8],0x1
  8fc126:	0f 84 ac 01 00 00    	je     0x8fc2d8
  8fc12c:	48 8b 42 18          	mov    rax,QWORD PTR [rdx+0x18]
  8fc130:	f6 80 98 00 00 00 20 	test   BYTE PTR [rax+0x98],0x20
  8fc137:	0f 84 9b 01 00 00    	je     0x8fc2d8
  8fc13d:	48 8b 78 48          	mov    rdi,QWORD PTR [rax+0x48]
  8fc141:	48 89 bd 30 ff ff ff 	mov    QWORD PTR [rbp-0xd0],rdi
  8fc148:	e8 13 df c4 ff       	call   0x54a060
  8fc14d:	48 8b 85 30 ff ff ff 	mov    rax,QWORD PTR [rbp-0xd0]
  8fc154:	48 8b bd 38 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xc8]
  8fc15b:	49 89 46 18          	mov    QWORD PTR [r14+0x18],rax
  8fc15f:	49 89 06             	mov    QWORD PTR [r14],rax
  8fc162:	e8 d9 e2 c4 ff       	call   0x54a440
  8fc167:	48 8b 8d 30 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xd0]
  8fc16e:	83 b9 d4 01 00 00 02 	cmp    DWORD PTR [rcx+0x1d4],0x2
  8fc175:	0f 85 52 01 00 00    	jne    0x8fc2cd
  8fc17b:	48 c7 85 28 ff ff ff 	mov    QWORD PTR [rbp-0xd8],0x0
  8fc182:	00 00 00 00 
  8fc186:	48 8d 85 48 ff ff ff 	lea    rax,[rbp-0xb8]
  8fc18d:	48 89 cf             	mov    rdi,rcx
  8fc190:	48 89 8d 30 ff ff ff 	mov    QWORD PTR [rbp-0xd0],rcx
  8fc197:	be 00 04 20 00       	mov    esi,0x200400
  8fc19c:	48 8d 15 57 92 a7 00 	lea    rdx,[rip+0xa79257]        # 0x13753fa
  8fc1a3:	b9 f0 10 00 00       	mov    ecx,0x10f0
  8fc1a8:	4c 89 ad 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],r13
  8fc1af:	4c 89 bd 50 ff ff ff 	mov    QWORD PTR [rbp-0xb0],r15
  8fc1b6:	48 89 85 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],rax
  8fc1bd:	8b 45 10             	mov    eax,DWORD PTR [rbp+0x10]
  8fc1c0:	c7 85 60 ff ff ff 01 	mov    DWORD PTR [rbp-0xa0],0x1
  8fc1c7:	00 00 00 
  8fc1ca:	c7 85 7c ff ff ff 00 	mov    DWORD PTR [rbp-0x84],0x0
  8fc1d1:	00 00 00 
  8fc1d4:	89 85 78 ff ff ff    	mov    DWORD PTR [rbp-0x88],eax
  8fc1da:	48 89 5d 80          	mov    QWORD PTR [rbp-0x80],rbx
  8fc1de:	e8 6d 39 db ff       	call   0x6afb50
  8fc1e3:	41 f6 84 24 ef 00 00 	test   BYTE PTR [r12+0xef],0x1
  8fc1ea:	00 01 
  8fc1ec:	74 0c                	je     0x8fc1fa
  8fc1ee:	48 8b bd 30 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xd0]
  8fc1f5:	e8 b6 87 b4 ff       	call   0x4449b0
  8fc1fa:	48 c7 85 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],0x0
  8fc201:	00 00 00 00 
  8fc205:	48 8d 0d 3c 04 1e 01 	lea    rcx,[rip+0x11e043c]        # 0x1adc648
  8fc20c:	48 8b 95 30 ff ff ff 	mov    rdx,QWORD PTR [rbp-0xd0]
  8fc213:	48 8d b5 58 ff ff ff 	lea    rsi,[rbp-0xa8]
  8fc21a:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
  8fc21e:	48 89 4d 88          	mov    QWORD PTR [rbp-0x78],rcx
  8fc222:	48 89 55 90          	mov    QWORD PTR [rbp-0x70],rdx
  8fc226:	48 89 75 98          	mov    QWORD PTR [rbp-0x68],rsi
  8fc22a:	48 8d 75 88          	lea    rsi,[rbp-0x78]
  8fc22e:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  8fc232:	48 8d 85 44 ff ff ff 	lea    rax,[rbp-0xbc]
  8fc239:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
  8fc23d:	48 c7 45 b0 00 00 00 	mov    QWORD PTR [rbp-0x50],0x0
  8fc244:	00 
  8fc245:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
  8fc24c:	00 
  8fc24d:	48 8b 7a 08          	mov    rdi,QWORD PTR [rdx+0x8]
  8fc251:	e8 ba 1e c9 ff       	call   0x58e110
  8fc256:	48 8b 8d 68 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x98]
  8fc25d:	85 c0                	test   eax,eax
  8fc25f:	0f 85 07 01 00 00    	jne    0x8fc36c
  8fc265:	4c 39 bd 70 ff ff ff 	cmp    QWORD PTR [rbp-0x90],r15
  8fc26c:	0f 85 09 01 00 00    	jne    0x8fc37b
  8fc272:	48 8b 95 30 ff ff ff 	mov    rdx,QWORD PTR [rbp-0xd0]
  8fc279:	f6 82 c8 01 00 00 01 	test   BYTE PTR [rdx+0x1c8],0x1
  8fc280:	74 56                	je     0x8fc2d8
  8fc282:	48 8b 42 18          	mov    rax,QWORD PTR [rdx+0x18]
  8fc286:	f6 80 98 00 00 00 20 	test   BYTE PTR [rax+0x98],0x20
  8fc28d:	74 49                	je     0x8fc2d8
  8fc28f:	48 8b 78 48          	mov    rdi,QWORD PTR [rax+0x48]
  8fc293:	48 89 bd 38 ff ff ff 	mov    QWORD PTR [rbp-0xc8],rdi
  8fc29a:	e8 c1 dd c4 ff       	call   0x54a060
  8fc29f:	48 8b 85 38 ff ff ff 	mov    rax,QWORD PTR [rbp-0xc8]
  8fc2a6:	48 8b bd 30 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xd0]
  8fc2ad:	49 89 46 18          	mov    QWORD PTR [r14+0x18],rax
  8fc2b1:	49 89 06             	mov    QWORD PTR [r14],rax
  8fc2b4:	e8 87 e1 c4 ff       	call   0x54a440
  8fc2b9:	48 8b 8d 38 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xc8]
  8fc2c0:	83 b9 d4 01 00 00 02 	cmp    DWORD PTR [rcx+0x1d4],0x2
  8fc2c7:	0f 84 b9 fe ff ff    	je     0x8fc186
  8fc2cd:	31 f6                	xor    esi,esi
  8fc2cf:	eb 6b                	jmp    0x8fc33c
  8fc2d1:	48 8b 95 38 ff ff ff 	mov    rdx,QWORD PTR [rbp-0xc8]
  8fc2d8:	49 89 cc             	mov    r12,rcx
  8fc2db:	48 8d 05 e6 0a 1e 01 	lea    rax,[rip+0x11e0ae6]        # 0x1adcdc8
  8fc2e2:	48 8d 75 88          	lea    rsi,[rbp-0x78]
  8fc2e6:	48 89 45 88          	mov    QWORD PTR [rbp-0x78],rax
  8fc2ea:	48 89 55 90          	mov    QWORD PTR [rbp-0x70],rdx
  8fc2ee:	c7 45 98 00 00 00 00 	mov    DWORD PTR [rbp-0x68],0x0
  8fc2f5:	48 8b 7a 08          	mov    rdi,QWORD PTR [rdx+0x8]
  8fc2f9:	e8 92 27 c9 ff       	call   0x58ea90
  8fc2fe:	48 8b 85 20 ff ff ff 	mov    rax,QWORD PTR [rbp-0xe0]
  8fc305:	48 8b 8d 28 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xd8]
  8fc30c:	48 89 08             	mov    QWORD PTR [rax],rcx
  8fc30f:	48 8b 8d 18 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xe8]
  8fc316:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
  8fc31d:	48 85 c9             	test   rcx,rcx
  8fc320:	74 03                	je     0x8fc325
  8fc322:	48 89 01             	mov    QWORD PTR [rcx],rax
  8fc325:	49 29 c7             	sub    r15,rax
  8fc328:	c7 85 40 ff ff ff 00 	mov    DWORD PTR [rbp-0xc0],0x0
  8fc32f:	00 00 00 
  8fc332:	4c 89 e6             	mov    rsi,r12
  8fc335:	4c 89 bb 08 04 00 00 	mov    QWORD PTR [rbx+0x408],r15
  8fc33c:	4c 89 f7             	mov    rdi,r14
  8fc33f:	31 d2                	xor    edx,edx
  8fc341:	e8 4a 44 db ff       	call   0x6b0790
  8fc346:	b8 ff ff ff ff       	mov    eax,0xffffffff
  8fc34b:	f0 41 0f c1 46 28    	lock xadd DWORD PTR [r14+0x28],eax
  8fc351:	83 f8 01             	cmp    eax,0x1
  8fc354:	75 0b                	jne    0x8fc361
  8fc356:	4c 89 f7             	mov    rdi,r14
  8fc359:	48 89 de             	mov    rsi,rbx
  8fc35c:	e8 1f f0 e2 ff       	call   0x72b380
  8fc361:	8b 85 40 ff ff ff    	mov    eax,DWORD PTR [rbp-0xc0]
  8fc367:	e9 af fb ff ff       	jmp    0x8fbf1b
  8fc36c:	49 89 cf             	mov    r15,rcx
  8fc36f:	48 8b 8d 30 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xd0]
  8fc376:	e9 57 fd ff ff       	jmp    0x8fc0d2
  8fc37b:	48 8b 95 30 ff ff ff 	mov    rdx,QWORD PTR [rbp-0xd0]
  8fc382:	e9 51 ff ff ff       	jmp    0x8fc2d8
  8fc387:	e8 24 13 e0 ff       	call   0x6fd6b0
  8fc38c:	0f 0b                	ud2
  8fc38e:	90                   	nop
  8fc38f:	90                   	nop
  8fc390:	55                   	push   rbp
  8fc391:	48 89 e5             	mov    rbp,rsp
  8fc394:	53                   	push   rbx
  8fc395:	48 83 ec 28          	sub    rsp,0x28
  8fc399:	48 8d 1d 70 ff 01 03 	lea    rbx,[rip+0x301ff70]        # 0x391c310
  8fc3a0:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  8fc3a3:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  8fc3a7:	8b 06                	mov    eax,DWORD PTR [rsi]
  8fc3a9:	89 45 d0             	mov    DWORD PTR [rbp-0x30],eax
  8fc3ac:	48 8b 46 08          	mov    rax,QWORD PTR [rsi+0x8]
  8fc3b0:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  8fc3b4:	8b 46 10             	mov    eax,DWORD PTR [rsi+0x10]
  8fc3b7:	48 8d 75 d0          	lea    rsi,[rbp-0x30]
  8fc3bb:	89 45 e0             	mov    DWORD PTR [rbp-0x20],eax
  8fc3be:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
  8fc3c5:	00 
  8fc3c6:	e8 15 f8 ff ff       	call   0x8fbbe0
  8fc3cb:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
  8fc3ce:	48 3b 4d f0          	cmp    rcx,QWORD PTR [rbp-0x10]
  8fc3d2:	75 07                	jne    0x8fc3db
  8fc3d4:	48 83 c4 28          	add    rsp,0x28
  8fc3d8:	5b                   	pop    rbx
  8fc3d9:	5d                   	pop    rbp
  8fc3da:	c3                   	ret
  8fc3db:	e8 d0 12 e0 ff       	call   0x6fd6b0
  8fc3e0:	0f 0b                	ud2
  8fc3e2:	90                   	nop
  8fc3e3:	90                   	nop
  8fc3e4:	90                   	nop
  8fc3e5:	90                   	nop
  8fc3e6:	90                   	nop
  8fc3e7:	90                   	nop
  8fc3e8:	90                   	nop
  8fc3e9:	90                   	nop
  8fc3ea:	90                   	nop
  8fc3eb:	90                   	nop
  8fc3ec:	90                   	nop
  8fc3ed:	90                   	nop
  8fc3ee:	90                   	nop
  8fc3ef:	90                   	nop
  8fc3f0:	55                   	push   rbp
  8fc3f1:	48 89 e5             	mov    rbp,rsp
  8fc3f4:	41 57                	push   r15
  8fc3f6:	41 56                	push   r14
  8fc3f8:	41 55                	push   r13
  8fc3fa:	41 54                	push   r12
  8fc3fc:	53                   	push   rbx
  8fc3fd:	50                   	push   rax
  8fc3fe:	8b 0e                	mov    ecx,DWORD PTR [rsi]
  8fc400:	48 89 f3             	mov    rbx,rsi
  8fc403:	49 89 fe             	mov    r14,rdi
  8fc406:	85 c9                	test   ecx,ecx
  8fc408:	74 1a                	je     0x8fc424
  8fc40a:	48 8d 3d 6a fa a2 00 	lea    rdi,[rip+0xa2fa6a]        # 0x132be7b
  8fc411:	48 8d 35 e9 3e 99 00 	lea    rsi,[rip+0x993ee9]        # 0x1290301
  8fc418:	ba 41 11 00 00       	mov    edx,0x1141
  8fc41d:	31 c0                	xor    eax,eax
  8fc41f:	e8 ec 0f 96 ff       	call   0x25d410
  8fc424:	4c 89 f7             	mov    rdi,r14
  8fc427:	be ab 02 00 00       	mov    esi,0x2ab
  8fc42c:	e8 ff 35 1e 00       	call   0xadfa30
  8fc431:	85 c0                	test   eax,eax
  8fc433:	75 45                	jne    0x8fc47a
  8fc435:	49 8b 4e 08          	mov    rcx,QWORD PTR [r14+0x8]
  8fc439:	31 f6                	xor    esi,esi
  8fc43b:	31 d2                	xor    edx,edx
  8fc43d:	41 89 c4             	mov    r12d,eax
  8fc440:	4c 8b 69 48          	mov    r13,QWORD PTR [rcx+0x48]
  8fc444:	31 c9                	xor    ecx,ecx
  8fc446:	4d 8d 7d 40          	lea    r15,[r13+0x40]
  8fc44a:	4c 89 ff             	mov    rdi,r15
  8fc44d:	e8 ce f6 34 00       	call   0xc4bb20
  8fc452:	41 0f b7 45 30       	movzx  eax,WORD PTR [r13+0x30]
  8fc457:	4c 89 ff             	mov    rdi,r15
  8fc45a:	31 f6                	xor    esi,esi
  8fc45c:	31 d2                	xor    edx,edx
  8fc45e:	49 89 86 08 04 00 00 	mov    QWORD PTR [r14+0x408],rax
  8fc465:	0f b7 03             	movzx  eax,WORD PTR [rbx]
  8fc468:	25 ff 0f 00 00       	and    eax,0xfff
  8fc46d:	66 41 89 45 30       	mov    WORD PTR [r13+0x30],ax
  8fc472:	e8 39 00 35 00       	call   0xc4c4b0
  8fc477:	44 89 e0             	mov    eax,r12d
  8fc47a:	48 83 c4 08          	add    rsp,0x8
  8fc47e:	5b                   	pop    rbx
  8fc47f:	41 5c                	pop    r12
  8fc481:	41 5d                	pop    r13
  8fc483:	41 5e                	pop    r14
  8fc485:	41 5f                	pop    r15
  8fc487:	5d                   	pop    rbp
  8fc488:	c3                   	ret
  8fc489:	90                   	nop
  8fc48a:	90                   	nop
  8fc48b:	90                   	nop
  8fc48c:	90                   	nop
  8fc48d:	90                   	nop
  8fc48e:	90                   	nop
  8fc48f:	90                   	nop
  8fc490:	55                   	push   rbp
  8fc491:	48 89 e5             	mov    rbp,rsp
  8fc494:	41 57                	push   r15
  8fc496:	41 56                	push   r14
  8fc498:	53                   	push   rbx
  8fc499:	48 81 ec b8 01 00 00 	sub    rsp,0x1b8
  8fc4a0:	4c 8d 3d 69 fe 01 03 	lea    r15,[rip+0x301fe69]        # 0x391c310
  8fc4a7:	48 89 f3             	mov    rbx,rsi
  8fc4aa:	be ab 02 00 00       	mov    esi,0x2ab
  8fc4af:	49 89 fe             	mov    r14,rdi
  8fc4b2:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fc4b5:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  8fc4b9:	e8 72 35 1e 00       	call   0xadfa30
  8fc4be:	85 c0                	test   eax,eax
  8fc4c0:	0f 85 b9 00 00 00    	jne    0x8fc57f
  8fc4c6:	4c 8b 03             	mov    r8,QWORD PTR [rbx]
  8fc4c9:	48 83 ec 08          	sub    rsp,0x8
  8fc4cd:	48 8d 9d f8 fe ff ff 	lea    rbx,[rbp-0x108]
  8fc4d4:	ba 44 00 00 04       	mov    edx,0x4000044
  8fc4d9:	31 f6                	xor    esi,esi
  8fc4db:	31 c9                	xor    ecx,ecx
  8fc4dd:	41 b9 9c ff ff ff    	mov    r9d,0xffffff9c
  8fc4e3:	48 89 df             	mov    rdi,rbx
  8fc4e6:	41 56                	push   r14
  8fc4e8:	6a 00                	push   0x0
  8fc4ea:	6a 00                	push   0x0
  8fc4ec:	e8 ef e1 cf ff       	call   0x5fa6e0
  8fc4f1:	48 83 c4 20          	add    rsp,0x20
  8fc4f5:	48 89 df             	mov    rdi,rbx
  8fc4f8:	e8 23 c7 cf ff       	call   0x5f8c20
  8fc4fd:	85 c0                	test   eax,eax
  8fc4ff:	75 7e                	jne    0x8fc57f
  8fc501:	48 8b 9d 58 ff ff ff 	mov    rbx,QWORD PTR [rbp-0xa8]
  8fc508:	48 8d bd f8 fe ff ff 	lea    rdi,[rbp-0x108]
  8fc50f:	be df ff ff ff       	mov    esi,0xffffffdf
  8fc514:	e8 67 e2 cf ff       	call   0x5fa780
  8fc519:	83 bb d4 01 00 00 04 	cmp    DWORD PTR [rbx+0x1d4],0x4
  8fc520:	b8 16 00 00 00       	mov    eax,0x16
  8fc525:	75 4c                	jne    0x8fc573
  8fc527:	48 83 7b 30 00       	cmp    QWORD PTR [rbx+0x30],0x0
  8fc52c:	74 45                	je     0x8fc573
  8fc52e:	49 8b 86 40 01 00 00 	mov    rax,QWORD PTR [r14+0x140]
  8fc535:	48 8d 0d 3c e8 1d 01 	lea    rcx,[rip+0x11de83c]        # 0x1adad78
  8fc53c:	48 8d 95 30 fe ff ff 	lea    rdx,[rbp-0x1d0]
  8fc543:	48 8d b5 d8 fe ff ff 	lea    rsi,[rbp-0x128]
  8fc54a:	48 89 8d d8 fe ff ff 	mov    QWORD PTR [rbp-0x128],rcx
  8fc551:	48 89 9d e0 fe ff ff 	mov    QWORD PTR [rbp-0x120],rbx
  8fc558:	48 89 95 e8 fe ff ff 	mov    QWORD PTR [rbp-0x118],rdx
  8fc55f:	48 89 85 f0 fe ff ff 	mov    QWORD PTR [rbp-0x110],rax
  8fc566:	48 8b 7b 08          	mov    rdi,QWORD PTR [rbx+0x8]
  8fc56a:	e8 51 fc c8 ff       	call   0x58c1c0
  8fc56f:	85 c0                	test   eax,eax
  8fc571:	74 23                	je     0x8fc596
  8fc573:	48 89 df             	mov    rdi,rbx
  8fc576:	89 c3                	mov    ebx,eax
  8fc578:	e8 c3 de c4 ff       	call   0x54a440
  8fc57d:	89 d8                	mov    eax,ebx
  8fc57f:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  8fc582:	48 3b 4d e0          	cmp    rcx,QWORD PTR [rbp-0x20]
  8fc586:	75 78                	jne    0x8fc600
  8fc588:	48 81 c4 b8 01 00 00 	add    rsp,0x1b8
  8fc58f:	5b                   	pop    rbx
  8fc590:	41 5e                	pop    r14
  8fc592:	41 5f                	pop    r15
  8fc594:	5d                   	pop    rbp
  8fc595:	c3                   	ret
  8fc596:	49 8b 86 40 01 00 00 	mov    rax,QWORD PTR [r14+0x140]
  8fc59d:	8b 40 04             	mov    eax,DWORD PTR [rax+0x4]
  8fc5a0:	3b 85 38 fe ff ff    	cmp    eax,DWORD PTR [rbp-0x1c8]
  8fc5a6:	74 11                	je     0x8fc5b9
  8fc5a8:	4c 89 f7             	mov    rdi,r14
  8fc5ab:	be 38 01 00 00       	mov    esi,0x138
  8fc5b0:	e8 7b 34 1e 00       	call   0xadfa30
  8fc5b5:	85 c0                	test   eax,eax
  8fc5b7:	75 ba                	jne    0x8fc573
  8fc5b9:	48 89 df             	mov    rdi,rbx
  8fc5bc:	e8 8f f0 c4 ff       	call   0x54b650
  8fc5c1:	89 c1                	mov    ecx,eax
  8fc5c3:	31 c0                	xor    eax,eax
  8fc5c5:	83 f9 02             	cmp    ecx,0x2
  8fc5c8:	7c a9                	jl     0x8fc573
  8fc5ca:	48 8d 05 a7 f3 1d 01 	lea    rax,[rip+0x11df3a7]        # 0x1adb978
  8fc5d1:	48 8d b5 d8 fe ff ff 	lea    rsi,[rbp-0x128]
  8fc5d8:	48 89 85 d8 fe ff ff 	mov    QWORD PTR [rbp-0x128],rax
  8fc5df:	48 89 9d e0 fe ff ff 	mov    QWORD PTR [rbp-0x120],rbx
  8fc5e6:	c7 85 e8 fe ff ff 01 	mov    DWORD PTR [rbp-0x118],0x1
  8fc5ed:	00 00 00 
  8fc5f0:	48 8b 7b 08          	mov    rdi,QWORD PTR [rbx+0x8]
  8fc5f4:	e8 c7 0b c9 ff       	call   0x58d1c0
  8fc5f9:	31 c0                	xor    eax,eax
  8fc5fb:	e9 73 ff ff ff       	jmp    0x8fc573
  8fc600:	e8 ab 10 e0 ff       	call   0x6fd6b0
  8fc605:	0f 0b                	ud2
  8fc607:	90                   	nop
  8fc608:	90                   	nop
  8fc609:	90                   	nop
  8fc60a:	90                   	nop
  8fc60b:	90                   	nop
  8fc60c:	90                   	nop
  8fc60d:	90                   	nop
  8fc60e:	90                   	nop
  8fc60f:	90                   	nop
  8fc610:	55                   	push   rbp
  8fc611:	48 89 e5             	mov    rbp,rsp
  8fc614:	41 57                	push   r15
  8fc616:	41 56                	push   r14
  8fc618:	53                   	push   rbx
  8fc619:	50                   	push   rax
  8fc61a:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  8fc61e:	48 89 fb             	mov    rbx,rdi
  8fc621:	31 f6                	xor    esi,esi
  8fc623:	31 d2                	xor    edx,edx
  8fc625:	31 c9                	xor    ecx,ecx
  8fc627:	4c 8b 78 48          	mov    r15,QWORD PTR [rax+0x48]
  8fc62b:	4d 8d 77 40          	lea    r14,[r15+0x40]
  8fc62f:	4c 89 f7             	mov    rdi,r14
  8fc632:	e8 e9 f4 34 00       	call   0xc4bb20
  8fc637:	49 8b 47 10          	mov    rax,QWORD PTR [r15+0x10]
  8fc63b:	31 c9                	xor    ecx,ecx
  8fc63d:	48 3b 05 cc ee 50 03 	cmp    rax,QWORD PTR [rip+0x350eecc]        # 0x3e0b510
  8fc644:	4c 89 f7             	mov    rdi,r14
  8fc647:	0f 95 c1             	setne  cl
  8fc64a:	31 f6                	xor    esi,esi
  8fc64c:	31 d2                	xor    edx,edx
  8fc64e:	48 89 8b 08 04 00 00 	mov    QWORD PTR [rbx+0x408],rcx
  8fc655:	e8 56 fe 34 00       	call   0xc4c4b0
  8fc65a:	31 c0                	xor    eax,eax
  8fc65c:	48 83 c4 08          	add    rsp,0x8
  8fc660:	5b                   	pop    rbx
  8fc661:	41 5e                	pop    r14
  8fc663:	41 5f                	pop    r15
  8fc665:	5d                   	pop    rbp
  8fc666:	c3                   	ret
  8fc667:	90                   	nop
  8fc668:	90                   	nop
  8fc669:	90                   	nop
  8fc66a:	90                   	nop
  8fc66b:	90                   	nop
  8fc66c:	90                   	nop
  8fc66d:	90                   	nop
  8fc66e:	90                   	nop
  8fc66f:	90                   	nop
  8fc670:	48 85 ff             	test   rdi,rdi
  8fc673:	74 6b                	je     0x8fc6e0
  8fc675:	55                   	push   rbp
  8fc676:	48 89 e5             	mov    rbp,rsp
  8fc679:	41 57                	push   r15
  8fc67b:	41 56                	push   r14
  8fc67d:	41 55                	push   r13
  8fc67f:	41 54                	push   r12
  8fc681:	53                   	push   rbx
  8fc682:	50                   	push   rax
  8fc683:	49 89 fd             	mov    r13,rdi
  8fc686:	bf 01 00 00 00       	mov    edi,0x1
  8fc68b:	41 89 f6             	mov    r14d,esi
  8fc68e:	49 89 d4             	mov    r12,rdx
  8fc691:	49 89 cf             	mov    r15,rcx
  8fc694:	4c 89 c3             	mov    rbx,r8
  8fc697:	e8 04 b8 1b 00       	call   0xab7ea0
  8fc69c:	85 c0                	test   eax,eax
  8fc69e:	75 59                	jne    0x8fc6f9
  8fc6a0:	4c 89 ef             	mov    rdi,r13
  8fc6a3:	e8 d8 a7 1c 00       	call   0xac6e80
  8fc6a8:	48 85 c0             	test   rax,rax
  8fc6ab:	74 39                	je     0x8fc6e6
  8fc6ad:	45 0f b6 f6          	movzx  r14d,r14b
  8fc6b1:	48 89 c7             	mov    rdi,rax
  8fc6b4:	4c 89 e2             	mov    rdx,r12
  8fc6b7:	4c 89 f9             	mov    rcx,r15
  8fc6ba:	49 89 d8             	mov    r8,rbx
  8fc6bd:	49 89 c5             	mov    r13,rax
  8fc6c0:	44 89 f6             	mov    esi,r14d
  8fc6c3:	e8 28 b5 18 00       	call   0xa87bf0
  8fc6c8:	85 c0                	test   eax,eax
  8fc6ca:	75 1f                	jne    0x8fc6eb
  8fc6cc:	4c 89 ef             	mov    rdi,r13
  8fc6cf:	44 89 f6             	mov    esi,r14d
  8fc6d2:	ba 01 00 00 00       	mov    edx,0x1
  8fc6d7:	e8 a4 f4 2e 00       	call   0xbebb80
  8fc6dc:	31 c0                	xor    eax,eax
  8fc6de:	eb 0b                	jmp    0x8fc6eb
  8fc6e0:	b8 01 10 00 00       	mov    eax,0x1001
  8fc6e5:	c3                   	ret
  8fc6e6:	b8 01 10 00 00       	mov    eax,0x1001
  8fc6eb:	bf 01 00 00 00       	mov    edi,0x1
  8fc6f0:	89 c3                	mov    ebx,eax
  8fc6f2:	e8 29 b8 1b 00       	call   0xab7f20
  8fc6f7:	89 d8                	mov    eax,ebx
  8fc6f9:	48 83 c4 08          	add    rsp,0x8
  8fc6fd:	5b                   	pop    rbx
  8fc6fe:	41 5c                	pop    r12
  8fc700:	41 5d                	pop    r13
  8fc702:	41 5e                	pop    r14
  8fc704:	41 5f                	pop    r15
  8fc706:	5d                   	pop    rbp
  8fc707:	c3                   	ret
  8fc708:	90                   	nop
  8fc709:	90                   	nop
  8fc70a:	90                   	nop
  8fc70b:	90                   	nop
  8fc70c:	90                   	nop
  8fc70d:	90                   	nop
  8fc70e:	90                   	nop
  8fc70f:	90                   	nop
  8fc710:	48 85 ff             	test   rdi,rdi
  8fc713:	74 75                	je     0x8fc78a
  8fc715:	55                   	push   rbp
  8fc716:	48 89 e5             	mov    rbp,rsp
  8fc719:	41 57                	push   r15
  8fc71b:	41 56                	push   r14
  8fc71d:	53                   	push   rbx
  8fc71e:	50                   	push   rax
  8fc71f:	48 89 fb             	mov    rbx,rdi
  8fc722:	bf 01 00 00 00       	mov    edi,0x1
  8fc727:	41 89 f7             	mov    r15d,esi
  8fc72a:	49 89 d6             	mov    r14,rdx
  8fc72d:	e8 6e b7 1b 00       	call   0xab7ea0
  8fc732:	85 c0                	test   eax,eax
  8fc734:	0f 85 ae 00 00 00    	jne    0x8fc7e8
  8fc73a:	48 89 df             	mov    rdi,rbx
  8fc73d:	e8 3e a7 1c 00       	call   0xac6e80
  8fc742:	b9 01 10 00 00       	mov    ecx,0x1001
  8fc747:	48 85 c0             	test   rax,rax
  8fc74a:	0f 84 8a 00 00 00    	je     0x8fc7da
  8fc750:	0f b6 50 09          	movzx  edx,BYTE PTR [rax+0x9]
  8fc754:	83 fa 0d             	cmp    edx,0xd
  8fc757:	77 37                	ja     0x8fc790
  8fc759:	be 40 30 00 00       	mov    esi,0x3040
  8fc75e:	0f a3 d6             	bt     esi,edx
  8fc761:	73 2d                	jae    0x8fc790
  8fc763:	48 89 c7             	mov    rdi,rax
  8fc766:	e8 55 ca cd ff       	call   0x5d91c0
  8fc76b:	48 85 c0             	test   rax,rax
  8fc76e:	74 65                	je     0x8fc7d5
  8fc770:	48 8b 58 20          	mov    rbx,QWORD PTR [rax+0x20]
  8fc774:	48 85 db             	test   rbx,rbx
  8fc777:	74 5c                	je     0x8fc7d5
  8fc779:	44 38 7b 0d          	cmp    BYTE PTR [rbx+0xd],r15b
  8fc77d:	75 1c                	jne    0x8fc79b
  8fc77f:	48 83 c0 20          	add    rax,0x20
  8fc783:	b9 01 10 00 00       	mov    ecx,0x1001
  8fc788:	eb 2c                	jmp    0x8fc7b6
  8fc78a:	b8 01 10 00 00       	mov    eax,0x1001
  8fc78f:	c3                   	ret
  8fc790:	48 3b 05 01 cf 0c 03 	cmp    rax,QWORD PTR [rip+0x30ccf01]        # 0x39c9698
  8fc797:	75 41                	jne    0x8fc7da
  8fc799:	eb c8                	jmp    0x8fc763
  8fc79b:	b9 01 10 00 00       	mov    ecx,0x1001
  8fc7a0:	48 89 d8             	mov    rax,rbx
  8fc7a3:	48 8b 5b 38          	mov    rbx,QWORD PTR [rbx+0x38]
  8fc7a7:	48 85 db             	test   rbx,rbx
  8fc7aa:	74 29                	je     0x8fc7d5
  8fc7ac:	44 38 7b 0d          	cmp    BYTE PTR [rbx+0xd],r15b
  8fc7b0:	75 ee                	jne    0x8fc7a0
  8fc7b2:	48 83 c0 38          	add    rax,0x38
  8fc7b6:	4c 39 73 10          	cmp    QWORD PTR [rbx+0x10],r14
  8fc7ba:	75 1e                	jne    0x8fc7da
  8fc7bc:	49 89 c6             	mov    r14,rax
  8fc7bf:	90                   	nop
  8fc7c0:	48 8b 7b 30          	mov    rdi,QWORD PTR [rbx+0x30]
  8fc7c4:	48 85 ff             	test   rdi,rdi
  8fc7c7:	74 2a                	je     0x8fc7f3
  8fc7c9:	be 01 00 00 00       	mov    esi,0x1
  8fc7ce:	e8 dd f7 2e 00       	call   0xbebfb0
  8fc7d3:	eb eb                	jmp    0x8fc7c0
  8fc7d5:	b9 06 00 00 00       	mov    ecx,0x6
  8fc7da:	bf 01 00 00 00       	mov    edi,0x1
  8fc7df:	89 cb                	mov    ebx,ecx
  8fc7e1:	e8 3a b7 1b 00       	call   0xab7f20
  8fc7e6:	89 d8                	mov    eax,ebx
  8fc7e8:	48 83 c4 08          	add    rsp,0x8
  8fc7ec:	5b                   	pop    rbx
  8fc7ed:	41 5e                	pop    r14
  8fc7ef:	41 5f                	pop    r15
  8fc7f1:	5d                   	pop    rbp
  8fc7f2:	c3                   	ret
  8fc7f3:	48 8b 43 38          	mov    rax,QWORD PTR [rbx+0x38]
  8fc7f7:	48 89 df             	mov    rdi,rbx
  8fc7fa:	49 89 06             	mov    QWORD PTR [r14],rax
  8fc7fd:	e8 be dc 24 00       	call   0xb4a4c0
  8fc802:	31 c9                	xor    ecx,ecx
  8fc804:	eb d4                	jmp    0x8fc7da
  8fc806:	90                   	nop
  8fc807:	90                   	nop
  8fc808:	90                   	nop
  8fc809:	90                   	nop
  8fc80a:	90                   	nop
  8fc80b:	90                   	nop
  8fc80c:	90                   	nop
  8fc80d:	90                   	nop
  8fc80e:	90                   	nop
  8fc80f:	90                   	nop
  8fc810:	55                   	push   rbp
  8fc811:	48 89 e5             	mov    rbp,rsp
  8fc814:	5d                   	pop    rbp
  8fc815:	e9 46 8f 96 ff       	jmp    0x265760
  8fc81a:	90                   	nop
  8fc81b:	90                   	nop
  8fc81c:	90                   	nop
  8fc81d:	90                   	nop
  8fc81e:	90                   	nop
  8fc81f:	90                   	nop
  8fc820:	55                   	push   rbp
  8fc821:	48 89 e5             	mov    rbp,rsp
  8fc824:	5d                   	pop    rbp
  8fc825:	e9 36 8f 96 ff       	jmp    0x265760
  8fc82a:	90                   	nop
  8fc82b:	90                   	nop
  8fc82c:	90                   	nop
  8fc82d:	90                   	nop
  8fc82e:	90                   	nop
  8fc82f:	90                   	nop
  8fc830:	8b 4e 2c             	mov    ecx,DWORD PTR [rsi+0x2c]
  8fc833:	31 c0                	xor    eax,eax
  8fc835:	f6 c1 01             	test   cl,0x1
  8fc838:	75 0a                	jne    0x8fc844
  8fc83a:	b8 4e 00 00 00       	mov    eax,0x4e
  8fc83f:	f6 c1 06             	test   cl,0x6
  8fc842:	74 01                	je     0x8fc845
  8fc844:	c3                   	ret
  8fc845:	55                   	push   rbp
  8fc846:	48 89 e5             	mov    rbp,rsp
  8fc849:	e8 02 51 ef ff       	call   0x7f1950
  8fc84e:	48 8d 3d f0 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff0]        # 0x8fc845
  8fc855:	e8 b6 4f ef ff       	call   0x7f1810
  8fc85a:	48 8d 35 6f 0d 9f 00 	lea    rsi,[rip+0x9f0d6f]        # 0x12ed5d0
  8fc861:	bf 03 00 00 00       	mov    edi,0x3
  8fc866:	31 c0                	xor    eax,eax
  8fc868:	e8 a3 e1 39 00       	call   0xc9aa10
  8fc86d:	0f 0b                	ud2
  8fc86f:	90                   	nop
  8fc870:	f6 46 2c 01          	test   BYTE PTR [rsi+0x2c],0x1
  8fc874:	74 01                	je     0x8fc877
  8fc876:	c3                   	ret
  8fc877:	55                   	push   rbp
  8fc878:	48 89 e5             	mov    rbp,rsp
  8fc87b:	e8 d0 50 ef ff       	call   0x7f1950
  8fc880:	48 8d 3d f0 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff0]        # 0x8fc877
  8fc887:	e8 84 4f ef ff       	call   0x7f1810
  8fc88c:	48 8d 35 3d 0d 9f 00 	lea    rsi,[rip+0x9f0d3d]        # 0x12ed5d0
  8fc893:	bf 07 00 00 00       	mov    edi,0x7
  8fc898:	31 c0                	xor    eax,eax
  8fc89a:	e8 71 e1 39 00       	call   0xc9aa10
  8fc89f:	0f 0b                	ud2
  8fc8a1:	90                   	nop
  8fc8a2:	90                   	nop
  8fc8a3:	90                   	nop
  8fc8a4:	90                   	nop
  8fc8a5:	90                   	nop
  8fc8a6:	90                   	nop
  8fc8a7:	90                   	nop
  8fc8a8:	90                   	nop
  8fc8a9:	90                   	nop
  8fc8aa:	90                   	nop
  8fc8ab:	90                   	nop
  8fc8ac:	90                   	nop
  8fc8ad:	90                   	nop
  8fc8ae:	90                   	nop
  8fc8af:	90                   	nop
  8fc8b0:	55                   	push   rbp
  8fc8b1:	48 89 e5             	mov    rbp,rsp
  8fc8b4:	41 57                	push   r15
  8fc8b6:	41 56                	push   r14
  8fc8b8:	41 55                	push   r13
  8fc8ba:	41 54                	push   r12
  8fc8bc:	53                   	push   rbx
  8fc8bd:	48 83 ec 18          	sub    rsp,0x18
  8fc8c1:	4c 8d 2d 48 fa 01 03 	lea    r13,[rip+0x301fa48]        # 0x391c310
  8fc8c8:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  8fc8cc:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fc8d0:	48 8b 5f 08          	mov    rbx,QWORD PTR [rdi+0x8]
  8fc8d4:	4c 8b 73 10          	mov    r14,QWORD PTR [rbx+0x10]
  8fc8d8:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
  8fc8df:	00 
  8fc8e0:	66 41 83 be 8c 00 00 	cmp    WORD PTR [r14+0x8c],0x0
  8fc8e7:	00 00 
  8fc8e9:	74 4b                	je     0x8fc936
  8fc8eb:	41 83 7e 34 00       	cmp    DWORD PTR [r14+0x34],0x0
  8fc8f0:	74 4c                	je     0x8fc93e
  8fc8f2:	66 41 83 be 8e 00 00 	cmp    WORD PTR [r14+0x8e],0x0
  8fc8f9:	00 00 
  8fc8fb:	0f 8f d2 00 00 00    	jg     0x8fc9d3
  8fc901:	49 8b 46 18          	mov    rax,QWORD PTR [r14+0x18]
  8fc905:	4c 8b b8 00 02 00 00 	mov    r15,QWORD PTR [rax+0x200]
  8fc90c:	48 8d 05 d5 43 96 ff 	lea    rax,[rip+0xffffffffff9643d5]        # 0x260ce8
  8fc913:	4c 29 f8             	sub    rax,r15
  8fc916:	48 c1 c8 03          	ror    rax,0x3
  8fc91a:	48 3d ff 06 00 00    	cmp    rax,0x6ff
  8fc920:	0f 87 4b 04 00 00    	ja     0x8fcd71
  8fc926:	4c 89 f7             	mov    rdi,r14
  8fc929:	41 ff d7             	call   r15
  8fc92c:	85 c0                	test   eax,eax
  8fc92e:	0f 85 9f 00 00 00    	jne    0x8fc9d3
  8fc934:	eb 18                	jmp    0x8fc94e
  8fc936:	45 31 ff             	xor    r15d,r15d
  8fc939:	e9 76 02 00 00       	jmp    0x8fcbb4
  8fc93e:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
  8fc942:	f7 80 99 00 00 00 00 	test   DWORD PTR [rax+0x99],0x1002000
  8fc949:	20 00 01 
  8fc94c:	74 a4                	je     0x8fc8f2
  8fc94e:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  8fc952:	48 89 df             	mov    rdi,rbx
  8fc955:	ba 02 00 00 00       	mov    edx,0x2
  8fc95a:	e8 11 45 db ff       	call   0x6b0e70
  8fc95f:	85 c0                	test   eax,eax
  8fc961:	74 70                	je     0x8fc9d3
  8fc963:	4c 8d 7d c8          	lea    r15,[rbp-0x38]
  8fc967:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  8fc96e:	00 00 
  8fc970:	f6 83 c4 01 00 00 80 	test   BYTE PTR [rbx+0x1c4],0x80
  8fc977:	75 49                	jne    0x8fc9c2
  8fc979:	48 8b 7d c8          	mov    rdi,QWORD PTR [rbp-0x38]
  8fc97d:	31 f6                	xor    esi,esi
  8fc97f:	31 d2                	xor    edx,edx
  8fc981:	31 c9                	xor    ecx,ecx
  8fc983:	48 83 c7 18          	add    rdi,0x18
  8fc987:	e8 74 a0 bc ff       	call   0x4c6a00
  8fc98c:	48 8b 7d c8          	mov    rdi,QWORD PTR [rbp-0x38]
  8fc990:	f6 87 93 00 00 00 14 	test   BYTE PTR [rdi+0x93],0x14
  8fc997:	0f 85 4d 02 00 00    	jne    0x8fcbea
  8fc99d:	48 83 c7 18          	add    rdi,0x18
  8fc9a1:	31 f6                	xor    esi,esi
  8fc9a3:	31 d2                	xor    edx,edx
  8fc9a5:	31 c9                	xor    ecx,ecx
  8fc9a7:	e8 f4 a5 bc ff       	call   0x4c6fa0
  8fc9ac:	48 89 df             	mov    rdi,rbx
  8fc9af:	4c 89 fe             	mov    rsi,r15
  8fc9b2:	ba 02 00 00 00       	mov    edx,0x2
  8fc9b7:	e8 b4 44 db ff       	call   0x6b0e70
  8fc9bc:	85 c0                	test   eax,eax
  8fc9be:	75 b0                	jne    0x8fc970
  8fc9c0:	eb 11                	jmp    0x8fc9d3
  8fc9c2:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  8fc9c6:	48 89 df             	mov    rdi,rbx
  8fc9c9:	ba 01 00 00 00       	mov    edx,0x1
  8fc9ce:	e8 9d 44 db ff       	call   0x6b0e70
  8fc9d3:	49 8b 46 18          	mov    rax,QWORD PTR [r14+0x18]
  8fc9d7:	49 8b 8e 90 00 00 00 	mov    rcx,QWORD PTR [r14+0x90]
  8fc9de:	48 83 78 28 02       	cmp    QWORD PTR [rax+0x28],0x2
  8fc9e3:	75 0d                	jne    0x8fc9f2
  8fc9e5:	49 8b 96 b0 00 00 00 	mov    rdx,QWORD PTR [r14+0xb0]
  8fc9ec:	8b 52 5c             	mov    edx,DWORD PTR [rdx+0x5c]
  8fc9ef:	48 01 d1             	add    rcx,rdx
  8fc9f2:	45 31 ff             	xor    r15d,r15d
  8fc9f5:	41 83 7e 34 00       	cmp    DWORD PTR [r14+0x34],0x0
  8fc9fa:	7f 30                	jg     0x8fca2c
  8fc9fc:	48 85 c9             	test   rcx,rcx
  8fc9ff:	74 2b                	je     0x8fca2c
  8fca01:	4c 8b a0 00 02 00 00 	mov    r12,QWORD PTR [rax+0x200]
  8fca08:	48 8d 05 d9 42 96 ff 	lea    rax,[rip+0xffffffffff9642d9]        # 0x260ce8
  8fca0f:	4c 29 e0             	sub    rax,r12
  8fca12:	48 c1 c8 03          	ror    rax,0x3
  8fca16:	48 3d ff 06 00 00    	cmp    rax,0x6ff
  8fca1c:	0f 87 27 03 00 00    	ja     0x8fcd49
  8fca22:	4c 89 f7             	mov    rdi,r14
  8fca25:	41 ff d4             	call   r12
  8fca28:	85 c0                	test   eax,eax
  8fca2a:	74 60                	je     0x8fca8c
  8fca2c:	66 41 83 be 8e 00 00 	cmp    WORD PTR [r14+0x8e],0x0
  8fca33:	00 00 
  8fca35:	0f 8e 9c 00 00 00    	jle    0x8fcad7
  8fca3b:	41 8b 46 20          	mov    eax,DWORD PTR [r14+0x20]
  8fca3f:	a8 0f                	test   al,0xf
  8fca41:	0f 84 62 01 00 00    	je     0x8fcba9
  8fca47:	a8 0e                	test   al,0xe
  8fca49:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  8fca4d:	0f 94 c1             	sete   cl
  8fca50:	48 85 c0             	test   rax,rax
  8fca53:	0f 94 c2             	sete   dl
  8fca56:	20 ca                	and    dl,cl
  8fca58:	80 fa 01             	cmp    dl,0x1
  8fca5b:	0f 85 00 01 00 00    	jne    0x8fcb61
  8fca61:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  8fca65:	48 89 df             	mov    rdi,rbx
  8fca68:	ba 02 00 00 00       	mov    edx,0x2
  8fca6d:	e8 fe 43 db ff       	call   0x6b0e70
  8fca72:	85 c0                	test   eax,eax
  8fca74:	0f 84 e3 00 00 00    	je     0x8fcb5d
  8fca7a:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
  8fca81:	00 
  8fca82:	41 80 66 20 fe       	and    BYTE PTR [r14+0x20],0xfe
  8fca87:	e9 1d 01 00 00       	jmp    0x8fcba9
  8fca8c:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
  8fca90:	48 8b 80 98 02 00 00 	mov    rax,QWORD PTR [rax+0x298]
  8fca97:	4c 8b b8 d8 01 00 00 	mov    r15,QWORD PTR [rax+0x1d8]
  8fca9e:	48 8d 05 53 2d 97 ff 	lea    rax,[rip+0xffffffffff972d53]        # 0x26f7f8
  8fcaa5:	4c 29 f8             	sub    rax,r15
  8fcaa8:	48 c1 c8 03          	ror    rax,0x3
  8fcaac:	48 83 f8 03          	cmp    rax,0x3
  8fcab0:	0f 87 e3 02 00 00    	ja     0x8fcd99
  8fcab6:	48 89 df             	mov    rdi,rbx
  8fcab9:	ba 00 0c 00 00       	mov    edx,0xc00
  8fcabe:	31 f6                	xor    esi,esi
  8fcac0:	31 c9                	xor    ecx,ecx
  8fcac2:	41 ff d7             	call   r15
  8fcac5:	41 89 c7             	mov    r15d,eax
  8fcac8:	66 41 83 be 8e 00 00 	cmp    WORD PTR [r14+0x8e],0x0
  8fcacf:	00 00 
  8fcad1:	0f 8f 64 ff ff ff    	jg     0x8fca3b
  8fcad7:	66 41 83 be 8c 00 00 	cmp    WORD PTR [r14+0x8c],0x0
  8fcade:	00 00 
  8fcae0:	0f 84 55 ff ff ff    	je     0x8fca3b
  8fcae6:	49 8b 46 18          	mov    rax,QWORD PTR [r14+0x18]
  8fcaea:	4c 8b a0 00 02 00 00 	mov    r12,QWORD PTR [rax+0x200]
  8fcaf1:	48 8d 05 f0 41 96 ff 	lea    rax,[rip+0xffffffffff9641f0]        # 0x260ce8
  8fcaf8:	4c 29 e0             	sub    rax,r12
  8fcafb:	48 c1 c8 03          	ror    rax,0x3
  8fcaff:	48 3d ff 06 00 00    	cmp    rax,0x6ff
  8fcb05:	0f 87 7a 02 00 00    	ja     0x8fcd85
  8fcb0b:	4c 89 f7             	mov    rdi,r14
  8fcb0e:	41 ff d4             	call   r12
  8fcb11:	85 c0                	test   eax,eax
  8fcb13:	0f 85 22 ff ff ff    	jne    0x8fca3b
  8fcb19:	49 8b 46 18          	mov    rax,QWORD PTR [r14+0x18]
  8fcb1d:	48 8b 40 28          	mov    rax,QWORD PTR [rax+0x28]
  8fcb21:	48 83 f8 02          	cmp    rax,0x2
  8fcb25:	75 19                	jne    0x8fcb40
  8fcb27:	49 8b 86 b0 00 00 00 	mov    rax,QWORD PTR [r14+0xb0]
  8fcb2e:	c7 80 f4 00 00 00 00 	mov    DWORD PTR [rax+0xf4],0x0
  8fcb35:	00 00 00 
  8fcb38:	49 8b 46 18          	mov    rax,QWORD PTR [r14+0x18]
  8fcb3c:	48 8b 40 28          	mov    rax,QWORD PTR [rax+0x28]
  8fcb40:	49 8b 8e b0 00 00 00 	mov    rcx,QWORD PTR [r14+0xb0]
  8fcb47:	48 83 f8 01          	cmp    rax,0x1
  8fcb4b:	0f 85 db 00 00 00    	jne    0x8fcc2c
  8fcb51:	c7 41 28 00 00 00 00 	mov    DWORD PTR [rcx+0x28],0x0
  8fcb58:	e9 d7 00 00 00       	jmp    0x8fcc34
  8fcb5d:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  8fcb61:	48 85 c0             	test   rax,rax
  8fcb64:	75 11                	jne    0x8fcb77
  8fcb66:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  8fcb6a:	48 89 df             	mov    rdi,rbx
  8fcb6d:	ba 01 00 00 00       	mov    edx,0x1
  8fcb72:	e8 f9 42 db ff       	call   0x6b0e70
  8fcb77:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
  8fcb7b:	48 8b 80 98 02 00 00 	mov    rax,QWORD PTR [rax+0x298]
  8fcb82:	4c 8b a0 e0 01 00 00 	mov    r12,QWORD PTR [rax+0x1e0]
  8fcb89:	48 8d 05 50 c5 96 ff 	lea    rax,[rip+0xffffffffff96c550]        # 0x2690e0
  8fcb90:	4c 29 e0             	sub    rax,r12
  8fcb93:	48 c1 c8 03          	ror    rax,0x3
  8fcb97:	48 83 f8 72          	cmp    rax,0x72
  8fcb9b:	0f 87 bc 01 00 00    	ja     0x8fcd5d
  8fcba1:	48 89 df             	mov    rdi,rbx
  8fcba4:	31 f6                	xor    esi,esi
  8fcba6:	41 ff d4             	call   r12
  8fcba9:	66 41 83 be 8c 00 00 	cmp    WORD PTR [r14+0x8c],0x0
  8fcbb0:	00 00 
  8fcbb2:	75 08                	jne    0x8fcbbc
  8fcbb4:	48 89 df             	mov    rdi,rbx
  8fcbb7:	e8 44 e6 c4 ff       	call   0x54b200
  8fcbbc:	48 8b 7d c8          	mov    rdi,QWORD PTR [rbp-0x38]
  8fcbc0:	48 85 ff             	test   rdi,rdi
  8fcbc3:	74 05                	je     0x8fcbca
  8fcbc5:	e8 56 44 db ff       	call   0x6b1020
  8fcbca:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  8fcbce:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  8fcbd2:	0f 85 6a 01 00 00    	jne    0x8fcd42
  8fcbd8:	44 89 f8             	mov    eax,r15d
  8fcbdb:	48 83 c4 18          	add    rsp,0x18
  8fcbdf:	5b                   	pop    rbx
  8fcbe0:	41 5c                	pop    r12
  8fcbe2:	41 5d                	pop    r13
  8fcbe4:	41 5e                	pop    r14
  8fcbe6:	41 5f                	pop    r15
  8fcbe8:	5d                   	pop    rbp
  8fcbe9:	c3                   	ret
  8fcbea:	4c 8d b3 b0 00 00 00 	lea    r14,[rbx+0xb0]
  8fcbf1:	45 31 ff             	xor    r15d,r15d
  8fcbf4:	31 f6                	xor    esi,esi
  8fcbf6:	31 d2                	xor    edx,edx
  8fcbf8:	31 c9                	xor    ecx,ecx
  8fcbfa:	4c 89 f7             	mov    rdi,r14
  8fcbfd:	e8 fe 9d bc ff       	call   0x4c6a00
  8fcc02:	80 8b c5 01 00 00 10 	or     BYTE PTR [rbx+0x1c5],0x10
  8fcc09:	4c 89 f7             	mov    rdi,r14
  8fcc0c:	31 f6                	xor    esi,esi
  8fcc0e:	31 d2                	xor    edx,edx
  8fcc10:	31 c9                	xor    ecx,ecx
  8fcc12:	e8 89 a3 bc ff       	call   0x4c6fa0
  8fcc17:	48 8b 7d c8          	mov    rdi,QWORD PTR [rbp-0x38]
  8fcc1b:	31 f6                	xor    esi,esi
  8fcc1d:	31 d2                	xor    edx,edx
  8fcc1f:	31 c9                	xor    ecx,ecx
  8fcc21:	48 83 c7 18          	add    rdi,0x18
  8fcc25:	e8 76 a3 bc ff       	call   0x4c6fa0
  8fcc2a:	eb 9e                	jmp    0x8fcbca
  8fcc2c:	48 c7 41 70 00 00 00 	mov    QWORD PTR [rcx+0x70],0x0
  8fcc33:	00 
  8fcc34:	45 0f b7 a6 8c 00 00 	movzx  r12d,WORD PTR [r14+0x8c]
  8fcc3b:	00 
  8fcc3c:	66 41 c7 86 8c 00 00 	mov    WORD PTR [r14+0x8c],0x0
  8fcc43:	00 00 00 
  8fcc46:	49 8b 86 b0 00 00 00 	mov    rax,QWORD PTR [r14+0xb0]
  8fcc4d:	66 c7 00 00 00       	mov    WORD PTR [rax],0x0
  8fcc52:	41 80 4e 20 06       	or     BYTE PTR [r14+0x20],0x6
  8fcc57:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
  8fcc5b:	f7 80 99 00 00 00 00 	test   DWORD PTR [rax+0x99],0x1002000
  8fcc62:	20 00 01 
  8fcc65:	74 1e                	je     0x8fcc85
  8fcc67:	4c 89 f7             	mov    rdi,r14
  8fcc6a:	e8 61 dd b1 ff       	call   0x41a9d0
  8fcc6f:	45 85 ff             	test   r15d,r15d
  8fcc72:	44 89 f9             	mov    ecx,r15d
  8fcc75:	0f 44 c8             	cmove  ecx,eax
  8fcc78:	85 c0                	test   eax,eax
  8fcc7a:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
  8fcc7e:	41 0f 44 cf          	cmove  ecx,r15d
  8fcc82:	41 89 cf             	mov    r15d,ecx
  8fcc85:	48 8b 80 98 02 00 00 	mov    rax,QWORD PTR [rax+0x298]
  8fcc8c:	4c 8b a8 f0 01 00 00 	mov    r13,QWORD PTR [rax+0x1f0]
  8fcc93:	48 8d 05 a6 2a 97 ff 	lea    rax,[rip+0xffffffffff972aa6]        # 0x26f740
  8fcc9a:	49 39 c5             	cmp    r13,rax
  8fcc9d:	0f 85 0a 01 00 00    	jne    0x8fcdad
  8fcca3:	41 8b 76 30          	mov    esi,DWORD PTR [r14+0x30]
  8fcca7:	48 89 df             	mov    rdi,rbx
  8fccaa:	44 89 e2             	mov    edx,r12d
  8fccad:	41 ff d5             	call   r13
  8fccb0:	41 81 7e 30 00 81 00 	cmp    DWORD PTR [r14+0x30],0x8100
  8fccb7:	00 
  8fccb8:	75 6d                	jne    0x8fcd27
  8fccba:	49 81 be a0 00 00 00 	cmp    QWORD PTR [r14+0xa0],0x202
  8fccc1:	02 02 00 00 
  8fccc5:	75 60                	jne    0x8fcd27
  8fccc7:	bf 38 02 00 00       	mov    edi,0x238
  8fcccc:	48 03 7b 18          	add    rdi,QWORD PTR [rbx+0x18]
  8fccd0:	48 8d 35 6e e1 a6 00 	lea    rsi,[rip+0xa6e16e]        # 0x136ae45
  8fccd7:	ba 0b 00 00 00       	mov    edx,0xb
  8fccdc:	41 89 c4             	mov    r12d,eax
  8fccdf:	e8 4c 4d fd ff       	call   0x8d1a30
  8fcce4:	89 c1                	mov    ecx,eax
  8fcce6:	44 89 e0             	mov    eax,r12d
  8fcce9:	85 c9                	test   ecx,ecx
  8fcceb:	75 3a                	jne    0x8fcd27
  8fcced:	65 48 8b 14 25 00 00 	mov    rdx,QWORD PTR gs:0x0
  8fccf4:	00 00 
  8fccf6:	45 8b 46 30          	mov    r8d,DWORD PTR [r14+0x30]
  8fccfa:	4d 8b 8e a0 00 00 00 	mov    r9,QWORD PTR [r14+0xa0]
  8fcd01:	48 81 c2 94 02 00 00 	add    rdx,0x294
  8fcd08:	48 8d 3d 35 87 a7 00 	lea    rdi,[rip+0xa78735]        # 0x1375444
  8fcd0f:	48 8d 35 61 dd 99 00 	lea    rsi,[rip+0x99dd61]        # 0x129aa77
  8fcd16:	48 8d 0d 4f 3f a6 00 	lea    rcx,[rip+0xa63f4f]        # 0x1360c6c
  8fcd1d:	31 c0                	xor    eax,eax
  8fcd1f:	e8 ec 06 96 ff       	call   0x25d410
  8fcd24:	44 89 e0             	mov    eax,r12d
  8fcd27:	4c 8d 2d e2 f5 01 03 	lea    r13,[rip+0x301f5e2]        # 0x391c310
  8fcd2e:	45 85 ff             	test   r15d,r15d
  8fcd31:	44 89 f9             	mov    ecx,r15d
  8fcd34:	0f 44 c8             	cmove  ecx,eax
  8fcd37:	85 c0                	test   eax,eax
  8fcd39:	44 0f 45 f9          	cmovne r15d,ecx
  8fcd3d:	e9 f9 fc ff ff       	jmp    0x8fca3b
  8fcd42:	e8 69 09 e0 ff       	call   0x6fd6b0
  8fcd47:	0f 0b                	ud2
  8fcd49:	48 8d 3d 90 1f c5 01 	lea    rdi,[rip+0x1c51f90]        # 0x254ece0
  8fcd50:	4c 89 e6             	mov    rsi,r12
  8fcd53:	e8 68 2b b5 ff       	call   0x44f8c0
  8fcd58:	e9 c5 fc ff ff       	jmp    0x8fca22
  8fcd5d:	48 8d 3d fc 1f c5 01 	lea    rdi,[rip+0x1c51ffc]        # 0x254ed60
  8fcd64:	4c 89 e6             	mov    rsi,r12
  8fcd67:	e8 54 2b b5 ff       	call   0x44f8c0
  8fcd6c:	e9 30 fe ff ff       	jmp    0x8fcba1
  8fcd71:	48 8d 3d 48 1f c5 01 	lea    rdi,[rip+0x1c51f48]        # 0x254ecc0
  8fcd78:	4c 89 fe             	mov    rsi,r15
  8fcd7b:	e8 40 2b b5 ff       	call   0x44f8c0
  8fcd80:	e9 a1 fb ff ff       	jmp    0x8fc926
  8fcd85:	48 8d 3d 94 1f c5 01 	lea    rdi,[rip+0x1c51f94]        # 0x254ed20
  8fcd8c:	4c 89 e6             	mov    rsi,r12
  8fcd8f:	e8 2c 2b b5 ff       	call   0x44f8c0
  8fcd94:	e9 72 fd ff ff       	jmp    0x8fcb0b
  8fcd99:	48 8d 3d 60 1f c5 01 	lea    rdi,[rip+0x1c51f60]        # 0x254ed00
  8fcda0:	4c 89 fe             	mov    rsi,r15
  8fcda3:	e8 18 2b b5 ff       	call   0x44f8c0
  8fcda8:	e9 09 fd ff ff       	jmp    0x8fcab6
  8fcdad:	48 8d 3d 8c 1f c5 01 	lea    rdi,[rip+0x1c51f8c]        # 0x254ed40
  8fcdb4:	4c 89 ee             	mov    rsi,r13
  8fcdb7:	e8 04 2b b5 ff       	call   0x44f8c0
  8fcdbc:	e9 e2 fe ff ff       	jmp    0x8fcca3
  8fcdc1:	90                   	nop
  8fcdc2:	90                   	nop
  8fcdc3:	90                   	nop
  8fcdc4:	90                   	nop
  8fcdc5:	90                   	nop
  8fcdc6:	90                   	nop
  8fcdc7:	90                   	nop
  8fcdc8:	90                   	nop
  8fcdc9:	90                   	nop
  8fcdca:	90                   	nop
  8fcdcb:	90                   	nop
  8fcdcc:	90                   	nop
  8fcdcd:	90                   	nop
  8fcdce:	90                   	nop
  8fcdcf:	90                   	nop
  8fcdd0:	55                   	push   rbp
  8fcdd1:	48 89 e5             	mov    rbp,rsp
  8fcdd4:	5d                   	pop    rbp
  8fcdd5:	e9 56 b7 da ff       	jmp    0x6a8530
  8fcdda:	90                   	nop
  8fcddb:	90                   	nop
  8fcddc:	90                   	nop
  8fcddd:	90                   	nop
  8fcdde:	90                   	nop
  8fcddf:	90                   	nop
  8fcde0:	55                   	push   rbp
  8fcde1:	48 89 e5             	mov    rbp,rsp
  8fcde4:	41 57                	push   r15
  8fcde6:	41 56                	push   r14
  8fcde8:	41 54                	push   r12
  8fcdea:	53                   	push   rbx
  8fcdeb:	4c 8b 7f 08          	mov    r15,QWORD PTR [rdi+0x8]
  8fcdef:	49 8b 5f 10          	mov    rbx,QWORD PTR [r15+0x10]
  8fcdf3:	45 8b a7 c8 01 00 00 	mov    r12d,DWORD PTR [r15+0x1c8]
  8fcdfa:	4c 89 ff             	mov    rdi,r15
  8fcdfd:	4c 8b 73 18          	mov    r14,QWORD PTR [rbx+0x18]
  8fce01:	e8 2a b7 da ff       	call   0x6a8530
  8fce06:	41 f7 c4 00 00 01 00 	test   r12d,0x10000
  8fce0d:	0f 85 9a 00 00 00    	jne    0x8fcead
  8fce13:	8b 43 20             	mov    eax,DWORD PTR [rbx+0x20]
  8fce16:	a8 40                	test   al,0x40
  8fce18:	74 06                	je     0x8fce20
  8fce1a:	83 c8 08             	or     eax,0x8
  8fce1d:	89 43 20             	mov    DWORD PTR [rbx+0x20],eax
  8fce20:	49 8b 47 18          	mov    rax,QWORD PTR [r15+0x18]
  8fce24:	48 8b 80 98 02 00 00 	mov    rax,QWORD PTR [rax+0x298]
  8fce2b:	4c 8b a0 e0 01 00 00 	mov    r12,QWORD PTR [rax+0x1e0]
  8fce32:	48 8d 05 a7 c2 96 ff 	lea    rax,[rip+0xffffffffff96c2a7]        # 0x2690e0
  8fce39:	4c 29 e0             	sub    rax,r12
  8fce3c:	48 c1 c8 03          	ror    rax,0x3
  8fce40:	48 83 f8 72          	cmp    rax,0x72
  8fce44:	0f 87 99 00 00 00    	ja     0x8fcee3
  8fce4a:	4c 89 ff             	mov    rdi,r15
  8fce4d:	31 f6                	xor    esi,esi
  8fce4f:	41 ff d4             	call   r12
  8fce52:	4c 89 ff             	mov    rdi,r15
  8fce55:	e8 56 2d 1e 00       	call   0xadfbb0
  8fce5a:	4d 8d a7 b0 00 00 00 	lea    r12,[r15+0xb0]
  8fce61:	31 f6                	xor    esi,esi
  8fce63:	31 d2                	xor    edx,edx
  8fce65:	31 c9                	xor    ecx,ecx
  8fce67:	4c 89 e7             	mov    rdi,r12
  8fce6a:	e8 91 9b bc ff       	call   0x4c6a00
  8fce6f:	4c 89 e7             	mov    rdi,r12
  8fce72:	49 c7 47 10 00 00 00 	mov    QWORD PTR [r15+0x10],0x0
  8fce79:	00 
  8fce7a:	31 f6                	xor    esi,esi
  8fce7c:	31 d2                	xor    edx,edx
  8fce7e:	31 c9                	xor    ecx,ecx
  8fce80:	e8 1b a1 bc ff       	call   0x4c6fa0
  8fce85:	4d 8b be f8 01 00 00 	mov    r15,QWORD PTR [r14+0x1f8]
  8fce8c:	48 8d 05 f5 af 96 ff 	lea    rax,[rip+0xffffffffff96aff5]        # 0x267e88
  8fce93:	4c 29 f8             	sub    rax,r15
  8fce96:	48 c1 c8 03          	ror    rax,0x3
  8fce9a:	48 3d 97 01 00 00    	cmp    rax,0x197
  8fcea0:	77 55                	ja     0x8fcef7
  8fcea2:	4c 89 f7             	mov    rdi,r14
  8fcea5:	48 89 de             	mov    rsi,rbx
  8fcea8:	41 ff d7             	call   r15
  8fceab:	eb 2b                	jmp    0x8fced8
  8fcead:	49 8d 9f b0 00 00 00 	lea    rbx,[r15+0xb0]
  8fceb4:	31 f6                	xor    esi,esi
  8fceb6:	31 d2                	xor    edx,edx
  8fceb8:	31 c9                	xor    ecx,ecx
  8fceba:	48 89 df             	mov    rdi,rbx
  8fcebd:	e8 3e 9b bc ff       	call   0x4c6a00
  8fcec2:	48 89 df             	mov    rdi,rbx
  8fcec5:	49 c7 47 10 00 00 00 	mov    QWORD PTR [r15+0x10],0x0
  8fcecc:	00 
  8fcecd:	31 f6                	xor    esi,esi
  8fcecf:	31 d2                	xor    edx,edx
  8fced1:	31 c9                	xor    ecx,ecx
  8fced3:	e8 c8 a0 bc ff       	call   0x4c6fa0
  8fced8:	31 c0                	xor    eax,eax
  8fceda:	5b                   	pop    rbx
  8fcedb:	41 5c                	pop    r12
  8fcedd:	41 5e                	pop    r14
  8fcedf:	41 5f                	pop    r15
  8fcee1:	5d                   	pop    rbp
  8fcee2:	c3                   	ret
  8fcee3:	48 8d 3d 96 1e c5 01 	lea    rdi,[rip+0x1c51e96]        # 0x254ed80
  8fceea:	4c 89 e6             	mov    rsi,r12
  8fceed:	e8 ce 29 b5 ff       	call   0x44f8c0
  8fcef2:	e9 53 ff ff ff       	jmp    0x8fce4a
  8fcef7:	48 8d 3d a2 1e c5 01 	lea    rdi,[rip+0x1c51ea2]        # 0x254eda0
  8fcefe:	4c 89 fe             	mov    rsi,r15
  8fcf01:	e8 ba 29 b5 ff       	call   0x44f8c0
  8fcf06:	eb 9a                	jmp    0x8fcea2
  8fcf08:	90                   	nop
  8fcf09:	90                   	nop
  8fcf0a:	90                   	nop
  8fcf0b:	90                   	nop
  8fcf0c:	90                   	nop
  8fcf0d:	90                   	nop
  8fcf0e:	90                   	nop
  8fcf0f:	90                   	nop
  8fcf10:	55                   	push   rbp
  8fcf11:	48 89 e5             	mov    rbp,rsp
  8fcf14:	48 8d 35 21 f8 a0 00 	lea    rsi,[rip+0xa0f821]        # 0x130c73c
  8fcf1b:	e8 10 6e 9b ff       	call   0x2b3d30
  8fcf20:	b8 9c ff ff ff       	mov    eax,0xffffff9c
  8fcf25:	5d                   	pop    rbp
  8fcf26:	c3                   	ret
  8fcf27:	90                   	nop
  8fcf28:	90                   	nop
  8fcf29:	90                   	nop
  8fcf2a:	90                   	nop
  8fcf2b:	90                   	nop
  8fcf2c:	90                   	nop
  8fcf2d:	90                   	nop
  8fcf2e:	90                   	nop
  8fcf2f:	90                   	nop
  8fcf30:	55                   	push   rbp
  8fcf31:	48 89 e5             	mov    rbp,rsp
  8fcf34:	41 56                	push   r14
  8fcf36:	53                   	push   rbx
  8fcf37:	48 89 fb             	mov    rbx,rdi
  8fcf3a:	e8 d1 5b 9b ff       	call   0x2b2b10
  8fcf3f:	48 8d 15 4a d6 58 00 	lea    rdx,[rip+0x58d64a]        # 0xe8a590
  8fcf46:	48 89 df             	mov    rdi,rbx
  8fcf49:	be 00 00 10 00       	mov    esi,0x100000
  8fcf4e:	b9 01 00 00 00       	mov    ecx,0x1
  8fcf53:	49 89 c6             	mov    r14,rax
  8fcf56:	e8 d5 d7 f1 ff       	call   0x81a730
  8fcf5b:	4c 89 f7             	mov    rdi,r14
  8fcf5e:	e8 2d c4 f1 ff       	call   0x819390
  8fcf63:	31 c0                	xor    eax,eax
  8fcf65:	5b                   	pop    rbx
  8fcf66:	41 5e                	pop    r14
  8fcf68:	5d                   	pop    rbp
  8fcf69:	c3                   	ret
  8fcf6a:	90                   	nop
  8fcf6b:	90                   	nop
  8fcf6c:	90                   	nop
  8fcf6d:	90                   	nop
  8fcf6e:	90                   	nop
  8fcf6f:	90                   	nop
  8fcf70:	55                   	push   rbp
  8fcf71:	48 89 e5             	mov    rbp,rsp
  8fcf74:	41 57                	push   r15
  8fcf76:	41 56                	push   r14
  8fcf78:	53                   	push   rbx
  8fcf79:	50                   	push   rax
  8fcf7a:	89 d3                	mov    ebx,edx
  8fcf7c:	49 89 fe             	mov    r14,rdi
  8fcf7f:	83 fa 01             	cmp    edx,0x1
  8fcf82:	74 0f                	je     0x8fcf93
  8fcf84:	83 fb 02             	cmp    ebx,0x2
  8fcf87:	75 17                	jne    0x8fcfa0
  8fcf89:	4c 89 f7             	mov    rdi,r14
  8fcf8c:	e8 ff c3 f1 ff       	call   0x819390
  8fcf91:	eb 0d                	jmp    0x8fcfa0
  8fcf93:	4c 89 f7             	mov    rdi,r14
  8fcf96:	e8 b5 ca f1 ff       	call   0x819a50
  8fcf9b:	83 f8 fe             	cmp    eax,0xfffffffe
  8fcf9e:	74 2e                	je     0x8fcfce
  8fcfa0:	49 8b 46 38          	mov    rax,QWORD PTR [r14+0x38]
  8fcfa4:	4c 8b 78 08          	mov    r15,QWORD PTR [rax+0x8]
  8fcfa8:	48 8d 05 21 83 96 ff 	lea    rax,[rip+0xffffffffff968321]        # 0x2652d0
  8fcfaf:	4c 29 f8             	sub    rax,r15
  8fcfb2:	48 c1 c8 03          	ror    rax,0x3
  8fcfb6:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  8fcfbc:	77 1d                	ja     0x8fcfdb
  8fcfbe:	4c 89 f7             	mov    rdi,r14
  8fcfc1:	41 ff d7             	call   r15
  8fcfc4:	4c 89 f7             	mov    rdi,r14
  8fcfc7:	89 de                	mov    esi,ebx
  8fcfc9:	e8 c2 ce f1 ff       	call   0x819e90
  8fcfce:	31 c0                	xor    eax,eax
  8fcfd0:	48 83 c4 08          	add    rsp,0x8
  8fcfd4:	5b                   	pop    rbx
  8fcfd5:	41 5e                	pop    r14
  8fcfd7:	41 5f                	pop    r15
  8fcfd9:	5d                   	pop    rbp
  8fcfda:	c3                   	ret
  8fcfdb:	48 8d 3d de 1e c5 01 	lea    rdi,[rip+0x1c51ede]        # 0x254eec0
  8fcfe2:	4c 89 fe             	mov    rsi,r15
  8fcfe5:	e8 d6 28 b5 ff       	call   0x44f8c0
  8fcfea:	eb d2                	jmp    0x8fcfbe
  8fcfec:	90                   	nop
  8fcfed:	90                   	nop
  8fcfee:	90                   	nop
  8fcfef:	90                   	nop
  8fcff0:	55                   	push   rbp
  8fcff1:	48 89 e5             	mov    rbp,rsp
  8fcff4:	41 56                	push   r14
  8fcff6:	53                   	push   rbx
  8fcff7:	89 fb                	mov    ebx,edi
  8fcff9:	bf 01 00 00 00       	mov    edi,0x1
  8fcffe:	e8 3d 2b 0a 00       	call   0x99fb40
  8fd003:	39 d8                	cmp    eax,ebx
  8fd005:	75 45                	jne    0x8fd04c
  8fd007:	4c 8d 35 22 c3 24 03 	lea    r14,[rip+0x324c322]        # 0x3b49330
  8fd00e:	31 f6                	xor    esi,esi
  8fd010:	31 d2                	xor    edx,edx
  8fd012:	31 c9                	xor    ecx,ecx
  8fd014:	4c 89 f7             	mov    rdi,r14
  8fd017:	e8 74 a1 bc ff       	call   0x4c7190
  8fd01c:	48 63 c3             	movsxd rax,ebx
  8fd01f:	48 8d 0d 1a c3 24 03 	lea    rcx,[rip+0x324c31a]        # 0x3b49340
  8fd026:	4c 89 f7             	mov    rdi,r14
  8fd029:	31 f6                	xor    esi,esi
  8fd02b:	31 d2                	xor    edx,edx
  8fd02d:	48 c1 e0 04          	shl    rax,0x4
  8fd031:	48 c7 04 08 ff ff ff 	mov    QWORD PTR [rax+rcx*1],0xffffffffffffffff
  8fd038:	ff 
  8fd039:	c7 44 08 08 00 00 00 	mov    DWORD PTR [rax+rcx*1+0x8],0x0
  8fd040:	00 
  8fd041:	31 c9                	xor    ecx,ecx
  8fd043:	5b                   	pop    rbx
  8fd044:	41 5e                	pop    r14
  8fd046:	5d                   	pop    rbp
  8fd047:	e9 d4 a4 bc ff       	jmp    0x4c7520
  8fd04c:	5b                   	pop    rbx
  8fd04d:	41 5e                	pop    r14
  8fd04f:	5d                   	pop    rbp
  8fd050:	c3                   	ret
  8fd051:	90                   	nop
  8fd052:	90                   	nop
  8fd053:	90                   	nop
  8fd054:	90                   	nop
  8fd055:	90                   	nop
  8fd056:	90                   	nop
  8fd057:	90                   	nop
  8fd058:	90                   	nop
  8fd059:	90                   	nop
  8fd05a:	90                   	nop
  8fd05b:	90                   	nop
  8fd05c:	90                   	nop
  8fd05d:	90                   	nop
  8fd05e:	90                   	nop
  8fd05f:	90                   	nop
  8fd060:	55                   	push   rbp
  8fd061:	48 89 e5             	mov    rbp,rsp
  8fd064:	41 57                	push   r15
  8fd066:	41 56                	push   r14
  8fd068:	53                   	push   rbx
  8fd069:	50                   	push   rax
  8fd06a:	89 fb                	mov    ebx,edi
  8fd06c:	bf 01 00 00 00       	mov    edi,0x1
  8fd071:	41 89 f6             	mov    r14d,esi
  8fd074:	e8 c7 2a 0a 00       	call   0x99fb40
  8fd079:	39 d8                	cmp    eax,ebx
  8fd07b:	75 55                	jne    0x8fd0d2
  8fd07d:	4c 8d 3d ac c2 24 03 	lea    r15,[rip+0x324c2ac]        # 0x3b49330
  8fd084:	31 f6                	xor    esi,esi
  8fd086:	31 d2                	xor    edx,edx
  8fd088:	31 c9                	xor    ecx,ecx
  8fd08a:	4c 89 ff             	mov    rdi,r15
  8fd08d:	e8 fe a0 bc ff       	call   0x4c7190
  8fd092:	8b 35 78 c2 24 03    	mov    esi,DWORD PTR [rip+0x324c278]        # 0x3b49310
  8fd098:	48 63 c3             	movsxd rax,ebx
  8fd09b:	89 df                	mov    edi,ebx
  8fd09d:	48 8d 0d 9c c2 24 03 	lea    rcx,[rip+0x324c29c]        # 0x3b49340
  8fd0a4:	48 c1 e0 04          	shl    rax,0x4
  8fd0a8:	48 c7 04 08 00 00 00 	mov    QWORD PTR [rax+rcx*1],0x0
  8fd0af:	00 
  8fd0b0:	44 89 74 08 08       	mov    DWORD PTR [rax+rcx*1+0x8],r14d
  8fd0b5:	e8 16 18 e9 ff       	call   0x78e8d0
  8fd0ba:	4c 89 ff             	mov    rdi,r15
  8fd0bd:	31 f6                	xor    esi,esi
  8fd0bf:	31 d2                	xor    edx,edx
  8fd0c1:	31 c9                	xor    ecx,ecx
  8fd0c3:	48 83 c4 08          	add    rsp,0x8
  8fd0c7:	5b                   	pop    rbx
  8fd0c8:	41 5e                	pop    r14
  8fd0ca:	41 5f                	pop    r15
  8fd0cc:	5d                   	pop    rbp
  8fd0cd:	e9 4e a4 bc ff       	jmp    0x4c7520
  8fd0d2:	48 83 c4 08          	add    rsp,0x8
  8fd0d6:	5b                   	pop    rbx
  8fd0d7:	41 5e                	pop    r14
  8fd0d9:	41 5f                	pop    r15
  8fd0db:	5d                   	pop    rbp
  8fd0dc:	c3                   	ret
  8fd0dd:	90                   	nop
  8fd0de:	90                   	nop
  8fd0df:	90                   	nop
  8fd0e0:	55                   	push   rbp
  8fd0e1:	48 89 e5             	mov    rbp,rsp
  8fd0e4:	41 57                	push   r15
  8fd0e6:	41 56                	push   r14
  8fd0e8:	53                   	push   rbx
  8fd0e9:	50                   	push   rax
  8fd0ea:	41 89 ff             	mov    r15d,edi
  8fd0ed:	31 ff                	xor    edi,edi
  8fd0ef:	48 89 f3             	mov    rbx,rsi
  8fd0f2:	45 31 f6             	xor    r14d,r14d
  8fd0f5:	e8 06 2b 0a 00       	call   0x99fc00
  8fd0fa:	44 39 f8             	cmp    eax,r15d
  8fd0fd:	75 4a                	jne    0x8fd149
  8fd0ff:	48 8d 3d 2a c2 24 03 	lea    rdi,[rip+0x324c22a]        # 0x3b49330
  8fd106:	31 f6                	xor    esi,esi
  8fd108:	31 d2                	xor    edx,edx
  8fd10a:	31 c9                	xor    ecx,ecx
  8fd10c:	e8 7f a0 bc ff       	call   0x4c7190
  8fd111:	bf 01 00 00 00       	mov    edi,0x1
  8fd116:	e8 25 2a 0a 00       	call   0x99fb40
  8fd11b:	85 c0                	test   eax,eax
  8fd11d:	78 11                	js     0x8fd130
  8fd11f:	89 c0                	mov    eax,eax
  8fd121:	48 8d 0d 18 c2 24 03 	lea    rcx,[rip+0x324c218]        # 0x3b49340
  8fd128:	48 c1 e0 04          	shl    rax,0x4
  8fd12c:	48 89 1c 08          	mov    QWORD PTR [rax+rcx*1],rbx
  8fd130:	44 8b 35 d9 c1 24 03 	mov    r14d,DWORD PTR [rip+0x324c1d9]        # 0x3b49310
  8fd137:	48 8d 3d f2 c1 24 03 	lea    rdi,[rip+0x324c1f2]        # 0x3b49330
  8fd13e:	31 f6                	xor    esi,esi
  8fd140:	31 d2                	xor    edx,edx
  8fd142:	31 c9                	xor    ecx,ecx
  8fd144:	e8 d7 a3 bc ff       	call   0x4c7520
  8fd149:	44 89 f0             	mov    eax,r14d
  8fd14c:	48 83 c4 08          	add    rsp,0x8
  8fd150:	5b                   	pop    rbx
  8fd151:	41 5e                	pop    r14
  8fd153:	41 5f                	pop    r15
  8fd155:	5d                   	pop    rbp
  8fd156:	c3                   	ret
  8fd157:	90                   	nop
  8fd158:	90                   	nop
  8fd159:	90                   	nop
  8fd15a:	90                   	nop
  8fd15b:	90                   	nop
  8fd15c:	90                   	nop
  8fd15d:	90                   	nop
  8fd15e:	90                   	nop
  8fd15f:	90                   	nop
  8fd160:	55                   	push   rbp
  8fd161:	48 89 e5             	mov    rbp,rsp
  8fd164:	41 57                	push   r15
  8fd166:	41 56                	push   r14
  8fd168:	41 54                	push   r12
  8fd16a:	53                   	push   rbx
  8fd16b:	41 bc ff ff ff ff    	mov    r12d,0xffffffff
  8fd171:	83 ff 01             	cmp    edi,0x1
  8fd174:	75 65                	jne    0x8fd1db
  8fd176:	48 8d 3d b3 c1 24 03 	lea    rdi,[rip+0x324c1b3]        # 0x3b49330
  8fd17d:	48 89 cb             	mov    rbx,rcx
  8fd180:	49 89 d6             	mov    r14,rdx
  8fd183:	41 89 f7             	mov    r15d,esi
  8fd186:	31 f6                	xor    esi,esi
  8fd188:	31 d2                	xor    edx,edx
  8fd18a:	31 c9                	xor    ecx,ecx
  8fd18c:	e8 ff 9f bc ff       	call   0x4c7190
  8fd191:	bf 01 00 00 00       	mov    edi,0x1
  8fd196:	e8 a5 29 0a 00       	call   0x99fb40
  8fd19b:	85 c0                	test   eax,eax
  8fd19d:	78 2a                	js     0x8fd1c9
  8fd19f:	89 c0                	mov    eax,eax
  8fd1a1:	48 8d 0d 98 c1 24 03 	lea    rcx,[rip+0x324c198]        # 0x3b49340
  8fd1a8:	44 89 3d 61 c1 24 03 	mov    DWORD PTR [rip+0x324c161],r15d        # 0x3b49310
  8fd1af:	48 c1 e0 04          	shl    rax,0x4
  8fd1b3:	48 8b 14 08          	mov    rdx,QWORD PTR [rax+rcx*1]
  8fd1b7:	48 ff c2             	inc    rdx
  8fd1ba:	49 89 16             	mov    QWORD PTR [r14],rdx
  8fd1bd:	8b 44 08 08          	mov    eax,DWORD PTR [rax+rcx*1+0x8]
  8fd1c1:	83 f8 01             	cmp    eax,0x1
  8fd1c4:	89 03                	mov    DWORD PTR [rbx],eax
  8fd1c6:	45 19 e4             	sbb    r12d,r12d
  8fd1c9:	48 8d 3d 60 c1 24 03 	lea    rdi,[rip+0x324c160]        # 0x3b49330
  8fd1d0:	31 f6                	xor    esi,esi
  8fd1d2:	31 d2                	xor    edx,edx
  8fd1d4:	31 c9                	xor    ecx,ecx
  8fd1d6:	e8 45 a3 bc ff       	call   0x4c7520
  8fd1db:	44 89 e0             	mov    eax,r12d
  8fd1de:	5b                   	pop    rbx
  8fd1df:	41 5c                	pop    r12
  8fd1e1:	41 5e                	pop    r14
  8fd1e3:	41 5f                	pop    r15
  8fd1e5:	5d                   	pop    rbp
  8fd1e6:	c3                   	ret
  8fd1e7:	90                   	nop
  8fd1e8:	90                   	nop
  8fd1e9:	90                   	nop
  8fd1ea:	90                   	nop
  8fd1eb:	90                   	nop
  8fd1ec:	90                   	nop
  8fd1ed:	90                   	nop
  8fd1ee:	90                   	nop
  8fd1ef:	90                   	nop
  8fd1f0:	55                   	push   rbp
  8fd1f1:	48 89 e5             	mov    rbp,rsp
  8fd1f4:	48 8d 3d 35 c1 24 03 	lea    rdi,[rip+0x324c135]        # 0x3b49330
  8fd1fb:	48 8d 35 82 d8 99 00 	lea    rsi,[rip+0x99d882]        # 0x129aa84
  8fd202:	b9 01 00 00 00       	mov    ecx,0x1
  8fd207:	31 d2                	xor    edx,edx
  8fd209:	e8 c2 ab bc ff       	call   0x4c7dd0
  8fd20e:	48 c7 05 27 c1 24 03 	mov    QWORD PTR [rip+0x324c127],0xffffffffffffffff        # 0x3b49340
  8fd215:	ff ff ff ff 
  8fd219:	c7 05 25 c1 24 03 00 	mov    DWORD PTR [rip+0x324c125],0x0        # 0x3b49348
  8fd220:	00 00 00 
  8fd223:	48 c7 05 22 c1 24 03 	mov    QWORD PTR [rip+0x324c122],0xffffffffffffffff        # 0x3b49350
  8fd22a:	ff ff ff ff 
  8fd22e:	c7 05 20 c1 24 03 00 	mov    DWORD PTR [rip+0x324c120],0x0        # 0x3b49358
  8fd235:	00 00 00 
  8fd238:	48 c7 05 1d c1 24 03 	mov    QWORD PTR [rip+0x324c11d],0xffffffffffffffff        # 0x3b49360
  8fd23f:	ff ff ff ff 
  8fd243:	c7 05 1b c1 24 03 00 	mov    DWORD PTR [rip+0x324c11b],0x0        # 0x3b49368
  8fd24a:	00 00 00 
  8fd24d:	48 c7 05 18 c1 24 03 	mov    QWORD PTR [rip+0x324c118],0xffffffffffffffff        # 0x3b49370
  8fd254:	ff ff ff ff 
  8fd258:	c7 05 16 c1 24 03 00 	mov    DWORD PTR [rip+0x324c116],0x0        # 0x3b49378
  8fd25f:	00 00 00 
  8fd262:	5d                   	pop    rbp
  8fd263:	c3                   	ret
  8fd264:	90                   	nop
  8fd265:	90                   	nop
  8fd266:	90                   	nop
  8fd267:	90                   	nop
  8fd268:	90                   	nop
  8fd269:	90                   	nop
  8fd26a:	90                   	nop
  8fd26b:	90                   	nop
  8fd26c:	90                   	nop
  8fd26d:	90                   	nop
  8fd26e:	90                   	nop
  8fd26f:	90                   	nop
  8fd270:	55                   	push   rbp
  8fd271:	48 89 e5             	mov    rbp,rsp
  8fd274:	48 8d 3d b5 c0 24 03 	lea    rdi,[rip+0x324c0b5]        # 0x3b49330
  8fd27b:	5d                   	pop    rbp
  8fd27c:	e9 cf ab bc ff       	jmp    0x4c7e50
  8fd281:	90                   	nop
  8fd282:	90                   	nop
  8fd283:	90                   	nop
  8fd284:	90                   	nop
  8fd285:	90                   	nop
  8fd286:	90                   	nop
  8fd287:	90                   	nop
  8fd288:	90                   	nop
  8fd289:	90                   	nop
  8fd28a:	90                   	nop
  8fd28b:	90                   	nop
  8fd28c:	90                   	nop
  8fd28d:	90                   	nop
  8fd28e:	90                   	nop
  8fd28f:	90                   	nop
  8fd290:	55                   	push   rbp
  8fd291:	48 89 e5             	mov    rbp,rsp
  8fd294:	31 c0                	xor    eax,eax
  8fd296:	5d                   	pop    rbp
  8fd297:	c3                   	ret
  8fd298:	90                   	nop
  8fd299:	90                   	nop
  8fd29a:	90                   	nop
  8fd29b:	90                   	nop
  8fd29c:	90                   	nop
  8fd29d:	90                   	nop
  8fd29e:	90                   	nop
  8fd29f:	90                   	nop
  8fd2a0:	b8 37 00 00 00       	mov    eax,0x37
  8fd2a5:	81 fe 00 00 01 00    	cmp    esi,0x10000
  8fd2ab:	0f 87 a2 00 00 00    	ja     0x8fd353
  8fd2b1:	55                   	push   rbp
  8fd2b2:	48 89 e5             	mov    rbp,rsp
  8fd2b5:	41 57                	push   r15
  8fd2b7:	41 56                	push   r14
  8fd2b9:	41 55                	push   r13
  8fd2bb:	41 54                	push   r12
  8fd2bd:	53                   	push   rbx
  8fd2be:	50                   	push   rax
  8fd2bf:	49 89 fc             	mov    r12,rdi
  8fd2c2:	45 31 ff             	xor    r15d,r15d
  8fd2c5:	49 83 f8 02          	cmp    r8,0x2
  8fd2c9:	48 8d 3d 38 ed 25 03 	lea    rdi,[rip+0x325ed38]        # 0x3b5c008
  8fd2d0:	41 89 ce             	mov    r14d,ecx
  8fd2d3:	48 89 d3             	mov    rbx,rdx
  8fd2d6:	41 89 f5             	mov    r13d,esi
  8fd2d9:	89 75 d4             	mov    DWORD PTR [rbp-0x2c],esi
  8fd2dc:	41 0f 94 c7          	sete   r15b
  8fd2e0:	31 f6                	xor    esi,esi
  8fd2e2:	31 d2                	xor    edx,edx
  8fd2e4:	31 c9                	xor    ecx,ecx
  8fd2e6:	e8 35 e8 34 00       	call   0xc4bb20
  8fd2eb:	48 8d 3d 0e ed 24 03 	lea    rdi,[rip+0x324ed0e]        # 0x3b4c000
  8fd2f2:	4c 89 e6             	mov    rsi,r12
  8fd2f5:	4c 89 ea             	mov    rdx,r13
  8fd2f8:	e8 b3 bd 95 ff       	call   0x2590b0
  8fd2fd:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
  8fd300:	44 89 f7             	mov    edi,r14d
  8fd303:	48 8d 35 f6 ec 24 03 	lea    rsi,[rip+0x324ecf6]        # 0x3b4c000
  8fd30a:	48 89 d9             	mov    rcx,rbx
  8fd30d:	45 89 f9             	mov    r9d,r15d
  8fd310:	45 31 c0             	xor    r8d,r8d
  8fd313:	e8 c8 f8 25 00       	call   0xb5cbe0
  8fd318:	48 8b 0d 01 ed 25 03 	mov    rcx,QWORD PTR [rip+0x325ed01]        # 0x3b5c020
  8fd31f:	f6 c1 01             	test   cl,0x1
  8fd322:	75 21                	jne    0x8fd345
  8fd324:	48 8b 0d f5 ec 25 03 	mov    rcx,QWORD PTR [rip+0x325ecf5]        # 0x3b5c020
  8fd32b:	48 83 f9 10          	cmp    rcx,0x10
  8fd32f:	72 14                	jb     0x8fd345
  8fd331:	48 8d 3d d0 ec 25 03 	lea    rdi,[rip+0x325ecd0]        # 0x3b5c008
  8fd338:	31 f6                	xor    esi,esi
  8fd33a:	31 d2                	xor    edx,edx
  8fd33c:	89 c3                	mov    ebx,eax
  8fd33e:	e8 6d f1 34 00       	call   0xc4c4b0
  8fd343:	89 d8                	mov    eax,ebx
  8fd345:	48 83 c4 08          	add    rsp,0x8
  8fd349:	5b                   	pop    rbx
  8fd34a:	41 5c                	pop    r12
  8fd34c:	41 5d                	pop    r13
  8fd34e:	41 5e                	pop    r14
  8fd350:	41 5f                	pop    r15
  8fd352:	5d                   	pop    rbp
  8fd353:	c3                   	ret
  8fd354:	90                   	nop
  8fd355:	90                   	nop
  8fd356:	90                   	nop
  8fd357:	90                   	nop
  8fd358:	90                   	nop
  8fd359:	90                   	nop
  8fd35a:	90                   	nop
  8fd35b:	90                   	nop
  8fd35c:	90                   	nop
  8fd35d:	90                   	nop
  8fd35e:	90                   	nop
  8fd35f:	90                   	nop
  8fd360:	b8 37 00 00 00       	mov    eax,0x37
  8fd365:	81 fe 00 00 01 00    	cmp    esi,0x10000
  8fd36b:	0f 87 ba 00 00 00    	ja     0x8fd42b
  8fd371:	55                   	push   rbp
  8fd372:	48 89 e5             	mov    rbp,rsp
  8fd375:	41 57                	push   r15
  8fd377:	41 56                	push   r14
  8fd379:	41 55                	push   r13
  8fd37b:	41 54                	push   r12
  8fd37d:	53                   	push   rbx
  8fd37e:	50                   	push   rax
  8fd37f:	48 89 fb             	mov    rbx,rdi
  8fd382:	48 8d 3d 7f ec 25 03 	lea    rdi,[rip+0x325ec7f]        # 0x3b5c008
  8fd389:	41 89 cc             	mov    r12d,ecx
  8fd38c:	49 89 d7             	mov    r15,rdx
  8fd38f:	41 89 f6             	mov    r14d,esi
  8fd392:	41 89 f5             	mov    r13d,esi
  8fd395:	31 f6                	xor    esi,esi
  8fd397:	31 d2                	xor    edx,edx
  8fd399:	31 c9                	xor    ecx,ecx
  8fd39b:	e8 80 e7 34 00       	call   0xc4bb20
  8fd3a0:	48 8d 3d 59 ec 24 03 	lea    rdi,[rip+0x324ec59]        # 0x3b4c000
  8fd3a7:	48 89 de             	mov    rsi,rbx
  8fd3aa:	4c 89 f2             	mov    rdx,r14
  8fd3ad:	4c 89 75 d0          	mov    QWORD PTR [rbp-0x30],r14
  8fd3b1:	e8 fa bc 95 ff       	call   0x2590b0
  8fd3b6:	44 89 e8             	mov    eax,r13d
  8fd3b9:	44 89 e7             	mov    edi,r12d
  8fd3bc:	48 8d 35 3d ec 24 03 	lea    rsi,[rip+0x324ec3d]        # 0x3b4c000
  8fd3c3:	44 89 ea             	mov    edx,r13d
  8fd3c6:	c1 e8 0c             	shr    eax,0xc
  8fd3c9:	4c 0f af f8          	imul   r15,rax
  8fd3cd:	4c 89 f9             	mov    rcx,r15
  8fd3d0:	e8 fb 01 26 00       	call   0xb5d5d0
  8fd3d5:	85 c0                	test   eax,eax
  8fd3d7:	75 17                	jne    0x8fd3f0
  8fd3d9:	48 8b 55 d0          	mov    rdx,QWORD PTR [rbp-0x30]
  8fd3dd:	48 89 df             	mov    rdi,rbx
  8fd3e0:	48 8d 35 19 ec 24 03 	lea    rsi,[rip+0x324ec19]        # 0x3b4c000
  8fd3e7:	89 c3                	mov    ebx,eax
  8fd3e9:	e8 c2 bc 95 ff       	call   0x2590b0
  8fd3ee:	89 d8                	mov    eax,ebx
  8fd3f0:	48 8b 0d 29 ec 25 03 	mov    rcx,QWORD PTR [rip+0x325ec29]        # 0x3b5c020
  8fd3f7:	f6 c1 01             	test   cl,0x1
  8fd3fa:	75 21                	jne    0x8fd41d
  8fd3fc:	48 8b 0d 1d ec 25 03 	mov    rcx,QWORD PTR [rip+0x325ec1d]        # 0x3b5c020
  8fd403:	48 83 f9 10          	cmp    rcx,0x10
  8fd407:	72 14                	jb     0x8fd41d
  8fd409:	48 8d 3d f8 eb 25 03 	lea    rdi,[rip+0x325ebf8]        # 0x3b5c008
  8fd410:	31 f6                	xor    esi,esi
  8fd412:	31 d2                	xor    edx,edx
  8fd414:	89 c3                	mov    ebx,eax
  8fd416:	e8 95 f0 34 00       	call   0xc4c4b0
  8fd41b:	89 d8                	mov    eax,ebx
  8fd41d:	48 83 c4 08          	add    rsp,0x8
  8fd421:	5b                   	pop    rbx
  8fd422:	41 5c                	pop    r12
  8fd424:	41 5d                	pop    r13
  8fd426:	41 5e                	pop    r14
  8fd428:	41 5f                	pop    r15
  8fd42a:	5d                   	pop    rbp
  8fd42b:	c3                   	ret
  8fd42c:	90                   	nop
  8fd42d:	90                   	nop
  8fd42e:	90                   	nop
  8fd42f:	90                   	nop
  8fd430:	55                   	push   rbp
  8fd431:	48 89 e5             	mov    rbp,rsp
  8fd434:	41 57                	push   r15
  8fd436:	41 56                	push   r14
  8fd438:	41 55                	push   r13
  8fd43a:	41 54                	push   r12
  8fd43c:	53                   	push   rbx
  8fd43d:	48 83 ec 18          	sub    rsp,0x18
  8fd441:	b8 37 00 00 00       	mov    eax,0x37
  8fd446:	48 89 7d d0          	mov    QWORD PTR [rbp-0x30],rdi
  8fd44a:	81 fe 00 00 01 00    	cmp    esi,0x10000
  8fd450:	0f 87 9e 00 00 00    	ja     0x8fd4f4
  8fd456:	48 8d 3d ab eb 25 03 	lea    rdi,[rip+0x325ebab]        # 0x3b5c008
  8fd45d:	41 89 cc             	mov    r12d,ecx
  8fd460:	49 89 d7             	mov    r15,rdx
  8fd463:	89 f3                	mov    ebx,esi
  8fd465:	41 89 f5             	mov    r13d,esi
  8fd468:	31 f6                	xor    esi,esi
  8fd46a:	31 d2                	xor    edx,edx
  8fd46c:	31 c9                	xor    ecx,ecx
  8fd46e:	e8 ad e6 34 00       	call   0xc4bb20
  8fd473:	48 8b 75 d0          	mov    rsi,QWORD PTR [rbp-0x30]
  8fd477:	4c 8d 35 82 eb 24 03 	lea    r14,[rip+0x324eb82]        # 0x3b4c000
  8fd47e:	48 89 da             	mov    rdx,rbx
  8fd481:	48 89 5d c8          	mov    QWORD PTR [rbp-0x38],rbx
  8fd485:	4c 89 f7             	mov    rdi,r14
  8fd488:	e8 23 bc 95 ff       	call   0x2590b0
  8fd48d:	44 89 e8             	mov    eax,r13d
  8fd490:	44 89 e7             	mov    edi,r12d
  8fd493:	4c 89 f6             	mov    rsi,r14
  8fd496:	4c 89 f2             	mov    rdx,r14
  8fd499:	44 89 e9             	mov    ecx,r13d
  8fd49c:	c1 e8 0c             	shr    eax,0xc
  8fd49f:	4c 0f af f8          	imul   r15,rax
  8fd4a3:	4d 89 f8             	mov    r8,r15
  8fd4a6:	e8 c5 fc 25 00       	call   0xb5d170
  8fd4ab:	85 c0                	test   eax,eax
  8fd4ad:	75 18                	jne    0x8fd4c7
  8fd4af:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
  8fd4b3:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
  8fd4b7:	48 8d 35 42 eb 24 03 	lea    rsi,[rip+0x324eb42]        # 0x3b4c000
  8fd4be:	89 c3                	mov    ebx,eax
  8fd4c0:	e8 eb bb 95 ff       	call   0x2590b0
  8fd4c5:	89 d8                	mov    eax,ebx
  8fd4c7:	48 8b 0d 52 eb 25 03 	mov    rcx,QWORD PTR [rip+0x325eb52]        # 0x3b5c020
  8fd4ce:	f6 c1 01             	test   cl,0x1
  8fd4d1:	75 21                	jne    0x8fd4f4
  8fd4d3:	48 8b 0d 46 eb 25 03 	mov    rcx,QWORD PTR [rip+0x325eb46]        # 0x3b5c020
  8fd4da:	48 83 f9 10          	cmp    rcx,0x10
  8fd4de:	72 14                	jb     0x8fd4f4
  8fd4e0:	48 8d 3d 21 eb 25 03 	lea    rdi,[rip+0x325eb21]        # 0x3b5c008
  8fd4e7:	31 f6                	xor    esi,esi
  8fd4e9:	31 d2                	xor    edx,edx
  8fd4eb:	89 c3                	mov    ebx,eax
  8fd4ed:	e8 be ef 34 00       	call   0xc4c4b0
  8fd4f2:	89 d8                	mov    eax,ebx
  8fd4f4:	48 83 c4 18          	add    rsp,0x18
  8fd4f8:	5b                   	pop    rbx
  8fd4f9:	41 5c                	pop    r12
  8fd4fb:	41 5d                	pop    r13
  8fd4fd:	41 5e                	pop    r14
  8fd4ff:	41 5f                	pop    r15
  8fd501:	5d                   	pop    rbp
  8fd502:	c3                   	ret
  8fd503:	90                   	nop
  8fd504:	90                   	nop
  8fd505:	90                   	nop
  8fd506:	90                   	nop
  8fd507:	90                   	nop
  8fd508:	90                   	nop
  8fd509:	90                   	nop
  8fd50a:	90                   	nop
  8fd50b:	90                   	nop
  8fd50c:	90                   	nop
  8fd50d:	90                   	nop
  8fd50e:	90                   	nop
  8fd50f:	90                   	nop
  8fd510:	55                   	push   rbp
  8fd511:	48 89 e5             	mov    rbp,rsp
  8fd514:	41 57                	push   r15
  8fd516:	41 56                	push   r14
  8fd518:	41 55                	push   r13
  8fd51a:	41 54                	push   r12
  8fd51c:	53                   	push   rbx
  8fd51d:	48 83 ec 18          	sub    rsp,0x18
  8fd521:	45 89 c5             	mov    r13d,r8d
  8fd524:	4d 89 cf             	mov    r15,r9
  8fd527:	48 89 cb             	mov    rbx,rcx
  8fd52a:	49 89 d0             	mov    r8,rdx
  8fd52d:	49 89 f4             	mov    r12,rsi
  8fd530:	49 89 fe             	mov    r14,rdi
  8fd533:	b8 01 00 00 00       	mov    eax,0x1
  8fd538:	f0 0f c1 05 c0 ea 25 	lock xadd DWORD PTR [rip+0x325eac0],eax        # 0x3b5c000
  8fd53f:	03 
  8fd540:	85 c0                	test   eax,eax
  8fd542:	74 20                	je     0x8fd564
  8fd544:	48 85 db             	test   rbx,rbx
  8fd547:	74 3d                	je     0x8fd586
  8fd549:	48 8b 75 10          	mov    rsi,QWORD PTR [rbp+0x10]
  8fd54d:	4c 89 ff             	mov    rdi,r15
  8fd550:	4c 89 f2             	mov    rdx,r14
  8fd553:	4c 89 e1             	mov    rcx,r12
  8fd556:	49 89 d9             	mov    r9,rbx
  8fd559:	44 89 2c 24          	mov    DWORD PTR [rsp],r13d
  8fd55d:	e8 7e f5 25 00       	call   0xb5cae0
  8fd562:	eb 27                	jmp    0x8fd58b
  8fd564:	48 8d 3d 9d ea 25 03 	lea    rdi,[rip+0x325ea9d]        # 0x3b5c008
  8fd56b:	48 8d 35 ec c6 a3 00 	lea    rsi,[rip+0xa3c6ec]        # 0x1339c5e
  8fd572:	31 d2                	xor    edx,edx
  8fd574:	4c 89 45 d0          	mov    QWORD PTR [rbp-0x30],r8
  8fd578:	e8 13 dd 34 00       	call   0xc4b290
  8fd57d:	4c 8b 45 d0          	mov    r8,QWORD PTR [rbp-0x30]
  8fd581:	48 85 db             	test   rbx,rbx
  8fd584:	75 c3                	jne    0x8fd549
  8fd586:	b8 16 00 00 00       	mov    eax,0x16
  8fd58b:	48 83 c4 18          	add    rsp,0x18
  8fd58f:	5b                   	pop    rbx
  8fd590:	41 5c                	pop    r12
  8fd592:	41 5d                	pop    r13
  8fd594:	41 5e                	pop    r14
  8fd596:	41 5f                	pop    r15
  8fd598:	5d                   	pop    rbp
  8fd599:	c3                   	ret
  8fd59a:	90                   	nop
  8fd59b:	90                   	nop
  8fd59c:	90                   	nop
  8fd59d:	90                   	nop
  8fd59e:	90                   	nop
  8fd59f:	90                   	nop
  8fd5a0:	55                   	push   rbp
  8fd5a1:	48 89 e5             	mov    rbp,rsp
  8fd5a4:	41 57                	push   r15
  8fd5a6:	41 56                	push   r14
  8fd5a8:	41 55                	push   r13
  8fd5aa:	41 54                	push   r12
  8fd5ac:	53                   	push   rbx
  8fd5ad:	48 83 ec 18          	sub    rsp,0x18
  8fd5b1:	45 89 c5             	mov    r13d,r8d
  8fd5b4:	4d 89 cf             	mov    r15,r9
  8fd5b7:	48 89 cb             	mov    rbx,rcx
  8fd5ba:	49 89 d0             	mov    r8,rdx
  8fd5bd:	49 89 f4             	mov    r12,rsi
  8fd5c0:	49 89 fe             	mov    r14,rdi
  8fd5c3:	b8 01 00 00 00       	mov    eax,0x1
  8fd5c8:	f0 0f c1 05 30 ea 25 	lock xadd DWORD PTR [rip+0x325ea30],eax        # 0x3b5c000
  8fd5cf:	03 
  8fd5d0:	85 c0                	test   eax,eax
  8fd5d2:	74 20                	je     0x8fd5f4
  8fd5d4:	48 85 db             	test   rbx,rbx
  8fd5d7:	74 3d                	je     0x8fd616
  8fd5d9:	48 8b 75 10          	mov    rsi,QWORD PTR [rbp+0x10]
  8fd5dd:	4c 89 ff             	mov    rdi,r15
  8fd5e0:	4c 89 f2             	mov    rdx,r14
  8fd5e3:	4c 89 e1             	mov    rcx,r12
  8fd5e6:	49 89 d9             	mov    r9,rbx
  8fd5e9:	44 89 2c 24          	mov    DWORD PTR [rsp],r13d
  8fd5ed:	e8 4e f5 25 00       	call   0xb5cb40
  8fd5f2:	eb 27                	jmp    0x8fd61b
  8fd5f4:	48 8d 3d 0d ea 25 03 	lea    rdi,[rip+0x325ea0d]        # 0x3b5c008
  8fd5fb:	48 8d 35 5c c6 a3 00 	lea    rsi,[rip+0xa3c65c]        # 0x1339c5e
  8fd602:	31 d2                	xor    edx,edx
  8fd604:	4c 89 45 d0          	mov    QWORD PTR [rbp-0x30],r8
  8fd608:	e8 83 dc 34 00       	call   0xc4b290
  8fd60d:	4c 8b 45 d0          	mov    r8,QWORD PTR [rbp-0x30]
  8fd611:	48 85 db             	test   rbx,rbx
  8fd614:	75 c3                	jne    0x8fd5d9
  8fd616:	b8 16 00 00 00       	mov    eax,0x16
  8fd61b:	48 83 c4 18          	add    rsp,0x18
  8fd61f:	5b                   	pop    rbx
  8fd620:	41 5c                	pop    r12
  8fd622:	41 5d                	pop    r13
  8fd624:	41 5e                	pop    r14
  8fd626:	41 5f                	pop    r15
  8fd628:	5d                   	pop    rbp
  8fd629:	c3                   	ret
  8fd62a:	90                   	nop
  8fd62b:	90                   	nop
  8fd62c:	90                   	nop
  8fd62d:	90                   	nop
  8fd62e:	90                   	nop
  8fd62f:	90                   	nop
  8fd630:	b8 ff ff ff ff       	mov    eax,0xffffffff
  8fd635:	f0 0f c1 05 c3 e9 25 	lock xadd DWORD PTR [rip+0x325e9c3],eax        # 0x3b5c000
  8fd63c:	03 
  8fd63d:	83 f8 01             	cmp    eax,0x1
  8fd640:	0f 85 4a f5 25 00    	jne    0xb5cb90
  8fd646:	55                   	push   rbp
  8fd647:	48 89 e5             	mov    rbp,rsp
  8fd64a:	41 56                	push   r14
  8fd64c:	53                   	push   rbx
  8fd64d:	48 8d 05 b4 e9 25 03 	lea    rax,[rip+0x325e9b4]        # 0x3b5c008
  8fd654:	89 fb                	mov    ebx,edi
  8fd656:	41 89 f6             	mov    r14d,esi
  8fd659:	48 89 c7             	mov    rdi,rax
  8fd65c:	e8 2f 3a 96 ff       	call   0x261090
  8fd661:	89 df                	mov    edi,ebx
  8fd663:	44 89 f6             	mov    esi,r14d
  8fd666:	5b                   	pop    rbx
  8fd667:	41 5e                	pop    r14
  8fd669:	5d                   	pop    rbp
  8fd66a:	e9 21 f5 25 00       	jmp    0xb5cb90
  8fd66f:	90                   	nop
  8fd670:	55                   	push   rbp
  8fd671:	48 89 e5             	mov    rbp,rsp
  8fd674:	48 8b 46 10          	mov    rax,QWORD PTR [rsi+0x10]
  8fd678:	eb 25                	jmp    0x8fd69f
  8fd67a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  8fd680:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  8fd687:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
  8fd68e:	48 89 c8             	mov    rax,rcx
  8fd691:	c7 41 18 01 00 00 00 	mov    DWORD PTR [rcx+0x18],0x1
  8fd698:	48 89 c6             	mov    rsi,rax
  8fd69b:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
  8fd69f:	48 85 c0             	test   rax,rax
  8fd6a2:	0f 84 99 01 00 00    	je     0x8fd841
  8fd6a8:	83 78 18 01          	cmp    DWORD PTR [rax+0x18],0x1
  8fd6ac:	0f 85 8f 01 00 00    	jne    0x8fd841
  8fd6b2:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
  8fd6b6:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  8fd6b9:	48 39 d0             	cmp    rax,rdx
  8fd6bc:	74 22                	je     0x8fd6e0
  8fd6be:	48 85 d2             	test   rdx,rdx
  8fd6c1:	74 06                	je     0x8fd6c9
  8fd6c3:	83 7a 18 01          	cmp    DWORD PTR [rdx+0x18],0x1
  8fd6c7:	74 b7                	je     0x8fd680
  8fd6c9:	48 8b 10             	mov    rdx,QWORD PTR [rax]
  8fd6cc:	48 39 f2             	cmp    rdx,rsi
  8fd6cf:	74 32                	je     0x8fd703
  8fd6d1:	48 89 c2             	mov    rdx,rax
  8fd6d4:	48 89 f0             	mov    rax,rsi
  8fd6d7:	e9 a6 00 00 00       	jmp    0x8fd782
  8fd6dc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  8fd6e0:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  8fd6e4:	48 85 d2             	test   rdx,rdx
  8fd6e7:	74 06                	je     0x8fd6ef
  8fd6e9:	83 7a 18 01          	cmp    DWORD PTR [rdx+0x18],0x1
  8fd6ed:	74 91                	je     0x8fd680
  8fd6ef:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
  8fd6f3:	48 39 f2             	cmp    rdx,rsi
  8fd6f6:	74 33                	je     0x8fd72b
  8fd6f8:	48 89 c2             	mov    rdx,rax
  8fd6fb:	48 89 f0             	mov    rax,rsi
  8fd6fe:	e9 f0 00 00 00       	jmp    0x8fd7f3
  8fd703:	4c 8b 42 08          	mov    r8,QWORD PTR [rdx+0x8]
  8fd707:	4c 89 00             	mov    QWORD PTR [rax],r8
  8fd70a:	4d 85 c0             	test   r8,r8
  8fd70d:	74 53                	je     0x8fd762
  8fd70f:	49 89 40 10          	mov    QWORD PTR [r8+0x10],rax
  8fd713:	4c 8b 40 10          	mov    r8,QWORD PTR [rax+0x10]
  8fd717:	4c 89 42 10          	mov    QWORD PTR [rdx+0x10],r8
  8fd71b:	4d 85 c0             	test   r8,r8
  8fd71e:	74 54                	je     0x8fd774
  8fd720:	49 3b 00             	cmp    rax,QWORD PTR [r8]
  8fd723:	74 4a                	je     0x8fd76f
  8fd725:	49 89 50 08          	mov    QWORD PTR [r8+0x8],rdx
  8fd729:	eb 4c                	jmp    0x8fd777
  8fd72b:	4c 8b 02             	mov    r8,QWORD PTR [rdx]
  8fd72e:	4c 89 40 08          	mov    QWORD PTR [rax+0x8],r8
  8fd732:	4d 85 c0             	test   r8,r8
  8fd735:	0f 84 95 00 00 00    	je     0x8fd7d0
  8fd73b:	49 89 40 10          	mov    QWORD PTR [r8+0x10],rax
  8fd73f:	4c 8b 40 10          	mov    r8,QWORD PTR [rax+0x10]
  8fd743:	4c 89 42 10          	mov    QWORD PTR [rdx+0x10],r8
  8fd747:	4d 85 c0             	test   r8,r8
  8fd74a:	0f 84 96 00 00 00    	je     0x8fd7e6
  8fd750:	49 3b 00             	cmp    rax,QWORD PTR [r8]
  8fd753:	0f 84 88 00 00 00    	je     0x8fd7e1
  8fd759:	49 89 50 08          	mov    QWORD PTR [r8+0x8],rdx
  8fd75d:	e9 87 00 00 00       	jmp    0x8fd7e9
  8fd762:	48 89 4a 10          	mov    QWORD PTR [rdx+0x10],rcx
  8fd766:	4c 8b 40 10          	mov    r8,QWORD PTR [rax+0x10]
  8fd76a:	49 3b 00             	cmp    rax,QWORD PTR [r8]
  8fd76d:	75 b6                	jne    0x8fd725
  8fd76f:	49 89 10             	mov    QWORD PTR [r8],rdx
  8fd772:	eb 03                	jmp    0x8fd777
  8fd774:	48 89 17             	mov    QWORD PTR [rdi],rdx
  8fd777:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
  8fd77b:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
  8fd77f:	48 89 f2             	mov    rdx,rsi
  8fd782:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  8fd789:	c7 41 18 01 00 00 00 	mov    DWORD PTR [rcx+0x18],0x1
  8fd790:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  8fd794:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  8fd797:	48 89 71 08          	mov    QWORD PTR [rcx+0x8],rsi
  8fd79b:	48 85 f6             	test   rsi,rsi
  8fd79e:	74 04                	je     0x8fd7a4
  8fd7a0:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  8fd7a4:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  8fd7a8:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  8fd7ac:	48 85 f6             	test   rsi,rsi
  8fd7af:	74 0b                	je     0x8fd7bc
  8fd7b1:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  8fd7b4:	74 0b                	je     0x8fd7c1
  8fd7b6:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  8fd7ba:	eb 08                	jmp    0x8fd7c4
  8fd7bc:	48 89 17             	mov    QWORD PTR [rdi],rdx
  8fd7bf:	eb 03                	jmp    0x8fd7c4
  8fd7c1:	48 89 16             	mov    QWORD PTR [rsi],rdx
  8fd7c4:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  8fd7c7:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  8fd7cb:	e9 c8 fe ff ff       	jmp    0x8fd698
  8fd7d0:	48 89 4a 10          	mov    QWORD PTR [rdx+0x10],rcx
  8fd7d4:	4c 8b 40 10          	mov    r8,QWORD PTR [rax+0x10]
  8fd7d8:	49 3b 00             	cmp    rax,QWORD PTR [r8]
  8fd7db:	0f 85 78 ff ff ff    	jne    0x8fd759
  8fd7e1:	49 89 10             	mov    QWORD PTR [r8],rdx
  8fd7e4:	eb 03                	jmp    0x8fd7e9
  8fd7e6:	48 89 17             	mov    QWORD PTR [rdi],rdx
  8fd7e9:	48 89 02             	mov    QWORD PTR [rdx],rax
  8fd7ec:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
  8fd7f0:	48 89 f2             	mov    rdx,rsi
  8fd7f3:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  8fd7fa:	c7 41 18 01 00 00 00 	mov    DWORD PTR [rcx+0x18],0x1
  8fd801:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  8fd804:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
  8fd808:	48 89 31             	mov    QWORD PTR [rcx],rsi
  8fd80b:	48 85 f6             	test   rsi,rsi
  8fd80e:	74 04                	je     0x8fd814
  8fd810:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  8fd814:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  8fd818:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  8fd81c:	48 85 f6             	test   rsi,rsi
  8fd81f:	74 0b                	je     0x8fd82c
  8fd821:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  8fd824:	74 0b                	je     0x8fd831
  8fd826:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  8fd82a:	eb 08                	jmp    0x8fd834
  8fd82c:	48 89 17             	mov    QWORD PTR [rdi],rdx
  8fd82f:	eb 03                	jmp    0x8fd834
  8fd831:	48 89 16             	mov    QWORD PTR [rsi],rdx
  8fd834:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  8fd838:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  8fd83c:	e9 57 fe ff ff       	jmp    0x8fd698
  8fd841:	48 8b 07             	mov    rax,QWORD PTR [rdi]
  8fd844:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
  8fd84b:	5d                   	pop    rbp
  8fd84c:	c3                   	ret
  8fd84d:	90                   	nop
  8fd84e:	90                   	nop
  8fd84f:	90                   	nop
  8fd850:	55                   	push   rbp
  8fd851:	48 89 e5             	mov    rbp,rsp
  8fd854:	48 8b 0e             	mov    rcx,QWORD PTR [rsi]
  8fd857:	4c 8b 4e 08          	mov    r9,QWORD PTR [rsi+0x8]
  8fd85b:	48 89 f0             	mov    rax,rsi
  8fd85e:	48 85 c9             	test   rcx,rcx
  8fd861:	74 3d                	je     0x8fd8a0
  8fd863:	4d 85 c9             	test   r9,r9
  8fd866:	74 49                	je     0x8fd8b1
  8fd868:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  8fd86f:	00 
  8fd870:	4d 89 c8             	mov    r8,r9
  8fd873:	4d 8b 09             	mov    r9,QWORD PTR [r9]
  8fd876:	4d 85 c9             	test   r9,r9
  8fd879:	75 f5                	jne    0x8fd870
  8fd87b:	49 8b 48 08          	mov    rcx,QWORD PTR [r8+0x8]
  8fd87f:	49 8b 50 10          	mov    rdx,QWORD PTR [r8+0x10]
  8fd883:	41 8b 70 18          	mov    esi,DWORD PTR [r8+0x18]
  8fd887:	48 85 c9             	test   rcx,rcx
  8fd88a:	74 04                	je     0x8fd890
  8fd88c:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  8fd890:	48 85 d2             	test   rdx,rdx
  8fd893:	74 37                	je     0x8fd8cc
  8fd895:	4c 39 02             	cmp    QWORD PTR [rdx],r8
  8fd898:	74 4a                	je     0x8fd8e4
  8fd89a:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  8fd89e:	eb 47                	jmp    0x8fd8e7
  8fd8a0:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
  8fd8a4:	8b 70 18             	mov    esi,DWORD PTR [rax+0x18]
  8fd8a7:	4d 85 c9             	test   r9,r9
  8fd8aa:	74 2a                	je     0x8fd8d6
  8fd8ac:	4c 89 c9             	mov    rcx,r9
  8fd8af:	eb 07                	jmp    0x8fd8b8
  8fd8b1:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
  8fd8b5:	8b 70 18             	mov    esi,DWORD PTR [rax+0x18]
  8fd8b8:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  8fd8bc:	48 85 d2             	test   rdx,rdx
  8fd8bf:	74 1c                	je     0x8fd8dd
  8fd8c1:	48 39 02             	cmp    QWORD PTR [rdx],rax
  8fd8c4:	74 0b                	je     0x8fd8d1
  8fd8c6:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  8fd8ca:	eb 71                	jmp    0x8fd93d
  8fd8cc:	48 89 0f             	mov    QWORD PTR [rdi],rcx
  8fd8cf:	eb 16                	jmp    0x8fd8e7
  8fd8d1:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  8fd8d4:	eb 67                	jmp    0x8fd93d
  8fd8d6:	31 c9                	xor    ecx,ecx
  8fd8d8:	48 85 d2             	test   rdx,rdx
  8fd8db:	75 e4                	jne    0x8fd8c1
  8fd8dd:	31 d2                	xor    edx,edx
  8fd8df:	48 89 0f             	mov    QWORD PTR [rdi],rcx
  8fd8e2:	eb 59                	jmp    0x8fd93d
  8fd8e4:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  8fd8e7:	4c 8b 48 18          	mov    r9,QWORD PTR [rax+0x18]
  8fd8eb:	49 39 40 10          	cmp    QWORD PTR [r8+0x10],rax
  8fd8ef:	4d 89 48 18          	mov    QWORD PTR [r8+0x18],r9
  8fd8f3:	4c 8b 48 10          	mov    r9,QWORD PTR [rax+0x10]
  8fd8f7:	49 0f 44 d0          	cmove  rdx,r8
  8fd8fb:	4d 89 48 10          	mov    QWORD PTR [r8+0x10],r9
  8fd8ff:	4c 8b 08             	mov    r9,QWORD PTR [rax]
  8fd902:	4c 8b 50 08          	mov    r10,QWORD PTR [rax+0x8]
  8fd906:	4d 89 50 08          	mov    QWORD PTR [r8+0x8],r10
  8fd90a:	4d 89 08             	mov    QWORD PTR [r8],r9
  8fd90d:	4c 8b 48 10          	mov    r9,QWORD PTR [rax+0x10]
  8fd911:	4d 85 c9             	test   r9,r9
  8fd914:	74 0b                	je     0x8fd921
  8fd916:	49 39 01             	cmp    QWORD PTR [r9],rax
  8fd919:	74 0b                	je     0x8fd926
  8fd91b:	4d 89 41 08          	mov    QWORD PTR [r9+0x8],r8
  8fd91f:	eb 08                	jmp    0x8fd929
  8fd921:	4c 89 07             	mov    QWORD PTR [rdi],r8
  8fd924:	eb 03                	jmp    0x8fd929
  8fd926:	4d 89 01             	mov    QWORD PTR [r9],r8
  8fd929:	4c 8b 08             	mov    r9,QWORD PTR [rax]
  8fd92c:	4d 89 41 10          	mov    QWORD PTR [r9+0x10],r8
  8fd930:	4c 8b 48 08          	mov    r9,QWORD PTR [rax+0x8]
  8fd934:	4d 85 c9             	test   r9,r9
  8fd937:	74 04                	je     0x8fd93d
  8fd939:	4d 89 41 10          	mov    QWORD PTR [r9+0x10],r8
  8fd93d:	85 f6                	test   esi,esi
  8fd93f:	74 1a                	je     0x8fd95b
  8fd941:	5d                   	pop    rbp
  8fd942:	c3                   	ret
  8fd943:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fd94a:	84 00 00 00 00 00 
  8fd950:	c7 42 18 01 00 00 00 	mov    DWORD PTR [rdx+0x18],0x1
  8fd957:	48 8b 51 10          	mov    rdx,QWORD PTR [rcx+0x10]
  8fd95b:	48 89 ce             	mov    rsi,rcx
  8fd95e:	48 89 d1             	mov    rcx,rdx
  8fd961:	48 85 f6             	test   rsi,rsi
  8fd964:	74 0a                	je     0x8fd970
  8fd966:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  8fd96a:	0f 85 3b 02 00 00    	jne    0x8fdbab
  8fd970:	48 3b 37             	cmp    rsi,QWORD PTR [rdi]
  8fd973:	0f 84 29 02 00 00    	je     0x8fdba2
  8fd979:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  8fd97c:	48 39 f2             	cmp    rdx,rsi
  8fd97f:	74 4f                	je     0x8fd9d0
  8fd981:	83 7a 18 01          	cmp    DWORD PTR [rdx+0x18],0x1
  8fd985:	0f 85 a0 00 00 00    	jne    0x8fda2b
  8fd98b:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  8fd992:	c7 41 18 01 00 00 00 	mov    DWORD PTR [rcx+0x18],0x1
  8fd999:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  8fd99c:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
  8fd9a0:	48 89 31             	mov    QWORD PTR [rcx],rsi
  8fd9a3:	48 85 f6             	test   rsi,rsi
  8fd9a6:	74 04                	je     0x8fd9ac
  8fd9a8:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  8fd9ac:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  8fd9b0:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  8fd9b4:	48 85 f6             	test   rsi,rsi
  8fd9b7:	74 5f                	je     0x8fda18
  8fd9b9:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  8fd9bc:	74 5f                	je     0x8fda1d
  8fd9be:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  8fd9c2:	eb 5c                	jmp    0x8fda20
  8fd9c4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fd9cb:	00 00 00 00 00 
  8fd9d0:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  8fd9d4:	83 7a 18 01          	cmp    DWORD PTR [rdx+0x18],0x1
  8fd9d8:	0f 85 8c 00 00 00    	jne    0x8fda6a
  8fd9de:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  8fd9e5:	c7 41 18 01 00 00 00 	mov    DWORD PTR [rcx+0x18],0x1
  8fd9ec:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  8fd9f0:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  8fd9f3:	48 89 71 08          	mov    QWORD PTR [rcx+0x8],rsi
  8fd9f7:	48 85 f6             	test   rsi,rsi
  8fd9fa:	74 04                	je     0x8fda00
  8fd9fc:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  8fda00:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  8fda04:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  8fda08:	48 85 f6             	test   rsi,rsi
  8fda0b:	74 4a                	je     0x8fda57
  8fda0d:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  8fda10:	74 4a                	je     0x8fda5c
  8fda12:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  8fda16:	eb 47                	jmp    0x8fda5f
  8fda18:	48 89 17             	mov    QWORD PTR [rdi],rdx
  8fda1b:	eb 03                	jmp    0x8fda20
  8fda1d:	48 89 16             	mov    QWORD PTR [rsi],rdx
  8fda20:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  8fda24:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  8fda28:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  8fda2b:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  8fda2e:	48 85 f6             	test   rsi,rsi
  8fda31:	74 0a                	je     0x8fda3d
  8fda33:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  8fda37:	0f 85 0b 01 00 00    	jne    0x8fdb48
  8fda3d:	4c 8b 42 08          	mov    r8,QWORD PTR [rdx+0x8]
  8fda41:	4d 85 c0             	test   r8,r8
  8fda44:	0f 84 06 ff ff ff    	je     0x8fd950
  8fda4a:	41 83 78 18 00       	cmp    DWORD PTR [r8+0x18],0x0
  8fda4f:	0f 84 fb fe ff ff    	je     0x8fd950
  8fda55:	eb 3d                	jmp    0x8fda94
  8fda57:	48 89 17             	mov    QWORD PTR [rdi],rdx
  8fda5a:	eb 03                	jmp    0x8fda5f
  8fda5c:	48 89 16             	mov    QWORD PTR [rsi],rdx
  8fda5f:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  8fda62:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  8fda66:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  8fda6a:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  8fda6d:	48 85 f6             	test   rsi,rsi
  8fda70:	74 06                	je     0x8fda78
  8fda72:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  8fda76:	75 66                	jne    0x8fdade
  8fda78:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
  8fda7c:	48 85 f6             	test   rsi,rsi
  8fda7f:	0f 84 cb fe ff ff    	je     0x8fd950
  8fda85:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  8fda89:	0f 84 c1 fe ff ff    	je     0x8fd950
  8fda8f:	e9 34 01 00 00       	jmp    0x8fdbc8
  8fda94:	48 85 f6             	test   rsi,rsi
  8fda97:	74 0a                	je     0x8fdaa3
  8fda99:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  8fda9d:	0f 85 a5 00 00 00    	jne    0x8fdb48
  8fdaa3:	41 c7 40 18 00 00 00 	mov    DWORD PTR [r8+0x18],0x0
  8fdaaa:	00 
  8fdaab:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
  8fdaaf:	c7 42 18 01 00 00 00 	mov    DWORD PTR [rdx+0x18],0x1
  8fdab6:	4c 8b 06             	mov    r8,QWORD PTR [rsi]
  8fdab9:	4c 89 42 08          	mov    QWORD PTR [rdx+0x8],r8
  8fdabd:	4d 85 c0             	test   r8,r8
  8fdac0:	74 04                	je     0x8fdac6
  8fdac2:	49 89 50 10          	mov    QWORD PTR [r8+0x10],rdx
  8fdac6:	4c 8b 42 10          	mov    r8,QWORD PTR [rdx+0x10]
  8fdaca:	4c 89 46 10          	mov    QWORD PTR [rsi+0x10],r8
  8fdace:	4d 85 c0             	test   r8,r8
  8fdad1:	74 63                	je     0x8fdb36
  8fdad3:	49 3b 10             	cmp    rdx,QWORD PTR [r8]
  8fdad6:	74 63                	je     0x8fdb3b
  8fdad8:	49 89 70 08          	mov    QWORD PTR [r8+0x8],rsi
  8fdadc:	eb 60                	jmp    0x8fdb3e
  8fdade:	4c 8b 42 08          	mov    r8,QWORD PTR [rdx+0x8]
  8fdae2:	4d 85 c0             	test   r8,r8
  8fdae5:	74 0b                	je     0x8fdaf2
  8fdae7:	41 83 78 18 00       	cmp    DWORD PTR [r8+0x18],0x0
  8fdaec:	0f 85 d6 00 00 00    	jne    0x8fdbc8
  8fdaf2:	c7 46 18 00 00 00 00 	mov    DWORD PTR [rsi+0x18],0x0
  8fdaf9:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  8fdafc:	c7 42 18 01 00 00 00 	mov    DWORD PTR [rdx+0x18],0x1
  8fdb03:	4c 8b 46 08          	mov    r8,QWORD PTR [rsi+0x8]
  8fdb07:	4c 89 02             	mov    QWORD PTR [rdx],r8
  8fdb0a:	4d 85 c0             	test   r8,r8
  8fdb0d:	74 04                	je     0x8fdb13
  8fdb0f:	49 89 50 10          	mov    QWORD PTR [r8+0x10],rdx
  8fdb13:	4c 8b 42 10          	mov    r8,QWORD PTR [rdx+0x10]
  8fdb17:	4c 89 46 10          	mov    QWORD PTR [rsi+0x10],r8
  8fdb1b:	4d 85 c0             	test   r8,r8
  8fdb1e:	0f 84 90 00 00 00    	je     0x8fdbb4
  8fdb24:	49 3b 10             	cmp    rdx,QWORD PTR [r8]
  8fdb27:	0f 84 8c 00 00 00    	je     0x8fdbb9
  8fdb2d:	49 89 70 08          	mov    QWORD PTR [r8+0x8],rsi
  8fdb31:	e9 86 00 00 00       	jmp    0x8fdbbc
  8fdb36:	48 89 37             	mov    QWORD PTR [rdi],rsi
  8fdb39:	eb 03                	jmp    0x8fdb3e
  8fdb3b:	49 89 30             	mov    QWORD PTR [r8],rsi
  8fdb3e:	48 89 16             	mov    QWORD PTR [rsi],rdx
  8fdb41:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  8fdb45:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  8fdb48:	8b 71 18             	mov    esi,DWORD PTR [rcx+0x18]
  8fdb4b:	89 72 18             	mov    DWORD PTR [rdx+0x18],esi
  8fdb4e:	c7 41 18 00 00 00 00 	mov    DWORD PTR [rcx+0x18],0x0
  8fdb55:	48 8b 12             	mov    rdx,QWORD PTR [rdx]
  8fdb58:	48 85 d2             	test   rdx,rdx
  8fdb5b:	74 07                	je     0x8fdb64
  8fdb5d:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  8fdb64:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  8fdb67:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
  8fdb6b:	48 89 31             	mov    QWORD PTR [rcx],rsi
  8fdb6e:	48 85 f6             	test   rsi,rsi
  8fdb71:	74 04                	je     0x8fdb77
  8fdb73:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  8fdb77:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  8fdb7b:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  8fdb7f:	48 85 f6             	test   rsi,rsi
  8fdb82:	74 0b                	je     0x8fdb8f
  8fdb84:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  8fdb87:	74 0b                	je     0x8fdb94
  8fdb89:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  8fdb8d:	eb 08                	jmp    0x8fdb97
  8fdb8f:	48 89 17             	mov    QWORD PTR [rdi],rdx
  8fdb92:	eb 03                	jmp    0x8fdb97
  8fdb94:	48 89 16             	mov    QWORD PTR [rsi],rdx
  8fdb97:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  8fdb9b:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  8fdb9f:	48 8b 37             	mov    rsi,QWORD PTR [rdi]
  8fdba2:	48 85 f6             	test   rsi,rsi
  8fdba5:	0f 84 96 fd ff ff    	je     0x8fd941
  8fdbab:	c7 46 18 00 00 00 00 	mov    DWORD PTR [rsi+0x18],0x0
  8fdbb2:	5d                   	pop    rbp
  8fdbb3:	c3                   	ret
  8fdbb4:	48 89 37             	mov    QWORD PTR [rdi],rsi
  8fdbb7:	eb 03                	jmp    0x8fdbbc
  8fdbb9:	49 89 30             	mov    QWORD PTR [r8],rsi
  8fdbbc:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  8fdbc0:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  8fdbc4:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  8fdbc8:	8b 71 18             	mov    esi,DWORD PTR [rcx+0x18]
  8fdbcb:	89 72 18             	mov    DWORD PTR [rdx+0x18],esi
  8fdbce:	c7 41 18 00 00 00 00 	mov    DWORD PTR [rcx+0x18],0x0
  8fdbd5:	48 8b 52 08          	mov    rdx,QWORD PTR [rdx+0x8]
  8fdbd9:	48 85 d2             	test   rdx,rdx
  8fdbdc:	74 07                	je     0x8fdbe5
  8fdbde:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  8fdbe5:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  8fdbe9:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  8fdbec:	48 89 71 08          	mov    QWORD PTR [rcx+0x8],rsi
  8fdbf0:	48 85 f6             	test   rsi,rsi
  8fdbf3:	74 04                	je     0x8fdbf9
  8fdbf5:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  8fdbf9:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  8fdbfd:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  8fdc01:	48 85 f6             	test   rsi,rsi
  8fdc04:	74 0e                	je     0x8fdc14
  8fdc06:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  8fdc09:	74 14                	je     0x8fdc1f
  8fdc0b:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  8fdc0f:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  8fdc12:	eb 87                	jmp    0x8fdb9b
  8fdc14:	48 89 17             	mov    QWORD PTR [rdi],rdx
  8fdc17:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  8fdc1a:	e9 7c ff ff ff       	jmp    0x8fdb9b
  8fdc1f:	48 89 16             	mov    QWORD PTR [rsi],rdx
  8fdc22:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  8fdc25:	e9 71 ff ff ff       	jmp    0x8fdb9b
  8fdc2a:	90                   	nop
  8fdc2b:	90                   	nop
  8fdc2c:	90                   	nop
  8fdc2d:	90                   	nop
  8fdc2e:	90                   	nop
  8fdc2f:	90                   	nop
  8fdc30:	55                   	push   rbp
  8fdc31:	48 89 e5             	mov    rbp,rsp
  8fdc34:	41 56                	push   r14
  8fdc36:	53                   	push   rbx
  8fdc37:	48 8b 1f             	mov    rbx,QWORD PTR [rdi]
  8fdc3a:	48 85 db             	test   rbx,rbx
  8fdc3d:	74 36                	je     0x8fdc75
  8fdc3f:	49 89 f6             	mov    r14,rsi
  8fdc42:	49 83 c6 20          	add    r14,0x20
  8fdc46:	eb 10                	jmp    0x8fdc58
  8fdc48:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  8fdc4f:	00 
  8fdc50:	48 8b 1b             	mov    rbx,QWORD PTR [rbx]
  8fdc53:	48 85 db             	test   rbx,rbx
  8fdc56:	74 1d                	je     0x8fdc75
  8fdc58:	48 8d 73 20          	lea    rsi,[rbx+0x20]
  8fdc5c:	ba 10 00 00 00       	mov    edx,0x10
  8fdc61:	4c 89 f7             	mov    rdi,r14
  8fdc64:	e8 67 bf a3 ff       	call   0x339bd0
  8fdc69:	85 c0                	test   eax,eax
  8fdc6b:	78 e3                	js     0x8fdc50
  8fdc6d:	74 08                	je     0x8fdc77
  8fdc6f:	48 83 c3 08          	add    rbx,0x8
  8fdc73:	eb db                	jmp    0x8fdc50
  8fdc75:	31 db                	xor    ebx,ebx
  8fdc77:	48 89 d8             	mov    rax,rbx
  8fdc7a:	5b                   	pop    rbx
  8fdc7b:	41 5e                	pop    r14
  8fdc7d:	5d                   	pop    rbp
  8fdc7e:	c3                   	ret
  8fdc7f:	90                   	nop
  8fdc80:	55                   	push   rbp
  8fdc81:	48 89 e5             	mov    rbp,rsp
  8fdc84:	48 8b 4f 08          	mov    rcx,QWORD PTR [rdi+0x8]
  8fdc88:	48 85 c9             	test   rcx,rcx
  8fdc8b:	74 10                	je     0x8fdc9d
  8fdc8d:	0f 1f 00             	nop    DWORD PTR [rax]
  8fdc90:	48 89 c8             	mov    rax,rcx
  8fdc93:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  8fdc96:	48 85 c9             	test   rcx,rcx
  8fdc99:	75 f5                	jne    0x8fdc90
  8fdc9b:	5d                   	pop    rbp
  8fdc9c:	c3                   	ret
  8fdc9d:	48 8b 47 10          	mov    rax,QWORD PTR [rdi+0x10]
  8fdca1:	48 85 c0             	test   rax,rax
  8fdca4:	74 0a                	je     0x8fdcb0
  8fdca6:	48 3b 38             	cmp    rdi,QWORD PTR [rax]
  8fdca9:	74 f0                	je     0x8fdc9b
  8fdcab:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  8fdcb0:	48 8b 47 10          	mov    rax,QWORD PTR [rdi+0x10]
  8fdcb4:	48 85 c0             	test   rax,rax
  8fdcb7:	74 0b                	je     0x8fdcc4
  8fdcb9:	48 3b 78 08          	cmp    rdi,QWORD PTR [rax+0x8]
  8fdcbd:	48 89 c7             	mov    rdi,rax
  8fdcc0:	74 ee                	je     0x8fdcb0
  8fdcc2:	eb d7                	jmp    0x8fdc9b
  8fdcc4:	31 c0                	xor    eax,eax
  8fdcc6:	5d                   	pop    rbp
  8fdcc7:	c3                   	ret
  8fdcc8:	90                   	nop
  8fdcc9:	90                   	nop
  8fdcca:	90                   	nop
  8fdccb:	90                   	nop
  8fdccc:	90                   	nop
  8fdccd:	90                   	nop
  8fdcce:	90                   	nop
  8fdccf:	90                   	nop
  8fdcd0:	48 8b 0f             	mov    rcx,QWORD PTR [rdi]
  8fdcd3:	48 85 c9             	test   rcx,rcx
  8fdcd6:	74 26                	je     0x8fdcfe
  8fdcd8:	55                   	push   rbp
  8fdcd9:	48 89 e5             	mov    rbp,rsp
  8fdcdc:	f7 d6                	not    esi
  8fdcde:	c1 ee 1f             	shr    esi,0x1f
  8fdce1:	c1 e6 03             	shl    esi,0x3
  8fdce4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fdceb:	00 00 00 00 00 
  8fdcf0:	48 89 c8             	mov    rax,rcx
  8fdcf3:	48 8b 0c 31          	mov    rcx,QWORD PTR [rcx+rsi*1]
  8fdcf7:	48 85 c9             	test   rcx,rcx
  8fdcfa:	75 f4                	jne    0x8fdcf0
  8fdcfc:	5d                   	pop    rbp
  8fdcfd:	c3                   	ret
  8fdcfe:	31 c0                	xor    eax,eax
  8fdd00:	c3                   	ret
  8fdd01:	90                   	nop
  8fdd02:	90                   	nop
  8fdd03:	90                   	nop
  8fdd04:	90                   	nop
  8fdd05:	90                   	nop
  8fdd06:	90                   	nop
  8fdd07:	90                   	nop
  8fdd08:	90                   	nop
  8fdd09:	90                   	nop
  8fdd0a:	90                   	nop
  8fdd0b:	90                   	nop
  8fdd0c:	90                   	nop
  8fdd0d:	90                   	nop
  8fdd0e:	90                   	nop
  8fdd0f:	90                   	nop
  8fdd10:	55                   	push   rbp
  8fdd11:	48 89 e5             	mov    rbp,rsp
  8fdd14:	41 57                	push   r15
  8fdd16:	41 56                	push   r14
  8fdd18:	41 55                	push   r13
  8fdd1a:	41 54                	push   r12
  8fdd1c:	53                   	push   rbx
  8fdd1d:	48 83 ec 58          	sub    rsp,0x58
  8fdd21:	49 89 f5             	mov    r13,rsi
  8fdd24:	48 8d 35 e5 e5 01 03 	lea    rsi,[rip+0x301e5e5]        # 0x391c310
  8fdd2b:	48 8b 06             	mov    rax,QWORD PTR [rsi]
  8fdd2e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fdd32:	b8 01 00 00 00       	mov    eax,0x1
  8fdd37:	4c 8b 77 10          	mov    r14,QWORD PTR [rdi+0x10]
  8fdd3b:	4d 85 f6             	test   r14,r14
  8fdd3e:	74 73                	je     0x8fddb3
  8fdd40:	49 89 d7             	mov    r15,rdx
  8fdd43:	0f b7 57 0a          	movzx  edx,WORD PTR [rdi+0xa]
  8fdd47:	48 85 d2             	test   rdx,rdx
  8fdd4a:	74 67                	je     0x8fddb3
  8fdd4c:	c1 e2 03             	shl    edx,0x3
  8fdd4f:	49 83 c7 08          	add    r15,0x8
  8fdd53:	48 89 7d 88          	mov    QWORD PTR [rbp-0x78],rdi
  8fdd57:	48 89 4d 80          	mov    QWORD PTR [rbp-0x80],rcx
  8fdd5b:	31 db                	xor    ebx,ebx
  8fdd5d:	4c 8d 24 52          	lea    r12,[rdx+rdx*2]
  8fdd61:	eb 2f                	jmp    0x8fdd92
  8fdd63:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fdd6a:	84 00 00 00 00 00 
  8fdd70:	48 83 c7 10          	add    rdi,0x10
  8fdd74:	ba 10 00 00 00       	mov    edx,0x10
  8fdd79:	4c 89 fe             	mov    rsi,r15
  8fdd7c:	e8 ff b2 95 ff       	call   0x259080
  8fdd81:	85 c0                	test   eax,eax
  8fdd83:	74 4a                	je     0x8fddcf
  8fdd85:	49 83 c6 08          	add    r14,0x8
  8fdd89:	48 83 c3 18          	add    rbx,0x18
  8fdd8d:	41 39 dc             	cmp    r12d,ebx
  8fdd90:	74 15                	je     0x8fdda7
  8fdd92:	49 8b 3e             	mov    rdi,QWORD PTR [r14]
  8fdd95:	48 85 ff             	test   rdi,rdi
  8fdd98:	74 eb                	je     0x8fdd85
  8fdd9a:	4d 85 ed             	test   r13,r13
  8fdd9d:	74 d1                	je     0x8fdd70
  8fdd9f:	4c 39 6f 20          	cmp    QWORD PTR [rdi+0x20],r13
  8fdda3:	75 e0                	jne    0x8fdd85
  8fdda5:	eb c9                	jmp    0x8fdd70
  8fdda7:	48 8d 35 62 e5 01 03 	lea    rsi,[rip+0x301e562]        # 0x391c310
  8fddae:	b8 01 00 00 00       	mov    eax,0x1
  8fddb3:	48 8b 0e             	mov    rcx,QWORD PTR [rsi]
  8fddb6:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  8fddba:	0f 85 a8 00 00 00    	jne    0x8fde68
  8fddc0:	48 83 c4 58          	add    rsp,0x58
  8fddc4:	5b                   	pop    rbx
  8fddc5:	41 5c                	pop    r12
  8fddc7:	41 5d                	pop    r13
  8fddc9:	41 5e                	pop    r14
  8fddcb:	41 5f                	pop    r15
  8fddcd:	5d                   	pop    rbp
  8fddce:	c3                   	ret
  8fddcf:	48 8b 45 88          	mov    rax,QWORD PTR [rbp-0x78]
  8fddd3:	48 8b 4d 80          	mov    rcx,QWORD PTR [rbp-0x80]
  8fddd7:	4c 8d 75 b0          	lea    r14,[rbp-0x50]
  8fdddb:	4c 89 f7             	mov    rdi,r14
  8fddde:	4c 8b 60 18          	mov    r12,QWORD PTR [rax+0x18]
  8fdde2:	48 8b 41 08          	mov    rax,QWORD PTR [rcx+0x8]
  8fdde6:	48 8b 49 10          	mov    rcx,QWORD PTR [rcx+0x10]
  8fddea:	45 0f b6 7c 1c 11    	movzx  r15d,BYTE PTR [r12+rbx*1+0x11]
  8fddf0:	48 89 4d b8          	mov    QWORD PTR [rbp-0x48],rcx
  8fddf4:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  8fddf8:	e8 73 4a 28 00       	call   0xb82870
  8fddfd:	49 8b 1c 1c          	mov    rbx,QWORD PTR [r12+rbx*1]
  8fde01:	eb 14                	jmp    0x8fde17
  8fde03:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fde0a:	84 00 00 00 00 00 
  8fde10:	48 83 c3 08          	add    rbx,0x8
  8fde14:	48 8b 1b             	mov    rbx,QWORD PTR [rbx]
  8fde17:	48 85 db             	test   rbx,rbx
  8fde1a:	74 2f                	je     0x8fde4b
  8fde1c:	48 8d 73 20          	lea    rsi,[rbx+0x20]
  8fde20:	ba 10 00 00 00       	mov    edx,0x10
  8fde25:	4c 89 f7             	mov    rdi,r14
  8fde28:	e8 a3 bd a3 ff       	call   0x339bd0
  8fde2d:	85 c0                	test   eax,eax
  8fde2f:	78 e3                	js     0x8fde14
  8fde31:	75 dd                	jne    0x8fde10
  8fde33:	48 8d 35 d6 e4 01 03 	lea    rsi,[rip+0x301e4d6]        # 0x391c310
  8fde3a:	b8 02 00 00 00       	mov    eax,0x2
  8fde3f:	44 38 7b 30          	cmp    BYTE PTR [rbx+0x30],r15b
  8fde43:	0f 85 6a ff ff ff    	jne    0x8fddb3
  8fde49:	eb 16                	jmp    0x8fde61
  8fde4b:	48 8d 35 be e4 01 03 	lea    rsi,[rip+0x301e4be]        # 0x391c310
  8fde52:	b8 02 00 00 00       	mov    eax,0x2
  8fde57:	41 80 ff 01          	cmp    r15b,0x1
  8fde5b:	0f 84 52 ff ff ff    	je     0x8fddb3
  8fde61:	31 c0                	xor    eax,eax
  8fde63:	e9 4b ff ff ff       	jmp    0x8fddb3
  8fde68:	e8 43 f8 df ff       	call   0x6fd6b0
  8fde6d:	0f 0b                	ud2
  8fde6f:	90                   	nop
  8fde70:	55                   	push   rbp
  8fde71:	48 89 e5             	mov    rbp,rsp
  8fde74:	41 57                	push   r15
  8fde76:	41 56                	push   r14
  8fde78:	41 55                	push   r13
  8fde7a:	41 54                	push   r12
  8fde7c:	53                   	push   rbx
  8fde7d:	50                   	push   rax
  8fde7e:	4c 8b 7f 10          	mov    r15,QWORD PTR [rdi+0x10]
  8fde82:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
  8fde89:	4d 85 ff             	test   r15,r15
  8fde8c:	74 5e                	je     0x8fdeec
  8fde8e:	44 0f b7 67 0a       	movzx  r12d,WORD PTR [rdi+0xa]
  8fde93:	4d 85 e4             	test   r12,r12
  8fde96:	74 54                	je     0x8fdeec
  8fde98:	48 89 d3             	mov    rbx,rdx
  8fde9b:	49 89 f6             	mov    r14,rsi
  8fde9e:	45 31 ed             	xor    r13d,r13d
  8fdea1:	48 83 c3 08          	add    rbx,0x8
  8fdea5:	eb 26                	jmp    0x8fdecd
  8fdea7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  8fdeae:	00 00 
  8fdeb0:	48 83 c7 10          	add    rdi,0x10
  8fdeb4:	ba 10 00 00 00       	mov    edx,0x10
  8fdeb9:	48 89 de             	mov    rsi,rbx
  8fdebc:	e8 bf b1 95 ff       	call   0x259080
  8fdec1:	85 c0                	test   eax,eax
  8fdec3:	74 24                	je     0x8fdee9
  8fdec5:	49 ff c5             	inc    r13
  8fdec8:	45 39 ec             	cmp    r12d,r13d
  8fdecb:	74 16                	je     0x8fdee3
  8fdecd:	4b 8b 3c ef          	mov    rdi,QWORD PTR [r15+r13*8]
  8fded1:	48 85 ff             	test   rdi,rdi
  8fded4:	74 ef                	je     0x8fdec5
  8fded6:	4d 85 f6             	test   r14,r14
  8fded9:	74 d5                	je     0x8fdeb0
  8fdedb:	4c 39 77 20          	cmp    QWORD PTR [rdi+0x20],r14
  8fdedf:	75 e4                	jne    0x8fdec5
  8fdee1:	eb cd                	jmp    0x8fdeb0
  8fdee3:	41 bd ff ff ff ff    	mov    r13d,0xffffffff
  8fdee9:	49 63 c5             	movsxd rax,r13d
  8fdeec:	48 83 c4 08          	add    rsp,0x8
  8fdef0:	5b                   	pop    rbx
  8fdef1:	41 5c                	pop    r12
  8fdef3:	41 5d                	pop    r13
  8fdef5:	41 5e                	pop    r14
  8fdef7:	41 5f                	pop    r15
  8fdef9:	5d                   	pop    rbp
  8fdefa:	c3                   	ret
  8fdefb:	90                   	nop
  8fdefc:	90                   	nop
  8fdefd:	90                   	nop
  8fdefe:	90                   	nop
  8fdeff:	90                   	nop
  8fdf00:	55                   	push   rbp
  8fdf01:	48 89 e5             	mov    rbp,rsp
  8fdf04:	41 57                	push   r15
  8fdf06:	41 56                	push   r14
  8fdf08:	41 54                	push   r12
  8fdf0a:	53                   	push   rbx
  8fdf0b:	48 83 ec 50          	sub    rsp,0x50
  8fdf0f:	4c 8d 3d fa e3 01 03 	lea    r15,[rip+0x301e3fa]        # 0x391c310
  8fdf16:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fdf19:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  8fdf1d:	48 8b 5f 18          	mov    rbx,QWORD PTR [rdi+0x18]
  8fdf21:	48 85 db             	test   rbx,rbx
  8fdf24:	74 4f                	je     0x8fdf75
  8fdf26:	48 8b 42 08          	mov    rax,QWORD PTR [rdx+0x8]
  8fdf2a:	48 8b 4a 10          	mov    rcx,QWORD PTR [rdx+0x10]
  8fdf2e:	4c 8d 75 b8          	lea    r14,[rbp-0x48]
  8fdf32:	4c 8d 24 76          	lea    r12,[rsi+rsi*2]
  8fdf36:	4c 89 f7             	mov    rdi,r14
  8fdf39:	48 89 4d c0          	mov    QWORD PTR [rbp-0x40],rcx
  8fdf3d:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
  8fdf41:	e8 2a 49 28 00       	call   0xb82870
  8fdf46:	4a 8b 1c e3          	mov    rbx,QWORD PTR [rbx+r12*8]
  8fdf4a:	eb 07                	jmp    0x8fdf53
  8fdf4c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  8fdf50:	48 8b 1b             	mov    rbx,QWORD PTR [rbx]
  8fdf53:	48 85 db             	test   rbx,rbx
  8fdf56:	74 1d                	je     0x8fdf75
  8fdf58:	48 8d 73 20          	lea    rsi,[rbx+0x20]
  8fdf5c:	ba 10 00 00 00       	mov    edx,0x10
  8fdf61:	4c 89 f7             	mov    rdi,r14
  8fdf64:	e8 67 bc a3 ff       	call   0x339bd0
  8fdf69:	85 c0                	test   eax,eax
  8fdf6b:	78 e3                	js     0x8fdf50
  8fdf6d:	74 08                	je     0x8fdf77
  8fdf6f:	48 83 c3 08          	add    rbx,0x8
  8fdf73:	eb db                	jmp    0x8fdf50
  8fdf75:	31 db                	xor    ebx,ebx
  8fdf77:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fdf7a:	48 3b 45 d8          	cmp    rax,QWORD PTR [rbp-0x28]
  8fdf7e:	75 10                	jne    0x8fdf90
  8fdf80:	48 89 d8             	mov    rax,rbx
  8fdf83:	48 83 c4 50          	add    rsp,0x50
  8fdf87:	5b                   	pop    rbx
  8fdf88:	41 5c                	pop    r12
  8fdf8a:	41 5e                	pop    r14
  8fdf8c:	41 5f                	pop    r15
  8fdf8e:	5d                   	pop    rbp
  8fdf8f:	c3                   	ret
  8fdf90:	e8 1b f7 df ff       	call   0x6fd6b0
  8fdf95:	0f 0b                	ud2
  8fdf97:	90                   	nop
  8fdf98:	90                   	nop
  8fdf99:	90                   	nop
  8fdf9a:	90                   	nop
  8fdf9b:	90                   	nop
  8fdf9c:	90                   	nop
  8fdf9d:	90                   	nop
  8fdf9e:	90                   	nop
  8fdf9f:	90                   	nop
  8fdfa0:	ff 4f 30             	dec    DWORD PTR [rdi+0x30]
  8fdfa3:	74 01                	je     0x8fdfa6
  8fdfa5:	c3                   	ret
  8fdfa6:	55                   	push   rbp
  8fdfa7:	48 89 e5             	mov    rbp,rsp
  8fdfaa:	41 57                	push   r15
  8fdfac:	41 56                	push   r14
  8fdfae:	41 55                	push   r13
  8fdfb0:	41 54                	push   r12
  8fdfb2:	53                   	push   rbx
  8fdfb3:	50                   	push   rax
  8fdfb4:	48 8b 47 28          	mov    rax,QWORD PTR [rdi+0x28]
  8fdfb8:	48 89 fb             	mov    rbx,rdi
  8fdfbb:	48 c7 40 30 00 00 00 	mov    QWORD PTR [rax+0x30],0x0
  8fdfc2:	00 
  8fdfc3:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fdfc7:	48 8b 47 50          	mov    rax,QWORD PTR [rdi+0x50]
  8fdfcb:	48 85 c0             	test   rax,rax
  8fdfce:	0f 84 a1 00 00 00    	je     0x8fe075
  8fdfd4:	4c 8d 7b 50          	lea    r15,[rbx+0x50]
  8fdfd8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  8fdfdf:	00 
  8fdfe0:	49 89 c6             	mov    r14,rax
  8fdfe3:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8fdfe6:	48 85 c0             	test   rax,rax
  8fdfe9:	75 f5                	jne    0x8fdfe0
  8fdfeb:	4c 8d 2d ae 10 c5 01 	lea    r13,[rip+0x1c510ae]        # 0x254f0a0
  8fdff2:	eb 2e                	jmp    0x8fe022
  8fdff4:	45 31 e4             	xor    r12d,r12d
  8fdff7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  8fdffe:	00 00 
  8fe000:	4c 89 ff             	mov    rdi,r15
  8fe003:	4c 89 f6             	mov    rsi,r14
  8fe006:	e8 45 f8 ff ff       	call   0x8fd850
  8fe00b:	4c 89 f7             	mov    rdi,r14
  8fe00e:	4c 89 ee             	mov    rsi,r13
  8fe011:	e8 da ad 30 00       	call   0xc08df0
  8fe016:	48 ff 4b 58          	dec    QWORD PTR [rbx+0x58]
  8fe01a:	4d 89 e6             	mov    r14,r12
  8fe01d:	4d 85 e4             	test   r12,r12
  8fe020:	74 53                	je     0x8fe075
  8fe022:	49 8b 46 08          	mov    rax,QWORD PTR [r14+0x8]
  8fe026:	48 85 c0             	test   rax,rax
  8fe029:	74 15                	je     0x8fe040
  8fe02b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  8fe030:	49 89 c4             	mov    r12,rax
  8fe033:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8fe036:	48 85 c0             	test   rax,rax
  8fe039:	75 f5                	jne    0x8fe030
  8fe03b:	eb c3                	jmp    0x8fe000
  8fe03d:	0f 1f 00             	nop    DWORD PTR [rax]
  8fe040:	4d 8b 66 10          	mov    r12,QWORD PTR [r14+0x10]
  8fe044:	4d 85 e4             	test   r12,r12
  8fe047:	74 06                	je     0x8fe04f
  8fe049:	4d 3b 34 24          	cmp    r14,QWORD PTR [r12]
  8fe04d:	74 b1                	je     0x8fe000
  8fe04f:	4c 89 f0             	mov    rax,r14
  8fe052:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fe059:	1f 84 00 00 00 00 00 
  8fe060:	4c 8b 60 10          	mov    r12,QWORD PTR [rax+0x10]
  8fe064:	4d 85 e4             	test   r12,r12
  8fe067:	74 8b                	je     0x8fdff4
  8fe069:	49 3b 44 24 08       	cmp    rax,QWORD PTR [r12+0x8]
  8fe06e:	4c 89 e0             	mov    rax,r12
  8fe071:	74 ed                	je     0x8fe060
  8fe073:	eb 8b                	jmp    0x8fe000
  8fe075:	48 8b 7b 60          	mov    rdi,QWORD PTR [rbx+0x60]
  8fe079:	48 8d 43 60          	lea    rax,[rbx+0x60]
  8fe07d:	48 c7 43 60 00 00 00 	mov    QWORD PTR [rbx+0x60],0x0
  8fe084:	00 
  8fe085:	48 89 43 68          	mov    QWORD PTR [rbx+0x68],rax
  8fe089:	c7 43 70 00 00 00 00 	mov    DWORD PTR [rbx+0x70],0x0
  8fe090:	48 85 ff             	test   rdi,rdi
  8fe093:	74 1c                	je     0x8fe0b1
  8fe095:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fe09c:	00 00 00 00 
  8fe0a0:	4c 8b 77 08          	mov    r14,QWORD PTR [rdi+0x8]
  8fe0a4:	e8 a7 c7 b2 ff       	call   0x42a850
  8fe0a9:	4c 89 f7             	mov    rdi,r14
  8fe0ac:	4d 85 f6             	test   r14,r14
  8fe0af:	75 ef                	jne    0x8fe0a0
  8fe0b1:	48 8d 35 c8 0f c5 01 	lea    rsi,[rip+0x1c50fc8]        # 0x254f080
  8fe0b8:	48 89 df             	mov    rdi,rbx
  8fe0bb:	e8 30 ad 30 00       	call   0xc08df0
  8fe0c0:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
  8fe0c4:	48 83 c4 08          	add    rsp,0x8
  8fe0c8:	5b                   	pop    rbx
  8fe0c9:	41 5c                	pop    r12
  8fe0cb:	41 5d                	pop    r13
  8fe0cd:	41 5e                	pop    r14
  8fe0cf:	41 5f                	pop    r15
  8fe0d1:	5d                   	pop    rbp
  8fe0d2:	e9 89 1a bc ff       	jmp    0x4bfb60
  8fe0d7:	90                   	nop
  8fe0d8:	90                   	nop
  8fe0d9:	90                   	nop
  8fe0da:	90                   	nop
  8fe0db:	90                   	nop
  8fe0dc:	90                   	nop
  8fe0dd:	90                   	nop
  8fe0de:	90                   	nop
  8fe0df:	90                   	nop
  8fe0e0:	48 8b 47 50          	mov    rax,QWORD PTR [rdi+0x50]
  8fe0e4:	48 85 c0             	test   rax,rax
  8fe0e7:	74 6c                	je     0x8fe155
  8fe0e9:	55                   	push   rbp
  8fe0ea:	48 89 e5             	mov    rbp,rsp
  8fe0ed:	0f 1f 00             	nop    DWORD PTR [rax]
  8fe0f0:	48 89 c1             	mov    rcx,rax
  8fe0f3:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8fe0f6:	48 85 c0             	test   rax,rax
  8fe0f9:	75 f5                	jne    0x8fe0f0
  8fe0fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  8fe100:	80 79 38 00          	cmp    BYTE PTR [rcx+0x38],0x0
  8fe104:	48 89 c8             	mov    rax,rcx
  8fe107:	74 0b                	je     0x8fe114
  8fe109:	c6 40 38 00          	mov    BYTE PTR [rax+0x38],0x0
  8fe10d:	66 ff 8f 9e 00 00 00 	dec    WORD PTR [rdi+0x9e]
  8fe114:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
  8fe118:	48 85 d2             	test   rdx,rdx
  8fe11b:	74 13                	je     0x8fe130
  8fe11d:	0f 1f 00             	nop    DWORD PTR [rax]
  8fe120:	48 89 d1             	mov    rcx,rdx
  8fe123:	48 8b 12             	mov    rdx,QWORD PTR [rdx]
  8fe126:	48 85 d2             	test   rdx,rdx
  8fe129:	75 f5                	jne    0x8fe120
  8fe12b:	eb d3                	jmp    0x8fe100
  8fe12d:	0f 1f 00             	nop    DWORD PTR [rax]
  8fe130:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
  8fe134:	48 85 c9             	test   rcx,rcx
  8fe137:	74 07                	je     0x8fe140
  8fe139:	48 3b 01             	cmp    rax,QWORD PTR [rcx]
  8fe13c:	74 c2                	je     0x8fe100
  8fe13e:	66 90                	xchg   ax,ax
  8fe140:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
  8fe144:	48 85 c9             	test   rcx,rcx
  8fe147:	74 0b                	je     0x8fe154
  8fe149:	48 3b 41 08          	cmp    rax,QWORD PTR [rcx+0x8]
  8fe14d:	48 89 c8             	mov    rax,rcx
  8fe150:	74 ee                	je     0x8fe140
  8fe152:	eb ac                	jmp    0x8fe100
  8fe154:	5d                   	pop    rbp
  8fe155:	c3                   	ret
  8fe156:	90                   	nop
  8fe157:	90                   	nop
  8fe158:	90                   	nop
  8fe159:	90                   	nop
  8fe15a:	90                   	nop
  8fe15b:	90                   	nop
  8fe15c:	90                   	nop
  8fe15d:	90                   	nop
  8fe15e:	90                   	nop
  8fe15f:	90                   	nop
  8fe160:	55                   	push   rbp
  8fe161:	48 89 e5             	mov    rbp,rsp
  8fe164:	41 57                	push   r15
  8fe166:	41 56                	push   r14
  8fe168:	41 55                	push   r13
  8fe16a:	41 54                	push   r12
  8fe16c:	53                   	push   rbx
  8fe16d:	48 83 ec 48          	sub    rsp,0x48
  8fe171:	4c 8d 3d 98 e1 01 03 	lea    r15,[rip+0x301e198]        # 0x391c310
  8fe178:	48 89 fb             	mov    rbx,rdi
  8fe17b:	4c 8d 65 b0          	lea    r12,[rbp-0x50]
  8fe17f:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fe182:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fe186:	48 8b 06             	mov    rax,QWORD PTR [rsi]
  8fe189:	48 8b 4e 08          	mov    rcx,QWORD PTR [rsi+0x8]
  8fe18d:	48 89 4d b8          	mov    QWORD PTR [rbp-0x48],rcx
  8fe191:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  8fe195:	4c 8b 77 50          	mov    r14,QWORD PTR [rdi+0x50]
  8fe199:	eb 08                	jmp    0x8fe1a3
  8fe19b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  8fe1a0:	4d 8b 36             	mov    r14,QWORD PTR [r14]
  8fe1a3:	4d 85 f6             	test   r14,r14
  8fe1a6:	74 21                	je     0x8fe1c9
  8fe1a8:	49 8d 76 20          	lea    rsi,[r14+0x20]
  8fe1ac:	ba 10 00 00 00       	mov    edx,0x10
  8fe1b1:	4c 89 e7             	mov    rdi,r12
  8fe1b4:	e8 17 ba a3 ff       	call   0x339bd0
  8fe1b9:	85 c0                	test   eax,eax
  8fe1bb:	78 e3                	js     0x8fe1a0
  8fe1bd:	0f 84 c2 00 00 00    	je     0x8fe285
  8fe1c3:	49 83 c6 08          	add    r14,0x8
  8fe1c7:	eb d7                	jmp    0x8fe1a0
  8fe1c9:	48 81 7b 58 00 02 00 	cmp    QWORD PTR [rbx+0x58],0x200
  8fe1d0:	00 
  8fe1d1:	b8 e4 ff ff ff       	mov    eax,0xffffffe4
  8fe1d6:	0f 84 2d 01 00 00    	je     0x8fe309
  8fe1dc:	48 8d 35 bd 0e c5 01 	lea    rsi,[rip+0x1c50ebd]        # 0x254f0a0
  8fe1e3:	bf 40 00 00 00       	mov    edi,0x40
  8fe1e8:	ba 01 01 00 00       	mov    edx,0x101
  8fe1ed:	e8 5e a9 30 00       	call   0xc08b50
  8fe1f2:	48 85 c0             	test   rax,rax
  8fe1f5:	0f 84 97 00 00 00    	je     0x8fe292
  8fe1fb:	49 8b 14 24          	mov    rdx,QWORD PTR [r12]
  8fe1ff:	49 8b 4c 24 08       	mov    rcx,QWORD PTR [r12+0x8]
  8fe204:	49 89 c6             	mov    r14,rax
  8fe207:	4c 8d 7b 50          	lea    r15,[rbx+0x50]
  8fe20b:	49 89 4e 28          	mov    QWORD PTR [r14+0x28],rcx
  8fe20f:	49 89 56 20          	mov    QWORD PTR [r14+0x20],rdx
  8fe213:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fe216:	48 85 c0             	test   rax,rax
  8fe219:	74 7e                	je     0x8fe299
  8fe21b:	4d 89 f4             	mov    r12,r14
  8fe21e:	49 83 c4 20          	add    r12,0x20
  8fe222:	eb 19                	jmp    0x8fe23d
  8fe224:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fe22b:	00 00 00 00 00 
  8fe230:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  8fe234:	48 85 c0             	test   rax,rax
  8fe237:	0f 84 80 00 00 00    	je     0x8fe2bd
  8fe23d:	48 8d 70 20          	lea    rsi,[rax+0x20]
  8fe241:	ba 10 00 00 00       	mov    edx,0x10
  8fe246:	4c 89 e7             	mov    rdi,r12
  8fe249:	49 89 c5             	mov    r13,rax
  8fe24c:	e8 7f b9 a3 ff       	call   0x339bd0
  8fe251:	85 c0                	test   eax,eax
  8fe253:	78 db                	js     0x8fe230
  8fe255:	0f 84 8c 00 00 00    	je     0x8fe2e7
  8fe25b:	49 8b 45 08          	mov    rax,QWORD PTR [r13+0x8]
  8fe25f:	48 85 c0             	test   rax,rax
  8fe262:	75 d9                	jne    0x8fe23d
  8fe264:	4d 89 6e 10          	mov    QWORD PTR [r14+0x10],r13
  8fe268:	49 c7 46 08 00 00 00 	mov    QWORD PTR [r14+0x8],0x0
  8fe26f:	00 
  8fe270:	49 c7 06 00 00 00 00 	mov    QWORD PTR [r14],0x0
  8fe277:	41 c7 46 18 01 00 00 	mov    DWORD PTR [r14+0x18],0x1
  8fe27e:	00 
  8fe27f:	4d 89 75 08          	mov    QWORD PTR [r13+0x8],r14
  8fe283:	eb 57                	jmp    0x8fe2dc
  8fe285:	31 c0                	xor    eax,eax
  8fe287:	41 80 7e 38 00       	cmp    BYTE PTR [r14+0x38],0x0
  8fe28c:	75 7b                	jne    0x8fe309
  8fe28e:	b0 01                	mov    al,0x1
  8fe290:	eb 67                	jmp    0x8fe2f9
  8fe292:	b8 f4 ff ff ff       	mov    eax,0xfffffff4
  8fe297:	eb 70                	jmp    0x8fe309
  8fe299:	49 c7 46 10 00 00 00 	mov    QWORD PTR [r14+0x10],0x0
  8fe2a0:	00 
  8fe2a1:	49 c7 46 08 00 00 00 	mov    QWORD PTR [r14+0x8],0x0
  8fe2a8:	00 
  8fe2a9:	49 c7 06 00 00 00 00 	mov    QWORD PTR [r14],0x0
  8fe2b0:	41 c7 46 18 01 00 00 	mov    DWORD PTR [r14+0x18],0x1
  8fe2b7:	00 
  8fe2b8:	4d 89 37             	mov    QWORD PTR [r15],r14
  8fe2bb:	eb 1f                	jmp    0x8fe2dc
  8fe2bd:	4d 89 6e 10          	mov    QWORD PTR [r14+0x10],r13
  8fe2c1:	49 c7 46 08 00 00 00 	mov    QWORD PTR [r14+0x8],0x0
  8fe2c8:	00 
  8fe2c9:	49 c7 06 00 00 00 00 	mov    QWORD PTR [r14],0x0
  8fe2d0:	41 c7 46 18 01 00 00 	mov    DWORD PTR [r14+0x18],0x1
  8fe2d7:	00 
  8fe2d8:	4d 89 75 00          	mov    QWORD PTR [r13+0x0],r14
  8fe2dc:	4c 89 ff             	mov    rdi,r15
  8fe2df:	4c 89 f6             	mov    rsi,r14
  8fe2e2:	e8 89 f3 ff ff       	call   0x8fd670
  8fe2e7:	48 ff 43 58          	inc    QWORD PTR [rbx+0x58]
  8fe2eb:	4c 8d 3d 1e e0 01 03 	lea    r15,[rip+0x301e01e]        # 0x391c310
  8fe2f2:	41 0f b6 46 38       	movzx  eax,BYTE PTR [r14+0x38]
  8fe2f7:	fe c0                	inc    al
  8fe2f9:	41 88 46 38          	mov    BYTE PTR [r14+0x38],al
  8fe2fd:	66 ff 83 9e 00 00 00 	inc    WORD PTR [rbx+0x9e]
  8fe304:	b8 01 00 00 00       	mov    eax,0x1
  8fe309:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  8fe30c:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  8fe310:	75 0f                	jne    0x8fe321
  8fe312:	48 83 c4 48          	add    rsp,0x48
  8fe316:	5b                   	pop    rbx
  8fe317:	41 5c                	pop    r12
  8fe319:	41 5d                	pop    r13
  8fe31b:	41 5e                	pop    r14
  8fe31d:	41 5f                	pop    r15
  8fe31f:	5d                   	pop    rbp
  8fe320:	c3                   	ret
  8fe321:	e8 8a f3 df ff       	call   0x6fd6b0
  8fe326:	0f 0b                	ud2
  8fe328:	90                   	nop
  8fe329:	90                   	nop
  8fe32a:	90                   	nop
  8fe32b:	90                   	nop
  8fe32c:	90                   	nop
  8fe32d:	90                   	nop
  8fe32e:	90                   	nop
  8fe32f:	90                   	nop
  8fe330:	55                   	push   rbp
  8fe331:	48 89 e5             	mov    rbp,rsp
  8fe334:	53                   	push   rbx
  8fe335:	50                   	push   rax
  8fe336:	48 89 fb             	mov    rbx,rdi
  8fe339:	e8 a2 00 00 00       	call   0x8fe3e0
  8fe33e:	48 8b 4b 50          	mov    rcx,QWORD PTR [rbx+0x50]
  8fe342:	48 85 c9             	test   rcx,rcx
  8fe345:	74 6d                	je     0x8fe3b4
  8fe347:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  8fe34e:	00 00 
  8fe350:	48 89 c8             	mov    rax,rcx
  8fe353:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  8fe356:	48 85 c9             	test   rcx,rcx
  8fe359:	75 f5                	jne    0x8fe350
  8fe35b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  8fe360:	48 89 c1             	mov    rcx,rax
  8fe363:	8b 40 34             	mov    eax,DWORD PTR [rax+0x34]
  8fe366:	89 41 30             	mov    DWORD PTR [rcx+0x30],eax
  8fe369:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  8fe36d:	48 85 d2             	test   rdx,rdx
  8fe370:	74 1e                	je     0x8fe390
  8fe372:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fe379:	1f 84 00 00 00 00 00 
  8fe380:	48 89 d0             	mov    rax,rdx
  8fe383:	48 8b 12             	mov    rdx,QWORD PTR [rdx]
  8fe386:	48 85 d2             	test   rdx,rdx
  8fe389:	75 f5                	jne    0x8fe380
  8fe38b:	eb d3                	jmp    0x8fe360
  8fe38d:	0f 1f 00             	nop    DWORD PTR [rax]
  8fe390:	48 8b 41 10          	mov    rax,QWORD PTR [rcx+0x10]
  8fe394:	48 85 c0             	test   rax,rax
  8fe397:	74 07                	je     0x8fe3a0
  8fe399:	48 3b 08             	cmp    rcx,QWORD PTR [rax]
  8fe39c:	74 c2                	je     0x8fe360
  8fe39e:	66 90                	xchg   ax,ax
  8fe3a0:	48 8b 41 10          	mov    rax,QWORD PTR [rcx+0x10]
  8fe3a4:	48 85 c0             	test   rax,rax
  8fe3a7:	74 0b                	je     0x8fe3b4
  8fe3a9:	48 3b 48 08          	cmp    rcx,QWORD PTR [rax+0x8]
  8fe3ad:	48 89 c1             	mov    rcx,rax
  8fe3b0:	74 ee                	je     0x8fe3a0
  8fe3b2:	eb ac                	jmp    0x8fe360
  8fe3b4:	0f b7 83 9e 00 00 00 	movzx  eax,WORD PTR [rbx+0x9e]
  8fe3bb:	66 89 83 94 00 00 00 	mov    WORD PTR [rbx+0x94],ax
  8fe3c2:	48 8b 83 96 00 00 00 	mov    rax,QWORD PTR [rbx+0x96]
  8fe3c9:	48 89 83 8c 00 00 00 	mov    QWORD PTR [rbx+0x8c],rax
  8fe3d0:	48 83 c4 08          	add    rsp,0x8
  8fe3d4:	5b                   	pop    rbx
  8fe3d5:	5d                   	pop    rbp
  8fe3d6:	c3                   	ret
  8fe3d7:	90                   	nop
  8fe3d8:	90                   	nop
  8fe3d9:	90                   	nop
  8fe3da:	90                   	nop
  8fe3db:	90                   	nop
  8fe3dc:	90                   	nop
  8fe3dd:	90                   	nop
  8fe3de:	90                   	nop
  8fe3df:	90                   	nop
  8fe3e0:	55                   	push   rbp
  8fe3e1:	48 89 e5             	mov    rbp,rsp
  8fe3e4:	41 57                	push   r15
  8fe3e6:	41 56                	push   r14
  8fe3e8:	41 54                	push   r12
  8fe3ea:	53                   	push   rbx
  8fe3eb:	48 83 ec 50          	sub    rsp,0x50
  8fe3ef:	4c 8d 3d 1a df 01 03 	lea    r15,[rip+0x301df1a]        # 0x391c310
  8fe3f6:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fe3f9:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  8fe3fd:	f6 05 4f a5 2f 02 10 	test   BYTE PTR [rip+0x22fa54f],0x10        # 0x2bf8953
  8fe404:	0f 84 4f 01 00 00    	je     0x8fe559
  8fe40a:	48 89 fb             	mov    rbx,rdi
  8fe40d:	48 8d 3d ae 21 a4 00 	lea    rdi,[rip+0xa421ae]        # 0x13405c2
  8fe414:	48 8d 35 50 aa 9d 00 	lea    rsi,[rip+0x9daa50]        # 0x12d8e6b
  8fe41b:	31 c0                	xor    eax,eax
  8fe41d:	48 89 da             	mov    rdx,rbx
  8fe420:	e8 eb ef 95 ff       	call   0x25d410
  8fe425:	48 8d 73 10          	lea    rsi,[rbx+0x10]
  8fe429:	48 8d 7d a0          	lea    rdi,[rbp-0x60]
  8fe42d:	e8 5e 7b 18 00       	call   0xa85f90
  8fe432:	48 8b 53 20          	mov    rdx,QWORD PTR [rbx+0x20]
  8fe436:	4c 8b 43 28          	mov    r8,QWORD PTR [rbx+0x28]
  8fe43a:	48 89 c6             	mov    rsi,rax
  8fe43d:	48 8d 3d 3d 0c aa 00 	lea    rdi,[rip+0xaa0c3d]        # 0x139f081
  8fe444:	31 c0                	xor    eax,eax
  8fe446:	48 8d 4a 60          	lea    rcx,[rdx+0x60]
  8fe44a:	e8 c1 ef 95 ff       	call   0x25d410
  8fe44f:	8b 43 34             	mov    eax,DWORD PTR [rbx+0x34]
  8fe452:	8b 73 38             	mov    esi,DWORD PTR [rbx+0x38]
  8fe455:	4c 8d 35 90 d4 a9 00 	lea    r14,[rip+0xa9d490]        # 0x139b8ec
  8fe45c:	4c 89 f2             	mov    rdx,r14
  8fe45f:	48 83 f8 09          	cmp    rax,0x9
  8fe463:	77 0e                	ja     0x8fe473
  8fe465:	48 8d 0d c8 e6 f1 00 	lea    rcx,[rip+0xf1e6c8]        # 0x181cb34
  8fe46c:	48 63 14 81          	movsxd rdx,DWORD PTR [rcx+rax*4]
  8fe470:	48 01 ca             	add    rdx,rcx
  8fe473:	8b 4b 30             	mov    ecx,DWORD PTR [rbx+0x30]
  8fe476:	44 8b 43 70          	mov    r8d,DWORD PTR [rbx+0x70]
  8fe47a:	48 8d 3d f8 27 a6 00 	lea    rdi,[rip+0xa627f8]        # 0x1360c79
  8fe481:	31 c0                	xor    eax,eax
  8fe483:	e8 88 ef 95 ff       	call   0x25d410
  8fe488:	48 8b 73 40          	mov    rsi,QWORD PTR [rbx+0x40]
  8fe48c:	48 8b 53 58          	mov    rdx,QWORD PTR [rbx+0x58]
  8fe490:	0f b7 8b 88 00 00 00 	movzx  ecx,WORD PTR [rbx+0x88]
  8fe497:	44 0f b7 83 8a 00 00 	movzx  r8d,WORD PTR [rbx+0x8a]
  8fe49e:	00 
  8fe49f:	48 8d 3d 8b 4a 9e 00 	lea    rdi,[rip+0x9e4a8b]        # 0x12e2f31
  8fe4a6:	31 c0                	xor    eax,eax
  8fe4a8:	e8 63 ef 95 ff       	call   0x25d410
  8fe4ad:	0f b7 83 8c 00 00 00 	movzx  eax,WORD PTR [rbx+0x8c]
  8fe4b4:	4c 8d 25 f5 c0 58 00 	lea    r12,[rip+0x58c0f5]        # 0xe8a5b0
  8fe4bb:	4c 89 f2             	mov    rdx,r14
  8fe4be:	48 83 f8 02          	cmp    rax,0x2
  8fe4c2:	77 04                	ja     0x8fe4c8
  8fe4c4:	49 8b 14 c4          	mov    rdx,QWORD PTR [r12+rax*8]
  8fe4c8:	0f b7 8b 8e 00 00 00 	movzx  ecx,WORD PTR [rbx+0x8e]
  8fe4cf:	44 0f b7 83 90 00 00 	movzx  r8d,WORD PTR [rbx+0x90]
  8fe4d6:	00 
  8fe4d7:	44 0f b7 8b 92 00 00 	movzx  r9d,WORD PTR [rbx+0x92]
  8fe4de:	00 
  8fe4df:	0f b7 83 94 00 00 00 	movzx  eax,WORD PTR [rbx+0x94]
  8fe4e6:	48 8d 3d c3 86 a1 00 	lea    rdi,[rip+0xa186c3]        # 0x1316bb0
  8fe4ed:	31 f6                	xor    esi,esi
  8fe4ef:	89 04 24             	mov    DWORD PTR [rsp],eax
  8fe4f2:	31 c0                	xor    eax,eax
  8fe4f4:	e8 17 ef 95 ff       	call   0x25d410
  8fe4f9:	0f b7 83 96 00 00 00 	movzx  eax,WORD PTR [rbx+0x96]
  8fe500:	48 83 f8 02          	cmp    rax,0x2
  8fe504:	77 04                	ja     0x8fe50a
  8fe506:	4d 8b 34 c4          	mov    r14,QWORD PTR [r12+rax*8]
  8fe50a:	0f b7 8b 98 00 00 00 	movzx  ecx,WORD PTR [rbx+0x98]
  8fe511:	44 0f b7 83 9a 00 00 	movzx  r8d,WORD PTR [rbx+0x9a]
  8fe518:	00 
  8fe519:	44 0f b7 8b 9c 00 00 	movzx  r9d,WORD PTR [rbx+0x9c]
  8fe520:	00 
  8fe521:	0f b7 83 9e 00 00 00 	movzx  eax,WORD PTR [rbx+0x9e]
  8fe528:	48 8d 3d 81 86 a1 00 	lea    rdi,[rip+0xa18681]        # 0x1316bb0
  8fe52f:	be 01 00 00 00       	mov    esi,0x1
  8fe534:	4c 89 f2             	mov    rdx,r14
  8fe537:	89 04 24             	mov    DWORD PTR [rsp],eax
  8fe53a:	31 c0                	xor    eax,eax
  8fe53c:	e8 cf ee 95 ff       	call   0x25d410
  8fe541:	48 8d 3d 46 c5 99 00 	lea    rdi,[rip+0x99c546]        # 0x129aa8e
  8fe548:	48 8d 35 1c a9 9d 00 	lea    rsi,[rip+0x9da91c]        # 0x12d8e6b
  8fe54f:	48 89 da             	mov    rdx,rbx
  8fe552:	31 c0                	xor    eax,eax
  8fe554:	e8 b7 ee 95 ff       	call   0x25d410
  8fe559:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fe55c:	48 3b 45 d8          	cmp    rax,QWORD PTR [rbp-0x28]
  8fe560:	75 0d                	jne    0x8fe56f
  8fe562:	48 83 c4 50          	add    rsp,0x50
  8fe566:	5b                   	pop    rbx
  8fe567:	41 5c                	pop    r12
  8fe569:	41 5e                	pop    r14
  8fe56b:	41 5f                	pop    r15
  8fe56d:	5d                   	pop    rbp
  8fe56e:	c3                   	ret
  8fe56f:	e8 3c f1 df ff       	call   0x6fd6b0
  8fe574:	0f 0b                	ud2
  8fe576:	90                   	nop
  8fe577:	90                   	nop
  8fe578:	90                   	nop
  8fe579:	90                   	nop
  8fe57a:	90                   	nop
  8fe57b:	90                   	nop
  8fe57c:	90                   	nop
  8fe57d:	90                   	nop
  8fe57e:	90                   	nop
  8fe57f:	90                   	nop
  8fe580:	55                   	push   rbp
  8fe581:	48 89 e5             	mov    rbp,rsp
  8fe584:	41 57                	push   r15
  8fe586:	41 56                	push   r14
  8fe588:	41 55                	push   r13
  8fe58a:	41 54                	push   r12
  8fe58c:	53                   	push   rbx
  8fe58d:	50                   	push   rax
  8fe58e:	49 89 d6             	mov    r14,rdx
  8fe591:	49 89 f7             	mov    r15,rsi
  8fe594:	49 89 fc             	mov    r12,rdi
  8fe597:	48 8d 35 e2 0a c5 01 	lea    rsi,[rip+0x1c50ae2]        # 0x254f080
  8fe59e:	bf 18 00 00 00       	mov    edi,0x18
  8fe5a3:	ba 01 00 00 00       	mov    edx,0x1
  8fe5a8:	41 89 cd             	mov    r13d,ecx
  8fe5ab:	e8 a0 a5 30 00       	call   0xc08b50
  8fe5b0:	48 85 c0             	test   rax,rax
  8fe5b3:	74 65                	je     0x8fe61a
  8fe5b5:	48 89 c3             	mov    rbx,rax
  8fe5b8:	43 8d 44 ad 00       	lea    eax,[r13+r13*4+0x0]
  8fe5bd:	48 8d 3d 7c da 25 03 	lea    rdi,[rip+0x325da7c]        # 0x3b5c040
  8fe5c4:	31 f6                	xor    esi,esi
  8fe5c6:	31 c9                	xor    ecx,ecx
  8fe5c8:	99                   	cdq
  8fe5c9:	f7 3d 71 1e 02 03    	idiv   DWORD PTR [rip+0x3021e71]        # 0x3920440
  8fe5cf:	31 d2                	xor    edx,edx
  8fe5d1:	41 89 c5             	mov    r13d,eax
  8fe5d4:	e8 27 84 bc ff       	call   0x4c6a00
  8fe5d9:	4c 89 e7             	mov    rdi,r12
  8fe5dc:	4c 89 fe             	mov    rsi,r15
  8fe5df:	48 89 d9             	mov    rcx,rbx
  8fe5e2:	45 89 e8             	mov    r8d,r13d
  8fe5e5:	31 d2                	xor    edx,edx
  8fe5e7:	e8 c4 01 00 00       	call   0x8fe7b0
  8fe5ec:	48 8d 3d 4d da 25 03 	lea    rdi,[rip+0x325da4d]        # 0x3b5c040
  8fe5f3:	41 89 c7             	mov    r15d,eax
  8fe5f6:	31 f6                	xor    esi,esi
  8fe5f8:	31 d2                	xor    edx,edx
  8fe5fa:	31 c9                	xor    ecx,ecx
  8fe5fc:	e8 9f 89 bc ff       	call   0x4c6fa0
  8fe601:	45 85 ff             	test   r15d,r15d
  8fe604:	74 1d                	je     0x8fe623
  8fe606:	48 8d 35 73 0a c5 01 	lea    rsi,[rip+0x1c50a73]        # 0x254f080
  8fe60d:	48 89 df             	mov    rdi,rbx
  8fe610:	45 89 3e             	mov    DWORD PTR [r14],r15d
  8fe613:	e8 d8 a7 30 00       	call   0xc08df0
  8fe618:	eb 07                	jmp    0x8fe621
  8fe61a:	41 c7 06 37 00 00 00 	mov    DWORD PTR [r14],0x37
  8fe621:	31 db                	xor    ebx,ebx
  8fe623:	48 89 d8             	mov    rax,rbx
  8fe626:	48 83 c4 08          	add    rsp,0x8
  8fe62a:	5b                   	pop    rbx
  8fe62b:	41 5c                	pop    r12
  8fe62d:	41 5d                	pop    r13
  8fe62f:	41 5e                	pop    r14
  8fe631:	41 5f                	pop    r15
  8fe633:	5d                   	pop    rbp
  8fe634:	c3                   	ret
  8fe635:	90                   	nop
  8fe636:	90                   	nop
  8fe637:	90                   	nop
  8fe638:	90                   	nop
  8fe639:	90                   	nop
  8fe63a:	90                   	nop
  8fe63b:	90                   	nop
  8fe63c:	90                   	nop
  8fe63d:	90                   	nop
  8fe63e:	90                   	nop
  8fe63f:	90                   	nop
  8fe640:	55                   	push   rbp
  8fe641:	48 89 e5             	mov    rbp,rsp
  8fe644:	41 57                	push   r15
  8fe646:	41 56                	push   r14
  8fe648:	41 55                	push   r13
  8fe64a:	41 54                	push   r12
  8fe64c:	53                   	push   rbx
  8fe64d:	48 83 ec 28          	sub    rsp,0x28
  8fe651:	4c 8d 25 b8 dc 01 03 	lea    r12,[rip+0x301dcb8]        # 0x391c310
  8fe658:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  8fe65c:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fe660:	48 8b 1f             	mov    rbx,QWORD PTR [rdi]
  8fe663:	48 85 db             	test   rbx,rbx
  8fe666:	74 65                	je     0x8fe6cd
  8fe668:	4c 8d 35 d1 d9 25 03 	lea    r14,[rip+0x325d9d1]        # 0x3b5c040
  8fe66f:	49 89 fd             	mov    r13,rdi
  8fe672:	31 f6                	xor    esi,esi
  8fe674:	31 d2                	xor    edx,edx
  8fe676:	31 c9                	xor    ecx,ecx
  8fe678:	4c 89 f7             	mov    rdi,r14
  8fe67b:	e8 80 83 bc ff       	call   0x4c6a00
  8fe680:	4c 8d 7d b8          	lea    r15,[rbp-0x48]
  8fe684:	be 18 00 00 00       	mov    esi,0x18
  8fe689:	4c 89 ff             	mov    rdi,r15
  8fe68c:	e8 5f a9 95 ff       	call   0x258ff0
  8fe691:	48 89 df             	mov    rdi,rbx
  8fe694:	4c 89 fe             	mov    rsi,r15
  8fe697:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
  8fe69e:	00 
  8fe69f:	66 c7 45 c8 02 00    	mov    WORD PTR [rbp-0x38],0x2
  8fe6a5:	e8 76 03 00 00       	call   0x8fea20
  8fe6aa:	48 89 df             	mov    rdi,rbx
  8fe6ad:	31 f6                	xor    esi,esi
  8fe6af:	e8 9c 6f da ff       	call   0x6a5650
  8fe6b4:	48 89 df             	mov    rdi,rbx
  8fe6b7:	e8 e4 f8 ff ff       	call   0x8fdfa0
  8fe6bc:	4c 89 f7             	mov    rdi,r14
  8fe6bf:	31 f6                	xor    esi,esi
  8fe6c1:	31 d2                	xor    edx,edx
  8fe6c3:	31 c9                	xor    ecx,ecx
  8fe6c5:	e8 d6 88 bc ff       	call   0x4c6fa0
  8fe6ca:	4c 89 ef             	mov    rdi,r13
  8fe6cd:	48 8d 35 ac 09 c5 01 	lea    rsi,[rip+0x1c509ac]        # 0x254f080
  8fe6d4:	e8 17 a7 30 00       	call   0xc08df0
  8fe6d9:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  8fe6dd:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  8fe6e1:	75 11                	jne    0x8fe6f4
  8fe6e3:	31 c0                	xor    eax,eax
  8fe6e5:	48 83 c4 28          	add    rsp,0x28
  8fe6e9:	5b                   	pop    rbx
  8fe6ea:	41 5c                	pop    r12
  8fe6ec:	41 5d                	pop    r13
  8fe6ee:	41 5e                	pop    r14
  8fe6f0:	41 5f                	pop    r15
  8fe6f2:	5d                   	pop    rbp
  8fe6f3:	c3                   	ret
  8fe6f4:	e8 b7 ef df ff       	call   0x6fd6b0
  8fe6f9:	0f 0b                	ud2
  8fe6fb:	90                   	nop
  8fe6fc:	90                   	nop
  8fe6fd:	90                   	nop
  8fe6fe:	90                   	nop
  8fe6ff:	90                   	nop
  8fe700:	55                   	push   rbp
  8fe701:	48 89 e5             	mov    rbp,rsp
  8fe704:	41 57                	push   r15
  8fe706:	41 56                	push   r14
  8fe708:	53                   	push   rbx
  8fe709:	48 83 ec 28          	sub    rsp,0x28
  8fe70d:	4c 8d 3d fc db 01 03 	lea    r15,[rip+0x301dbfc]        # 0x391c310
  8fe714:	48 89 fb             	mov    rbx,rdi
  8fe717:	48 8d 3d 22 d9 25 03 	lea    rdi,[rip+0x325d922]        # 0x3b5c040
  8fe71e:	49 89 f6             	mov    r14,rsi
  8fe721:	31 f6                	xor    esi,esi
  8fe723:	31 d2                	xor    edx,edx
  8fe725:	31 c9                	xor    ecx,ecx
  8fe727:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fe72a:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  8fe72e:	e8 cd 82 bc ff       	call   0x4c6a00
  8fe733:	4d 85 f6             	test   r14,r14
  8fe736:	75 1f                	jne    0x8fe757
  8fe738:	4c 8d 75 c8          	lea    r14,[rbp-0x38]
  8fe73c:	be 18 00 00 00       	mov    esi,0x18
  8fe741:	4c 89 f7             	mov    rdi,r14
  8fe744:	e8 a7 a8 95 ff       	call   0x258ff0
  8fe749:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
  8fe750:	00 
  8fe751:	66 c7 45 d8 02 00    	mov    WORD PTR [rbp-0x28],0x2
  8fe757:	48 89 df             	mov    rdi,rbx
  8fe75a:	4c 89 f6             	mov    rsi,r14
  8fe75d:	e8 be 02 00 00       	call   0x8fea20
  8fe762:	48 89 df             	mov    rdi,rbx
  8fe765:	31 f6                	xor    esi,esi
  8fe767:	e8 e4 6e da ff       	call   0x6a5650
  8fe76c:	48 89 df             	mov    rdi,rbx
  8fe76f:	41 89 c6             	mov    r14d,eax
  8fe772:	e8 29 f8 ff ff       	call   0x8fdfa0
  8fe777:	48 8d 3d c2 d8 25 03 	lea    rdi,[rip+0x325d8c2]        # 0x3b5c040
  8fe77e:	31 f6                	xor    esi,esi
  8fe780:	31 d2                	xor    edx,edx
  8fe782:	31 c9                	xor    ecx,ecx
  8fe784:	e8 17 88 bc ff       	call   0x4c6fa0
  8fe789:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fe78c:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
  8fe790:	75 0e                	jne    0x8fe7a0
  8fe792:	44 89 f0             	mov    eax,r14d
  8fe795:	48 83 c4 28          	add    rsp,0x28
  8fe799:	5b                   	pop    rbx
  8fe79a:	41 5e                	pop    r14
  8fe79c:	41 5f                	pop    r15
  8fe79e:	5d                   	pop    rbp
  8fe79f:	c3                   	ret
  8fe7a0:	e8 0b ef df ff       	call   0x6fd6b0
  8fe7a5:	0f 0b                	ud2
  8fe7a7:	90                   	nop
  8fe7a8:	90                   	nop
  8fe7a9:	90                   	nop
  8fe7aa:	90                   	nop
  8fe7ab:	90                   	nop
  8fe7ac:	90                   	nop
  8fe7ad:	90                   	nop
  8fe7ae:	90                   	nop
  8fe7af:	90                   	nop
  8fe7b0:	55                   	push   rbp
  8fe7b1:	48 89 e5             	mov    rbp,rsp
  8fe7b4:	41 57                	push   r15
  8fe7b6:	41 56                	push   r14
  8fe7b8:	41 55                	push   r13
  8fe7ba:	41 54                	push   r12
  8fe7bc:	53                   	push   rbx
  8fe7bd:	48 83 ec 68          	sub    rsp,0x68
  8fe7c1:	48 8d 05 48 db 01 03 	lea    rax,[rip+0x301db48]        # 0x391c310
  8fe7c8:	44 89 45 8c          	mov    DWORD PTR [rbp-0x74],r8d
  8fe7cc:	48 89 4d 80          	mov    QWORD PTR [rbp-0x80],rcx
  8fe7d0:	49 89 d6             	mov    r14,rdx
  8fe7d3:	48 89 f3             	mov    rbx,rsi
  8fe7d6:	49 89 fd             	mov    r13,rdi
  8fe7d9:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8fe7dc:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fe7e0:	48 85 d2             	test   rdx,rdx
  8fe7e3:	75 1f                	jne    0x8fe804
  8fe7e5:	4c 8d 75 98          	lea    r14,[rbp-0x68]
  8fe7e9:	be 18 00 00 00       	mov    esi,0x18
  8fe7ee:	4c 89 f7             	mov    rdi,r14
  8fe7f1:	e8 fa a7 95 ff       	call   0x258ff0
  8fe7f6:	48 c7 45 98 00 00 00 	mov    QWORD PTR [rbp-0x68],0x0
  8fe7fd:	00 
  8fe7fe:	66 c7 45 a8 00 02    	mov    WORD PTR [rbp-0x58],0x200
  8fe804:	4d 8d a5 78 02 00 00 	lea    r12,[r13+0x278]
  8fe80b:	4c 89 b5 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],r14
  8fe812:	31 f6                	xor    esi,esi
  8fe814:	31 d2                	xor    edx,edx
  8fe816:	4c 89 e7             	mov    rdi,r12
  8fe819:	e8 82 5e ed ff       	call   0x7d46a0
  8fe81e:	4d 8b bd 90 02 00 00 	mov    r15,QWORD PTR [r13+0x290]
  8fe825:	eb 0c                	jmp    0x8fe833
  8fe827:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  8fe82e:	00 00 
  8fe830:	4d 8b 3f             	mov    r15,QWORD PTR [r15]
  8fe833:	4d 85 ff             	test   r15,r15
  8fe836:	74 28                	je     0x8fe860
  8fe838:	49 8b 47 10          	mov    rax,QWORD PTR [r15+0x10]
  8fe83c:	80 78 01 1c          	cmp    BYTE PTR [rax+0x1],0x1c
  8fe840:	75 ee                	jne    0x8fe830
  8fe842:	4d 8b 77 30          	mov    r14,QWORD PTR [r15+0x30]
  8fe846:	ba 10 00 00 00       	mov    edx,0x10
  8fe84b:	48 89 de             	mov    rsi,rbx
  8fe84e:	49 8d 7e 10          	lea    rdi,[r14+0x10]
  8fe852:	e8 29 a8 95 ff       	call   0x259080
  8fe857:	85 c0                	test   eax,eax
  8fe859:	75 d5                	jne    0x8fe830
  8fe85b:	4d 85 f6             	test   r14,r14
  8fe85e:	75 65                	jne    0x8fe8c5
  8fe860:	4c 8d 75 b4          	lea    r14,[rbp-0x4c]
  8fe864:	be 1c 00 00 00       	mov    esi,0x1c
  8fe869:	4c 89 f7             	mov    rdi,r14
  8fe86c:	e8 7f a7 95 ff       	call   0x258ff0
  8fe871:	66 c7 45 b4 1c 1c    	mov    WORD PTR [rbp-0x4c],0x1c1c
  8fe877:	4c 89 e7             	mov    rdi,r12
  8fe87a:	31 f6                	xor    esi,esi
  8fe87c:	31 d2                	xor    edx,edx
  8fe87e:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  8fe881:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
  8fe885:	48 89 45 bc          	mov    QWORD PTR [rbp-0x44],rax
  8fe889:	48 89 4d c4          	mov    QWORD PTR [rbp-0x3c],rcx
  8fe88d:	e8 1e 66 ed ff       	call   0x7d4eb0
  8fe892:	48 8d 55 90          	lea    rdx,[rbp-0x70]
  8fe896:	4c 89 ef             	mov    rdi,r13
  8fe899:	4c 89 f6             	mov    rsi,r14
  8fe89c:	e8 9f fc bb ff       	call   0x4be540
  8fe8a1:	41 89 c7             	mov    r15d,eax
  8fe8a4:	85 c0                	test   eax,eax
  8fe8a6:	75 79                	jne    0x8fe921
  8fe8a8:	4c 89 e7             	mov    rdi,r12
  8fe8ab:	31 f6                	xor    esi,esi
  8fe8ad:	31 d2                	xor    edx,edx
  8fe8af:	e8 ec 5d ed ff       	call   0x7d46a0
  8fe8b4:	48 8b 45 90          	mov    rax,QWORD PTR [rbp-0x70]
  8fe8b8:	4c 8b 70 30          	mov    r14,QWORD PTR [rax+0x30]
  8fe8bc:	4d 85 f6             	test   r14,r14
  8fe8bf:	0f 84 82 00 00 00    	je     0x8fe947
  8fe8c5:	41 ff 46 30          	inc    DWORD PTR [r14+0x30]
  8fe8c9:	4c 89 e7             	mov    rdi,r12
  8fe8cc:	31 f6                	xor    esi,esi
  8fe8ce:	31 d2                	xor    edx,edx
  8fe8d0:	e8 db 65 ed ff       	call   0x7d4eb0
  8fe8d5:	41 83 7e 34 09       	cmp    DWORD PTR [r14+0x34],0x9
  8fe8da:	75 14                	jne    0x8fe8f0
  8fe8dc:	66 41 c7 86 8c 00 00 	mov    WORD PTR [r14+0x8c],0x0
  8fe8e3:	00 00 00 
  8fe8e6:	66 41 c7 86 96 00 00 	mov    WORD PTR [r14+0x96],0x0
  8fe8ed:	00 00 00 
  8fe8f0:	48 8b b5 78 ff ff ff 	mov    rsi,QWORD PTR [rbp-0x88]
  8fe8f7:	4c 89 f7             	mov    rdi,r14
  8fe8fa:	e8 21 01 00 00       	call   0x8fea20
  8fe8ff:	85 c0                	test   eax,eax
  8fe901:	75 13                	jne    0x8fe916
  8fe903:	8b 75 8c             	mov    esi,DWORD PTR [rbp-0x74]
  8fe906:	4c 89 f7             	mov    rdi,r14
  8fe909:	e8 42 6d da ff       	call   0x6a5650
  8fe90e:	85 c0                	test   eax,eax
  8fe910:	0f 84 cb 00 00 00    	je     0x8fe9e1
  8fe916:	4c 89 f7             	mov    rdi,r14
  8fe919:	41 89 c7             	mov    r15d,eax
  8fe91c:	e8 7f f6 ff ff       	call   0x8fdfa0
  8fe921:	48 8d 05 e8 d9 01 03 	lea    rax,[rip+0x301d9e8]        # 0x391c310
  8fe928:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8fe92b:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  8fe92f:	0f 85 db 00 00 00    	jne    0x8fea10
  8fe935:	44 89 f8             	mov    eax,r15d
  8fe938:	48 83 c4 68          	add    rsp,0x68
  8fe93c:	5b                   	pop    rbx
  8fe93d:	41 5c                	pop    r12
  8fe93f:	41 5d                	pop    r13
  8fe941:	41 5e                	pop    r14
  8fe943:	41 5f                	pop    r15
  8fe945:	5d                   	pop    rbp
  8fe946:	c3                   	ret
  8fe947:	48 8d 35 32 07 c5 01 	lea    rsi,[rip+0x1c50732]        # 0x254f080
  8fe94e:	bf a0 00 00 00       	mov    edi,0xa0
  8fe953:	ba 01 01 00 00       	mov    edx,0x101
  8fe958:	e8 f3 a1 30 00       	call   0xc08b50
  8fe95d:	48 85 c0             	test   rax,rax
  8fe960:	0f 84 8a 00 00 00    	je     0x8fe9f0
  8fe966:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
  8fe969:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
  8fe96d:	49 89 c6             	mov    r14,rax
  8fe970:	48 8b 75 90          	mov    rsi,QWORD PTR [rbp-0x70]
  8fe974:	49 89 4e 18          	mov    QWORD PTR [r14+0x18],rcx
  8fe978:	49 89 56 10          	mov    QWORD PTR [r14+0x10],rdx
  8fe97c:	4d 89 6e 20          	mov    QWORD PTR [r14+0x20],r13
  8fe980:	4c 89 f1             	mov    rcx,r14
  8fe983:	48 ba 00 00 00 00 18 	movabs rdx,0x1800000000
  8fe98a:	00 00 00 
  8fe98d:	49 8b 85 b8 03 00 00 	mov    rax,QWORD PTR [r13+0x3b8]
  8fe994:	48 83 c1 60          	add    rcx,0x60
  8fe998:	48 8b 40 28          	mov    rax,QWORD PTR [rax+0x28]
  8fe99c:	49 89 46 40          	mov    QWORD PTR [r14+0x40],rax
  8fe9a0:	49 89 76 28          	mov    QWORD PTR [r14+0x28],rsi
  8fe9a4:	49 c7 46 30 01 00 00 	mov    QWORD PTR [r14+0x30],0x1
  8fe9ab:	00 
  8fe9ac:	49 c7 46 60 00 00 00 	mov    QWORD PTR [r14+0x60],0x0
  8fe9b3:	00 
  8fe9b4:	49 89 4e 68          	mov    QWORD PTR [r14+0x68],rcx
  8fe9b8:	49 89 56 70          	mov    QWORD PTR [r14+0x70],rdx
  8fe9bc:	66 41 c7 86 8c 00 00 	mov    WORD PTR [r14+0x8c],0x0
  8fe9c3:	00 00 00 
  8fe9c6:	66 41 c7 86 96 00 00 	mov    WORD PTR [r14+0x96],0x0
  8fe9cd:	00 00 00 
  8fe9d0:	49 c7 46 50 00 00 00 	mov    QWORD PTR [r14+0x50],0x0
  8fe9d7:	00 
  8fe9d8:	4c 89 76 30          	mov    QWORD PTR [rsi+0x30],r14
  8fe9dc:	e9 e8 fe ff ff       	jmp    0x8fe8c9
  8fe9e1:	48 8b 45 80          	mov    rax,QWORD PTR [rbp-0x80]
  8fe9e5:	45 31 ff             	xor    r15d,r15d
  8fe9e8:	4c 89 30             	mov    QWORD PTR [rax],r14
  8fe9eb:	e9 31 ff ff ff       	jmp    0x8fe921
  8fe9f0:	4c 89 e7             	mov    rdi,r12
  8fe9f3:	31 f6                	xor    esi,esi
  8fe9f5:	31 d2                	xor    edx,edx
  8fe9f7:	e8 b4 64 ed ff       	call   0x7d4eb0
  8fe9fc:	48 8b 7d 90          	mov    rdi,QWORD PTR [rbp-0x70]
  8fea00:	e8 5b 11 bc ff       	call   0x4bfb60
  8fea05:	41 bf 0c 00 00 00    	mov    r15d,0xc
  8fea0b:	e9 11 ff ff ff       	jmp    0x8fe921
  8fea10:	e8 9b ec df ff       	call   0x6fd6b0
  8fea15:	0f 0b                	ud2
  8fea17:	90                   	nop
  8fea18:	90                   	nop
  8fea19:	90                   	nop
  8fea1a:	90                   	nop
  8fea1b:	90                   	nop
  8fea1c:	90                   	nop
  8fea1d:	90                   	nop
  8fea1e:	90                   	nop
  8fea1f:	90                   	nop
  8fea20:	55                   	push   rbp
  8fea21:	48 89 e5             	mov    rbp,rsp
  8fea24:	41 57                	push   r15
  8fea26:	41 56                	push   r14
  8fea28:	41 55                	push   r13
  8fea2a:	41 54                	push   r12
  8fea2c:	53                   	push   rbx
  8fea2d:	48 83 ec 78          	sub    rsp,0x78
  8fea31:	48 8d 05 d8 d8 01 03 	lea    rax,[rip+0x301d8d8]        # 0x391c310
  8fea38:	48 89 fb             	mov    rbx,rdi
  8fea3b:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8fea3e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8fea42:	48 89 bd 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rdi
  8fea49:	48 8b 0e             	mov    rcx,QWORD PTR [rsi]
  8fea4c:	48 85 c9             	test   rcx,rcx
  8fea4f:	0f 84 fd 02 00 00    	je     0x8fed52
  8fea55:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fea5c:	00 00 00 00 
  8fea60:	48 89 c8             	mov    rax,rcx
  8fea63:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  8fea66:	48 85 c9             	test   rcx,rcx
  8fea69:	75 f5                	jne    0x8fea60
  8fea6b:	48 8d 4b 50          	lea    rcx,[rbx+0x50]
  8fea6f:	31 ff                	xor    edi,edi
  8fea71:	31 d2                	xor    edx,edx
  8fea73:	c7 45 88 00 00 00 00 	mov    DWORD PTR [rbp-0x78],0x0
  8fea7a:	48 89 b5 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],rsi
  8fea81:	48 89 4d 80          	mov    QWORD PTR [rbp-0x80],rcx
  8fea85:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fea8c:	00 00 00 00 
  8fea90:	49 89 c4             	mov    r12,rax
  8fea93:	0f b6 40 30          	movzx  eax,BYTE PTR [rax+0x30]
  8fea97:	45 31 f6             	xor    r14d,r14d
  8fea9a:	3a 46 10             	cmp    al,BYTE PTR [rsi+0x10]
  8fea9d:	41 0f b6 4c 24 31    	movzx  ecx,BYTE PTR [r12+0x31]
  8feaa3:	0f 94 45 8e          	sete   BYTE PTR [rbp-0x72]
  8feaa7:	3a 4e 11             	cmp    cl,BYTE PTR [rsi+0x11]
  8feaaa:	0f 94 45 8f          	sete   BYTE PTR [rbp-0x71]
  8feaae:	38 c8                	cmp    al,cl
  8feab0:	75 1e                	jne    0x8fead0
  8feab2:	0f b6 4d 8f          	movzx  ecx,BYTE PTR [rbp-0x71]
  8feab6:	44 0f b6 45 8e       	movzx  r8d,BYTE PTR [rbp-0x72]
  8feabb:	4d 89 fd             	mov    r13,r15
  8feabe:	31 c0                	xor    eax,eax
  8feac0:	e9 0c 02 00 00       	jmp    0x8fecd1
  8feac5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  8feacc:	00 00 00 00 
  8fead0:	49 8b 4c 24 28       	mov    rcx,QWORD PTR [r12+0x28]
  8fead5:	89 95 7c ff ff ff    	mov    DWORD PTR [rbp-0x84],edx
  8feadb:	49 8b 74 24 20       	mov    rsi,QWORD PTR [r12+0x20]
  8feae0:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
  8feae4:	49 8d 44 24 20       	lea    rax,[r12+0x20]
  8feae9:	89 bd 78 ff ff ff    	mov    DWORD PTR [rbp-0x88],edi
  8feaef:	48 89 85 60 ff ff ff 	mov    QWORD PTR [rbp-0xa0],rax
  8feaf6:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  8feafa:	48 8b 4d 80          	mov    rcx,QWORD PTR [rbp-0x80]
  8feafe:	48 89 32             	mov    QWORD PTR [rdx],rsi
  8feb01:	4c 8b 29             	mov    r13,QWORD PTR [rcx]
  8feb04:	eb 12                	jmp    0x8feb18
  8feb06:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  8feb0d:	00 00 00 
  8feb10:	49 83 c5 08          	add    r13,0x8
  8feb14:	4d 8b 6d 00          	mov    r13,QWORD PTR [r13+0x0]
  8feb18:	4d 85 ed             	test   r13,r13
  8feb1b:	74 23                	je     0x8feb40
  8feb1d:	49 8d 75 20          	lea    rsi,[r13+0x20]
  8feb21:	ba 10 00 00 00       	mov    edx,0x10
  8feb26:	48 8d 7d b0          	lea    rdi,[rbp-0x50]
  8feb2a:	e8 a1 b0 a3 ff       	call   0x339bd0
  8feb2f:	85 c0                	test   eax,eax
  8feb31:	78 e1                	js     0x8feb14
  8feb33:	75 db                	jne    0x8feb10
  8feb35:	e9 12 01 00 00       	jmp    0x8fec4c
  8feb3a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  8feb40:	48 81 7b 58 00 02 00 	cmp    QWORD PTR [rbx+0x58],0x200
  8feb47:	00 
  8feb48:	0f 84 17 04 00 00    	je     0x8fef65
  8feb4e:	bf 40 00 00 00       	mov    edi,0x40
  8feb53:	48 8d 35 46 05 c5 01 	lea    rsi,[rip+0x1c50546]        # 0x254f0a0
  8feb5a:	ba 01 01 00 00       	mov    edx,0x101
  8feb5f:	e8 ec 9f 30 00       	call   0xc08b50
  8feb64:	48 85 c0             	test   rax,rax
  8feb67:	0f 84 00 04 00 00    	je     0x8fef6d
  8feb6d:	48 8b 8d 60 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xa0]
  8feb74:	49 89 c5             	mov    r13,rax
  8feb77:	48 8b 7d 80          	mov    rdi,QWORD PTR [rbp-0x80]
  8feb7b:	48 8b 01             	mov    rax,QWORD PTR [rcx]
  8feb7e:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
  8feb82:	49 89 4d 28          	mov    QWORD PTR [r13+0x28],rcx
  8feb86:	49 89 45 20          	mov    QWORD PTR [r13+0x20],rax
  8feb8a:	48 8b 07             	mov    rax,QWORD PTR [rdi]
  8feb8d:	48 85 c0             	test   rax,rax
  8feb90:	74 5f                	je     0x8febf1
  8feb92:	4d 89 ef             	mov    r15,r13
  8feb95:	49 83 c7 20          	add    r15,0x20
  8feb99:	eb 0d                	jmp    0x8feba8
  8feb9b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  8feba0:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  8feba3:	48 85 c0             	test   rax,rax
  8feba6:	74 6e                	je     0x8fec16
  8feba8:	48 8d 70 20          	lea    rsi,[rax+0x20]
  8febac:	ba 10 00 00 00       	mov    edx,0x10
  8febb1:	4c 89 ff             	mov    rdi,r15
  8febb4:	48 89 c3             	mov    rbx,rax
  8febb7:	e8 14 b0 a3 ff       	call   0x339bd0
  8febbc:	85 c0                	test   eax,eax
  8febbe:	78 e0                	js     0x8feba0
  8febc0:	74 7f                	je     0x8fec41
  8febc2:	48 8b 43 08          	mov    rax,QWORD PTR [rbx+0x8]
  8febc6:	48 85 c0             	test   rax,rax
  8febc9:	75 dd                	jne    0x8feba8
  8febcb:	48 8b 7d 80          	mov    rdi,QWORD PTR [rbp-0x80]
  8febcf:	49 89 5d 10          	mov    QWORD PTR [r13+0x10],rbx
  8febd3:	49 c7 45 08 00 00 00 	mov    QWORD PTR [r13+0x8],0x0
  8febda:	00 
  8febdb:	49 c7 45 00 00 00 00 	mov    QWORD PTR [r13+0x0],0x0
  8febe2:	00 
  8febe3:	41 c7 45 18 01 00 00 	mov    DWORD PTR [r13+0x18],0x1
  8febea:	00 
  8febeb:	4c 89 6b 08          	mov    QWORD PTR [rbx+0x8],r13
  8febef:	eb 48                	jmp    0x8fec39
  8febf1:	49 c7 45 10 00 00 00 	mov    QWORD PTR [r13+0x10],0x0
  8febf8:	00 
  8febf9:	49 c7 45 08 00 00 00 	mov    QWORD PTR [r13+0x8],0x0
  8fec00:	00 
  8fec01:	49 c7 45 00 00 00 00 	mov    QWORD PTR [r13+0x0],0x0
  8fec08:	00 
  8fec09:	41 c7 45 18 01 00 00 	mov    DWORD PTR [r13+0x18],0x1
  8fec10:	00 
  8fec11:	4c 89 2f             	mov    QWORD PTR [rdi],r13
  8fec14:	eb 23                	jmp    0x8fec39
  8fec16:	48 8b 7d 80          	mov    rdi,QWORD PTR [rbp-0x80]
  8fec1a:	49 89 5d 10          	mov    QWORD PTR [r13+0x10],rbx
  8fec1e:	49 c7 45 08 00 00 00 	mov    QWORD PTR [r13+0x8],0x0
  8fec25:	00 
  8fec26:	49 c7 45 00 00 00 00 	mov    QWORD PTR [r13+0x0],0x0
  8fec2d:	00 
  8fec2e:	41 c7 45 18 01 00 00 	mov    DWORD PTR [r13+0x18],0x1
  8fec35:	00 
  8fec36:	4c 89 2b             	mov    QWORD PTR [rbx],r13
  8fec39:	4c 89 ee             	mov    rsi,r13
  8fec3c:	e8 2f ea ff ff       	call   0x8fd670
  8fec41:	48 8b 9d 70 ff ff ff 	mov    rbx,QWORD PTR [rbp-0x90]
  8fec48:	48 ff 43 58          	inc    QWORD PTR [rbx+0x58]
  8fec4c:	48 8b b5 60 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xa0]
  8fec53:	48 8d 7d 90          	lea    rdi,[rbp-0x70]
  8fec57:	e8 34 73 18 00       	call   0xa85f90
  8fec5c:	41 0f b6 44 24 30    	movzx  eax,BYTE PTR [r12+0x30]
  8fec62:	44 0f b6 45 8e       	movzx  r8d,BYTE PTR [rbp-0x72]
  8fec67:	83 f8 01             	cmp    eax,0x1
  8fec6a:	74 23                	je     0x8fec8f
  8fec6c:	48 8b b5 68 ff ff ff 	mov    rsi,QWORD PTR [rbp-0x98]
  8fec73:	8b bd 78 ff ff ff    	mov    edi,DWORD PTR [rbp-0x88]
  8fec79:	8b 95 7c ff ff ff    	mov    edx,DWORD PTR [rbp-0x84]
  8fec7f:	0f b6 4d 8f          	movzx  ecx,BYTE PTR [rbp-0x71]
  8fec83:	83 f8 02             	cmp    eax,0x2
  8fec86:	75 23                	jne    0x8fecab
  8fec88:	66 41 ff 4d 34       	dec    WORD PTR [r13+0x34]
  8fec8d:	eb 1c                	jmp    0x8fecab
  8fec8f:	66 41 ff 4d 36       	dec    WORD PTR [r13+0x36]
  8fec94:	48 8b b5 68 ff ff ff 	mov    rsi,QWORD PTR [rbp-0x98]
  8fec9b:	8b bd 78 ff ff ff    	mov    edi,DWORD PTR [rbp-0x88]
  8feca1:	8b 95 7c ff ff ff    	mov    edx,DWORD PTR [rbp-0x84]
  8feca7:	0f b6 4d 8f          	movzx  ecx,BYTE PTR [rbp-0x71]
  8fecab:	41 0f b6 44 24 31    	movzx  eax,BYTE PTR [r12+0x31]
  8fecb1:	83 f8 01             	cmp    eax,0x1
  8fecb4:	74 11                	je     0x8fecc7
  8fecb6:	83 f8 02             	cmp    eax,0x2
  8fecb9:	b8 00 00 00 00       	mov    eax,0x0
  8fecbe:	75 0e                	jne    0x8fecce
  8fecc0:	66 41 ff 45 34       	inc    WORD PTR [r13+0x34]
  8fecc5:	eb 07                	jmp    0x8fecce
  8fecc7:	66 41 ff 45 36       	inc    WORD PTR [r13+0x36]
  8feccc:	31 c0                	xor    eax,eax
  8fecce:	ff 45 88             	inc    DWORD PTR [rbp-0x78]
  8fecd1:	88 c8                	mov    al,cl
  8fecd3:	49 8b 4c 24 08       	mov    rcx,QWORD PTR [r12+0x8]
  8fecd8:	45 88 c6             	mov    r14b,r8b
  8fecdb:	44 01 f2             	add    edx,r14d
  8fecde:	01 c7                	add    edi,eax
  8fece0:	48 85 c9             	test   rcx,rcx
  8fece3:	74 2b                	je     0x8fed10
  8fece5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fecec:	00 00 00 00 
  8fecf0:	48 89 c8             	mov    rax,rcx
  8fecf3:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  8fecf6:	48 85 c9             	test   rcx,rcx
  8fecf9:	75 f5                	jne    0x8fecf0
  8fecfb:	4d 89 ef             	mov    r15,r13
  8fecfe:	e9 8d fd ff ff       	jmp    0x8fea90
  8fed03:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fed0a:	84 00 00 00 00 00 
  8fed10:	49 8b 44 24 10       	mov    rax,QWORD PTR [r12+0x10]
  8fed15:	48 85 c0             	test   rax,rax
  8fed18:	74 16                	je     0x8fed30
  8fed1a:	4d 89 ef             	mov    r15,r13
  8fed1d:	4c 3b 20             	cmp    r12,QWORD PTR [rax]
  8fed20:	0f 84 6a fd ff ff    	je     0x8fea90
  8fed26:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  8fed2d:	00 00 00 
  8fed30:	49 8b 44 24 10       	mov    rax,QWORD PTR [r12+0x10]
  8fed35:	48 85 c0             	test   rax,rax
  8fed38:	74 11                	je     0x8fed4b
  8fed3a:	4c 3b 60 08          	cmp    r12,QWORD PTR [rax+0x8]
  8fed3e:	49 89 c4             	mov    r12,rax
  8fed41:	74 ed                	je     0x8fed30
  8fed43:	4d 89 ef             	mov    r15,r13
  8fed46:	e9 45 fd ff ff       	jmp    0x8fea90
  8fed4b:	85 d2                	test   edx,edx
  8fed4d:	0f 94 c0             	sete   al
  8fed50:	eb 0b                	jmp    0x8fed5d
  8fed52:	b0 01                	mov    al,0x1
  8fed54:	c7 45 88 00 00 00 00 	mov    DWORD PTR [rbp-0x78],0x0
  8fed5b:	31 ff                	xor    edi,edi
  8fed5d:	0f b6 56 10          	movzx  edx,BYTE PTR [rsi+0x10]
  8fed61:	0f b6 4e 11          	movzx  ecx,BYTE PTR [rsi+0x11]
  8fed65:	38 ca                	cmp    dl,cl
  8fed67:	75 18                	jne    0x8fed81
  8fed69:	80 fa 01             	cmp    dl,0x1
  8fed6c:	75 54                	jne    0x8fedc2
  8fed6e:	85 ff                	test   edi,edi
  8fed70:	75 50                	jne    0x8fedc2
  8fed72:	66 ff 8b 9c 00 00 00 	dec    WORD PTR [rbx+0x9c]
  8fed79:	0f b6 56 10          	movzx  edx,BYTE PTR [rsi+0x10]
  8fed7d:	0f b6 4e 11          	movzx  ecx,BYTE PTR [rsi+0x11]
  8fed81:	38 ca                	cmp    dl,cl
  8fed83:	74 3d                	je     0x8fedc2
  8fed85:	80 fa 02             	cmp    dl,0x2
  8fed88:	74 0f                	je     0x8fed99
  8fed8a:	0f b6 d2             	movzx  edx,dl
  8fed8d:	83 fa 01             	cmp    edx,0x1
  8fed90:	75 14                	jne    0x8feda6
  8fed92:	b9 9c 00 00 00       	mov    ecx,0x9c
  8fed97:	eb 05                	jmp    0x8fed9e
  8fed99:	b9 9a 00 00 00       	mov    ecx,0x9a
  8fed9e:	66 ff 0c 0b          	dec    WORD PTR [rbx+rcx*1]
  8feda2:	0f b6 4e 11          	movzx  ecx,BYTE PTR [rsi+0x11]
  8feda6:	ba 9a 00 00 00       	mov    edx,0x9a
  8fedab:	80 f9 02             	cmp    cl,0x2
  8fedae:	74 0e                	je     0x8fedbe
  8fedb0:	80 f9 01             	cmp    cl,0x1
  8fedb3:	75 0d                	jne    0x8fedc2
  8fedb5:	ba 9c 00 00 00       	mov    edx,0x9c
  8fedba:	85 ff                	test   edi,edi
  8fedbc:	7e 04                	jle    0x8fedc2
  8fedbe:	66 ff 04 13          	inc    WORD PTR [rbx+rdx*1]
  8fedc2:	66 83 bb 9a 00 00 00 	cmp    WORD PTR [rbx+0x9a],0x0
  8fedc9:	00 
  8fedca:	66 b9 02 00          	mov    cx,0x2
  8fedce:	75 0d                	jne    0x8feddd
  8fedd0:	31 c9                	xor    ecx,ecx
  8fedd2:	66 83 bb 9c 00 00 00 	cmp    WORD PTR [rbx+0x9c],0x0
  8fedd9:	00 
  8fedda:	0f 95 c1             	setne  cl
  8feddd:	66 89 8b 96 00 00 00 	mov    WORD PTR [rbx+0x96],cx
  8fede4:	80 7e 10 02          	cmp    BYTE PTR [rsi+0x10],0x2
  8fede8:	0f b6 4e 11          	movzx  ecx,BYTE PTR [rsi+0x11]
  8fedec:	0f 94 c2             	sete   dl
  8fedef:	20 c2                	and    dl,al
  8fedf1:	80 fa 01             	cmp    dl,0x1
  8fedf4:	75 16                	jne    0x8fee0c
  8fedf6:	80 f9 02             	cmp    cl,0x2
  8fedf9:	75 06                	jne    0x8fee01
  8fedfb:	b1 02                	mov    cl,0x2
  8fedfd:	85 ff                	test   edi,edi
  8fedff:	7e 0b                	jle    0x8fee0c
  8fee01:	66 ff 8b 98 00 00 00 	dec    WORD PTR [rbx+0x98]
  8fee08:	0f b6 4e 11          	movzx  ecx,BYTE PTR [rsi+0x11]
  8fee0c:	80 f9 02             	cmp    cl,0x2
  8fee0f:	75 0b                	jne    0x8fee1c
  8fee11:	85 ff                	test   edi,edi
  8fee13:	75 07                	jne    0x8fee1c
  8fee15:	66 ff 83 98 00 00 00 	inc    WORD PTR [rbx+0x98]
  8fee1c:	48 89 df             	mov    rdi,rbx
  8fee1f:	e8 bc f5 ff ff       	call   0x8fe3e0
  8fee24:	45 31 e4             	xor    r12d,r12d
  8fee27:	8b 45 88             	mov    eax,DWORD PTR [rbp-0x78]
  8fee2a:	85 c0                	test   eax,eax
  8fee2c:	0f 8e 0d 01 00 00    	jle    0x8fef3f
  8fee32:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
  8fee39:	48 8b 40 50          	mov    rax,QWORD PTR [rax+0x50]
  8fee3d:	48 85 c0             	test   rax,rax
  8fee40:	0f 84 f9 00 00 00    	je     0x8fef3f
  8fee46:	48 8b 8d 70 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x90]
  8fee4d:	48 8d 59 50          	lea    rbx,[rcx+0x50]
  8fee51:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fee58:	0f 1f 84 00 00 00 00 
  8fee5f:	00 
  8fee60:	49 89 c5             	mov    r13,rax
  8fee63:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8fee66:	48 85 c0             	test   rax,rax
  8fee69:	75 f5                	jne    0x8fee60
  8fee6b:	4c 8d 35 2e 02 c5 01 	lea    r14,[rip+0x1c5022e]        # 0x254f0a0
  8fee72:	eb 15                	jmp    0x8fee89
  8fee74:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fee7b:	00 00 00 00 00 
  8fee80:	4d 85 ed             	test   r13,r13
  8fee83:	0f 84 b6 00 00 00    	je     0x8fef3f
  8fee89:	49 8b 45 08          	mov    rax,QWORD PTR [r13+0x8]
  8fee8d:	4d 89 ef             	mov    r15,r13
  8fee90:	48 85 c0             	test   rax,rax
  8fee93:	74 6b                	je     0x8fef00
  8fee95:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fee9c:	00 00 00 00 
  8feea0:	49 89 c5             	mov    r13,rax
  8feea3:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8feea6:	48 85 c0             	test   rax,rax
  8feea9:	75 f5                	jne    0x8feea0
  8feeab:	66 41 83 7f 30 00    	cmp    WORD PTR [r15+0x30],0x0
  8feeb1:	75 cd                	jne    0x8fee80
  8feeb3:	66 41 83 7f 32 00    	cmp    WORD PTR [r15+0x32],0x0
  8feeb9:	75 c5                	jne    0x8fee80
  8feebb:	66 41 83 7f 34 00    	cmp    WORD PTR [r15+0x34],0x0
  8feec1:	75 bd                	jne    0x8fee80
  8feec3:	66 41 83 7f 36 00    	cmp    WORD PTR [r15+0x36],0x0
  8feec9:	75 b5                	jne    0x8fee80
  8feecb:	41 80 7f 38 00       	cmp    BYTE PTR [r15+0x38],0x0
  8feed0:	75 ae                	jne    0x8fee80
  8feed2:	48 89 df             	mov    rdi,rbx
  8feed5:	4c 89 fe             	mov    rsi,r15
  8feed8:	e8 73 e9 ff ff       	call   0x8fd850
  8feedd:	4c 89 ff             	mov    rdi,r15
  8feee0:	4c 89 f6             	mov    rsi,r14
  8feee3:	e8 08 9f 30 00       	call   0xc08df0
  8feee8:	48 8b 85 70 ff ff ff 	mov    rax,QWORD PTR [rbp-0x90]
  8feeef:	48 ff 48 58          	dec    QWORD PTR [rax+0x58]
  8feef3:	eb 8b                	jmp    0x8fee80
  8feef5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  8feefc:	00 00 00 00 
  8fef00:	4d 8b 6f 10          	mov    r13,QWORD PTR [r15+0x10]
  8fef04:	4d 85 ed             	test   r13,r13
  8fef07:	74 06                	je     0x8fef0f
  8fef09:	4d 3b 7d 00          	cmp    r15,QWORD PTR [r13+0x0]
  8fef0d:	74 9c                	je     0x8feeab
  8fef0f:	4c 89 f8             	mov    rax,r15
  8fef12:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8fef19:	1f 84 00 00 00 00 00 
  8fef20:	4c 8b 68 10          	mov    r13,QWORD PTR [rax+0x10]
  8fef24:	4d 85 ed             	test   r13,r13
  8fef27:	74 0e                	je     0x8fef37
  8fef29:	49 3b 45 08          	cmp    rax,QWORD PTR [r13+0x8]
  8fef2d:	4c 89 e8             	mov    rax,r13
  8fef30:	74 ee                	je     0x8fef20
  8fef32:	e9 74 ff ff ff       	jmp    0x8feeab
  8fef37:	45 31 ed             	xor    r13d,r13d
  8fef3a:	e9 6c ff ff ff       	jmp    0x8feeab
  8fef3f:	48 8d 05 ca d3 01 03 	lea    rax,[rip+0x301d3ca]        # 0x391c310
  8fef46:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8fef49:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  8fef4d:	0f 85 4f 01 00 00    	jne    0x8ff0a2
  8fef53:	44 89 e0             	mov    eax,r12d
  8fef56:	48 83 c4 78          	add    rsp,0x78
  8fef5a:	5b                   	pop    rbx
  8fef5b:	41 5c                	pop    r12
  8fef5d:	41 5d                	pop    r13
  8fef5f:	41 5e                	pop    r14
  8fef61:	41 5f                	pop    r15
  8fef63:	5d                   	pop    rbp
  8fef64:	c3                   	ret
  8fef65:	41 bc 1c 00 00 00    	mov    r12d,0x1c
  8fef6b:	eb 06                	jmp    0x8fef73
  8fef6d:	41 bc 0c 00 00 00    	mov    r12d,0xc
  8fef73:	8b 45 88             	mov    eax,DWORD PTR [rbp-0x78]
  8fef76:	ff c0                	inc    eax
  8fef78:	4d 85 ff             	test   r15,r15
  8fef7b:	0f 84 a9 fe ff ff    	je     0x8fee2a
  8fef81:	89 45 88             	mov    DWORD PTR [rbp-0x78],eax
  8fef84:	eb 13                	jmp    0x8fef99
  8fef86:	66 ff 4b 36          	dec    WORD PTR [rbx+0x36]
  8fef8a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  8fef90:	4d 85 ff             	test   r15,r15
  8fef93:	0f 84 8e fe ff ff    	je     0x8fee27
  8fef99:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8fef9c:	4d 89 fe             	mov    r14,r15
  8fef9f:	48 85 c0             	test   rax,rax
  8fefa2:	0f 84 98 00 00 00    	je     0x8ff040
  8fefa8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  8fefaf:	00 
  8fefb0:	49 89 c7             	mov    r15,rax
  8fefb3:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  8fefb7:	48 85 c0             	test   rax,rax
  8fefba:	75 f4                	jne    0x8fefb0
  8fefbc:	41 0f b6 46 30       	movzx  eax,BYTE PTR [r14+0x30]
  8fefc1:	41 3a 46 31          	cmp    al,BYTE PTR [r14+0x31]
  8fefc5:	74 c9                	je     0x8fef90
  8fefc7:	49 8b 4e 28          	mov    rcx,QWORD PTR [r14+0x28]
  8fefcb:	49 8b 46 20          	mov    rax,QWORD PTR [r14+0x20]
  8fefcf:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
  8fefd3:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  8fefd7:	48 8b 4d 80          	mov    rcx,QWORD PTR [rbp-0x80]
  8fefdb:	48 89 02             	mov    QWORD PTR [rdx],rax
  8fefde:	48 8b 19             	mov    rbx,QWORD PTR [rcx]
  8fefe1:	48 85 db             	test   rbx,rbx
  8fefe4:	74 aa                	je     0x8fef90
  8fefe6:	4d 8d 6e 20          	lea    r13,[r14+0x20]
  8fefea:	eb 10                	jmp    0x8feffc
  8fefec:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  8feff0:	48 83 c3 08          	add    rbx,0x8
  8feff4:	48 8b 1b             	mov    rbx,QWORD PTR [rbx]
  8feff7:	48 85 db             	test   rbx,rbx
  8feffa:	74 94                	je     0x8fef90
  8feffc:	48 8d 73 20          	lea    rsi,[rbx+0x20]
  8ff000:	ba 10 00 00 00       	mov    edx,0x10
  8ff005:	48 8d 7d b0          	lea    rdi,[rbp-0x50]
  8ff009:	e8 c2 ab a3 ff       	call   0x339bd0
  8ff00e:	85 c0                	test   eax,eax
  8ff010:	78 e2                	js     0x8feff4
  8ff012:	75 dc                	jne    0x8feff0
  8ff014:	48 8d 7d 90          	lea    rdi,[rbp-0x70]
  8ff018:	4c 89 ee             	mov    rsi,r13
  8ff01b:	e8 70 6f 18 00       	call   0xa85f90
  8ff020:	41 0f b6 46 30       	movzx  eax,BYTE PTR [r14+0x30]
  8ff025:	83 f8 01             	cmp    eax,0x1
  8ff028:	74 54                	je     0x8ff07e
  8ff02a:	83 f8 02             	cmp    eax,0x2
  8ff02d:	75 53                	jne    0x8ff082
  8ff02f:	66 ff 43 34          	inc    WORD PTR [rbx+0x34]
  8ff033:	eb 4d                	jmp    0x8ff082
  8ff035:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  8ff03c:	00 00 00 00 
  8ff040:	4d 8b 7e 10          	mov    r15,QWORD PTR [r14+0x10]
  8ff044:	4d 85 ff             	test   r15,r15
  8ff047:	74 0a                	je     0x8ff053
  8ff049:	4d 3b 77 08          	cmp    r14,QWORD PTR [r15+0x8]
  8ff04d:	0f 84 69 ff ff ff    	je     0x8fefbc
  8ff053:	4c 89 f0             	mov    rax,r14
  8ff056:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  8ff05d:	00 00 00 
  8ff060:	4c 8b 78 10          	mov    r15,QWORD PTR [rax+0x10]
  8ff064:	4d 85 ff             	test   r15,r15
  8ff067:	74 0d                	je     0x8ff076
  8ff069:	49 3b 07             	cmp    rax,QWORD PTR [r15]
  8ff06c:	4c 89 f8             	mov    rax,r15
  8ff06f:	74 ef                	je     0x8ff060
  8ff071:	e9 46 ff ff ff       	jmp    0x8fefbc
  8ff076:	45 31 ff             	xor    r15d,r15d
  8ff079:	e9 3e ff ff ff       	jmp    0x8fefbc
  8ff07e:	66 ff 43 36          	inc    WORD PTR [rbx+0x36]
  8ff082:	41 0f b6 46 31       	movzx  eax,BYTE PTR [r14+0x31]
  8ff087:	83 f8 01             	cmp    eax,0x1
  8ff08a:	0f 84 f6 fe ff ff    	je     0x8fef86
  8ff090:	83 f8 02             	cmp    eax,0x2
  8ff093:	0f 85 f7 fe ff ff    	jne    0x8fef90
  8ff099:	66 ff 4b 34          	dec    WORD PTR [rbx+0x34]
  8ff09d:	e9 ee fe ff ff       	jmp    0x8fef90
  8ff0a2:	e8 09 e6 df ff       	call   0x6fd6b0
  8ff0a7:	0f 0b                	ud2
  8ff0a9:	90                   	nop
  8ff0aa:	90                   	nop
  8ff0ab:	90                   	nop
  8ff0ac:	90                   	nop
  8ff0ad:	90                   	nop
  8ff0ae:	90                   	nop
  8ff0af:	90                   	nop
  8ff0b0:	55                   	push   rbp
  8ff0b1:	48 89 e5             	mov    rbp,rsp
  8ff0b4:	41 57                	push   r15
  8ff0b6:	41 56                	push   r14
  8ff0b8:	53                   	push   rbx
  8ff0b9:	48 83 ec 28          	sub    rsp,0x28
  8ff0bd:	4c 8d 3d 4c d2 01 03 	lea    r15,[rip+0x301d24c]        # 0x391c310
  8ff0c4:	48 89 fb             	mov    rbx,rdi
  8ff0c7:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8ff0ca:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  8ff0ce:	48 85 f6             	test   rsi,rsi
  8ff0d1:	75 22                	jne    0x8ff0f5
  8ff0d3:	4c 8d 75 c8          	lea    r14,[rbp-0x38]
  8ff0d7:	be 18 00 00 00       	mov    esi,0x18
  8ff0dc:	4c 89 f7             	mov    rdi,r14
  8ff0df:	e8 0c 9f 95 ff       	call   0x258ff0
  8ff0e4:	4c 89 f6             	mov    rsi,r14
  8ff0e7:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
  8ff0ee:	00 
  8ff0ef:	66 c7 45 d8 02 00    	mov    WORD PTR [rbp-0x28],0x2
  8ff0f5:	48 89 df             	mov    rdi,rbx
  8ff0f8:	e8 23 f9 ff ff       	call   0x8fea20
  8ff0fd:	48 89 df             	mov    rdi,rbx
  8ff100:	31 f6                	xor    esi,esi
  8ff102:	e8 49 65 da ff       	call   0x6a5650
  8ff107:	48 89 df             	mov    rdi,rbx
  8ff10a:	e8 91 ee ff ff       	call   0x8fdfa0
  8ff10f:	49 8b 07             	mov    rax,QWORD PTR [r15]
  8ff112:	48 3b 45 e0          	cmp    rax,QWORD PTR [rbp-0x20]
  8ff116:	75 0b                	jne    0x8ff123
  8ff118:	48 83 c4 28          	add    rsp,0x28
  8ff11c:	5b                   	pop    rbx
  8ff11d:	41 5e                	pop    r14
  8ff11f:	41 5f                	pop    r15
  8ff121:	5d                   	pop    rbp
  8ff122:	c3                   	ret
  8ff123:	e8 88 e5 df ff       	call   0x6fd6b0
  8ff128:	0f 0b                	ud2
  8ff12a:	90                   	nop
  8ff12b:	90                   	nop
  8ff12c:	90                   	nop
  8ff12d:	90                   	nop
  8ff12e:	90                   	nop
  8ff12f:	90                   	nop
  8ff130:	55                   	push   rbp
  8ff131:	48 89 e5             	mov    rbp,rsp
  8ff134:	41 57                	push   r15
  8ff136:	41 56                	push   r14
  8ff138:	41 55                	push   r13
  8ff13a:	41 54                	push   r12
  8ff13c:	53                   	push   rbx
  8ff13d:	48 83 ec 38          	sub    rsp,0x38
  8ff141:	48 8d 05 c8 d1 01 03 	lea    rax,[rip+0x301d1c8]        # 0x391c310
  8ff148:	48 89 fb             	mov    rbx,rdi
  8ff14b:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8ff14e:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  8ff152:	0f b7 47 0a          	movzx  eax,WORD PTR [rdi+0xa]
  8ff156:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
  8ff15a:	48 85 c0             	test   rax,rax
  8ff15d:	0f 84 2d 02 00 00    	je     0x8ff390
  8ff163:	4c 8d 25 56 ff c4 01 	lea    r12,[rip+0x1c4ff56]        # 0x254f0c0
  8ff16a:	45 31 f6             	xor    r14d,r14d
  8ff16d:	48 89 5d b0          	mov    QWORD PTR [rbp-0x50],rbx
  8ff171:	e9 7f 00 00 00       	jmp    0x8ff1f5
  8ff176:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  8ff17d:	00 00 00 
  8ff180:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  8ff184:	48 8d 3d b5 ce 25 03 	lea    rdi,[rip+0x325ceb5]        # 0x3b5c040
  8ff18b:	31 f6                	xor    esi,esi
  8ff18d:	31 d2                	xor    edx,edx
  8ff18f:	31 c9                	xor    ecx,ecx
  8ff191:	4e 8b 3c f0          	mov    r15,QWORD PTR [rax+r14*8]
  8ff195:	e8 66 78 bc ff       	call   0x4c6a00
  8ff19a:	4c 8d 6d b8          	lea    r13,[rbp-0x48]
  8ff19e:	be 18 00 00 00       	mov    esi,0x18
  8ff1a3:	4c 89 ef             	mov    rdi,r13
  8ff1a6:	e8 45 9e 95 ff       	call   0x258ff0
  8ff1ab:	4c 89 ff             	mov    rdi,r15
  8ff1ae:	4c 89 ee             	mov    rsi,r13
  8ff1b1:	48 c7 45 b8 00 00 00 	mov    QWORD PTR [rbp-0x48],0x0
  8ff1b8:	00 
  8ff1b9:	66 c7 45 c8 02 00    	mov    WORD PTR [rbp-0x38],0x2
  8ff1bf:	e8 5c f8 ff ff       	call   0x8fea20
  8ff1c4:	4c 89 ff             	mov    rdi,r15
  8ff1c7:	31 f6                	xor    esi,esi
  8ff1c9:	e8 82 64 da ff       	call   0x6a5650
  8ff1ce:	4c 89 ff             	mov    rdi,r15
  8ff1d1:	e8 ca ed ff ff       	call   0x8fdfa0
  8ff1d6:	48 8d 3d 63 ce 25 03 	lea    rdi,[rip+0x325ce63]        # 0x3b5c040
  8ff1dd:	31 f6                	xor    esi,esi
  8ff1df:	31 d2                	xor    edx,edx
  8ff1e1:	31 c9                	xor    ecx,ecx
  8ff1e3:	e8 b8 7d bc ff       	call   0x4c6fa0
  8ff1e8:	49 ff c6             	inc    r14
  8ff1eb:	4c 3b 75 a8          	cmp    r14,QWORD PTR [rbp-0x58]
  8ff1ef:	0f 84 9b 01 00 00    	je     0x8ff390
  8ff1f5:	48 8b 43 18          	mov    rax,QWORD PTR [rbx+0x18]
  8ff1f9:	4f 8d 2c 76          	lea    r13,[r14+r14*2]
  8ff1fd:	48 85 c0             	test   rax,rax
  8ff200:	0f 94 c1             	sete   cl
  8ff203:	49 c1 e5 03          	shl    r13,0x3
  8ff207:	49 01 c5             	add    r13,rax
  8ff20a:	0f 94 c0             	sete   al
  8ff20d:	08 c8                	or     al,cl
  8ff20f:	0f 85 6b ff ff ff    	jne    0x8ff180
  8ff215:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  8ff219:	48 85 c9             	test   rcx,rcx
  8ff21c:	74 72                	je     0x8ff290
  8ff21e:	66 90                	xchg   ax,ax
  8ff220:	48 89 c8             	mov    rax,rcx
  8ff223:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  8ff226:	48 85 c9             	test   rcx,rcx
  8ff229:	75 f5                	jne    0x8ff220
  8ff22b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  8ff230:	c6 40 31 00          	mov    BYTE PTR [rax+0x31],0x0
  8ff234:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
  8ff238:	48 85 d2             	test   rdx,rdx
  8ff23b:	74 13                	je     0x8ff250
  8ff23d:	0f 1f 00             	nop    DWORD PTR [rax]
  8ff240:	48 89 d0             	mov    rax,rdx
  8ff243:	48 8b 12             	mov    rdx,QWORD PTR [rdx]
  8ff246:	48 85 d2             	test   rdx,rdx
  8ff249:	75 f5                	jne    0x8ff240
  8ff24b:	eb e3                	jmp    0x8ff230
  8ff24d:	0f 1f 00             	nop    DWORD PTR [rax]
  8ff250:	48 89 c1             	mov    rcx,rax
  8ff253:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
  8ff257:	48 85 c0             	test   rax,rax
  8ff25a:	74 14                	je     0x8ff270
  8ff25c:	48 3b 08             	cmp    rcx,QWORD PTR [rax]
  8ff25f:	74 cf                	je     0x8ff230
  8ff261:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8ff268:	0f 1f 84 00 00 00 00 
  8ff26f:	00 
  8ff270:	48 8b 41 10          	mov    rax,QWORD PTR [rcx+0x10]
  8ff274:	48 85 c0             	test   rax,rax
  8ff277:	74 17                	je     0x8ff290
  8ff279:	48 3b 48 08          	cmp    rcx,QWORD PTR [rax+0x8]
  8ff27d:	48 89 c1             	mov    rcx,rax
  8ff280:	74 ee                	je     0x8ff270
  8ff282:	eb ac                	jmp    0x8ff230
  8ff284:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8ff28b:	00 00 00 00 00 
  8ff290:	41 c6 45 11 01       	mov    BYTE PTR [r13+0x11],0x1
  8ff295:	31 f6                	xor    esi,esi
  8ff297:	31 d2                	xor    edx,edx
  8ff299:	31 c9                	xor    ecx,ecx
  8ff29b:	48 8b 43 10          	mov    rax,QWORD PTR [rbx+0x10]
  8ff29f:	48 8d 1d 9a cd 25 03 	lea    rbx,[rip+0x325cd9a]        # 0x3b5c040
  8ff2a6:	48 89 df             	mov    rdi,rbx
  8ff2a9:	4e 8b 3c f0          	mov    r15,QWORD PTR [rax+r14*8]
  8ff2ad:	e8 4e 77 bc ff       	call   0x4c6a00
  8ff2b2:	4c 89 ff             	mov    rdi,r15
  8ff2b5:	4c 89 ee             	mov    rsi,r13
  8ff2b8:	e8 63 f7 ff ff       	call   0x8fea20
  8ff2bd:	4c 89 ff             	mov    rdi,r15
  8ff2c0:	31 f6                	xor    esi,esi
  8ff2c2:	e8 89 63 da ff       	call   0x6a5650
  8ff2c7:	4c 89 ff             	mov    rdi,r15
  8ff2ca:	e8 d1 ec ff ff       	call   0x8fdfa0
  8ff2cf:	48 89 df             	mov    rdi,rbx
  8ff2d2:	31 f6                	xor    esi,esi
  8ff2d4:	31 d2                	xor    edx,edx
  8ff2d6:	31 c9                	xor    ecx,ecx
  8ff2d8:	e8 c3 7c bc ff       	call   0x4c6fa0
  8ff2dd:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  8ff2e1:	48 85 c0             	test   rax,rax
  8ff2e4:	0f 84 96 00 00 00    	je     0x8ff380
  8ff2ea:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  8ff2f0:	48 89 c3             	mov    rbx,rax
  8ff2f3:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8ff2f6:	48 85 c0             	test   rax,rax
  8ff2f9:	75 f5                	jne    0x8ff2f0
  8ff2fb:	eb 25                	jmp    0x8ff322
  8ff2fd:	45 31 ff             	xor    r15d,r15d
  8ff300:	4c 89 ef             	mov    rdi,r13
  8ff303:	48 89 de             	mov    rsi,rbx
  8ff306:	e8 45 e5 ff ff       	call   0x8fd850
  8ff30b:	48 89 df             	mov    rdi,rbx
  8ff30e:	4c 89 e6             	mov    rsi,r12
  8ff311:	e8 da 9a 30 00       	call   0xc08df0
  8ff316:	49 ff 4d 08          	dec    QWORD PTR [r13+0x8]
  8ff31a:	4c 89 fb             	mov    rbx,r15
  8ff31d:	4d 85 ff             	test   r15,r15
  8ff320:	74 5e                	je     0x8ff380
  8ff322:	48 8b 43 08          	mov    rax,QWORD PTR [rbx+0x8]
  8ff326:	48 85 c0             	test   rax,rax
  8ff329:	74 15                	je     0x8ff340
  8ff32b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  8ff330:	49 89 c7             	mov    r15,rax
  8ff333:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8ff336:	48 85 c0             	test   rax,rax
  8ff339:	75 f5                	jne    0x8ff330
  8ff33b:	eb c3                	jmp    0x8ff300
  8ff33d:	0f 1f 00             	nop    DWORD PTR [rax]
  8ff340:	4c 8b 7b 10          	mov    r15,QWORD PTR [rbx+0x10]
  8ff344:	4d 85 ff             	test   r15,r15
  8ff347:	74 05                	je     0x8ff34e
  8ff349:	49 3b 1f             	cmp    rbx,QWORD PTR [r15]
  8ff34c:	74 b2                	je     0x8ff300
  8ff34e:	48 89 d8             	mov    rax,rbx
  8ff351:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8ff358:	0f 1f 84 00 00 00 00 
  8ff35f:	00 
  8ff360:	4c 8b 78 10          	mov    r15,QWORD PTR [rax+0x10]
  8ff364:	4d 85 ff             	test   r15,r15
  8ff367:	74 94                	je     0x8ff2fd
  8ff369:	49 3b 47 08          	cmp    rax,QWORD PTR [r15+0x8]
  8ff36d:	4c 89 f8             	mov    rax,r15
  8ff370:	74 ee                	je     0x8ff360
  8ff372:	eb 8c                	jmp    0x8ff300
  8ff374:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  8ff37b:	00 00 00 00 00 
  8ff380:	48 8b 5d b0          	mov    rbx,QWORD PTR [rbp-0x50]
  8ff384:	66 41 c7 45 10 00 00 	mov    WORD PTR [r13+0x10],0x0
  8ff38b:	e9 58 fe ff ff       	jmp    0x8ff1e8
  8ff390:	48 8b 7b 18          	mov    rdi,QWORD PTR [rbx+0x18]
  8ff394:	48 85 ff             	test   rdi,rdi
  8ff397:	74 0c                	je     0x8ff3a5
  8ff399:	48 8d 35 20 fd c4 01 	lea    rsi,[rip+0x1c4fd20]        # 0x254f0c0
  8ff3a0:	e8 4b 9a 30 00       	call   0xc08df0
  8ff3a5:	48 8b 7b 10          	mov    rdi,QWORD PTR [rbx+0x10]
  8ff3a9:	4c 8d 35 30 fd c4 01 	lea    r14,[rip+0x1c4fd30]        # 0x254f0e0
  8ff3b0:	4c 89 f6             	mov    rsi,r14
  8ff3b3:	e8 38 9a 30 00       	call   0xc08df0
  8ff3b8:	48 8d 05 51 cf 01 03 	lea    rax,[rip+0x301cf51]        # 0x391c310
  8ff3bf:	48 8b 00             	mov    rax,QWORD PTR [rax]
  8ff3c2:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  8ff3c6:	75 19                	jne    0x8ff3e1
  8ff3c8:	48 89 df             	mov    rdi,rbx
  8ff3cb:	4c 89 f6             	mov    rsi,r14
  8ff3ce:	48 83 c4 38          	add    rsp,0x38
  8ff3d2:	5b                   	pop    rbx
  8ff3d3:	41 5c                	pop    r12
  8ff3d5:	41 5d                	pop    r13
  8ff3d7:	41 5e                	pop    r14
  8ff3d9:	41 5f                	pop    r15
  8ff3db:	5d                   	pop    rbp
  8ff3dc:	e9 0f 9a 30 00       	jmp    0xc08df0
  8ff3e1:	e8 ca e2 df ff       	call   0x6fd6b0
  8ff3e6:	0f 0b                	ud2
  8ff3e8:	90                   	nop
  8ff3e9:	90                   	nop
  8ff3ea:	90                   	nop
  8ff3eb:	90                   	nop
  8ff3ec:	90                   	nop
  8ff3ed:	90                   	nop
  8ff3ee:	90                   	nop
  8ff3ef:	90                   	nop
  8ff3f0:	48 8b 0f             	mov    rcx,QWORD PTR [rdi]
  8ff3f3:	48 85 c9             	test   rcx,rcx
  8ff3f6:	74 6d                	je     0x8ff465
  8ff3f8:	55                   	push   rbp
  8ff3f9:	48 89 e5             	mov    rbp,rsp
  8ff3fc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  8ff400:	48 89 c8             	mov    rax,rcx
  8ff403:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  8ff406:	48 85 c9             	test   rcx,rcx
  8ff409:	75 f5                	jne    0x8ff400
  8ff40b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  8ff410:	c6 40 31 00          	mov    BYTE PTR [rax+0x31],0x0
  8ff414:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
  8ff418:	48 85 d2             	test   rdx,rdx
  8ff41b:	74 13                	je     0x8ff430
  8ff41d:	0f 1f 00             	nop    DWORD PTR [rax]
  8ff420:	48 89 d0             	mov    rax,rdx
  8ff423:	48 8b 12             	mov    rdx,QWORD PTR [rdx]
  8ff426:	48 85 d2             	test   rdx,rdx
  8ff429:	75 f5                	jne    0x8ff420
  8ff42b:	eb e3                	jmp    0x8ff410
  8ff42d:	0f 1f 00             	nop    DWORD PTR [rax]
  8ff430:	48 89 c1             	mov    rcx,rax
  8ff433:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
  8ff437:	48 85 c0             	test   rax,rax
  8ff43a:	74 14                	je     0x8ff450
  8ff43c:	48 3b 08             	cmp    rcx,QWORD PTR [rax]
  8ff43f:	74                   	.byte 0x74

; ===== SUPPLEMENTAL GNU objdump linear disassembly: ALL 4096 ORIGINAL BYTES =====
; This section is not REA output. It includes CC padding as decoded INT3.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_663.bin:     file format binary


Disassembly of section .data:

0000000000265720 <.data>:
  265720:	e9 cb aa 14 00       	jmp    0x3b01f0
  265725:	cc                   	int3
  265726:	cc                   	int3
  265727:	cc                   	int3
  265728:	e9 83 b8 14 00       	jmp    0x3b0fb0
  26572d:	cc                   	int3
  26572e:	cc                   	int3
  26572f:	cc                   	int3
  265730:	e9 3b bf 14 00       	jmp    0x3b1670
  265735:	cc                   	int3
  265736:	cc                   	int3
  265737:	cc                   	int3
  265738:	e9 43 bf 14 00       	jmp    0x3b1680
  26573d:	cc                   	int3
  26573e:	cc                   	int3
  26573f:	cc                   	int3
  265740:	e9 1b c9 14 00       	jmp    0x3b2060
  265745:	cc                   	int3
  265746:	cc                   	int3
  265747:	cc                   	int3
  265748:	e9 83 d1 14 00       	jmp    0x3b28d0
  26574d:	cc                   	int3
  26574e:	cc                   	int3
  26574f:	cc                   	int3
  265750:	e9 fb d5 14 00       	jmp    0x3b2d50
  265755:	cc                   	int3
  265756:	cc                   	int3
  265757:	cc                   	int3
  265758:	e9 33 d9 14 00       	jmp    0x3b3090
  26575d:	cc                   	int3
  26575e:	cc                   	int3
  26575f:	cc                   	int3
  265760:	e9 7b c9 2f 00       	jmp    0x5620e0
  265765:	cc                   	int3
  265766:	cc                   	int3
  265767:	cc                   	int3
  265768:	e9 b3 08 15 00       	jmp    0x3b6020
  26576d:	cc                   	int3
  26576e:	cc                   	int3
  26576f:	cc                   	int3
  265770:	e9 cb 0a 15 00       	jmp    0x3b6240
  265775:	cc                   	int3
  265776:	cc                   	int3
  265777:	cc                   	int3
  265778:	e9 93 c6 15 00       	jmp    0x3c1e10
  26577d:	cc                   	int3
  26577e:	cc                   	int3
  26577f:	cc                   	int3
  265780:	e9 bb ca 15 00       	jmp    0x3c2240
  265785:	cc                   	int3
  265786:	cc                   	int3
  265787:	cc                   	int3
  265788:	e9 53 a0 ec ff       	jmp    0x12f7e0
  26578d:	cc                   	int3
  26578e:	cc                   	int3
  26578f:	cc                   	int3
  265790:	e9 bb 89 16 00       	jmp    0x3ce150
  265795:	cc                   	int3
  265796:	cc                   	int3
  265797:	cc                   	int3
  265798:	e9 13 fb 16 00       	jmp    0x3d52b0
  26579d:	cc                   	int3
  26579e:	cc                   	int3
  26579f:	cc                   	int3
  2657a0:	e9 fb 02 18 00       	jmp    0x3e5aa0
  2657a5:	cc                   	int3
  2657a6:	cc                   	int3
  2657a7:	cc                   	int3
  2657a8:	e9 23 03 18 00       	jmp    0x3e5ad0
  2657ad:	cc                   	int3
  2657ae:	cc                   	int3
  2657af:	cc                   	int3
  2657b0:	e9 3b 03 18 00       	jmp    0x3e5af0
  2657b5:	cc                   	int3
  2657b6:	cc                   	int3
  2657b7:	cc                   	int3
  2657b8:	e9 83 6b 18 00       	jmp    0x3ec340
  2657bd:	cc                   	int3
  2657be:	cc                   	int3
  2657bf:	cc                   	int3
  2657c0:	e9 fb ad 18 00       	jmp    0x3f05c0
  2657c5:	cc                   	int3
  2657c6:	cc                   	int3
  2657c7:	cc                   	int3
  2657c8:	e9 43 d0 18 00       	jmp    0x3f2810
  2657cd:	cc                   	int3
  2657ce:	cc                   	int3
  2657cf:	cc                   	int3
  2657d0:	e9 8b d3 18 00       	jmp    0x3f2b60
  2657d5:	cc                   	int3
  2657d6:	cc                   	int3
  2657d7:	cc                   	int3
  2657d8:	e9 43 76 2a 00       	jmp    0x50ce20
  2657dd:	cc                   	int3
  2657de:	cc                   	int3
  2657df:	cc                   	int3
  2657e0:	e9 ab e7 18 00       	jmp    0x3f3f90
  2657e5:	cc                   	int3
  2657e6:	cc                   	int3
  2657e7:	cc                   	int3
  2657e8:	e9 a3 3f 1a 00       	jmp    0x409790
  2657ed:	cc                   	int3
  2657ee:	cc                   	int3
  2657ef:	cc                   	int3
  2657f0:	e9 4b 1a 98 00       	jmp    0xbe7240
  2657f5:	cc                   	int3
  2657f6:	cc                   	int3
  2657f7:	cc                   	int3
  2657f8:	e9 93 bb a4 00       	jmp    0xcb1390
  2657fd:	cc                   	int3
  2657fe:	cc                   	int3
  2657ff:	cc                   	int3
  265800:	e9 fb 67 28 00       	jmp    0x4ec000
  265805:	cc                   	int3
  265806:	cc                   	int3
  265807:	cc                   	int3
  265808:	e9 53 6d 28 00       	jmp    0x4ec560
  26580d:	cc                   	int3
  26580e:	cc                   	int3
  26580f:	cc                   	int3
  265810:	e9 eb 15 69 00       	jmp    0x8f6e00
  265815:	cc                   	int3
  265816:	cc                   	int3
  265817:	cc                   	int3
  265818:	e9 e3 66 4c 00       	jmp    0x72bf00
  26581d:	cc                   	int3
  26581e:	cc                   	int3
  26581f:	cc                   	int3
  265820:	e9 6b 2a 98 00       	jmp    0xbe8290
  265825:	cc                   	int3
  265826:	cc                   	int3
  265827:	cc                   	int3
  265828:	e9 23 2d 69 00       	jmp    0x8f8550
  26582d:	cc                   	int3
  26582e:	cc                   	int3
  26582f:	cc                   	int3
  265830:	e9 eb 12 69 00       	jmp    0x8f6b20
  265835:	cc                   	int3
  265836:	cc                   	int3
  265837:	cc                   	int3
  265838:	e9 03 43 69 00       	jmp    0x8f9b40
  26583d:	cc                   	int3
  26583e:	cc                   	int3
  26583f:	cc                   	int3
  265840:	e9 9b d1 2c 00       	jmp    0x5329e0
  265845:	cc                   	int3
  265846:	cc                   	int3
  265847:	cc                   	int3
  265848:	e9 93 c9 2c 00       	jmp    0x5321e0
  26584d:	cc                   	int3
  26584e:	cc                   	int3
  26584f:	cc                   	int3
  265850:	e9 7b d0 2c 00       	jmp    0x5328d0
  265855:	cc                   	int3
  265856:	cc                   	int3
  265857:	cc                   	int3
  265858:	e9 23 b8 2c 00       	jmp    0x531080
  26585d:	cc                   	int3
  26585e:	cc                   	int3
  26585f:	cc                   	int3
  265860:	e9 ab da 2c 00       	jmp    0x533310
  265865:	cc                   	int3
  265866:	cc                   	int3
  265867:	cc                   	int3
  265868:	e9 c3 d7 2c 00       	jmp    0x533030
  26586d:	cc                   	int3
  26586e:	cc                   	int3
  26586f:	cc                   	int3
  265870:	e9 6b 33 69 00       	jmp    0x8f8be0
  265875:	cc                   	int3
  265876:	cc                   	int3
  265877:	cc                   	int3
  265878:	e9 33 3d 69 00       	jmp    0x8f95b0
  26587d:	cc                   	int3
  26587e:	cc                   	int3
  26587f:	cc                   	int3
  265880:	e9 db 3e 69 00       	jmp    0x8f9760
  265885:	cc                   	int3
  265886:	cc                   	int3
  265887:	cc                   	int3
  265888:	e9 93 04 69 00       	jmp    0x8f5d20
  26588d:	cc                   	int3
  26588e:	cc                   	int3
  26588f:	cc                   	int3
  265890:	e9 1b 9d 2f 00       	jmp    0x55f5b0
  265895:	cc                   	int3
  265896:	cc                   	int3
  265897:	cc                   	int3
  265898:	e9 e3 44 4c 00       	jmp    0x729d80
  26589d:	cc                   	int3
  26589e:	cc                   	int3
  26589f:	cc                   	int3
  2658a0:	e9 eb d4 59 00       	jmp    0x802d90
  2658a5:	cc                   	int3
  2658a6:	cc                   	int3
  2658a7:	cc                   	int3
  2658a8:	e9 23 8c 1f 00       	jmp    0x45e4d0
  2658ad:	cc                   	int3
  2658ae:	cc                   	int3
  2658af:	cc                   	int3
  2658b0:	e9 4b 9b 2f 00       	jmp    0x55f400
  2658b5:	cc                   	int3
  2658b6:	cc                   	int3
  2658b7:	cc                   	int3
  2658b8:	e9 83 76 28 00       	jmp    0x4ecf40
  2658bd:	cc                   	int3
  2658be:	cc                   	int3
  2658bf:	cc                   	int3
  2658c0:	e9 4b ef 57 00       	jmp    0x7e4810
  2658c5:	cc                   	int3
  2658c6:	cc                   	int3
  2658c7:	cc                   	int3
  2658c8:	e9 c3 6b 69 00       	jmp    0x8fc490
  2658cd:	cc                   	int3
  2658ce:	cc                   	int3
  2658cf:	cc                   	int3
  2658d0:	e9 eb d4 47 00       	jmp    0x6e2dc0
  2658d5:	cc                   	int3
  2658d6:	cc                   	int3
  2658d7:	cc                   	int3
  2658d8:	e9 13 32 85 00       	jmp    0xab8af0
  2658dd:	cc                   	int3
  2658de:	cc                   	int3
  2658df:	cc                   	int3
  2658e0:	e9 cb 32 85 00       	jmp    0xab8bb0
  2658e5:	cc                   	int3
  2658e6:	cc                   	int3
  2658e7:	cc                   	int3
  2658e8:	e9 33 34 85 00       	jmp    0xab8d20
  2658ed:	cc                   	int3
  2658ee:	cc                   	int3
  2658ef:	cc                   	int3
  2658f0:	e9 0b 35 85 00       	jmp    0xab8e00
  2658f5:	cc                   	int3
  2658f6:	cc                   	int3
  2658f7:	cc                   	int3
  2658f8:	e9 c3 35 85 00       	jmp    0xab8ec0
  2658fd:	cc                   	int3
  2658fe:	cc                   	int3
  2658ff:	cc                   	int3
  265900:	e9 bb 73 45 00       	jmp    0x6bccc0
  265905:	cc                   	int3
  265906:	cc                   	int3
  265907:	cc                   	int3
  265908:	e9 13 71 45 00       	jmp    0x6bca20
  26590d:	cc                   	int3
  26590e:	cc                   	int3
  26590f:	cc                   	int3
  265910:	e9 db 40 4c 00       	jmp    0x7299f0
  265915:	cc                   	int3
  265916:	cc                   	int3
  265917:	cc                   	int3
  265918:	e9 23 41 4c 00       	jmp    0x729a40
  26591d:	cc                   	int3
  26591e:	cc                   	int3
  26591f:	cc                   	int3
  265920:	e9 9b 44 4c 00       	jmp    0x729dc0
  265925:	cc                   	int3
  265926:	cc                   	int3
  265927:	cc                   	int3
  265928:	e9 83 8b 28 00       	jmp    0x4ee4b0
  26592d:	cc                   	int3
  26592e:	cc                   	int3
  26592f:	cc                   	int3
  265930:	e9 fb 5a 69 00       	jmp    0x8fb430
  265935:	cc                   	int3
  265936:	cc                   	int3
  265937:	cc                   	int3
  265938:	e9 43 a6 23 00       	jmp    0x49ff80
  26593d:	cc                   	int3
  26593e:	cc                   	int3
  26593f:	cc                   	int3
  265940:	e9 ab 9f 2c 00       	jmp    0x52f8f0
  265945:	cc                   	int3
  265946:	cc                   	int3
  265947:	cc                   	int3
  265948:	e9 13 b9 2c 00       	jmp    0x531260
  26594d:	cc                   	int3
  26594e:	cc                   	int3
  26594f:	cc                   	int3
  265950:	e9 8b a3 2c 00       	jmp    0x52fce0
  265955:	cc                   	int3
  265956:	cc                   	int3
  265957:	cc                   	int3
  265958:	e9 93 a3 23 00       	jmp    0x49fcf0
  26595d:	cc                   	int3
  26595e:	cc                   	int3
  26595f:	cc                   	int3
  265960:	e9 9b a3 2c 00       	jmp    0x52fd00
  265965:	cc                   	int3
  265966:	cc                   	int3
  265967:	cc                   	int3
  265968:	e9 93 a4 2c 00       	jmp    0x52fe00
  26596d:	cc                   	int3
  26596e:	cc                   	int3
  26596f:	cc                   	int3
  265970:	e9 0b ab 2c 00       	jmp    0x530480
  265975:	cc                   	int3
  265976:	cc                   	int3
  265977:	cc                   	int3
  265978:	e9 43 d2 2c 00       	jmp    0x532bc0
  26597d:	cc                   	int3
  26597e:	cc                   	int3
  26597f:	cc                   	int3
  265980:	e9 4b ae 2c 00       	jmp    0x5307d0
  265985:	cc                   	int3
  265986:	cc                   	int3
  265987:	cc                   	int3
  265988:	e9 53 a1 2c 00       	jmp    0x52fae0
  26598d:	cc                   	int3
  26598e:	cc                   	int3
  26598f:	cc                   	int3
  265990:	e9 ab 67 4c 00       	jmp    0x72c140
  265995:	cc                   	int3
  265996:	cc                   	int3
  265997:	cc                   	int3
  265998:	e9 63 6e 45 00       	jmp    0x6bc800
  26599d:	cc                   	int3
  26599e:	cc                   	int3
  26599f:	cc                   	int3
  2659a0:	e9 fb c1 23 00       	jmp    0x4a1ba0
  2659a5:	cc                   	int3
  2659a6:	cc                   	int3
  2659a7:	cc                   	int3
  2659a8:	e9 23 d3 2c 00       	jmp    0x532cd0
  2659ad:	cc                   	int3
  2659ae:	cc                   	int3
  2659af:	cc                   	int3
  2659b0:	e9 0b 69 28 00       	jmp    0x4ec2c0
  2659b5:	cc                   	int3
  2659b6:	cc                   	int3
  2659b7:	cc                   	int3
  2659b8:	e9 23 6f 28 00       	jmp    0x4ec8e0
  2659bd:	cc                   	int3
  2659be:	cc                   	int3
  2659bf:	cc                   	int3
  2659c0:	e9 0b 6f 45 00       	jmp    0x6bc8d0
  2659c5:	cc                   	int3
  2659c6:	cc                   	int3
  2659c7:	cc                   	int3
  2659c8:	e9 73 43 69 00       	jmp    0x8f9d40
  2659cd:	cc                   	int3
  2659ce:	cc                   	int3
  2659cf:	cc                   	int3
  2659d0:	e9 9b a4 2c 00       	jmp    0x52fe70
  2659d5:	cc                   	int3
  2659d6:	cc                   	int3
  2659d7:	cc                   	int3
  2659d8:	e9 73 5a 69 00       	jmp    0x8fb450
  2659dd:	cc                   	int3
  2659de:	cc                   	int3
  2659df:	cc                   	int3
  2659e0:	e9 ab 8b 4c 00       	jmp    0x72e590
  2659e5:	cc                   	int3
  2659e6:	cc                   	int3
  2659e7:	cc                   	int3
  2659e8:	e9 43 c1 2c 00       	jmp    0x531b30
  2659ed:	cc                   	int3
  2659ee:	cc                   	int3
  2659ef:	cc                   	int3
  2659f0:	e9 fb d0 2c 00       	jmp    0x532af0
  2659f5:	cc                   	int3
  2659f6:	cc                   	int3
  2659f7:	cc                   	int3
  2659f8:	e9 23 bd 2c 00       	jmp    0x531720
  2659fd:	cc                   	int3
  2659fe:	cc                   	int3
  2659ff:	cc                   	int3
  265a00:	e9 db 5e 69 00       	jmp    0x8fb8e0
  265a05:	cc                   	int3
  265a06:	cc                   	int3
  265a07:	cc                   	int3
  265a08:	e9 b3 61 69 00       	jmp    0x8fbbc0
  265a0d:	cc                   	int3
  265a0e:	cc                   	int3
  265a0f:	cc                   	int3
  265a10:	e9 fb 48 69 00       	jmp    0x8fa310
  265a15:	cc                   	int3
  265a16:	cc                   	int3
  265a17:	cc                   	int3
  265a18:	e9 13 56 21 00       	jmp    0x47b030
  265a1d:	cc                   	int3
  265a1e:	cc                   	int3
  265a1f:	cc                   	int3
  265a20:	e9 fb 33 69 00       	jmp    0x8f8e20
  265a25:	cc                   	int3
  265a26:	cc                   	int3
  265a27:	cc                   	int3
  265a28:	e9 23 67 4c 00       	jmp    0x72c150
  265a2d:	cc                   	int3
  265a2e:	cc                   	int3
  265a2f:	cc                   	int3
  265a30:	e9 2b 38 69 00       	jmp    0x8f9260
  265a35:	cc                   	int3
  265a36:	cc                   	int3
  265a37:	cc                   	int3
  265a38:	e9 d3 38 69 00       	jmp    0x8f9310
  265a3d:	cc                   	int3
  265a3e:	cc                   	int3
  265a3f:	cc                   	int3
  265a40:	e9 9b 69 4c 00       	jmp    0x72c3e0
  265a45:	cc                   	int3
  265a46:	cc                   	int3
  265a47:	cc                   	int3
  265a48:	e9 93 b9 23 00       	jmp    0x4a13e0
  265a4d:	cc                   	int3
  265a4e:	cc                   	int3
  265a4f:	cc                   	int3
  265a50:	e9 db b1 23 00       	jmp    0x4a0c30
  265a55:	cc                   	int3
  265a56:	cc                   	int3
  265a57:	cc                   	int3
  265a58:	e9 83 61 69 00       	jmp    0x8fbbe0
  265a5d:	cc                   	int3
  265a5e:	cc                   	int3
  265a5f:	cc                   	int3
  265a60:	e9 7b 27 2f 00       	jmp    0x5581e0
  265a65:	cc                   	int3
  265a66:	cc                   	int3
  265a67:	cc                   	int3
  265a68:	e9 e3 39 85 00       	jmp    0xab9450
  265a6d:	cc                   	int3
  265a6e:	cc                   	int3
  265a6f:	cc                   	int3
  265a70:	e9 9b 3c 85 00       	jmp    0xab9710
  265a75:	cc                   	int3
  265a76:	cc                   	int3
  265a77:	cc                   	int3
  265a78:	e9 63 4e 69 00       	jmp    0x8fa8e0
  265a7d:	cc                   	int3
  265a7e:	cc                   	int3
  265a7f:	cc                   	int3
  265a80:	e9 cb 8a 28 00       	jmp    0x4ee550
  265a85:	cc                   	int3
  265a86:	cc                   	int3
  265a87:	cc                   	int3
  265a88:	e9 83 6d 69 00       	jmp    0x8fc810
  265a8d:	cc                   	int3
  265a8e:	cc                   	int3
  265a8f:	cc                   	int3
  265a90:	e9 8b 6d 69 00       	jmp    0x8fc820
  265a95:	cc                   	int3
  265a96:	cc                   	int3
  265a97:	cc                   	int3
  265a98:	e9 d3 5b 45 00       	jmp    0x6bb670
  265a9d:	cc                   	int3
  265a9e:	cc                   	int3
  265a9f:	cc                   	int3
  265aa0:	e9 7b 62 45 00       	jmp    0x6bbd20
  265aa5:	cc                   	int3
  265aa6:	cc                   	int3
  265aa7:	cc                   	int3
  265aa8:	e9 83 65 45 00       	jmp    0x6bc030
  265aad:	cc                   	int3
  265aae:	cc                   	int3
  265aaf:	cc                   	int3
  265ab0:	e9 bb 7a 45 00       	jmp    0x6bd570
  265ab5:	cc                   	int3
  265ab6:	cc                   	int3
  265ab7:	cc                   	int3
  265ab8:	e9 e3 84 45 00       	jmp    0x6bdfa0
  265abd:	cc                   	int3
  265abe:	cc                   	int3
  265abf:	cc                   	int3
  265ac0:	e9 eb 84 45 00       	jmp    0x6bdfb0
  265ac5:	cc                   	int3
  265ac6:	cc                   	int3
  265ac7:	cc                   	int3
  265ac8:	e9 03 87 45 00       	jmp    0x6be1d0
  265acd:	cc                   	int3
  265ace:	cc                   	int3
  265acf:	cc                   	int3
  265ad0:	e9 9b 88 45 00       	jmp    0x6be370
  265ad5:	cc                   	int3
  265ad6:	cc                   	int3
  265ad7:	cc                   	int3
  265ad8:	e9 03 6a 45 00       	jmp    0x6bc4e0
  265add:	cc                   	int3
  265ade:	cc                   	int3
  265adf:	cc                   	int3
  265ae0:	e9 cb bf a4 00       	jmp    0xcb1ab0
  265ae5:	cc                   	int3
  265ae6:	cc                   	int3
  265ae7:	cc                   	int3
  265ae8:	e9 a3 68 69 00       	jmp    0x8fc390
  265aed:	cc                   	int3
  265aee:	cc                   	int3
  265aef:	cc                   	int3
  265af0:	e9 eb 69 28 00       	jmp    0x4ec4e0
  265af5:	cc                   	int3
  265af6:	cc                   	int3
  265af7:	cc                   	int3
  265af8:	e9 73 71 28 00       	jmp    0x4ecc70
  265afd:	cc                   	int3
  265afe:	cc                   	int3
  265aff:	cc                   	int3
  265b00:	e9 5b 8e 91 00       	jmp    0xb7e960
  265b05:	cc                   	int3
  265b06:	cc                   	int3
  265b07:	cc                   	int3
  265b08:	e9 73 3a 85 00       	jmp    0xab9580
  265b0d:	cc                   	int3
  265b0e:	cc                   	int3
  265b0f:	cc                   	int3
  265b10:	e9 7b 3b 85 00       	jmp    0xab9690
  265b15:	cc                   	int3
  265b16:	cc                   	int3
  265b17:	cc                   	int3
  265b18:	e9 43 df 33 00       	jmp    0x5a3a60
  265b1d:	cc                   	int3
  265b1e:	cc                   	int3
  265b1f:	cc                   	int3
  265b20:	e9 2b e0 33 00       	jmp    0x5a3b50
  265b25:	cc                   	int3
  265b26:	cc                   	int3
  265b27:	cc                   	int3
  265b28:	e9 33 e1 33 00       	jmp    0x5a3c60
  265b2d:	cc                   	int3
  265b2e:	cc                   	int3
  265b2f:	cc                   	int3
  265b30:	e9 4b e2 33 00       	jmp    0x5a3d80
  265b35:	cc                   	int3
  265b36:	cc                   	int3
  265b37:	cc                   	int3
  265b38:	e9 33 e3 33 00       	jmp    0x5a3e70
  265b3d:	cc                   	int3
  265b3e:	cc                   	int3
  265b3f:	cc                   	int3
  265b40:	e9 4b e3 33 00       	jmp    0x5a3e90
  265b45:	cc                   	int3
  265b46:	cc                   	int3
  265b47:	cc                   	int3
  265b48:	e9 a3 e3 33 00       	jmp    0x5a3ef0
  265b4d:	cc                   	int3
  265b4e:	cc                   	int3
  265b4f:	cc                   	int3
  265b50:	e9 fb e3 33 00       	jmp    0x5a3f50
  265b55:	cc                   	int3
  265b56:	cc                   	int3
  265b57:	cc                   	int3
  265b58:	e9 63 82 2f 00       	jmp    0x55ddc0
  265b5d:	cc                   	int3
  265b5e:	cc                   	int3
  265b5f:	cc                   	int3
  265b60:	e9 0b 92 2f 00       	jmp    0x55ed70
  265b65:	cc                   	int3
  265b66:	cc                   	int3
  265b67:	cc                   	int3
  265b68:	e9 23 91 2f 00       	jmp    0x55ec90
  265b6d:	cc                   	int3
  265b6e:	cc                   	int3
  265b6f:	cc                   	int3
  265b70:	e9 db 89 2f 00       	jmp    0x55e550
  265b75:	cc                   	int3
  265b76:	cc                   	int3
  265b77:	cc                   	int3
  265b78:	e9 03 8b 2f 00       	jmp    0x55e680
  265b7d:	cc                   	int3
  265b7e:	cc                   	int3
  265b7f:	cc                   	int3
  265b80:	e9 fb 61 85 00       	jmp    0xabbd80
  265b85:	cc                   	int3
  265b86:	cc                   	int3
  265b87:	cc                   	int3
  265b88:	e9 53 e5 5c 00       	jmp    0x8340e0
  265b8d:	cc                   	int3
  265b8e:	cc                   	int3
  265b8f:	cc                   	int3
  265b90:	e9 8b 05 69 00       	jmp    0x8f6120
  265b95:	cc                   	int3
  265b96:	cc                   	int3
  265b97:	cc                   	int3
  265b98:	e9 63 d3 9d 00       	jmp    0xc42f00
  265b9d:	cc                   	int3
  265b9e:	cc                   	int3
  265b9f:	cc                   	int3
  265ba0:	e9 6b d4 9d 00       	jmp    0xc43010
  265ba5:	cc                   	int3
  265ba6:	cc                   	int3
  265ba7:	cc                   	int3
  265ba8:	e9 c3 d5 9d 00       	jmp    0xc43170
  265bad:	cc                   	int3
  265bae:	cc                   	int3
  265baf:	cc                   	int3
  265bb0:	e9 eb d8 9d 00       	jmp    0xc434a0
  265bb5:	cc                   	int3
  265bb6:	cc                   	int3
  265bb7:	cc                   	int3
  265bb8:	e9 a3 cb 9d 00       	jmp    0xc42760
  265bbd:	cc                   	int3
  265bbe:	cc                   	int3
  265bbf:	cc                   	int3
  265bc0:	e9 cb cf 9d 00       	jmp    0xc42b90
  265bc5:	cc                   	int3
  265bc6:	cc                   	int3
  265bc7:	cc                   	int3
  265bc8:	e9 f3 cf 9d 00       	jmp    0xc42bc0
  265bcd:	cc                   	int3
  265bce:	cc                   	int3
  265bcf:	cc                   	int3
  265bd0:	e9 eb d8 9d 00       	jmp    0xc434c0
  265bd5:	cc                   	int3
  265bd6:	cc                   	int3
  265bd7:	cc                   	int3
  265bd8:	e9 43 da 9d 00       	jmp    0xc43620
  265bdd:	cc                   	int3
  265bde:	cc                   	int3
  265bdf:	cc                   	int3
  265be0:	e9 db 74 2f 00       	jmp    0x55d0c0
  265be5:	cc                   	int3
  265be6:	cc                   	int3
  265be7:	cc                   	int3
  265be8:	e9 93 16 7a 00       	jmp    0xa07280
  265bed:	cc                   	int3
  265bee:	cc                   	int3
  265bef:	cc                   	int3
  265bf0:	e9 6b 1c 9d 00       	jmp    0xc37860
  265bf5:	cc                   	int3
  265bf6:	cc                   	int3
  265bf7:	cc                   	int3
  265bf8:	e9 73 1d 9d 00       	jmp    0xc37970
  265bfd:	cc                   	int3
  265bfe:	cc                   	int3
  265bff:	cc                   	int3
  265c00:	e9 1b 1e 9d 00       	jmp    0xc37a20
  265c05:	cc                   	int3
  265c06:	cc                   	int3
  265c07:	cc                   	int3
  265c08:	e9 a3 82 2f 00       	jmp    0x55deb0
  265c0d:	cc                   	int3
  265c0e:	cc                   	int3
  265c0f:	cc                   	int3
  265c10:	e9 db 20 1d 00       	jmp    0x437cf0
  265c15:	cc                   	int3
  265c16:	cc                   	int3
  265c17:	cc                   	int3
  265c18:	e9 d3 27 1d 00       	jmp    0x4383f0
  265c1d:	cc                   	int3
  265c1e:	cc                   	int3
  265c1f:	cc                   	int3
  265c20:	e9 9b 27 1d 00       	jmp    0x4383c0
  265c25:	cc                   	int3
  265c26:	cc                   	int3
  265c27:	cc                   	int3
  265c28:	e9 33 29 1d 00       	jmp    0x438560
  265c2d:	cc                   	int3
  265c2e:	cc                   	int3
  265c2f:	cc                   	int3
  265c30:	e9 bb d7 9d 00       	jmp    0xc433f0
  265c35:	cc                   	int3
  265c36:	cc                   	int3
  265c37:	cc                   	int3
  265c38:	e9 83 2c 1d 00       	jmp    0x4388c0
  265c3d:	cc                   	int3
  265c3e:	cc                   	int3
  265c3f:	cc                   	int3
  265c40:	e9 6b 2e 1d 00       	jmp    0x438ab0
  265c45:	cc                   	int3
  265c46:	cc                   	int3
  265c47:	cc                   	int3
  265c48:	e9 d3 cf 2e 00       	jmp    0x552c20
  265c4d:	cc                   	int3
  265c4e:	cc                   	int3
  265c4f:	cc                   	int3
  265c50:	e9 8b 21 1d 00       	jmp    0x437de0
  265c55:	cc                   	int3
  265c56:	cc                   	int3
  265c57:	cc                   	int3
  265c58:	e9 c3 9f 2f 00       	jmp    0x55fc20
  265c5d:	cc                   	int3
  265c5e:	cc                   	int3
  265c5f:	cc                   	int3
  265c60:	e9 fb 2e 1d 00       	jmp    0x438b60
  265c65:	cc                   	int3
  265c66:	cc                   	int3
  265c67:	cc                   	int3
  265c68:	e9 93 a7 23 00       	jmp    0x4a0400
  265c6d:	cc                   	int3
  265c6e:	cc                   	int3
  265c6f:	cc                   	int3
  265c70:	e9 ab 64 28 00       	jmp    0x4ec120
  265c75:	cc                   	int3
  265c76:	cc                   	int3
  265c77:	cc                   	int3
  265c78:	e9 c3 6a 28 00       	jmp    0x4ec740
  265c7d:	cc                   	int3
  265c7e:	cc                   	int3
  265c7f:	cc                   	int3
  265c80:	e9 3b 27 85 00       	jmp    0xab83c0
  265c85:	cc                   	int3
  265c86:	cc                   	int3
  265c87:	cc                   	int3
  265c88:	e9 23 2e 69 00       	jmp    0x8f8ab0
  265c8d:	cc                   	int3
  265c8e:	cc                   	int3
  265c8f:	cc                   	int3
  265c90:	e9 0b 53 69 00       	jmp    0x8fafa0
  265c95:	cc                   	int3
  265c96:	cc                   	int3
  265c97:	cc                   	int3
  265c98:	e9 83 72 28 00       	jmp    0x4ecf20
  265c9d:	cc                   	int3
  265c9e:	cc                   	int3
  265c9f:	cc                   	int3
  265ca0:	e9 4b 2a 1d 00       	jmp    0x4386f0
  265ca5:	cc                   	int3
  265ca6:	cc                   	int3
  265ca7:	cc                   	int3
  265ca8:	e9 93 7a 5a 00       	jmp    0x80d740
  265cad:	cc                   	int3
  265cae:	cc                   	int3
  265caf:	cc                   	int3
  265cb0:	e9 1b 7f 5a 00       	jmp    0x80dbd0
  265cb5:	cc                   	int3
  265cb6:	cc                   	int3
  265cb7:	cc                   	int3
  265cb8:	e9 73 7b 5d 00       	jmp    0x83d830
  265cbd:	cc                   	int3
  265cbe:	cc                   	int3
  265cbf:	cc                   	int3
  265cc0:	e9 9b 81 5d 00       	jmp    0x83de60
  265cc5:	cc                   	int3
  265cc6:	cc                   	int3
  265cc7:	cc                   	int3
  265cc8:	e9 53 86 5d 00       	jmp    0x83e320
  265ccd:	cc                   	int3
  265cce:	cc                   	int3
  265ccf:	cc                   	int3
  265cd0:	e9 7b 11 69 00       	jmp    0x8f6e50
  265cd5:	cc                   	int3
  265cd6:	cc                   	int3
  265cd7:	cc                   	int3
  265cd8:	e9 d3 53 23 00       	jmp    0x49b0b0
  265cdd:	cc                   	int3
  265cde:	cc                   	int3
  265cdf:	cc                   	int3
  265ce0:	e9 db 76 28 00       	jmp    0x4ed3c0
  265ce5:	cc                   	int3
  265ce6:	cc                   	int3
  265ce7:	cc                   	int3
  265ce8:	e9 53 a3 88 00       	jmp    0xaf0040
  265ced:	cc                   	int3
  265cee:	cc                   	int3
  265cef:	cc                   	int3
  265cf0:	e9 8b fb 49 00       	jmp    0x705880
  265cf5:	cc                   	int3
  265cf6:	cc                   	int3
  265cf7:	cc                   	int3
  265cf8:	e9 63 ff 49 00       	jmp    0x705c60
  265cfd:	cc                   	int3
  265cfe:	cc                   	int3
  265cff:	cc                   	int3
  265d00:	e9 eb 08 29 00       	jmp    0x4f65f0
  265d05:	cc                   	int3
  265d06:	cc                   	int3
  265d07:	cc                   	int3
  265d08:	e9 63 0d 29 00       	jmp    0x4f6a70
  265d0d:	cc                   	int3
  265d0e:	cc                   	int3
  265d0f:	cc                   	int3
  265d10:	e9 6b 9d 94 00       	jmp    0xbafa80
  265d15:	cc                   	int3
  265d16:	cc                   	int3
  265d17:	cc                   	int3
  265d18:	e9 d3 9f 94 00       	jmp    0xbafcf0
  265d1d:	cc                   	int3
  265d1e:	cc                   	int3
  265d1f:	cc                   	int3
  265d20:	e9 0b a6 94 00       	jmp    0xbb0330
  265d25:	cc                   	int3
  265d26:	cc                   	int3
  265d27:	cc                   	int3
  265d28:	e9 63 a7 94 00       	jmp    0xbb0490
  265d2d:	cc                   	int3
  265d2e:	cc                   	int3
  265d2f:	cc                   	int3
  265d30:	e9 1b a1 94 00       	jmp    0xbafe50
  265d35:	cc                   	int3
  265d36:	cc                   	int3
  265d37:	cc                   	int3
  265d38:	e9 f3 a2 94 00       	jmp    0xbb0030
  265d3d:	cc                   	int3
  265d3e:	cc                   	int3
  265d3f:	cc                   	int3
  265d40:	e9 0b a4 94 00       	jmp    0xbb0150
  265d45:	cc                   	int3
  265d46:	cc                   	int3
  265d47:	cc                   	int3
  265d48:	e9 83 a4 94 00       	jmp    0xbb01d0
  265d4d:	cc                   	int3
  265d4e:	cc                   	int3
  265d4f:	cc                   	int3
  265d50:	e9 2b a5 94 00       	jmp    0xbb0280
  265d55:	cc                   	int3
  265d56:	cc                   	int3
  265d57:	cc                   	int3
  265d58:	e9 e3 47 85 00       	jmp    0xaba540
  265d5d:	cc                   	int3
  265d5e:	cc                   	int3
  265d5f:	cc                   	int3
  265d60:	e9 fb 60 85 00       	jmp    0xabbe60
  265d65:	cc                   	int3
  265d66:	cc                   	int3
  265d67:	cc                   	int3
  265d68:	e9 b3 02 9b 00       	jmp    0xc16020
  265d6d:	cc                   	int3
  265d6e:	cc                   	int3
  265d6f:	cc                   	int3
  265d70:	e9 fb 04 9b 00       	jmp    0xc16270
  265d75:	cc                   	int3
  265d76:	cc                   	int3
  265d77:	cc                   	int3
  265d78:	e9 a3 09 9b 00       	jmp    0xc16720
  265d7d:	cc                   	int3
  265d7e:	cc                   	int3
  265d7f:	cc                   	int3
  265d80:	e9 fb 0a 9b 00       	jmp    0xc16880
  265d85:	cc                   	int3
  265d86:	cc                   	int3
  265d87:	cc                   	int3
  265d88:	e9 43 06 9b 00       	jmp    0xc163d0
  265d8d:	cc                   	int3
  265d8e:	cc                   	int3
  265d8f:	cc                   	int3
  265d90:	e9 5b 07 9b 00       	jmp    0xc164f0
  265d95:	cc                   	int3
  265d96:	cc                   	int3
  265d97:	cc                   	int3
  265d98:	e9 33 08 9b 00       	jmp    0xc165d0
  265d9d:	cc                   	int3
  265d9e:	cc                   	int3
  265d9f:	cc                   	int3
  265da0:	e9 bb 08 9b 00       	jmp    0xc16660
  265da5:	cc                   	int3
  265da6:	cc                   	int3
  265da7:	cc                   	int3
  265da8:	e9 93 14 86 00       	jmp    0xac7240
  265dad:	cc                   	int3
  265dae:	cc                   	int3
  265daf:	cc                   	int3
  265db0:	e9 0b 16 86 00       	jmp    0xac73c0
  265db5:	cc                   	int3
  265db6:	cc                   	int3
  265db7:	cc                   	int3
  265db8:	e9 53 67 85 00       	jmp    0xabc510
  265dbd:	cc                   	int3
  265dbe:	cc                   	int3
  265dbf:	cc                   	int3
  265dc0:	e9 9b 00 29 00       	jmp    0x4f5e60
  265dc5:	cc                   	int3
  265dc6:	cc                   	int3
  265dc7:	cc                   	int3
  265dc8:	e9 13 d2 39 00       	jmp    0x602fe0
  265dcd:	cc                   	int3
  265dce:	cc                   	int3
  265dcf:	cc                   	int3
  265dd0:	e9 8b d4 39 00       	jmp    0x603260
  265dd5:	cc                   	int3
  265dd6:	cc                   	int3
  265dd7:	cc                   	int3
  265dd8:	e9 03 d7 39 00       	jmp    0x6034e0
  265ddd:	cc                   	int3
  265dde:	cc                   	int3
  265ddf:	cc                   	int3
  265de0:	e9 2b d9 39 00       	jmp    0x603710
  265de5:	cc                   	int3
  265de6:	cc                   	int3
  265de7:	cc                   	int3
  265de8:	e9 e3 db 39 00       	jmp    0x6039d0
  265ded:	cc                   	int3
  265dee:	cc                   	int3
  265def:	cc                   	int3
  265df0:	e9 5b 4e 85 00       	jmp    0xabac50
  265df5:	cc                   	int3
  265df6:	cc                   	int3
  265df7:	cc                   	int3
  265df8:	e9 13 68 69 00       	jmp    0x8fc610
  265dfd:	cc                   	int3
  265dfe:	cc                   	int3
  265dff:	cc                   	int3
  265e00:	e9 6b bc 27 00       	jmp    0x4e1a70
  265e05:	cc                   	int3
  265e06:	cc                   	int3
  265e07:	cc                   	int3
  265e08:	e9 e3 67 85 00       	jmp    0xabc5f0
  265e0d:	cc                   	int3
  265e0e:	cc                   	int3
  265e0f:	cc                   	int3
  265e10:	e9 cb 09 7d 00       	jmp    0xa367e0
  265e15:	cc                   	int3
  265e16:	cc                   	int3
  265e17:	cc                   	int3
  265e18:	e9 13 a8 a3 00       	jmp    0xca0630
  265e1d:	cc                   	int3
  265e1e:	cc                   	int3
  265e1f:	cc                   	int3
  265e20:	e9 bb 0a 7d 00       	jmp    0xa368e0
  265e25:	cc                   	int3
  265e26:	cc                   	int3
  265e27:	cc                   	int3
  265e28:	e9 93 8e 4c 00       	jmp    0x72ecc0
  265e2d:	cc                   	int3
  265e2e:	cc                   	int3
  265e2f:	cc                   	int3
  265e30:	e9 3b 15 29 00       	jmp    0x4f7370
  265e35:	cc                   	int3
  265e36:	cc                   	int3
  265e37:	cc                   	int3
  265e38:	e9 c3 0c 7d 00       	jmp    0xa36b00
  265e3d:	cc                   	int3
  265e3e:	cc                   	int3
  265e3f:	cc                   	int3
  265e40:	e9 4b 0d 7d 00       	jmp    0xa36b90
  265e45:	cc                   	int3
  265e46:	cc                   	int3
  265e47:	cc                   	int3
  265e48:	e9 c3 68 85 00       	jmp    0xabc710
  265e4d:	cc                   	int3
  265e4e:	cc                   	int3
  265e4f:	cc                   	int3
  265e50:	e9 0b 21 34 00       	jmp    0x5a7f60
  265e55:	cc                   	int3
  265e56:	cc                   	int3
  265e57:	cc                   	int3
  265e58:	e9 63 0d 7d 00       	jmp    0xa36bc0
  265e5d:	cc                   	int3
  265e5e:	cc                   	int3
  265e5f:	cc                   	int3
  265e60:	e9 ab 6b 85 00       	jmp    0xabca10
  265e65:	cc                   	int3
  265e66:	cc                   	int3
  265e67:	cc                   	int3
  265e68:	e9 93 6d 85 00       	jmp    0xabcc00
  265e6d:	cc                   	int3
  265e6e:	cc                   	int3
  265e6f:	cc                   	int3
  265e70:	e9 1b 2e 1d 00       	jmp    0x438c90
  265e75:	cc                   	int3
  265e76:	cc                   	int3
  265e77:	cc                   	int3
  265e78:	e9 f3 c6 66 00       	jmp    0x8d2570
  265e7d:	cc                   	int3
  265e7e:	cc                   	int3
  265e7f:	cc                   	int3
  265e80:	e9 6b 72 85 00       	jmp    0xabd0f0
  265e85:	cc                   	int3
  265e86:	cc                   	int3
  265e87:	cc                   	int3
  265e88:	e9 c3 17 7d 00       	jmp    0xa37650
  265e8d:	cc                   	int3
  265e8e:	cc                   	int3
  265e8f:	cc                   	int3
  265e90:	e9 9b 75 85 00       	jmp    0xabd430
  265e95:	cc                   	int3
  265e96:	cc                   	int3
  265e97:	cc                   	int3
  265e98:	e9 a3 6e 57 00       	jmp    0x7dcd40
  265e9d:	cc                   	int3
  265e9e:	cc                   	int3
  265e9f:	cc                   	int3
  265ea0:	e9 fb c6 66 00       	jmp    0x8d25a0
  265ea5:	cc                   	int3
  265ea6:	cc                   	int3
  265ea7:	cc                   	int3
  265ea8:	e9 43 76 85 00       	jmp    0xabd4f0
  265ead:	cc                   	int3
  265eae:	cc                   	int3
  265eaf:	cc                   	int3
  265eb0:	e9 db dd 39 00       	jmp    0x603c90
  265eb5:	cc                   	int3
  265eb6:	cc                   	int3
  265eb7:	cc                   	int3
  265eb8:	e9 33 ee 39 00       	jmp    0x604cf0
  265ebd:	cc                   	int3
  265ebe:	cc                   	int3
  265ebf:	cc                   	int3
  265ec0:	e9 8b c9 23 00       	jmp    0x4a2850
  265ec5:	cc                   	int3
  265ec6:	cc                   	int3
  265ec7:	cc                   	int3
  265ec8:	e9 73 76 85 00       	jmp    0xabd540
  265ecd:	cc                   	int3
  265ece:	cc                   	int3
  265ecf:	cc                   	int3
  265ed0:	e9 6b 67 6b 00       	jmp    0x91c640
  265ed5:	cc                   	int3
  265ed6:	cc                   	int3
  265ed7:	cc                   	int3
  265ed8:	e9 93 6d 6b 00       	jmp    0x91cc70
  265edd:	cc                   	int3
  265ede:	cc                   	int3
  265edf:	cc                   	int3
  265ee0:	e9 4b 2f 1d 00       	jmp    0x438e30
  265ee5:	cc                   	int3
  265ee6:	cc                   	int3
  265ee7:	cc                   	int3
  265ee8:	e9 83 31 1d 00       	jmp    0x439070
  265eed:	cc                   	int3
  265eee:	cc                   	int3
  265eef:	cc                   	int3
  265ef0:	e9 5b 32 1d 00       	jmp    0x439150
  265ef5:	cc                   	int3
  265ef6:	cc                   	int3
  265ef7:	cc                   	int3
  265ef8:	e9 a3 34 1d 00       	jmp    0x4393a0
  265efd:	cc                   	int3
  265efe:	cc                   	int3
  265eff:	cc                   	int3
  265f00:	e9 cb 85 45 00       	jmp    0x6be4d0
  265f05:	cc                   	int3
  265f06:	cc                   	int3
  265f07:	cc                   	int3
  265f08:	e9 23 7a 85 00       	jmp    0xabd930
  265f0d:	cc                   	int3
  265f0e:	cc                   	int3
  265f0f:	cc                   	int3
  265f10:	e9 ab 86 45 00       	jmp    0x6be5c0
  265f15:	cc                   	int3
  265f16:	cc                   	int3
  265f17:	cc                   	int3
  265f18:	e9 e3 88 45 00       	jmp    0x6be800
  265f1d:	cc                   	int3
  265f1e:	cc                   	int3
  265f1f:	cc                   	int3
  265f20:	e9 eb ae 82 00       	jmp    0xa90e10
  265f25:	cc                   	int3
  265f26:	cc                   	int3
  265f27:	cc                   	int3
  265f28:	e9 b3 ce 23 00       	jmp    0x4a2de0
  265f2d:	cc                   	int3
  265f2e:	cc                   	int3
  265f2f:	cc                   	int3
  265f30:	e9 9b 7b 85 00       	jmp    0xabdad0
  265f35:	cc                   	int3
  265f36:	cc                   	int3
  265f37:	cc                   	int3
  265f38:	e9 23 17 7d 00       	jmp    0xa37660
  265f3d:	cc                   	int3
  265f3e:	cc                   	int3
  265f3f:	cc                   	int3
  265f40:	e9 7b 82 85 00       	jmp    0xabe1c0
  265f45:	cc                   	int3
  265f46:	cc                   	int3
  265f47:	cc                   	int3
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
