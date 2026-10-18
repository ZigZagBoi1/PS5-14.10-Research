; Handler 668: REA6.7.0 / Ghidra12.1.4 static function-aware assembly.
; All addresses are kernel RVAs; runtime VA = 0xffffffff8a9c0000 + RVA.
; Original 4096-byte input SHA256 ab1f0022f2fc7a338f010efc5bb908bc38634819a456ec64af2d2ed326f6e67c.
; Actual target RVA 0x3af8e0; adjacent recovered functions are context.

; ===== REA full original-window trampoline functions and verified padding =====
; COMPLETE ORIGINAL INPUT WINDOW: handler_668.bin, 4096 bytes
; SHA256 ab1f0022f2fc7a338f010efc5bb908bc38634819a456ec64af2d2ed326f6e67c; file offset zero = kernel RVA 0x265708.
; REA 6.7.0 / Ghidra 12.1.4 procedure_assembly disassembled every JMP below.
; Each function range is its five-byte tail-JMP; three CC padding bytes follow.
; INT3 padding is decoded from verified original bytes; GNU full-byte listing is supplied separately.
; Evidence source: byte-identical slice of raw_union.bin; evidence IDs per procedure.

; FUNCTION thunk_265708 [0x265708, 0x26570c] | file +0x0 | ev_b6bdfcb7fa6b476800c032a87f312ce12794bc79da48eebe5d32541e885939e1
thunk_265708:
0x265708: JMP 0x003af8e0
; END FUNCTION thunk_265708
0x26570d: INT3 ; original byte CC, padding
0x26570e: INT3 ; original byte CC, padding
0x26570f: INT3 ; original byte CC, padding

; FUNCTION thunk_265710 [0x265710, 0x265714] | file +0x8 | ev_a7bbccaa887f1dc74dd5a20eceae5368575f08b1d5ecd8282f6df24e299ce536
thunk_265710:
0x265710: JMP 0x003af8f0
; END FUNCTION thunk_265710
0x265715: INT3 ; original byte CC, padding
0x265716: INT3 ; original byte CC, padding
0x265717: INT3 ; original byte CC, padding

; FUNCTION thunk_265718 [0x265718, 0x26571c] | file +0x10 | ev_38789675eca62443741b8e1bab095e841cecf87a00496a78c4bf3372253bc2b2
thunk_265718:
0x265718: JMP 0x003af900
; END FUNCTION thunk_265718
0x26571d: INT3 ; original byte CC, padding
0x26571e: INT3 ; original byte CC, padding
0x26571f: INT3 ; original byte CC, padding

; FUNCTION thunk_265720 [0x265720, 0x265724] | file +0x18 | ev_663b0a68a7b3c2be7c9493c0aead17e89f76910d56519503799ba2ffda9209d0
thunk_265720:
0x265720: JMP 0x003b01f0
; END FUNCTION thunk_265720
0x265725: INT3 ; original byte CC, padding
0x265726: INT3 ; original byte CC, padding
0x265727: INT3 ; original byte CC, padding

; FUNCTION thunk_265728 [0x265728, 0x26572c] | file +0x20 | ev_d69bbc7a859c476d6141155d3b2d923da60bf9e3f5f4355d77f3bcedce013985
thunk_265728:
0x265728: JMP 0x003b0fb0
; END FUNCTION thunk_265728
0x26572d: INT3 ; original byte CC, padding
0x26572e: INT3 ; original byte CC, padding
0x26572f: INT3 ; original byte CC, padding

; FUNCTION thunk_265730 [0x265730, 0x265734] | file +0x28 | ev_cf4a0758f2319cf7845c9debebe9582bfd69286eb3a26b66f296653aa9038eb8
thunk_265730:
0x265730: JMP 0x003b1670
; END FUNCTION thunk_265730
0x265735: INT3 ; original byte CC, padding
0x265736: INT3 ; original byte CC, padding
0x265737: INT3 ; original byte CC, padding

; FUNCTION thunk_265738 [0x265738, 0x26573c] | file +0x30 | ev_92ce22eed051fe8e75b8bc76827733d13e499e4d8d596bf46af0d7d5c1429ef3
thunk_265738:
0x265738: JMP 0x003b1680
; END FUNCTION thunk_265738
0x26573d: INT3 ; original byte CC, padding
0x26573e: INT3 ; original byte CC, padding
0x26573f: INT3 ; original byte CC, padding

; FUNCTION thunk_265740 [0x265740, 0x265744] | file +0x38 | ev_33530924e7685bff9fddd82f68a628a756c5337ce46b62cbd6d38d80f5fa6096
thunk_265740:
0x265740: JMP 0x003b2060
; END FUNCTION thunk_265740
0x265745: INT3 ; original byte CC, padding
0x265746: INT3 ; original byte CC, padding
0x265747: INT3 ; original byte CC, padding

; FUNCTION thunk_265748 [0x265748, 0x26574c] | file +0x40 | ev_de67cf534443a31bebab6a25bf45f5fd82945002817eb37fa40aaff619e6d23a
thunk_265748:
0x265748: JMP 0x003b28d0
; END FUNCTION thunk_265748
0x26574d: INT3 ; original byte CC, padding
0x26574e: INT3 ; original byte CC, padding
0x26574f: INT3 ; original byte CC, padding

; FUNCTION thunk_265750 [0x265750, 0x265754] | file +0x48 | ev_132234fcaf537fa6a42b874d00a2e1aad642c7a28a779da7ebbeaa20c0874aaa
thunk_265750:
0x265750: JMP 0x003b2d50
; END FUNCTION thunk_265750
0x265755: INT3 ; original byte CC, padding
0x265756: INT3 ; original byte CC, padding
0x265757: INT3 ; original byte CC, padding

; FUNCTION thunk_265758 [0x265758, 0x26575c] | file +0x50 | ev_068558a7684bdcceb36c61662c628b8e88ef07ac65492f923014b5c82b93fade
thunk_265758:
0x265758: JMP 0x003b3090
; END FUNCTION thunk_265758
0x26575d: INT3 ; original byte CC, padding
0x26575e: INT3 ; original byte CC, padding
0x26575f: INT3 ; original byte CC, padding

; FUNCTION thunk_265760 [0x265760, 0x265764] | file +0x58 | ev_bd63dc1cd6837db427a1056eb97158fe259206066faca40c28dcf7934f20ba4d
thunk_265760:
0x265760: JMP 0x005620e0
; END FUNCTION thunk_265760
0x265765: INT3 ; original byte CC, padding
0x265766: INT3 ; original byte CC, padding
0x265767: INT3 ; original byte CC, padding

; FUNCTION thunk_265768 [0x265768, 0x26576c] | file +0x60 | ev_1d901a1b7fdb0a3a9f237abaa418c80c2b2fea99395acd4e1fbac26e3445716b
thunk_265768:
0x265768: JMP 0x003b6020
; END FUNCTION thunk_265768
0x26576d: INT3 ; original byte CC, padding
0x26576e: INT3 ; original byte CC, padding
0x26576f: INT3 ; original byte CC, padding

; FUNCTION thunk_265770 [0x265770, 0x265774] | file +0x68 | ev_b6804c0eb21d9151919aae4a42f9c0cfc063fb2f53e6396e6dc77cbac8e2a1ba
thunk_265770:
0x265770: JMP 0x003b6240
; END FUNCTION thunk_265770
0x265775: INT3 ; original byte CC, padding
0x265776: INT3 ; original byte CC, padding
0x265777: INT3 ; original byte CC, padding

; FUNCTION thunk_265778 [0x265778, 0x26577c] | file +0x70 | ev_34f74d2743a15a04b1f71fa6f65bd4bd17e95b886cba7359e78b5faeff6c856d
thunk_265778:
0x265778: JMP 0x003c1e10
; END FUNCTION thunk_265778
0x26577d: INT3 ; original byte CC, padding
0x26577e: INT3 ; original byte CC, padding
0x26577f: INT3 ; original byte CC, padding

; FUNCTION thunk_265780 [0x265780, 0x265784] | file +0x78 | ev_10c0daa579f734a4a7decbb86d19d366ccc650fa23eb00375ad24032a5e6e0b8
thunk_265780:
0x265780: JMP 0x003c2240
; END FUNCTION thunk_265780
0x265785: INT3 ; original byte CC, padding
0x265786: INT3 ; original byte CC, padding
0x265787: INT3 ; original byte CC, padding

; FUNCTION thunk_265788 [0x265788, 0x26578c] | file +0x80 | ev_f3de7310226151c0183fe0d6a12e4162a8775d55c90b0d1ecb962e5e74c27fbf
thunk_265788:
0x265788: JMP 0x0012f7e0
; END FUNCTION thunk_265788
0x26578d: INT3 ; original byte CC, padding
0x26578e: INT3 ; original byte CC, padding
0x26578f: INT3 ; original byte CC, padding

; FUNCTION thunk_265790 [0x265790, 0x265794] | file +0x88 | ev_ce96bb8ef60d99823c5763a8166e15725e79734fa2c841d7a584703f32adc295
thunk_265790:
0x265790: JMP 0x003ce150
; END FUNCTION thunk_265790
0x265795: INT3 ; original byte CC, padding
0x265796: INT3 ; original byte CC, padding
0x265797: INT3 ; original byte CC, padding

; FUNCTION thunk_265798 [0x265798, 0x26579c] | file +0x90 | ev_0f8dc4e185eda329d0f5b8a0e374280c6e3304d1ed60a8d7d32f05850edf66e6
thunk_265798:
0x265798: JMP 0x003d52b0
; END FUNCTION thunk_265798
0x26579d: INT3 ; original byte CC, padding
0x26579e: INT3 ; original byte CC, padding
0x26579f: INT3 ; original byte CC, padding

; FUNCTION thunk_2657a0 [0x2657a0, 0x2657a4] | file +0x98 | ev_e2f761a65fdd84dab59b1b13e22a3b855068bf5d9a5be19d82c77854c4429308
thunk_2657a0:
0x2657a0: JMP 0x003e5aa0
; END FUNCTION thunk_2657a0
0x2657a5: INT3 ; original byte CC, padding
0x2657a6: INT3 ; original byte CC, padding
0x2657a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657a8 [0x2657a8, 0x2657ac] | file +0xa0 | ev_6697810b038fc1b12c4d4c9a9b0dd049ff025f425f50042e871cec4631353f94
thunk_2657a8:
0x2657a8: JMP 0x003e5ad0
; END FUNCTION thunk_2657a8
0x2657ad: INT3 ; original byte CC, padding
0x2657ae: INT3 ; original byte CC, padding
0x2657af: INT3 ; original byte CC, padding

; FUNCTION thunk_2657b0 [0x2657b0, 0x2657b4] | file +0xa8 | ev_ebf7b57120fb86445774a5dca464139125d8f4d01fa8fb9287d3638ebaef2c34
thunk_2657b0:
0x2657b0: JMP 0x003e5af0
; END FUNCTION thunk_2657b0
0x2657b5: INT3 ; original byte CC, padding
0x2657b6: INT3 ; original byte CC, padding
0x2657b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657b8 [0x2657b8, 0x2657bc] | file +0xb0 | ev_f18742952a9bc02a461e135a15fb6ef707ecbaf16ba12b4da18dbdae79073308
thunk_2657b8:
0x2657b8: JMP 0x003ec340
; END FUNCTION thunk_2657b8
0x2657bd: INT3 ; original byte CC, padding
0x2657be: INT3 ; original byte CC, padding
0x2657bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2657c0 [0x2657c0, 0x2657c4] | file +0xb8 | ev_91f732a1a4e63f6a6eb155545811fa0e43b164dacb291025c69d8da804414ace
thunk_2657c0:
0x2657c0: JMP 0x003f05c0
; END FUNCTION thunk_2657c0
0x2657c5: INT3 ; original byte CC, padding
0x2657c6: INT3 ; original byte CC, padding
0x2657c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657c8 [0x2657c8, 0x2657cc] | file +0xc0 | ev_c7b98d7ba8ab37f6d1800ccac069f4d56bde69cdec76707b570744d7e7dc1d69
thunk_2657c8:
0x2657c8: JMP 0x003f2810
; END FUNCTION thunk_2657c8
0x2657cd: INT3 ; original byte CC, padding
0x2657ce: INT3 ; original byte CC, padding
0x2657cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2657d0 [0x2657d0, 0x2657d4] | file +0xc8 | ev_4f51d5c363cf402cd2db4e9f992362fbab4776f0ecbd528c24eb13344bbd3dca
thunk_2657d0:
0x2657d0: JMP 0x003f2b60
; END FUNCTION thunk_2657d0
0x2657d5: INT3 ; original byte CC, padding
0x2657d6: INT3 ; original byte CC, padding
0x2657d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657d8 [0x2657d8, 0x2657dc] | file +0xd0 | ev_1fa68ba64ca0d7c70f430e815cb0b0f22e75fe57ded1c269a505586d5c58f4d2
thunk_2657d8:
0x2657d8: JMP 0x0050ce20
; END FUNCTION thunk_2657d8
0x2657dd: INT3 ; original byte CC, padding
0x2657de: INT3 ; original byte CC, padding
0x2657df: INT3 ; original byte CC, padding

; FUNCTION thunk_2657e0 [0x2657e0, 0x2657e4] | file +0xd8 | ev_cdf4533c696eba4277540c786b459e9ea015d47fce9d5d76f4a652cb6ac58172
thunk_2657e0:
0x2657e0: JMP 0x003f3f90
; END FUNCTION thunk_2657e0
0x2657e5: INT3 ; original byte CC, padding
0x2657e6: INT3 ; original byte CC, padding
0x2657e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657e8 [0x2657e8, 0x2657ec] | file +0xe0 | ev_374afdf2cce64a46acab5a174134a7f968029c9c59d14d6742cd560ce5213f23
thunk_2657e8:
0x2657e8: JMP 0x00409790
; END FUNCTION thunk_2657e8
0x2657ed: INT3 ; original byte CC, padding
0x2657ee: INT3 ; original byte CC, padding
0x2657ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2657f0 [0x2657f0, 0x2657f4] | file +0xe8 | ev_58e9f1700ab212c7bbdd085f1ce9a5bdbaedb7fab614a122c69f2a9c6762e1bd
thunk_2657f0:
0x2657f0: JMP 0x00be7240
; END FUNCTION thunk_2657f0
0x2657f5: INT3 ; original byte CC, padding
0x2657f6: INT3 ; original byte CC, padding
0x2657f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657f8 [0x2657f8, 0x2657fc] | file +0xf0 | ev_f6bc973f7dcabf9e89f903c9e2bf5dbf21259650a2b611915c1164b66fa72741
thunk_2657f8:
0x2657f8: JMP 0x00cb1390
; END FUNCTION thunk_2657f8
0x2657fd: INT3 ; original byte CC, padding
0x2657fe: INT3 ; original byte CC, padding
0x2657ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265800 [0x265800, 0x265804] | file +0xf8 | ev_21b84e85838248825fd2de74126e431447c58868f9b80275e73f098e74c945cf
thunk_265800:
0x265800: JMP 0x004ec000
; END FUNCTION thunk_265800
0x265805: INT3 ; original byte CC, padding
0x265806: INT3 ; original byte CC, padding
0x265807: INT3 ; original byte CC, padding

; FUNCTION thunk_265808 [0x265808, 0x26580c] | file +0x100 | ev_ed36ff2d496580222b1f83b896dfddfaf483e38fce8c3c285a7c9581d5ef186f
thunk_265808:
0x265808: JMP 0x004ec560
; END FUNCTION thunk_265808
0x26580d: INT3 ; original byte CC, padding
0x26580e: INT3 ; original byte CC, padding
0x26580f: INT3 ; original byte CC, padding

; FUNCTION thunk_265810 [0x265810, 0x265814] | file +0x108 | ev_89727ec834a0cfe20eb32510eb9c2eae50ce027f3e6a558042ad62d7e27d8e1b
thunk_265810:
0x265810: JMP 0x008f6e00
; END FUNCTION thunk_265810
0x265815: INT3 ; original byte CC, padding
0x265816: INT3 ; original byte CC, padding
0x265817: INT3 ; original byte CC, padding

; FUNCTION thunk_265818 [0x265818, 0x26581c] | file +0x110 | ev_eefb66ff0c291781258b8a7b7ae899d7e3dcf66c5c651f06811347f6134cff7e
thunk_265818:
0x265818: JMP 0x0072bf00
; END FUNCTION thunk_265818
0x26581d: INT3 ; original byte CC, padding
0x26581e: INT3 ; original byte CC, padding
0x26581f: INT3 ; original byte CC, padding

; FUNCTION thunk_265820 [0x265820, 0x265824] | file +0x118 | ev_b01c8ded1e53f1229648a8fc823292f76ba1e191912f08da40a003017916d032
thunk_265820:
0x265820: JMP 0x00be8290
; END FUNCTION thunk_265820
0x265825: INT3 ; original byte CC, padding
0x265826: INT3 ; original byte CC, padding
0x265827: INT3 ; original byte CC, padding

; FUNCTION thunk_265828 [0x265828, 0x26582c] | file +0x120 | ev_e877aa9a22237e98d7eb06a87171e8dc74a5766852423ce01502627d2dfb95bb
thunk_265828:
0x265828: JMP 0x008f8550
; END FUNCTION thunk_265828
0x26582d: INT3 ; original byte CC, padding
0x26582e: INT3 ; original byte CC, padding
0x26582f: INT3 ; original byte CC, padding

; FUNCTION thunk_265830 [0x265830, 0x265834] | file +0x128 | ev_ba7051f63021a6fd1c6284d1f82b4898b77f53988089d8426c18b784cb611820
thunk_265830:
0x265830: JMP 0x008f6b20
; END FUNCTION thunk_265830
0x265835: INT3 ; original byte CC, padding
0x265836: INT3 ; original byte CC, padding
0x265837: INT3 ; original byte CC, padding

; FUNCTION thunk_265838 [0x265838, 0x26583c] | file +0x130 | ev_29e270b89c7ed4c79f5d94bb4bd94f9805dda1cdee86aa988991baafe5cab9bf
thunk_265838:
0x265838: JMP 0x008f9b40
; END FUNCTION thunk_265838
0x26583d: INT3 ; original byte CC, padding
0x26583e: INT3 ; original byte CC, padding
0x26583f: INT3 ; original byte CC, padding

; FUNCTION thunk_265840 [0x265840, 0x265844] | file +0x138 | ev_2286b3dda1e7e72b42d6a92a0a0aefa2f61011e9c731cefc24e2698890829772
thunk_265840:
0x265840: JMP 0x005329e0
; END FUNCTION thunk_265840
0x265845: INT3 ; original byte CC, padding
0x265846: INT3 ; original byte CC, padding
0x265847: INT3 ; original byte CC, padding

; FUNCTION thunk_265848 [0x265848, 0x26584c] | file +0x140 | ev_01217ef4807cb3458c4e52bd4cc87292cea659508dadb94fb69d13110186d725
thunk_265848:
0x265848: JMP 0x005321e0
; END FUNCTION thunk_265848
0x26584d: INT3 ; original byte CC, padding
0x26584e: INT3 ; original byte CC, padding
0x26584f: INT3 ; original byte CC, padding

; FUNCTION thunk_265850 [0x265850, 0x265854] | file +0x148 | ev_6d5fd951eb8cbb265a712cc176037c10716ffd34adb58ee287e6ce7605307018
thunk_265850:
0x265850: JMP 0x005328d0
; END FUNCTION thunk_265850
0x265855: INT3 ; original byte CC, padding
0x265856: INT3 ; original byte CC, padding
0x265857: INT3 ; original byte CC, padding

; FUNCTION thunk_265858 [0x265858, 0x26585c] | file +0x150 | ev_5090551b84c0f978635bfd1de6823dd5bef2c93d319a2411da7d400cedf97693
thunk_265858:
0x265858: JMP 0x00531080
; END FUNCTION thunk_265858
0x26585d: INT3 ; original byte CC, padding
0x26585e: INT3 ; original byte CC, padding
0x26585f: INT3 ; original byte CC, padding

; FUNCTION thunk_265860 [0x265860, 0x265864] | file +0x158 | ev_01c5c090c8cdb41592a81f1781d3f81583f8dd4d4fe769363a8450c7d1f7a771
thunk_265860:
0x265860: JMP 0x00533310
; END FUNCTION thunk_265860
0x265865: INT3 ; original byte CC, padding
0x265866: INT3 ; original byte CC, padding
0x265867: INT3 ; original byte CC, padding

; FUNCTION thunk_265868 [0x265868, 0x26586c] | file +0x160 | ev_c24a1e048aeb103df20b0435af6b29a74f5df513f9f5c72aaa03666f01eb6fdc
thunk_265868:
0x265868: JMP 0x00533030
; END FUNCTION thunk_265868
0x26586d: INT3 ; original byte CC, padding
0x26586e: INT3 ; original byte CC, padding
0x26586f: INT3 ; original byte CC, padding

; FUNCTION thunk_265870 [0x265870, 0x265874] | file +0x168 | ev_76ba314b67213efa76858206a61bcd4163406a9f26e42af0d8698645842db016
thunk_265870:
0x265870: JMP 0x008f8be0
; END FUNCTION thunk_265870
0x265875: INT3 ; original byte CC, padding
0x265876: INT3 ; original byte CC, padding
0x265877: INT3 ; original byte CC, padding

; FUNCTION thunk_265878 [0x265878, 0x26587c] | file +0x170 | ev_896c34d770fdd0c212052502dd983d487250108abf025f4f05b524748fb80c86
thunk_265878:
0x265878: JMP 0x008f95b0
; END FUNCTION thunk_265878
0x26587d: INT3 ; original byte CC, padding
0x26587e: INT3 ; original byte CC, padding
0x26587f: INT3 ; original byte CC, padding

; FUNCTION thunk_265880 [0x265880, 0x265884] | file +0x178 | ev_f8863d096867a30cdba9addd987914e5d320e078b4aade3ac9e818e1f98319d5
thunk_265880:
0x265880: JMP 0x008f9760
; END FUNCTION thunk_265880
0x265885: INT3 ; original byte CC, padding
0x265886: INT3 ; original byte CC, padding
0x265887: INT3 ; original byte CC, padding

; FUNCTION thunk_265888 [0x265888, 0x26588c] | file +0x180 | ev_85141131e97cdc037a66618a2dab05c4883afdef7550bb962d7c3b1108406661
thunk_265888:
0x265888: JMP 0x008f5d20
; END FUNCTION thunk_265888
0x26588d: INT3 ; original byte CC, padding
0x26588e: INT3 ; original byte CC, padding
0x26588f: INT3 ; original byte CC, padding

; FUNCTION thunk_265890 [0x265890, 0x265894] | file +0x188 | ev_5ede924fc5154e62e37e7bf8c3f811e88e9b2faec58b249284bb80f0fb48025b
thunk_265890:
0x265890: JMP 0x0055f5b0
; END FUNCTION thunk_265890
0x265895: INT3 ; original byte CC, padding
0x265896: INT3 ; original byte CC, padding
0x265897: INT3 ; original byte CC, padding

; FUNCTION thunk_265898 [0x265898, 0x26589c] | file +0x190 | ev_a23d17f391f4d36d97e50a18a5186539d45e2bed5fc87ffe4a0dcc4d6db07939
thunk_265898:
0x265898: JMP 0x00729d80
; END FUNCTION thunk_265898
0x26589d: INT3 ; original byte CC, padding
0x26589e: INT3 ; original byte CC, padding
0x26589f: INT3 ; original byte CC, padding

; FUNCTION thunk_2658a0 [0x2658a0, 0x2658a4] | file +0x198 | ev_b7a1dccb9d6a6d2325e92a7739fa6f321de83fb32cf43179dc7d2b1beed1ac61
thunk_2658a0:
0x2658a0: JMP 0x00802d90
; END FUNCTION thunk_2658a0
0x2658a5: INT3 ; original byte CC, padding
0x2658a6: INT3 ; original byte CC, padding
0x2658a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658a8 [0x2658a8, 0x2658ac] | file +0x1a0 | ev_b19515a52787f810c0fc8a150c253edf5a09f1ecb6685c5ddb19a7fcbd31e7f0
thunk_2658a8:
0x2658a8: JMP 0x0045e4d0
; END FUNCTION thunk_2658a8
0x2658ad: INT3 ; original byte CC, padding
0x2658ae: INT3 ; original byte CC, padding
0x2658af: INT3 ; original byte CC, padding

; FUNCTION thunk_2658b0 [0x2658b0, 0x2658b4] | file +0x1a8 | ev_5b2cef43eb0f5d13ddd9c2fd9b7fa4dd2b081756fab4a5992d820a192c878767
thunk_2658b0:
0x2658b0: JMP 0x0055f400
; END FUNCTION thunk_2658b0
0x2658b5: INT3 ; original byte CC, padding
0x2658b6: INT3 ; original byte CC, padding
0x2658b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658b8 [0x2658b8, 0x2658bc] | file +0x1b0 | ev_17fe6fbebe1335a99ecaeac06f571ba24b9ad7de60e42acf82b9b228106d6104
thunk_2658b8:
0x2658b8: JMP 0x004ecf40
; END FUNCTION thunk_2658b8
0x2658bd: INT3 ; original byte CC, padding
0x2658be: INT3 ; original byte CC, padding
0x2658bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2658c0 [0x2658c0, 0x2658c4] | file +0x1b8 | ev_eee7a1b6ecdce4e0b77d92dfc20a43dc2782e75827d3f98726902e4b96738d77
thunk_2658c0:
0x2658c0: JMP 0x007e4810
; END FUNCTION thunk_2658c0
0x2658c5: INT3 ; original byte CC, padding
0x2658c6: INT3 ; original byte CC, padding
0x2658c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658c8 [0x2658c8, 0x2658cc] | file +0x1c0 | ev_845ed6badef4ae9ef77ba2e779a2375a56564fca34ec6fbcd0911725b268c459
thunk_2658c8:
0x2658c8: JMP 0x008fc490
; END FUNCTION thunk_2658c8
0x2658cd: INT3 ; original byte CC, padding
0x2658ce: INT3 ; original byte CC, padding
0x2658cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2658d0 [0x2658d0, 0x2658d4] | file +0x1c8 | ev_d1b9e0d38d6434e6a73c7cd5580db593062890703035603def4048e5f0f70516
thunk_2658d0:
0x2658d0: JMP 0x006e2dc0
; END FUNCTION thunk_2658d0
0x2658d5: INT3 ; original byte CC, padding
0x2658d6: INT3 ; original byte CC, padding
0x2658d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658d8 [0x2658d8, 0x2658dc] | file +0x1d0 | ev_ef22b085ea6deaa05e80e7ecc0348d6d86c49968e69baffefc4836914656a99f
thunk_2658d8:
0x2658d8: JMP 0x00ab8af0
; END FUNCTION thunk_2658d8
0x2658dd: INT3 ; original byte CC, padding
0x2658de: INT3 ; original byte CC, padding
0x2658df: INT3 ; original byte CC, padding

; FUNCTION thunk_2658e0 [0x2658e0, 0x2658e4] | file +0x1d8 | ev_4f526ca80fe3367a5a614419397741f41bb8b497bda0c49a4d7663d093a8a633
thunk_2658e0:
0x2658e0: JMP 0x00ab8bb0
; END FUNCTION thunk_2658e0
0x2658e5: INT3 ; original byte CC, padding
0x2658e6: INT3 ; original byte CC, padding
0x2658e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658e8 [0x2658e8, 0x2658ec] | file +0x1e0 | ev_6df4f33e4cce4fbceedd1cb5393b063a0eedd64e4998eb6e45e4de8a5ac03640
thunk_2658e8:
0x2658e8: JMP 0x00ab8d20
; END FUNCTION thunk_2658e8
0x2658ed: INT3 ; original byte CC, padding
0x2658ee: INT3 ; original byte CC, padding
0x2658ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2658f0 [0x2658f0, 0x2658f4] | file +0x1e8 | ev_890257df8433a0b7603458bc3bad772ae2bbe8da754402853cc8349d35c35c69
thunk_2658f0:
0x2658f0: JMP 0x00ab8e00
; END FUNCTION thunk_2658f0
0x2658f5: INT3 ; original byte CC, padding
0x2658f6: INT3 ; original byte CC, padding
0x2658f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658f8 [0x2658f8, 0x2658fc] | file +0x1f0 | ev_fccee6840eafe44da8599577bb9231c256a751d24cfad1a211d736e7cc16a240
thunk_2658f8:
0x2658f8: JMP 0x00ab8ec0
; END FUNCTION thunk_2658f8
0x2658fd: INT3 ; original byte CC, padding
0x2658fe: INT3 ; original byte CC, padding
0x2658ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265900 [0x265900, 0x265904] | file +0x1f8 | ev_c4d18df255e8b78afdffc056ebfd253100811ec71a1ccc354048d17e93f0b70a
thunk_265900:
0x265900: JMP 0x006bccc0
; END FUNCTION thunk_265900
0x265905: INT3 ; original byte CC, padding
0x265906: INT3 ; original byte CC, padding
0x265907: INT3 ; original byte CC, padding

; FUNCTION thunk_265908 [0x265908, 0x26590c] | file +0x200 | ev_1d8c648b8c949bddfa542a680881a2b6d34989bc252b7c050d7498240ee980e3
thunk_265908:
0x265908: JMP 0x006bca20
; END FUNCTION thunk_265908
0x26590d: INT3 ; original byte CC, padding
0x26590e: INT3 ; original byte CC, padding
0x26590f: INT3 ; original byte CC, padding

; FUNCTION thunk_265910 [0x265910, 0x265914] | file +0x208 | ev_2fbce8ef0f6b1d956a901b81cb57c9f16ae0b93127324c46ac5e0c8dc797f3fb
thunk_265910:
0x265910: JMP 0x007299f0
; END FUNCTION thunk_265910
0x265915: INT3 ; original byte CC, padding
0x265916: INT3 ; original byte CC, padding
0x265917: INT3 ; original byte CC, padding

; FUNCTION thunk_265918 [0x265918, 0x26591c] | file +0x210 | ev_51a7fedd9d37821417b557dbf67683f2594f508d9320da3f13e506d0066051e8
thunk_265918:
0x265918: JMP 0x00729a40
; END FUNCTION thunk_265918
0x26591d: INT3 ; original byte CC, padding
0x26591e: INT3 ; original byte CC, padding
0x26591f: INT3 ; original byte CC, padding

; FUNCTION thunk_265920 [0x265920, 0x265924] | file +0x218 | ev_c39c0d1fff985a45fbc3bd1198cf1b0ecd31692fb4a457f2d3a91762a9715145
thunk_265920:
0x265920: JMP 0x00729dc0
; END FUNCTION thunk_265920
0x265925: INT3 ; original byte CC, padding
0x265926: INT3 ; original byte CC, padding
0x265927: INT3 ; original byte CC, padding

; FUNCTION thunk_265928 [0x265928, 0x26592c] | file +0x220 | ev_6ed115f20180546ca451c6a4143e4cbcf49238cec1d7281f9c760435a3f48a16
thunk_265928:
0x265928: JMP 0x004ee4b0
; END FUNCTION thunk_265928
0x26592d: INT3 ; original byte CC, padding
0x26592e: INT3 ; original byte CC, padding
0x26592f: INT3 ; original byte CC, padding

; FUNCTION thunk_265930 [0x265930, 0x265934] | file +0x228 | ev_168128ab332fee133851c8c2c0dfed0372d386808a7ee24636fca3e8f350e72b
thunk_265930:
0x265930: JMP 0x008fb430
; END FUNCTION thunk_265930
0x265935: INT3 ; original byte CC, padding
0x265936: INT3 ; original byte CC, padding
0x265937: INT3 ; original byte CC, padding

; FUNCTION thunk_265938 [0x265938, 0x26593c] | file +0x230 | ev_c519c25eba1520b948eb17ada921ff130548b371bb9e749cd1a8197150ae7c7e
thunk_265938:
0x265938: JMP 0x0049ff80
; END FUNCTION thunk_265938
0x26593d: INT3 ; original byte CC, padding
0x26593e: INT3 ; original byte CC, padding
0x26593f: INT3 ; original byte CC, padding

; FUNCTION thunk_265940 [0x265940, 0x265944] | file +0x238 | ev_b31257a300ab503ae550e8b75e4beed9089c4d8aeff2ef13c06811b5f847cdcf
thunk_265940:
0x265940: JMP 0x0052f8f0
; END FUNCTION thunk_265940
0x265945: INT3 ; original byte CC, padding
0x265946: INT3 ; original byte CC, padding
0x265947: INT3 ; original byte CC, padding

; FUNCTION thunk_265948 [0x265948, 0x26594c] | file +0x240 | ev_6a0bec579f7db081777d62e5e84debe5bdb67589729a3712805f516afce5c16d
thunk_265948:
0x265948: JMP 0x00531260
; END FUNCTION thunk_265948
0x26594d: INT3 ; original byte CC, padding
0x26594e: INT3 ; original byte CC, padding
0x26594f: INT3 ; original byte CC, padding

; FUNCTION thunk_265950 [0x265950, 0x265954] | file +0x248 | ev_4ce2255d03764bdadf7c883b0fef92a89073cd0f77961ad7c78a4b7f395b1148
thunk_265950:
0x265950: JMP 0x0052fce0
; END FUNCTION thunk_265950
0x265955: INT3 ; original byte CC, padding
0x265956: INT3 ; original byte CC, padding
0x265957: INT3 ; original byte CC, padding

; FUNCTION thunk_265958 [0x265958, 0x26595c] | file +0x250 | ev_46ac121cd15ec4f1eef7e953216a00693eb003f1b8f3a51d54159f9c8db904ba
thunk_265958:
0x265958: JMP 0x0049fcf0
; END FUNCTION thunk_265958
0x26595d: INT3 ; original byte CC, padding
0x26595e: INT3 ; original byte CC, padding
0x26595f: INT3 ; original byte CC, padding

; FUNCTION thunk_265960 [0x265960, 0x265964] | file +0x258 | ev_58f2dc23be3ba21d60623d9e300f14eff0866f1b9d61326b6f93f17a5fe0e31d
thunk_265960:
0x265960: JMP 0x0052fd00
; END FUNCTION thunk_265960
0x265965: INT3 ; original byte CC, padding
0x265966: INT3 ; original byte CC, padding
0x265967: INT3 ; original byte CC, padding

; FUNCTION thunk_265968 [0x265968, 0x26596c] | file +0x260 | ev_7edf4937f75b34607d7282f661231292fd6b0e1043adabcdb3cec2032a84ae52
thunk_265968:
0x265968: JMP 0x0052fe00
; END FUNCTION thunk_265968
0x26596d: INT3 ; original byte CC, padding
0x26596e: INT3 ; original byte CC, padding
0x26596f: INT3 ; original byte CC, padding

; FUNCTION thunk_265970 [0x265970, 0x265974] | file +0x268 | ev_a61179069aea9d46cde19c9c505ec477bfafb1f1307b2ecb9a5dd4481f9599b0
thunk_265970:
0x265970: JMP 0x00530480
; END FUNCTION thunk_265970
0x265975: INT3 ; original byte CC, padding
0x265976: INT3 ; original byte CC, padding
0x265977: INT3 ; original byte CC, padding

; FUNCTION thunk_265978 [0x265978, 0x26597c] | file +0x270 | ev_8f68cf96d5c5641edab50be0cecfebf44ffa93a70f88e3e350a9ed6c39d0444f
thunk_265978:
0x265978: JMP 0x00532bc0
; END FUNCTION thunk_265978
0x26597d: INT3 ; original byte CC, padding
0x26597e: INT3 ; original byte CC, padding
0x26597f: INT3 ; original byte CC, padding

; FUNCTION thunk_265980 [0x265980, 0x265984] | file +0x278 | ev_96bd70da6010511498989cf153467883d54c72197753f7d56914e6848963c666
thunk_265980:
0x265980: JMP 0x005307d0
; END FUNCTION thunk_265980
0x265985: INT3 ; original byte CC, padding
0x265986: INT3 ; original byte CC, padding
0x265987: INT3 ; original byte CC, padding

; FUNCTION thunk_265988 [0x265988, 0x26598c] | file +0x280 | ev_ad263442a4957628c3651d02ff31caf3ff123d91ac6e612316130ef55a06fc41
thunk_265988:
0x265988: JMP 0x0052fae0
; END FUNCTION thunk_265988
0x26598d: INT3 ; original byte CC, padding
0x26598e: INT3 ; original byte CC, padding
0x26598f: INT3 ; original byte CC, padding

; FUNCTION thunk_265990 [0x265990, 0x265994] | file +0x288 | ev_6ddca225a8844f0a956e72eb36adca2fe53bd90a89eff3a53ef68aef49eda57d
thunk_265990:
0x265990: JMP 0x0072c140
; END FUNCTION thunk_265990
0x265995: INT3 ; original byte CC, padding
0x265996: INT3 ; original byte CC, padding
0x265997: INT3 ; original byte CC, padding

; FUNCTION thunk_265998 [0x265998, 0x26599c] | file +0x290 | ev_65c2b3b478763fa59180871059f420c13f43e74bbb5db32ea6e8a3ba14aed9c9
thunk_265998:
0x265998: JMP 0x006bc800
; END FUNCTION thunk_265998
0x26599d: INT3 ; original byte CC, padding
0x26599e: INT3 ; original byte CC, padding
0x26599f: INT3 ; original byte CC, padding

; FUNCTION thunk_2659a0 [0x2659a0, 0x2659a4] | file +0x298 | ev_3737c135be6511a09efc868cc07a5c07499ffae8ae300ed846470a34637263b2
thunk_2659a0:
0x2659a0: JMP 0x004a1ba0
; END FUNCTION thunk_2659a0
0x2659a5: INT3 ; original byte CC, padding
0x2659a6: INT3 ; original byte CC, padding
0x2659a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659a8 [0x2659a8, 0x2659ac] | file +0x2a0 | ev_1c8053eb5bc3aa09b01e0bc4d2c28858562f68c983c137ac0e898b243011a3f4
thunk_2659a8:
0x2659a8: JMP 0x00532cd0
; END FUNCTION thunk_2659a8
0x2659ad: INT3 ; original byte CC, padding
0x2659ae: INT3 ; original byte CC, padding
0x2659af: INT3 ; original byte CC, padding

; FUNCTION thunk_2659b0 [0x2659b0, 0x2659b4] | file +0x2a8 | ev_1a5b353552123c0d975b18fde8275291d3bc26fef98318c05a592f13ef508e30
thunk_2659b0:
0x2659b0: JMP 0x004ec2c0
; END FUNCTION thunk_2659b0
0x2659b5: INT3 ; original byte CC, padding
0x2659b6: INT3 ; original byte CC, padding
0x2659b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659b8 [0x2659b8, 0x2659bc] | file +0x2b0 | ev_ed5e8fd16ab4df76ed7f71c3c304a25e832678c51f3912fc41e30f28750c643e
thunk_2659b8:
0x2659b8: JMP 0x004ec8e0
; END FUNCTION thunk_2659b8
0x2659bd: INT3 ; original byte CC, padding
0x2659be: INT3 ; original byte CC, padding
0x2659bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2659c0 [0x2659c0, 0x2659c4] | file +0x2b8 | ev_42388928d43dbee314a6c1ce3245c8d49c8390da3c4bc594fb5aaddafc070ab7
thunk_2659c0:
0x2659c0: JMP 0x006bc8d0
; END FUNCTION thunk_2659c0
0x2659c5: INT3 ; original byte CC, padding
0x2659c6: INT3 ; original byte CC, padding
0x2659c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659c8 [0x2659c8, 0x2659cc] | file +0x2c0 | ev_aa1de99500333816fe82e6a0e9e23204b7b21bb793b90cf9923a4574ffd80d7c
thunk_2659c8:
0x2659c8: JMP 0x008f9d40
; END FUNCTION thunk_2659c8
0x2659cd: INT3 ; original byte CC, padding
0x2659ce: INT3 ; original byte CC, padding
0x2659cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2659d0 [0x2659d0, 0x2659d4] | file +0x2c8 | ev_d7c4da6f51e0244008bec03e69af471e068616e27e56eaaba7cd17e57aee7856
thunk_2659d0:
0x2659d0: JMP 0x0052fe70
; END FUNCTION thunk_2659d0
0x2659d5: INT3 ; original byte CC, padding
0x2659d6: INT3 ; original byte CC, padding
0x2659d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659d8 [0x2659d8, 0x2659dc] | file +0x2d0 | ev_d812c2321b5e8acb07f8f189c4f83d49099c0d10ab687c950cf9040645c78369
thunk_2659d8:
0x2659d8: JMP 0x008fb450
; END FUNCTION thunk_2659d8
0x2659dd: INT3 ; original byte CC, padding
0x2659de: INT3 ; original byte CC, padding
0x2659df: INT3 ; original byte CC, padding

; FUNCTION thunk_2659e0 [0x2659e0, 0x2659e4] | file +0x2d8 | ev_eeaf3a8beaaed8e90f29f246e32ffa9b14bf76351f9c7cdd7b75a5907064074e
thunk_2659e0:
0x2659e0: JMP 0x0072e590
; END FUNCTION thunk_2659e0
0x2659e5: INT3 ; original byte CC, padding
0x2659e6: INT3 ; original byte CC, padding
0x2659e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659e8 [0x2659e8, 0x2659ec] | file +0x2e0 | ev_93e5bf490834f1047815cb55d92a50b3522304ffe4de081ae3e2a6297c559350
thunk_2659e8:
0x2659e8: JMP 0x00531b30
; END FUNCTION thunk_2659e8
0x2659ed: INT3 ; original byte CC, padding
0x2659ee: INT3 ; original byte CC, padding
0x2659ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2659f0 [0x2659f0, 0x2659f4] | file +0x2e8 | ev_57eee56aad063f12744228690ca7ce45177d557dbda4f1cfc4949d59a3dd76f2
thunk_2659f0:
0x2659f0: JMP 0x00532af0
; END FUNCTION thunk_2659f0
0x2659f5: INT3 ; original byte CC, padding
0x2659f6: INT3 ; original byte CC, padding
0x2659f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659f8 [0x2659f8, 0x2659fc] | file +0x2f0 | ev_db6ed9d2e0cae311a8d595ad0e20575d70be3c6634b7afa4daa42c7afdd41d1c
thunk_2659f8:
0x2659f8: JMP 0x00531720
; END FUNCTION thunk_2659f8
0x2659fd: INT3 ; original byte CC, padding
0x2659fe: INT3 ; original byte CC, padding
0x2659ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265a00 [0x265a00, 0x265a04] | file +0x2f8 | ev_b9362fe323a442adbbe22eddd8cb779a87e9f35aa42d1392c2f78475a282a46c
thunk_265a00:
0x265a00: JMP 0x008fb8e0
; END FUNCTION thunk_265a00
0x265a05: INT3 ; original byte CC, padding
0x265a06: INT3 ; original byte CC, padding
0x265a07: INT3 ; original byte CC, padding

; FUNCTION thunk_265a08 [0x265a08, 0x265a0c] | file +0x300 | ev_e101e165d55e3c023ea9702dfff16f6e79246d887abaaf2a48215537ac448782
thunk_265a08:
0x265a08: JMP 0x008fbbc0
; END FUNCTION thunk_265a08
0x265a0d: INT3 ; original byte CC, padding
0x265a0e: INT3 ; original byte CC, padding
0x265a0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a10 [0x265a10, 0x265a14] | file +0x308 | ev_ab047a2ffd77c7fb21b69d50e06b794aa9de69186983e5cd51eb5c80a01023a4
thunk_265a10:
0x265a10: JMP 0x008fa310
; END FUNCTION thunk_265a10
0x265a15: INT3 ; original byte CC, padding
0x265a16: INT3 ; original byte CC, padding
0x265a17: INT3 ; original byte CC, padding

; FUNCTION thunk_265a18 [0x265a18, 0x265a1c] | file +0x310 | ev_457281366867d82ba2e84e2eeef2531b31b5cda653fa8dea15200204f38ec3dc
thunk_265a18:
0x265a18: JMP 0x0047b030
; END FUNCTION thunk_265a18
0x265a1d: INT3 ; original byte CC, padding
0x265a1e: INT3 ; original byte CC, padding
0x265a1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a20 [0x265a20, 0x265a24] | file +0x318 | ev_4cb9f4b02ac3982206479c7a415db43ef9663b9930a274e8917298018a4f8c09
thunk_265a20:
0x265a20: JMP 0x008f8e20
; END FUNCTION thunk_265a20
0x265a25: INT3 ; original byte CC, padding
0x265a26: INT3 ; original byte CC, padding
0x265a27: INT3 ; original byte CC, padding

; FUNCTION thunk_265a28 [0x265a28, 0x265a2c] | file +0x320 | ev_6aeeb89ab9fdd62d9997b8bb32c9bed71748578a672c0ba09686d984be5a9bdc
thunk_265a28:
0x265a28: JMP 0x0072c150
; END FUNCTION thunk_265a28
0x265a2d: INT3 ; original byte CC, padding
0x265a2e: INT3 ; original byte CC, padding
0x265a2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a30 [0x265a30, 0x265a34] | file +0x328 | ev_be064326b7431503cdcb02908a7217e744357b729e72e1614dc1328bc1ea66b1
thunk_265a30:
0x265a30: JMP 0x008f9260
; END FUNCTION thunk_265a30
0x265a35: INT3 ; original byte CC, padding
0x265a36: INT3 ; original byte CC, padding
0x265a37: INT3 ; original byte CC, padding

; FUNCTION thunk_265a38 [0x265a38, 0x265a3c] | file +0x330 | ev_eb91a911fcc71da70f30352af205783637b459c9f8d67b0eed63722a8d86b1cf
thunk_265a38:
0x265a38: JMP 0x008f9310
; END FUNCTION thunk_265a38
0x265a3d: INT3 ; original byte CC, padding
0x265a3e: INT3 ; original byte CC, padding
0x265a3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a40 [0x265a40, 0x265a44] | file +0x338 | ev_a3a52775b98c6fc5df9d7b69dd708e06229385519208b8f9465b77c8a0e0b83d
thunk_265a40:
0x265a40: JMP 0x0072c3e0
; END FUNCTION thunk_265a40
0x265a45: INT3 ; original byte CC, padding
0x265a46: INT3 ; original byte CC, padding
0x265a47: INT3 ; original byte CC, padding

; FUNCTION thunk_265a48 [0x265a48, 0x265a4c] | file +0x340 | ev_96925a78451c47ba5cdc7f70b51a7168ab595113055ce5d9d6b7261f687e8714
thunk_265a48:
0x265a48: JMP 0x004a13e0
; END FUNCTION thunk_265a48
0x265a4d: INT3 ; original byte CC, padding
0x265a4e: INT3 ; original byte CC, padding
0x265a4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a50 [0x265a50, 0x265a54] | file +0x348 | ev_06598b27113e0dd15bfe1ee2bc7d1d3b941c688d483dbbb8500b929308de0685
thunk_265a50:
0x265a50: JMP 0x004a0c30
; END FUNCTION thunk_265a50
0x265a55: INT3 ; original byte CC, padding
0x265a56: INT3 ; original byte CC, padding
0x265a57: INT3 ; original byte CC, padding

; FUNCTION thunk_265a58 [0x265a58, 0x265a5c] | file +0x350 | ev_ee56e932effb8cd11abcdecf19d018c0439a597586b5af12955784334c9c2e4c
thunk_265a58:
0x265a58: JMP 0x008fbbe0
; END FUNCTION thunk_265a58
0x265a5d: INT3 ; original byte CC, padding
0x265a5e: INT3 ; original byte CC, padding
0x265a5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a60 [0x265a60, 0x265a64] | file +0x358 | ev_c95aaa86727ffe60a4df1d510d7c3093e8db94cd313c902d93a5997623489575
thunk_265a60:
0x265a60: JMP 0x005581e0
; END FUNCTION thunk_265a60
0x265a65: INT3 ; original byte CC, padding
0x265a66: INT3 ; original byte CC, padding
0x265a67: INT3 ; original byte CC, padding

; FUNCTION thunk_265a68 [0x265a68, 0x265a6c] | file +0x360 | ev_a0b1537d4bc5be6705b058b5985864a5157864850b1bd21bf57c9b2325380cf6
thunk_265a68:
0x265a68: JMP 0x00ab9450
; END FUNCTION thunk_265a68
0x265a6d: INT3 ; original byte CC, padding
0x265a6e: INT3 ; original byte CC, padding
0x265a6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a70 [0x265a70, 0x265a74] | file +0x368 | ev_e362c6c038b8a2de4031260263b33b300becdbb2a86e2dc2d06b1a513f67a290
thunk_265a70:
0x265a70: JMP 0x00ab9710
; END FUNCTION thunk_265a70
0x265a75: INT3 ; original byte CC, padding
0x265a76: INT3 ; original byte CC, padding
0x265a77: INT3 ; original byte CC, padding

; FUNCTION thunk_265a78 [0x265a78, 0x265a7c] | file +0x370 | ev_495d3038041b1a058b06ff2e731663ea4085c3483dad60be8c277ec4650ae131
thunk_265a78:
0x265a78: JMP 0x008fa8e0
; END FUNCTION thunk_265a78
0x265a7d: INT3 ; original byte CC, padding
0x265a7e: INT3 ; original byte CC, padding
0x265a7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a80 [0x265a80, 0x265a84] | file +0x378 | ev_01494b260f43259ae66379dfaa4ec3220cf27d283f5fa293cc9016f999ef5a95
thunk_265a80:
0x265a80: JMP 0x004ee550
; END FUNCTION thunk_265a80
0x265a85: INT3 ; original byte CC, padding
0x265a86: INT3 ; original byte CC, padding
0x265a87: INT3 ; original byte CC, padding

; FUNCTION thunk_265a88 [0x265a88, 0x265a8c] | file +0x380 | ev_44497fb3e04c8f7d5d0ac5c7e05dd2da54ffa2c8543f7248613743fa2124e22e
thunk_265a88:
0x265a88: JMP 0x008fc810
; END FUNCTION thunk_265a88
0x265a8d: INT3 ; original byte CC, padding
0x265a8e: INT3 ; original byte CC, padding
0x265a8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a90 [0x265a90, 0x265a94] | file +0x388 | ev_9ae732fc69c6cc412b0330c58f2d0bb51a78ab4d537f32b719ec38209eac178a
thunk_265a90:
0x265a90: JMP 0x008fc820
; END FUNCTION thunk_265a90
0x265a95: INT3 ; original byte CC, padding
0x265a96: INT3 ; original byte CC, padding
0x265a97: INT3 ; original byte CC, padding

; FUNCTION thunk_265a98 [0x265a98, 0x265a9c] | file +0x390 | ev_703f3a9a7f45ff25eec1878f102b43f3b14214814250fb5f5c02f5bb7cae1c1b
thunk_265a98:
0x265a98: JMP 0x006bb670
; END FUNCTION thunk_265a98
0x265a9d: INT3 ; original byte CC, padding
0x265a9e: INT3 ; original byte CC, padding
0x265a9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265aa0 [0x265aa0, 0x265aa4] | file +0x398 | ev_74184725994ed2974629c910264ae0ce707c4aedf51a50f3a0ed2fdb4811bafd
thunk_265aa0:
0x265aa0: JMP 0x006bbd20
; END FUNCTION thunk_265aa0
0x265aa5: INT3 ; original byte CC, padding
0x265aa6: INT3 ; original byte CC, padding
0x265aa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265aa8 [0x265aa8, 0x265aac] | file +0x3a0 | ev_e9fefd27bc7e8195f87b57be11e34664c183dddbdafa1971b6354208ba73289c
thunk_265aa8:
0x265aa8: JMP 0x006bc030
; END FUNCTION thunk_265aa8
0x265aad: INT3 ; original byte CC, padding
0x265aae: INT3 ; original byte CC, padding
0x265aaf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ab0 [0x265ab0, 0x265ab4] | file +0x3a8 | ev_d6bb2d3864dfa8653d8b0a1a1a301a0ec61fc622efb8ed1a8c716a6616500d8c
thunk_265ab0:
0x265ab0: JMP 0x006bd570
; END FUNCTION thunk_265ab0
0x265ab5: INT3 ; original byte CC, padding
0x265ab6: INT3 ; original byte CC, padding
0x265ab7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ab8 [0x265ab8, 0x265abc] | file +0x3b0 | ev_da8086beb71b8289e8a89ced618b14099f0e550d9c8b00b77e86342eb26afc6b
thunk_265ab8:
0x265ab8: JMP 0x006bdfa0
; END FUNCTION thunk_265ab8
0x265abd: INT3 ; original byte CC, padding
0x265abe: INT3 ; original byte CC, padding
0x265abf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ac0 [0x265ac0, 0x265ac4] | file +0x3b8 | ev_a7a4b472e4d5050be1e8b517eb6b54f185b39ba3a423190aeff61c75a894d6a6
thunk_265ac0:
0x265ac0: JMP 0x006bdfb0
; END FUNCTION thunk_265ac0
0x265ac5: INT3 ; original byte CC, padding
0x265ac6: INT3 ; original byte CC, padding
0x265ac7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ac8 [0x265ac8, 0x265acc] | file +0x3c0 | ev_f5662ab849c8da53ecae1ad0eeaddb1df22fad5b85181d96d1a93b3c3137080b
thunk_265ac8:
0x265ac8: JMP 0x006be1d0
; END FUNCTION thunk_265ac8
0x265acd: INT3 ; original byte CC, padding
0x265ace: INT3 ; original byte CC, padding
0x265acf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ad0 [0x265ad0, 0x265ad4] | file +0x3c8 | ev_a83086b17cb41202f8a783e29293a14cf7083aef07c71243350a67baf6a55783
thunk_265ad0:
0x265ad0: JMP 0x006be370
; END FUNCTION thunk_265ad0
0x265ad5: INT3 ; original byte CC, padding
0x265ad6: INT3 ; original byte CC, padding
0x265ad7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ad8 [0x265ad8, 0x265adc] | file +0x3d0 | ev_8b313a4cd4e03d138294806bc1259185344520a276b48d244c4a89477c4c787c
thunk_265ad8:
0x265ad8: JMP 0x006bc4e0
; END FUNCTION thunk_265ad8
0x265add: INT3 ; original byte CC, padding
0x265ade: INT3 ; original byte CC, padding
0x265adf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ae0 [0x265ae0, 0x265ae4] | file +0x3d8 | ev_f30b4d187411d67d73401e1457f57a54727fc2e9e0ff00e7587ba82b85313d03
thunk_265ae0:
0x265ae0: JMP 0x00cb1ab0
; END FUNCTION thunk_265ae0
0x265ae5: INT3 ; original byte CC, padding
0x265ae6: INT3 ; original byte CC, padding
0x265ae7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ae8 [0x265ae8, 0x265aec] | file +0x3e0 | ev_afba907846997d56d0b1e5c1e415974c601de5cf6166c57a19b6f6715465b552
thunk_265ae8:
0x265ae8: JMP 0x008fc390
; END FUNCTION thunk_265ae8
0x265aed: INT3 ; original byte CC, padding
0x265aee: INT3 ; original byte CC, padding
0x265aef: INT3 ; original byte CC, padding

; FUNCTION thunk_265af0 [0x265af0, 0x265af4] | file +0x3e8 | ev_cd81f5026adc4e739b1631c6db8bc6dfcb618f6a8d7556dd3134662e421e165f
thunk_265af0:
0x265af0: JMP 0x004ec4e0
; END FUNCTION thunk_265af0
0x265af5: INT3 ; original byte CC, padding
0x265af6: INT3 ; original byte CC, padding
0x265af7: INT3 ; original byte CC, padding

; FUNCTION thunk_265af8 [0x265af8, 0x265afc] | file +0x3f0 | ev_3a07c8c9cac85f4902d53fd0bdeb88f36620f674b725f543cc5ddc1cfe02744f
thunk_265af8:
0x265af8: JMP 0x004ecc70
; END FUNCTION thunk_265af8
0x265afd: INT3 ; original byte CC, padding
0x265afe: INT3 ; original byte CC, padding
0x265aff: INT3 ; original byte CC, padding

; FUNCTION thunk_265b00 [0x265b00, 0x265b04] | file +0x3f8 | ev_3421d95e17cc4a1925878bcf237c85a181496eb13254fc09214051717e3bf956
thunk_265b00:
0x265b00: JMP 0x00b7e960
; END FUNCTION thunk_265b00
0x265b05: INT3 ; original byte CC, padding
0x265b06: INT3 ; original byte CC, padding
0x265b07: INT3 ; original byte CC, padding

; FUNCTION thunk_265b08 [0x265b08, 0x265b0c] | file +0x400 | ev_75fd94589e78a26fe265113c01ec72d5cc7b39e10c9ab4703526f635bb918b90
thunk_265b08:
0x265b08: JMP 0x00ab9580
; END FUNCTION thunk_265b08
0x265b0d: INT3 ; original byte CC, padding
0x265b0e: INT3 ; original byte CC, padding
0x265b0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b10 [0x265b10, 0x265b14] | file +0x408 | ev_af1b623e4e48ac4d33130b6c322bad5504b08c7fcfd69f2794de5fdd99e36ba2
thunk_265b10:
0x265b10: JMP 0x00ab9690
; END FUNCTION thunk_265b10
0x265b15: INT3 ; original byte CC, padding
0x265b16: INT3 ; original byte CC, padding
0x265b17: INT3 ; original byte CC, padding

; FUNCTION thunk_265b18 [0x265b18, 0x265b1c] | file +0x410 | ev_6f08de602f743b11af2a3ca81a92e66b4599a09ea231bf06d2b2b6b3b5eaaca6
thunk_265b18:
0x265b18: JMP 0x005a3a60
; END FUNCTION thunk_265b18
0x265b1d: INT3 ; original byte CC, padding
0x265b1e: INT3 ; original byte CC, padding
0x265b1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b20 [0x265b20, 0x265b24] | file +0x418 | ev_c564b04ab0134458f3ec21037b36c3c93539d25c908e0ad6ca22354547c06438
thunk_265b20:
0x265b20: JMP 0x005a3b50
; END FUNCTION thunk_265b20
0x265b25: INT3 ; original byte CC, padding
0x265b26: INT3 ; original byte CC, padding
0x265b27: INT3 ; original byte CC, padding

; FUNCTION thunk_265b28 [0x265b28, 0x265b2c] | file +0x420 | ev_5affb35aa9906b7dce9056179ac6876de7facd3be39c71c34d941337286ca5a6
thunk_265b28:
0x265b28: JMP 0x005a3c60
; END FUNCTION thunk_265b28
0x265b2d: INT3 ; original byte CC, padding
0x265b2e: INT3 ; original byte CC, padding
0x265b2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b30 [0x265b30, 0x265b34] | file +0x428 | ev_c7936173b4efa1a6af8d0aa07fef51e96aec939bed94b875ebdf5c5837764184
thunk_265b30:
0x265b30: JMP 0x005a3d80
; END FUNCTION thunk_265b30
0x265b35: INT3 ; original byte CC, padding
0x265b36: INT3 ; original byte CC, padding
0x265b37: INT3 ; original byte CC, padding

; FUNCTION thunk_265b38 [0x265b38, 0x265b3c] | file +0x430 | ev_0e76e0fad593dfb982ea3a62cc569e5ea657347adda0b8922d71b521086b1c2b
thunk_265b38:
0x265b38: JMP 0x005a3e70
; END FUNCTION thunk_265b38
0x265b3d: INT3 ; original byte CC, padding
0x265b3e: INT3 ; original byte CC, padding
0x265b3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b40 [0x265b40, 0x265b44] | file +0x438 | ev_f1fc0fe618834671b18566b6c97f93eb32d77f7ff6bc3a5c418a0488c6417721
thunk_265b40:
0x265b40: JMP 0x005a3e90
; END FUNCTION thunk_265b40
0x265b45: INT3 ; original byte CC, padding
0x265b46: INT3 ; original byte CC, padding
0x265b47: INT3 ; original byte CC, padding

; FUNCTION thunk_265b48 [0x265b48, 0x265b4c] | file +0x440 | ev_297e4ad1506e4fa588be7ffb3cc64d2c156a60c7398949f2861c53f18d5b17d2
thunk_265b48:
0x265b48: JMP 0x005a3ef0
; END FUNCTION thunk_265b48
0x265b4d: INT3 ; original byte CC, padding
0x265b4e: INT3 ; original byte CC, padding
0x265b4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b50 [0x265b50, 0x265b54] | file +0x448 | ev_957aacb527787eb0bbe4be89cd09cb9d646bdb0b0eef73532724401411d3f83f
thunk_265b50:
0x265b50: JMP 0x005a3f50
; END FUNCTION thunk_265b50
0x265b55: INT3 ; original byte CC, padding
0x265b56: INT3 ; original byte CC, padding
0x265b57: INT3 ; original byte CC, padding

; FUNCTION thunk_265b58 [0x265b58, 0x265b5c] | file +0x450 | ev_cdf8cfb3dbfa1c991b88c6fb6c622969311bf5929ddd06d485acb7358d3b157f
thunk_265b58:
0x265b58: JMP 0x0055ddc0
; END FUNCTION thunk_265b58
0x265b5d: INT3 ; original byte CC, padding
0x265b5e: INT3 ; original byte CC, padding
0x265b5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b60 [0x265b60, 0x265b64] | file +0x458 | ev_ff82123b8e6c256e78638c22fe7f10d74d0dfa36b00ec56cab6d9ea3a0aa3319
thunk_265b60:
0x265b60: JMP 0x0055ed70
; END FUNCTION thunk_265b60
0x265b65: INT3 ; original byte CC, padding
0x265b66: INT3 ; original byte CC, padding
0x265b67: INT3 ; original byte CC, padding

; FUNCTION thunk_265b68 [0x265b68, 0x265b6c] | file +0x460 | ev_741b6004488946980cd7fb46c8ac97d67f459efd27fe6f2f52fb1230a023caee
thunk_265b68:
0x265b68: JMP 0x0055ec90
; END FUNCTION thunk_265b68
0x265b6d: INT3 ; original byte CC, padding
0x265b6e: INT3 ; original byte CC, padding
0x265b6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b70 [0x265b70, 0x265b74] | file +0x468 | ev_a80907af4d4322c151a28c2e6b435566f63b91608759d6b7eed94f2c1d82e756
thunk_265b70:
0x265b70: JMP 0x0055e550
; END FUNCTION thunk_265b70
0x265b75: INT3 ; original byte CC, padding
0x265b76: INT3 ; original byte CC, padding
0x265b77: INT3 ; original byte CC, padding

; FUNCTION thunk_265b78 [0x265b78, 0x265b7c] | file +0x470 | ev_fdf4707818758567a82e30ec2143b122d38d08eb7ed927cd231371fdc7e00e94
thunk_265b78:
0x265b78: JMP 0x0055e680
; END FUNCTION thunk_265b78
0x265b7d: INT3 ; original byte CC, padding
0x265b7e: INT3 ; original byte CC, padding
0x265b7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b80 [0x265b80, 0x265b84] | file +0x478 | ev_799415689b58e85117b40d602cd6f0ae72c9367f920780d6dac67533b8fab27b
thunk_265b80:
0x265b80: JMP 0x00abbd80
; END FUNCTION thunk_265b80
0x265b85: INT3 ; original byte CC, padding
0x265b86: INT3 ; original byte CC, padding
0x265b87: INT3 ; original byte CC, padding

; FUNCTION thunk_265b88 [0x265b88, 0x265b8c] | file +0x480 | ev_f76ebe4feb3b350240ced19a248ba11b57b55594dfd79f35b9487d256cc6a04d
thunk_265b88:
0x265b88: JMP 0x008340e0
; END FUNCTION thunk_265b88
0x265b8d: INT3 ; original byte CC, padding
0x265b8e: INT3 ; original byte CC, padding
0x265b8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b90 [0x265b90, 0x265b94] | file +0x488 | ev_e804e814208779b292184c09528d5b06b191b5e662769ad648d37c00fa89bdff
thunk_265b90:
0x265b90: JMP 0x008f6120
; END FUNCTION thunk_265b90
0x265b95: INT3 ; original byte CC, padding
0x265b96: INT3 ; original byte CC, padding
0x265b97: INT3 ; original byte CC, padding

; FUNCTION thunk_265b98 [0x265b98, 0x265b9c] | file +0x490 | ev_8e023189980448d6df30dad824c60fca8197963af4cd274e52ca66e3592e2094
thunk_265b98:
0x265b98: JMP 0x00c42f00
; END FUNCTION thunk_265b98
0x265b9d: INT3 ; original byte CC, padding
0x265b9e: INT3 ; original byte CC, padding
0x265b9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ba0 [0x265ba0, 0x265ba4] | file +0x498 | ev_14db88a56f2d598b9fe53ff7e638f60ded442f1493152fa12749722dc00d28f1
thunk_265ba0:
0x265ba0: JMP 0x00c43010
; END FUNCTION thunk_265ba0
0x265ba5: INT3 ; original byte CC, padding
0x265ba6: INT3 ; original byte CC, padding
0x265ba7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ba8 [0x265ba8, 0x265bac] | file +0x4a0 | ev_32b9f7cf53a0920034e238f86f0960da31d0a690a74474aa4d053cbe623c8890
thunk_265ba8:
0x265ba8: JMP 0x00c43170
; END FUNCTION thunk_265ba8
0x265bad: INT3 ; original byte CC, padding
0x265bae: INT3 ; original byte CC, padding
0x265baf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bb0 [0x265bb0, 0x265bb4] | file +0x4a8 | ev_d4fef26238f87cdb8b610f00be41942cd7a349cc61e68316a81cb39b0b1c2fce
thunk_265bb0:
0x265bb0: JMP 0x00c434a0
; END FUNCTION thunk_265bb0
0x265bb5: INT3 ; original byte CC, padding
0x265bb6: INT3 ; original byte CC, padding
0x265bb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bb8 [0x265bb8, 0x265bbc] | file +0x4b0 | ev_4b8412f013e4a4161e3b194fda8f6cb9c414b2af1de1c4afbc24c0ea4644503e
thunk_265bb8:
0x265bb8: JMP 0x00c42760
; END FUNCTION thunk_265bb8
0x265bbd: INT3 ; original byte CC, padding
0x265bbe: INT3 ; original byte CC, padding
0x265bbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bc0 [0x265bc0, 0x265bc4] | file +0x4b8 | ev_542f037da7f8c1fbbbbe4388bc2a8965614ae5b299d19f951ab10f851c55470f
thunk_265bc0:
0x265bc0: JMP 0x00c42b90
; END FUNCTION thunk_265bc0
0x265bc5: INT3 ; original byte CC, padding
0x265bc6: INT3 ; original byte CC, padding
0x265bc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bc8 [0x265bc8, 0x265bcc] | file +0x4c0 | ev_2abf1503fb82f595215032a28e2b77328058162fd3991569beaaaa185103b9d0
thunk_265bc8:
0x265bc8: JMP 0x00c42bc0
; END FUNCTION thunk_265bc8
0x265bcd: INT3 ; original byte CC, padding
0x265bce: INT3 ; original byte CC, padding
0x265bcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bd0 [0x265bd0, 0x265bd4] | file +0x4c8 | ev_387932b9517a57a82c27fdbdcbf9e370a164e0a05fff89ca14b8746cdc73bab3
thunk_265bd0:
0x265bd0: JMP 0x00c434c0
; END FUNCTION thunk_265bd0
0x265bd5: INT3 ; original byte CC, padding
0x265bd6: INT3 ; original byte CC, padding
0x265bd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bd8 [0x265bd8, 0x265bdc] | file +0x4d0 | ev_26ee89d746438e99e644a6e16f3f2b9c9ff970be35a07e54a2046ea564c57865
thunk_265bd8:
0x265bd8: JMP 0x00c43620
; END FUNCTION thunk_265bd8
0x265bdd: INT3 ; original byte CC, padding
0x265bde: INT3 ; original byte CC, padding
0x265bdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265be0 [0x265be0, 0x265be4] | file +0x4d8 | ev_0d9cd2755c606972ae8da0395a90246782c03e5283edfa37f3d50fb9cae6a53a
thunk_265be0:
0x265be0: JMP 0x0055d0c0
; END FUNCTION thunk_265be0
0x265be5: INT3 ; original byte CC, padding
0x265be6: INT3 ; original byte CC, padding
0x265be7: INT3 ; original byte CC, padding

; FUNCTION thunk_265be8 [0x265be8, 0x265bec] | file +0x4e0 | ev_a8aa7da9f0f61c34383d7c33eac6c441db1c5fc2aa8b978bdcf95961ef7abd04
thunk_265be8:
0x265be8: JMP 0x00a07280
; END FUNCTION thunk_265be8
0x265bed: INT3 ; original byte CC, padding
0x265bee: INT3 ; original byte CC, padding
0x265bef: INT3 ; original byte CC, padding

; FUNCTION thunk_265bf0 [0x265bf0, 0x265bf4] | file +0x4e8 | ev_679c3d1f43637f11cd7695c288b451925ec6002f64d269f54c771928525841a5
thunk_265bf0:
0x265bf0: JMP 0x00c37860
; END FUNCTION thunk_265bf0
0x265bf5: INT3 ; original byte CC, padding
0x265bf6: INT3 ; original byte CC, padding
0x265bf7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bf8 [0x265bf8, 0x265bfc] | file +0x4f0 | ev_be190519692c8275063e286d6fffd6a64efe639bb6af22a923b4fd232f4105db
thunk_265bf8:
0x265bf8: JMP 0x00c37970
; END FUNCTION thunk_265bf8
0x265bfd: INT3 ; original byte CC, padding
0x265bfe: INT3 ; original byte CC, padding
0x265bff: INT3 ; original byte CC, padding

; FUNCTION thunk_265c00 [0x265c00, 0x265c04] | file +0x4f8 | ev_376b188e787a152b612ae47a3648a443bb8a8cfcaff267f96a1ec4874ac9450a
thunk_265c00:
0x265c00: JMP 0x00c37a20
; END FUNCTION thunk_265c00
0x265c05: INT3 ; original byte CC, padding
0x265c06: INT3 ; original byte CC, padding
0x265c07: INT3 ; original byte CC, padding

; FUNCTION thunk_265c08 [0x265c08, 0x265c0c] | file +0x500 | ev_f434a76a40f2b0300bd3a5e9385326262ff52dd8d7886dc762ba81360a2ddf87
thunk_265c08:
0x265c08: JMP 0x0055deb0
; END FUNCTION thunk_265c08
0x265c0d: INT3 ; original byte CC, padding
0x265c0e: INT3 ; original byte CC, padding
0x265c0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c10 [0x265c10, 0x265c14] | file +0x508 | ev_931e459cfa2bc89ce67e5db8224a8c392853e680b03a61f1c4b53790ccfef13e
thunk_265c10:
0x265c10: JMP 0x00437cf0
; END FUNCTION thunk_265c10
0x265c15: INT3 ; original byte CC, padding
0x265c16: INT3 ; original byte CC, padding
0x265c17: INT3 ; original byte CC, padding

; FUNCTION thunk_265c18 [0x265c18, 0x265c1c] | file +0x510 | ev_438aeee9179dc8a6bb52273c75cf0e13486940563f28b22cd10ca70617ffdc84
thunk_265c18:
0x265c18: JMP 0x004383f0
; END FUNCTION thunk_265c18
0x265c1d: INT3 ; original byte CC, padding
0x265c1e: INT3 ; original byte CC, padding
0x265c1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c20 [0x265c20, 0x265c24] | file +0x518 | ev_4c312f6e9064ce367f20897f87104b54edcf7a4040d829ac34ce64a41d5cccef
thunk_265c20:
0x265c20: JMP 0x004383c0
; END FUNCTION thunk_265c20
0x265c25: INT3 ; original byte CC, padding
0x265c26: INT3 ; original byte CC, padding
0x265c27: INT3 ; original byte CC, padding

; FUNCTION thunk_265c28 [0x265c28, 0x265c2c] | file +0x520 | ev_0ab289f3bd62320e6566baa85db7e1202ddfc9373809b3e3b041b9f8ffd735c7
thunk_265c28:
0x265c28: JMP 0x00438560
; END FUNCTION thunk_265c28
0x265c2d: INT3 ; original byte CC, padding
0x265c2e: INT3 ; original byte CC, padding
0x265c2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c30 [0x265c30, 0x265c34] | file +0x528 | ev_bb6054e8c6fb2f121bcafd7a5c5ec8cff8a0d4c62a9156a3ea7fba134abf1536
thunk_265c30:
0x265c30: JMP 0x00c433f0
; END FUNCTION thunk_265c30
0x265c35: INT3 ; original byte CC, padding
0x265c36: INT3 ; original byte CC, padding
0x265c37: INT3 ; original byte CC, padding

; FUNCTION thunk_265c38 [0x265c38, 0x265c3c] | file +0x530 | ev_1696320a0b23b1fbe9014e786637c3aa0ebe7eb95ac14323feb57d182773a829
thunk_265c38:
0x265c38: JMP 0x004388c0
; END FUNCTION thunk_265c38
0x265c3d: INT3 ; original byte CC, padding
0x265c3e: INT3 ; original byte CC, padding
0x265c3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c40 [0x265c40, 0x265c44] | file +0x538 | ev_91a591a481a2b0fa31e530f862c8de090450922e52945aee314f278a55712a96
thunk_265c40:
0x265c40: JMP 0x00438ab0
; END FUNCTION thunk_265c40
0x265c45: INT3 ; original byte CC, padding
0x265c46: INT3 ; original byte CC, padding
0x265c47: INT3 ; original byte CC, padding

; FUNCTION thunk_265c48 [0x265c48, 0x265c4c] | file +0x540 | ev_709ff95251ab30ee92ca67ec919accb694556039b483a052b3e048988602a70c
thunk_265c48:
0x265c48: JMP 0x00552c20
; END FUNCTION thunk_265c48
0x265c4d: INT3 ; original byte CC, padding
0x265c4e: INT3 ; original byte CC, padding
0x265c4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c50 [0x265c50, 0x265c54] | file +0x548 | ev_4eafb23dc2edda248c508804926a68aac0c3aea458e04a43c2944debfa602ca4
thunk_265c50:
0x265c50: JMP 0x00437de0
; END FUNCTION thunk_265c50
0x265c55: INT3 ; original byte CC, padding
0x265c56: INT3 ; original byte CC, padding
0x265c57: INT3 ; original byte CC, padding

; FUNCTION thunk_265c58 [0x265c58, 0x265c5c] | file +0x550 | ev_cc3a07b8d71a1d4520dc7a3471d16d389cb9a545dbea33c1f9ead630c8c24e8c
thunk_265c58:
0x265c58: JMP 0x0055fc20
; END FUNCTION thunk_265c58
0x265c5d: INT3 ; original byte CC, padding
0x265c5e: INT3 ; original byte CC, padding
0x265c5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c60 [0x265c60, 0x265c64] | file +0x558 | ev_a9da2e1f21296d36267a024dc9f6baa872bd760111b710b4e17e73fab083ee82
thunk_265c60:
0x265c60: JMP 0x00438b60
; END FUNCTION thunk_265c60
0x265c65: INT3 ; original byte CC, padding
0x265c66: INT3 ; original byte CC, padding
0x265c67: INT3 ; original byte CC, padding

; FUNCTION thunk_265c68 [0x265c68, 0x265c6c] | file +0x560 | ev_ade79c344fa8f9813a509184257a796302ce52c97d848f153069b605de1f1255
thunk_265c68:
0x265c68: JMP 0x004a0400
; END FUNCTION thunk_265c68
0x265c6d: INT3 ; original byte CC, padding
0x265c6e: INT3 ; original byte CC, padding
0x265c6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c70 [0x265c70, 0x265c74] | file +0x568 | ev_93839e631c81c2700fc2f343594258766f1e42358948e7d0d9f8d4bac559696a
thunk_265c70:
0x265c70: JMP 0x004ec120
; END FUNCTION thunk_265c70
0x265c75: INT3 ; original byte CC, padding
0x265c76: INT3 ; original byte CC, padding
0x265c77: INT3 ; original byte CC, padding

; FUNCTION thunk_265c78 [0x265c78, 0x265c7c] | file +0x570 | ev_10871a7c7ae092e887b02fb009ac16eb48ee7f55f6163c265dcb6fb32f10ebcd
thunk_265c78:
0x265c78: JMP 0x004ec740
; END FUNCTION thunk_265c78
0x265c7d: INT3 ; original byte CC, padding
0x265c7e: INT3 ; original byte CC, padding
0x265c7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c80 [0x265c80, 0x265c84] | file +0x578 | ev_0e11dae06b7985255741a13a2e75201ff96088ebbdc4cb6c011b2b4b9d93dddc
thunk_265c80:
0x265c80: JMP 0x00ab83c0
; END FUNCTION thunk_265c80
0x265c85: INT3 ; original byte CC, padding
0x265c86: INT3 ; original byte CC, padding
0x265c87: INT3 ; original byte CC, padding

; FUNCTION thunk_265c88 [0x265c88, 0x265c8c] | file +0x580 | ev_ca4309404d7e3f813e8c3bdf066f86347e96654cb670f2fc40c3d6f4e27ed389
thunk_265c88:
0x265c88: JMP 0x008f8ab0
; END FUNCTION thunk_265c88
0x265c8d: INT3 ; original byte CC, padding
0x265c8e: INT3 ; original byte CC, padding
0x265c8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c90 [0x265c90, 0x265c94] | file +0x588 | ev_bda1c7672eafac7c695ffd553b29b18e662a3681aa39f879c1bb0c52ae1c896d
thunk_265c90:
0x265c90: JMP 0x008fafa0
; END FUNCTION thunk_265c90
0x265c95: INT3 ; original byte CC, padding
0x265c96: INT3 ; original byte CC, padding
0x265c97: INT3 ; original byte CC, padding

; FUNCTION thunk_265c98 [0x265c98, 0x265c9c] | file +0x590 | ev_78454f2614f7a8c5aa0ce1cc9f62c1aa06794fd78c8d46cb05f945f619e752d6
thunk_265c98:
0x265c98: JMP 0x004ecf20
; END FUNCTION thunk_265c98
0x265c9d: INT3 ; original byte CC, padding
0x265c9e: INT3 ; original byte CC, padding
0x265c9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ca0 [0x265ca0, 0x265ca4] | file +0x598 | ev_260b63cf8aaa76d66b218e0f85b6398abb5808a76e2f61128df3ff7e757ecae0
thunk_265ca0:
0x265ca0: JMP 0x004386f0
; END FUNCTION thunk_265ca0
0x265ca5: INT3 ; original byte CC, padding
0x265ca6: INT3 ; original byte CC, padding
0x265ca7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ca8 [0x265ca8, 0x265cac] | file +0x5a0 | ev_ff272acd78e9f5676eecf4bdd04b9434bee5314e6ff5aa418a1d299d01201bb5
thunk_265ca8:
0x265ca8: JMP 0x0080d740
; END FUNCTION thunk_265ca8
0x265cad: INT3 ; original byte CC, padding
0x265cae: INT3 ; original byte CC, padding
0x265caf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cb0 [0x265cb0, 0x265cb4] | file +0x5a8 | ev_6f1a3bda27ebdb29a3f400241102983207b2bfad15583ecd4555d9330af029ed
thunk_265cb0:
0x265cb0: JMP 0x0080dbd0
; END FUNCTION thunk_265cb0
0x265cb5: INT3 ; original byte CC, padding
0x265cb6: INT3 ; original byte CC, padding
0x265cb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cb8 [0x265cb8, 0x265cbc] | file +0x5b0 | ev_e1fa139b401f6c9470b4fa81c12a54c9a5f32c84d99ca333038c5ed29ad90765
thunk_265cb8:
0x265cb8: JMP 0x0083d830
; END FUNCTION thunk_265cb8
0x265cbd: INT3 ; original byte CC, padding
0x265cbe: INT3 ; original byte CC, padding
0x265cbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cc0 [0x265cc0, 0x265cc4] | file +0x5b8 | ev_a8e7b48f6f0f8d93bd1602d0953c8af3f8fdd570ad0089e5fd0e55eab5ed37b8
thunk_265cc0:
0x265cc0: JMP 0x0083de60
; END FUNCTION thunk_265cc0
0x265cc5: INT3 ; original byte CC, padding
0x265cc6: INT3 ; original byte CC, padding
0x265cc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cc8 [0x265cc8, 0x265ccc] | file +0x5c0 | ev_88c2cc843bca285bfdccb1db75a05ab3b1a284ae03f9a895638b74e0eddca2ac
thunk_265cc8:
0x265cc8: JMP 0x0083e320
; END FUNCTION thunk_265cc8
0x265ccd: INT3 ; original byte CC, padding
0x265cce: INT3 ; original byte CC, padding
0x265ccf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cd0 [0x265cd0, 0x265cd4] | file +0x5c8 | ev_f750b507c4e2d19e5d98f168eeeb8418fecfabdb7a02fc8699620ec54d8bdb56
thunk_265cd0:
0x265cd0: JMP 0x008f6e50
; END FUNCTION thunk_265cd0
0x265cd5: INT3 ; original byte CC, padding
0x265cd6: INT3 ; original byte CC, padding
0x265cd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cd8 [0x265cd8, 0x265cdc] | file +0x5d0 | ev_6eeb7e7ddd34548c87c2bdde79cfe3f25d5b61dd128d96f044c33c798a9b1c6c
thunk_265cd8:
0x265cd8: JMP 0x0049b0b0
; END FUNCTION thunk_265cd8
0x265cdd: INT3 ; original byte CC, padding
0x265cde: INT3 ; original byte CC, padding
0x265cdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ce0 [0x265ce0, 0x265ce4] | file +0x5d8 | ev_955b59f34dcc82d326f8019b5a4ef7d192713861deb00f603f64834614e2f0db
thunk_265ce0:
0x265ce0: JMP 0x004ed3c0
; END FUNCTION thunk_265ce0
0x265ce5: INT3 ; original byte CC, padding
0x265ce6: INT3 ; original byte CC, padding
0x265ce7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ce8 [0x265ce8, 0x265cec] | file +0x5e0 | ev_ddd096685219d6ca376c0ace419e984924567abf06917bc2cdfb8084533d37cf
thunk_265ce8:
0x265ce8: JMP 0x00af0040
; END FUNCTION thunk_265ce8
0x265ced: INT3 ; original byte CC, padding
0x265cee: INT3 ; original byte CC, padding
0x265cef: INT3 ; original byte CC, padding

; FUNCTION thunk_265cf0 [0x265cf0, 0x265cf4] | file +0x5e8 | ev_eb3f8a47c49ea4c24498ce29ef78200d49662ce3715f6d19d2959697e1e145d3
thunk_265cf0:
0x265cf0: JMP 0x00705880
; END FUNCTION thunk_265cf0
0x265cf5: INT3 ; original byte CC, padding
0x265cf6: INT3 ; original byte CC, padding
0x265cf7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cf8 [0x265cf8, 0x265cfc] | file +0x5f0 | ev_11ce4b2a7e8dafd791795576150b7e1fbf7fc1d3e8daa84958e281d2f2f0500a
thunk_265cf8:
0x265cf8: JMP 0x00705c60
; END FUNCTION thunk_265cf8
0x265cfd: INT3 ; original byte CC, padding
0x265cfe: INT3 ; original byte CC, padding
0x265cff: INT3 ; original byte CC, padding

; FUNCTION thunk_265d00 [0x265d00, 0x265d04] | file +0x5f8 | ev_da3f4081ffd1cca782d99510df16611df388a87eebce2f5108c2fa7c8173b36a
thunk_265d00:
0x265d00: JMP 0x004f65f0
; END FUNCTION thunk_265d00
0x265d05: INT3 ; original byte CC, padding
0x265d06: INT3 ; original byte CC, padding
0x265d07: INT3 ; original byte CC, padding

; FUNCTION thunk_265d08 [0x265d08, 0x265d0c] | file +0x600 | ev_91f3053d25aad314c50b29f764dc1a5ac85bdd695d16fb9c87e18cc475c3e9f0
thunk_265d08:
0x265d08: JMP 0x004f6a70
; END FUNCTION thunk_265d08
0x265d0d: INT3 ; original byte CC, padding
0x265d0e: INT3 ; original byte CC, padding
0x265d0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d10 [0x265d10, 0x265d14] | file +0x608 | ev_141bedc32617e72efe65c1855a21c5bc10119939626978056e0e307ade7c92a3
thunk_265d10:
0x265d10: JMP 0x00bafa80
; END FUNCTION thunk_265d10
0x265d15: INT3 ; original byte CC, padding
0x265d16: INT3 ; original byte CC, padding
0x265d17: INT3 ; original byte CC, padding

; FUNCTION thunk_265d18 [0x265d18, 0x265d1c] | file +0x610 | ev_b24101c8493214775072a4b243b882c271212957cc7bac7568a9482b23581da1
thunk_265d18:
0x265d18: JMP 0x00bafcf0
; END FUNCTION thunk_265d18
0x265d1d: INT3 ; original byte CC, padding
0x265d1e: INT3 ; original byte CC, padding
0x265d1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d20 [0x265d20, 0x265d24] | file +0x618 | ev_3f2696dc3468757284ec2bbccc5407f8851ad569f6a2098b096e4c156360a8f2
thunk_265d20:
0x265d20: JMP 0x00bb0330
; END FUNCTION thunk_265d20
0x265d25: INT3 ; original byte CC, padding
0x265d26: INT3 ; original byte CC, padding
0x265d27: INT3 ; original byte CC, padding

; FUNCTION thunk_265d28 [0x265d28, 0x265d2c] | file +0x620 | ev_9e1a530419c38b63f1c5c7f52f378f12933697777c29a2da5b9ab03f35a25121
thunk_265d28:
0x265d28: JMP 0x00bb0490
; END FUNCTION thunk_265d28
0x265d2d: INT3 ; original byte CC, padding
0x265d2e: INT3 ; original byte CC, padding
0x265d2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d30 [0x265d30, 0x265d34] | file +0x628 | ev_017269beca73fffa4d0e24415f9e851d880f86cbab93db9eca9ee4b129e29848
thunk_265d30:
0x265d30: JMP 0x00bafe50
; END FUNCTION thunk_265d30
0x265d35: INT3 ; original byte CC, padding
0x265d36: INT3 ; original byte CC, padding
0x265d37: INT3 ; original byte CC, padding

; FUNCTION thunk_265d38 [0x265d38, 0x265d3c] | file +0x630 | ev_7e8aa0703fa40d1dc25c26b650facf9165e8413fb00e01a9cb67b371c16e4761
thunk_265d38:
0x265d38: JMP 0x00bb0030
; END FUNCTION thunk_265d38
0x265d3d: INT3 ; original byte CC, padding
0x265d3e: INT3 ; original byte CC, padding
0x265d3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d40 [0x265d40, 0x265d44] | file +0x638 | ev_c6bd5b3b4689c932c0734de76323ffb6e492cd71b7f45059a8ee63b1b8c956c9
thunk_265d40:
0x265d40: JMP 0x00bb0150
; END FUNCTION thunk_265d40
0x265d45: INT3 ; original byte CC, padding
0x265d46: INT3 ; original byte CC, padding
0x265d47: INT3 ; original byte CC, padding

; FUNCTION thunk_265d48 [0x265d48, 0x265d4c] | file +0x640 | ev_139615a2fdde2cf350858d9f99c761a3bffb85be8daeae5c86b4510bc7b09c47
thunk_265d48:
0x265d48: JMP 0x00bb01d0
; END FUNCTION thunk_265d48
0x265d4d: INT3 ; original byte CC, padding
0x265d4e: INT3 ; original byte CC, padding
0x265d4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d50 [0x265d50, 0x265d54] | file +0x648 | ev_8e719955e834476320223e8cef9d48b6df5226ae75bcb7e95f0b800f19159d18
thunk_265d50:
0x265d50: JMP 0x00bb0280
; END FUNCTION thunk_265d50
0x265d55: INT3 ; original byte CC, padding
0x265d56: INT3 ; original byte CC, padding
0x265d57: INT3 ; original byte CC, padding

; FUNCTION thunk_265d58 [0x265d58, 0x265d5c] | file +0x650 | ev_572d12d696e0f9e3cebbf9442f0836c3e6d0e75fa7911b310cd02e3443ebaddd
thunk_265d58:
0x265d58: JMP 0x00aba540
; END FUNCTION thunk_265d58
0x265d5d: INT3 ; original byte CC, padding
0x265d5e: INT3 ; original byte CC, padding
0x265d5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d60 [0x265d60, 0x265d64] | file +0x658 | ev_cd34b10aeff44368d17a22690ff8671d8217d50f3346247d9fa38371455636fe
thunk_265d60:
0x265d60: JMP 0x00abbe60
; END FUNCTION thunk_265d60
0x265d65: INT3 ; original byte CC, padding
0x265d66: INT3 ; original byte CC, padding
0x265d67: INT3 ; original byte CC, padding

; FUNCTION thunk_265d68 [0x265d68, 0x265d6c] | file +0x660 | ev_ee7d3692358008761769bce5e91ce6601167a43b7111c85cc4784ff8ad6d3bde
thunk_265d68:
0x265d68: JMP 0x00c16020
; END FUNCTION thunk_265d68
0x265d6d: INT3 ; original byte CC, padding
0x265d6e: INT3 ; original byte CC, padding
0x265d6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d70 [0x265d70, 0x265d74] | file +0x668 | ev_853d03a7b64b35632fb036feb750d9f78ec2536e8b530ba4ab6afc35d8f1d24d
thunk_265d70:
0x265d70: JMP 0x00c16270
; END FUNCTION thunk_265d70
0x265d75: INT3 ; original byte CC, padding
0x265d76: INT3 ; original byte CC, padding
0x265d77: INT3 ; original byte CC, padding

; FUNCTION thunk_265d78 [0x265d78, 0x265d7c] | file +0x670 | ev_470381e6a7ac04b89f9f77aa051e4885ac56ec195c7b436ac9ad7c5e0046851e
thunk_265d78:
0x265d78: JMP 0x00c16720
; END FUNCTION thunk_265d78
0x265d7d: INT3 ; original byte CC, padding
0x265d7e: INT3 ; original byte CC, padding
0x265d7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d80 [0x265d80, 0x265d84] | file +0x678 | ev_b3a359056b1cc38b9cfdd428c2a96dceba507535f64dfe81267ffcc5df21a579
thunk_265d80:
0x265d80: JMP 0x00c16880
; END FUNCTION thunk_265d80
0x265d85: INT3 ; original byte CC, padding
0x265d86: INT3 ; original byte CC, padding
0x265d87: INT3 ; original byte CC, padding

; FUNCTION thunk_265d88 [0x265d88, 0x265d8c] | file +0x680 | ev_cda830d9a5b4a90b869dad8f56aaf69560ea49a89ebde10424aa99d79655dcef
thunk_265d88:
0x265d88: JMP 0x00c163d0
; END FUNCTION thunk_265d88
0x265d8d: INT3 ; original byte CC, padding
0x265d8e: INT3 ; original byte CC, padding
0x265d8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d90 [0x265d90, 0x265d94] | file +0x688 | ev_4ea4d752366a09794902acd3fe0b4bd1ce883c98227d2b06608bfaf43c6cf3ac
thunk_265d90:
0x265d90: JMP 0x00c164f0
; END FUNCTION thunk_265d90
0x265d95: INT3 ; original byte CC, padding
0x265d96: INT3 ; original byte CC, padding
0x265d97: INT3 ; original byte CC, padding

; FUNCTION thunk_265d98 [0x265d98, 0x265d9c] | file +0x690 | ev_67145635d96053dc90aef304f72ee68efa38f57d726896667daf6347ff26cf97
thunk_265d98:
0x265d98: JMP 0x00c165d0
; END FUNCTION thunk_265d98
0x265d9d: INT3 ; original byte CC, padding
0x265d9e: INT3 ; original byte CC, padding
0x265d9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265da0 [0x265da0, 0x265da4] | file +0x698 | ev_b269cf020b1a2b49192d23123b900d40fdfd1262e814a7c11b1158bf584f301e
thunk_265da0:
0x265da0: JMP 0x00c16660
; END FUNCTION thunk_265da0
0x265da5: INT3 ; original byte CC, padding
0x265da6: INT3 ; original byte CC, padding
0x265da7: INT3 ; original byte CC, padding

; FUNCTION thunk_265da8 [0x265da8, 0x265dac] | file +0x6a0 | ev_8b66b6a15fdc1e32825941008d7389a84c5f3bfab207a8160af754f27c44ec26
thunk_265da8:
0x265da8: JMP 0x00ac7240
; END FUNCTION thunk_265da8
0x265dad: INT3 ; original byte CC, padding
0x265dae: INT3 ; original byte CC, padding
0x265daf: INT3 ; original byte CC, padding

; FUNCTION thunk_265db0 [0x265db0, 0x265db4] | file +0x6a8 | ev_caa1cbb55e05df95cb7a1c0ce004a24f59594389be3f808e779476ba59b0e12d
thunk_265db0:
0x265db0: JMP 0x00ac73c0
; END FUNCTION thunk_265db0
0x265db5: INT3 ; original byte CC, padding
0x265db6: INT3 ; original byte CC, padding
0x265db7: INT3 ; original byte CC, padding

; FUNCTION thunk_265db8 [0x265db8, 0x265dbc] | file +0x6b0 | ev_f72dc88d903f73c825320375b4c5b23400d62ed612ceea71d002d5806cc18bd5
thunk_265db8:
0x265db8: JMP 0x00abc510
; END FUNCTION thunk_265db8
0x265dbd: INT3 ; original byte CC, padding
0x265dbe: INT3 ; original byte CC, padding
0x265dbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265dc0 [0x265dc0, 0x265dc4] | file +0x6b8 | ev_df8ffb00941eaaf1b014b9d6c1debb830d74d4b57a56dfe8ab7727dd09742b59
thunk_265dc0:
0x265dc0: JMP 0x004f5e60
; END FUNCTION thunk_265dc0
0x265dc5: INT3 ; original byte CC, padding
0x265dc6: INT3 ; original byte CC, padding
0x265dc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265dc8 [0x265dc8, 0x265dcc] | file +0x6c0 | ev_b994f7e6a252748c518087af66f7152ad8d94eabf90061c7d242006164705cd4
thunk_265dc8:
0x265dc8: JMP 0x00602fe0
; END FUNCTION thunk_265dc8
0x265dcd: INT3 ; original byte CC, padding
0x265dce: INT3 ; original byte CC, padding
0x265dcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265dd0 [0x265dd0, 0x265dd4] | file +0x6c8 | ev_b9500ecd1e28f4f0264d22e68110cfb13a646405f1b50760c958118427d85260
thunk_265dd0:
0x265dd0: JMP 0x00603260
; END FUNCTION thunk_265dd0
0x265dd5: INT3 ; original byte CC, padding
0x265dd6: INT3 ; original byte CC, padding
0x265dd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265dd8 [0x265dd8, 0x265ddc] | file +0x6d0 | ev_7425e6bc0085d8c1456a00d22cd5d65cd23b05743dad6a46e24781fb3e860bda
thunk_265dd8:
0x265dd8: JMP 0x006034e0
; END FUNCTION thunk_265dd8
0x265ddd: INT3 ; original byte CC, padding
0x265dde: INT3 ; original byte CC, padding
0x265ddf: INT3 ; original byte CC, padding

; FUNCTION thunk_265de0 [0x265de0, 0x265de4] | file +0x6d8 | ev_c756130153707d47e6f24f71ad62949a6e53f64ef061495df5aa42fa423d1347
thunk_265de0:
0x265de0: JMP 0x00603710
; END FUNCTION thunk_265de0
0x265de5: INT3 ; original byte CC, padding
0x265de6: INT3 ; original byte CC, padding
0x265de7: INT3 ; original byte CC, padding

; FUNCTION thunk_265de8 [0x265de8, 0x265dec] | file +0x6e0 | ev_dd794267e63b1a5d75db5ef8f5a9ec6ac215c996345f89df19f48e44500dbd91
thunk_265de8:
0x265de8: JMP 0x006039d0
; END FUNCTION thunk_265de8
0x265ded: INT3 ; original byte CC, padding
0x265dee: INT3 ; original byte CC, padding
0x265def: INT3 ; original byte CC, padding

; FUNCTION thunk_265df0 [0x265df0, 0x265df4] | file +0x6e8 | ev_53445b4101b0607d7f53ee9f9b9f829a516dfcc063bd5e9678540b6141875405
thunk_265df0:
0x265df0: JMP 0x00abac50
; END FUNCTION thunk_265df0
0x265df5: INT3 ; original byte CC, padding
0x265df6: INT3 ; original byte CC, padding
0x265df7: INT3 ; original byte CC, padding

; FUNCTION thunk_265df8 [0x265df8, 0x265dfc] | file +0x6f0 | ev_9053ea6113d1fcbce07ea7bc6c773a1d6f872daaa256ef7f8d5d773b8df8a05f
thunk_265df8:
0x265df8: JMP 0x008fc610
; END FUNCTION thunk_265df8
0x265dfd: INT3 ; original byte CC, padding
0x265dfe: INT3 ; original byte CC, padding
0x265dff: INT3 ; original byte CC, padding

; FUNCTION thunk_265e00 [0x265e00, 0x265e04] | file +0x6f8 | ev_2d379c587a389af961b4e370bc502d7a019631a3244916178756499037519ad1
thunk_265e00:
0x265e00: JMP 0x004e1a70
; END FUNCTION thunk_265e00
0x265e05: INT3 ; original byte CC, padding
0x265e06: INT3 ; original byte CC, padding
0x265e07: INT3 ; original byte CC, padding

; FUNCTION thunk_265e08 [0x265e08, 0x265e0c] | file +0x700 | ev_722615ccce74c58107e60906b1e967da2cf0d8bcd78bf5b3a5b0de5a214caa92
thunk_265e08:
0x265e08: JMP 0x00abc5f0
; END FUNCTION thunk_265e08
0x265e0d: INT3 ; original byte CC, padding
0x265e0e: INT3 ; original byte CC, padding
0x265e0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e10 [0x265e10, 0x265e14] | file +0x708 | ev_37aca5cf7d1c28c8bf849e9f04e45dfb04b41d726aaf5258a5d30105bdb04598
thunk_265e10:
0x265e10: JMP 0x00a367e0
; END FUNCTION thunk_265e10
0x265e15: INT3 ; original byte CC, padding
0x265e16: INT3 ; original byte CC, padding
0x265e17: INT3 ; original byte CC, padding

; FUNCTION thunk_265e18 [0x265e18, 0x265e1c] | file +0x710 | ev_43884718e58292c832ea8a998b28d3eebdf76b31de0e8e8b295848bcb18f19c2
thunk_265e18:
0x265e18: JMP 0x00ca0630
; END FUNCTION thunk_265e18
0x265e1d: INT3 ; original byte CC, padding
0x265e1e: INT3 ; original byte CC, padding
0x265e1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e20 [0x265e20, 0x265e24] | file +0x718 | ev_d1bafefb5ca66c2b59f724e32941436f01a1d668cb2dcf44bb98e501c91513bb
thunk_265e20:
0x265e20: JMP 0x00a368e0
; END FUNCTION thunk_265e20
0x265e25: INT3 ; original byte CC, padding
0x265e26: INT3 ; original byte CC, padding
0x265e27: INT3 ; original byte CC, padding

; FUNCTION thunk_265e28 [0x265e28, 0x265e2c] | file +0x720 | ev_76740d04bd0fa44e04809a29e736e4d4de8c1aa42303e07fba3012a1ad03f667
thunk_265e28:
0x265e28: JMP 0x0072ecc0
; END FUNCTION thunk_265e28
0x265e2d: INT3 ; original byte CC, padding
0x265e2e: INT3 ; original byte CC, padding
0x265e2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e30 [0x265e30, 0x265e34] | file +0x728 | ev_5b470392df3096545b35171d8830430e529dc2885ed7fd63673b636ec696f9f9
thunk_265e30:
0x265e30: JMP 0x004f7370
; END FUNCTION thunk_265e30
0x265e35: INT3 ; original byte CC, padding
0x265e36: INT3 ; original byte CC, padding
0x265e37: INT3 ; original byte CC, padding

; FUNCTION thunk_265e38 [0x265e38, 0x265e3c] | file +0x730 | ev_6f9f1ce71e9ea4c394db6586515d83d76fa68b271bc3da58988e7910cbc2fb54
thunk_265e38:
0x265e38: JMP 0x00a36b00
; END FUNCTION thunk_265e38
0x265e3d: INT3 ; original byte CC, padding
0x265e3e: INT3 ; original byte CC, padding
0x265e3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e40 [0x265e40, 0x265e44] | file +0x738 | ev_ef143793367f3451c5a8e0bdc8eb37f1f6c13b48c2e7c0e098d30077555b904d
thunk_265e40:
0x265e40: JMP 0x00a36b90
; END FUNCTION thunk_265e40
0x265e45: INT3 ; original byte CC, padding
0x265e46: INT3 ; original byte CC, padding
0x265e47: INT3 ; original byte CC, padding

; FUNCTION thunk_265e48 [0x265e48, 0x265e4c] | file +0x740 | ev_2f42ab8d4c7f316be09068c535ab8450158592cf54991840e19304610d5a1d07
thunk_265e48:
0x265e48: JMP 0x00abc710
; END FUNCTION thunk_265e48
0x265e4d: INT3 ; original byte CC, padding
0x265e4e: INT3 ; original byte CC, padding
0x265e4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e50 [0x265e50, 0x265e54] | file +0x748 | ev_85c7b01fc12753dce03c87eee1509d51a78a63de5f53132f6e6614707b3c8db5
thunk_265e50:
0x265e50: JMP 0x005a7f60
; END FUNCTION thunk_265e50
0x265e55: INT3 ; original byte CC, padding
0x265e56: INT3 ; original byte CC, padding
0x265e57: INT3 ; original byte CC, padding

; FUNCTION thunk_265e58 [0x265e58, 0x265e5c] | file +0x750 | ev_df8ea304f646c11a583b14aae4ca1a483f4782e1e9354dce034d074761991e9d
thunk_265e58:
0x265e58: JMP 0x00a36bc0
; END FUNCTION thunk_265e58
0x265e5d: INT3 ; original byte CC, padding
0x265e5e: INT3 ; original byte CC, padding
0x265e5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e60 [0x265e60, 0x265e64] | file +0x758 | ev_6198524f60231153a0e06f7b2780b66fc77694781b03b7891c043a5d885ab756
thunk_265e60:
0x265e60: JMP 0x00abca10
; END FUNCTION thunk_265e60
0x265e65: INT3 ; original byte CC, padding
0x265e66: INT3 ; original byte CC, padding
0x265e67: INT3 ; original byte CC, padding

; FUNCTION thunk_265e68 [0x265e68, 0x265e6c] | file +0x760 | ev_8623a41ef8f18a1433f4d8d8d8c4ae56a20bc22464b1afdd5e3060271c537bb3
thunk_265e68:
0x265e68: JMP 0x00abcc00
; END FUNCTION thunk_265e68
0x265e6d: INT3 ; original byte CC, padding
0x265e6e: INT3 ; original byte CC, padding
0x265e6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e70 [0x265e70, 0x265e74] | file +0x768 | ev_4b8b732890c7585fee162dd206d6db0bca27e0c19731e4fc6697ccd7f847c1bf
thunk_265e70:
0x265e70: JMP 0x00438c90
; END FUNCTION thunk_265e70
0x265e75: INT3 ; original byte CC, padding
0x265e76: INT3 ; original byte CC, padding
0x265e77: INT3 ; original byte CC, padding

; FUNCTION thunk_265e78 [0x265e78, 0x265e7c] | file +0x770 | ev_1768279b2851f65325ade262735a2b5161d0b00c0cb0153a8119e17cfac138e3
thunk_265e78:
0x265e78: JMP 0x008d2570
; END FUNCTION thunk_265e78
0x265e7d: INT3 ; original byte CC, padding
0x265e7e: INT3 ; original byte CC, padding
0x265e7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e80 [0x265e80, 0x265e84] | file +0x778 | ev_4d0dc7aa1e73570e5e303d05b62b42265a0a127393c36cc0ffb723f7e92ae586
thunk_265e80:
0x265e80: JMP 0x00abd0f0
; END FUNCTION thunk_265e80
0x265e85: INT3 ; original byte CC, padding
0x265e86: INT3 ; original byte CC, padding
0x265e87: INT3 ; original byte CC, padding

; FUNCTION thunk_265e88 [0x265e88, 0x265e8c] | file +0x780 | ev_327b227bd6c213499654b0860aa855d48da53a03261343aaf271ac55682e0e1b
thunk_265e88:
0x265e88: JMP 0x00a37650
; END FUNCTION thunk_265e88
0x265e8d: INT3 ; original byte CC, padding
0x265e8e: INT3 ; original byte CC, padding
0x265e8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e90 [0x265e90, 0x265e94] | file +0x788 | ev_c570d0bb05504dfdb65b965e7ab8343f01e31ce22848c7beb6085619a0f039d1
thunk_265e90:
0x265e90: JMP 0x00abd430
; END FUNCTION thunk_265e90
0x265e95: INT3 ; original byte CC, padding
0x265e96: INT3 ; original byte CC, padding
0x265e97: INT3 ; original byte CC, padding

; FUNCTION thunk_265e98 [0x265e98, 0x265e9c] | file +0x790 | ev_9f8fcd7e7582e90f4ae8d10d3700626945970635f835f002c08ae61b8aef4e2c
thunk_265e98:
0x265e98: JMP 0x007dcd40
; END FUNCTION thunk_265e98
0x265e9d: INT3 ; original byte CC, padding
0x265e9e: INT3 ; original byte CC, padding
0x265e9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ea0 [0x265ea0, 0x265ea4] | file +0x798 | ev_5d32621c61a283e9ed381e98bbdc04f8f8e60e693addd2854e40ea89656581d7
thunk_265ea0:
0x265ea0: JMP 0x008d25a0
; END FUNCTION thunk_265ea0
0x265ea5: INT3 ; original byte CC, padding
0x265ea6: INT3 ; original byte CC, padding
0x265ea7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ea8 [0x265ea8, 0x265eac] | file +0x7a0 | ev_581d77043fca64b9008dbb77b35ef67701738522ff4a29c87647c8175679d453
thunk_265ea8:
0x265ea8: JMP 0x00abd4f0
; END FUNCTION thunk_265ea8
0x265ead: INT3 ; original byte CC, padding
0x265eae: INT3 ; original byte CC, padding
0x265eaf: INT3 ; original byte CC, padding

; FUNCTION thunk_265eb0 [0x265eb0, 0x265eb4] | file +0x7a8 | ev_98633b69352d8d9e092c2f8a57ed6c394087995b60f18753830b9031469b16fb
thunk_265eb0:
0x265eb0: JMP 0x00603c90
; END FUNCTION thunk_265eb0
0x265eb5: INT3 ; original byte CC, padding
0x265eb6: INT3 ; original byte CC, padding
0x265eb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265eb8 [0x265eb8, 0x265ebc] | file +0x7b0 | ev_cab9ba7fa07157798e9f5cadc43dcf8c8285cfde5e57ed64baa9330bdb4b3364
thunk_265eb8:
0x265eb8: JMP 0x00604cf0
; END FUNCTION thunk_265eb8
0x265ebd: INT3 ; original byte CC, padding
0x265ebe: INT3 ; original byte CC, padding
0x265ebf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ec0 [0x265ec0, 0x265ec4] | file +0x7b8 | ev_cac1613c2427686035e9e95ee09e19b96ec40c6b3c8b1ebaece49035e0658fe3
thunk_265ec0:
0x265ec0: JMP 0x004a2850
; END FUNCTION thunk_265ec0
0x265ec5: INT3 ; original byte CC, padding
0x265ec6: INT3 ; original byte CC, padding
0x265ec7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ec8 [0x265ec8, 0x265ecc] | file +0x7c0 | ev_b54802e9cb78880b4fcd87bbbf1e79334bfe9d710c70defaf9d16dcf467d49e5
thunk_265ec8:
0x265ec8: JMP 0x00abd540
; END FUNCTION thunk_265ec8
0x265ecd: INT3 ; original byte CC, padding
0x265ece: INT3 ; original byte CC, padding
0x265ecf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ed0 [0x265ed0, 0x265ed4] | file +0x7c8 | ev_b4dff738d0aa6573e8ba8ee944a868d36f40233c03506de9cd019889e249d2ae
thunk_265ed0:
0x265ed0: JMP 0x0091c640
; END FUNCTION thunk_265ed0
0x265ed5: INT3 ; original byte CC, padding
0x265ed6: INT3 ; original byte CC, padding
0x265ed7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ed8 [0x265ed8, 0x265edc] | file +0x7d0 | ev_2ca4a5aae0e3cb568cb359f5a033eb6c099fe6e02d90047fe6e63bfdb4e4e39a
thunk_265ed8:
0x265ed8: JMP 0x0091cc70
; END FUNCTION thunk_265ed8
0x265edd: INT3 ; original byte CC, padding
0x265ede: INT3 ; original byte CC, padding
0x265edf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ee0 [0x265ee0, 0x265ee4] | file +0x7d8 | ev_d6cb9b9d3c6df35bf074ba1290f1451b1704e84cbd4f89e4635d0a2f9a7f33cf
thunk_265ee0:
0x265ee0: JMP 0x00438e30
; END FUNCTION thunk_265ee0
0x265ee5: INT3 ; original byte CC, padding
0x265ee6: INT3 ; original byte CC, padding
0x265ee7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ee8 [0x265ee8, 0x265eec] | file +0x7e0 | ev_17e3eae79b71b98f1e0494ebf42f465c42d9d98f8fe67f6e80e7a8148ca93d38
thunk_265ee8:
0x265ee8: JMP 0x00439070
; END FUNCTION thunk_265ee8
0x265eed: INT3 ; original byte CC, padding
0x265eee: INT3 ; original byte CC, padding
0x265eef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ef0 [0x265ef0, 0x265ef4] | file +0x7e8 | ev_3d7f77fcd4287dd192f950799646d851d1d0457ce890de81f01f63e41251b5ee
thunk_265ef0:
0x265ef0: JMP 0x00439150
; END FUNCTION thunk_265ef0
0x265ef5: INT3 ; original byte CC, padding
0x265ef6: INT3 ; original byte CC, padding
0x265ef7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ef8 [0x265ef8, 0x265efc] | file +0x7f0 | ev_a4235e90b5a1ccc8ef061ee289bbbd9ef9237b96b7d7228147c2913d89618ad1
thunk_265ef8:
0x265ef8: JMP 0x004393a0
; END FUNCTION thunk_265ef8
0x265efd: INT3 ; original byte CC, padding
0x265efe: INT3 ; original byte CC, padding
0x265eff: INT3 ; original byte CC, padding

; FUNCTION thunk_265f00 [0x265f00, 0x265f04] | file +0x7f8 | ev_23d77d4e06bbb9201cb88289fdc0b83e75b775d8a447532847bc445292f7ab97
thunk_265f00:
0x265f00: JMP 0x006be4d0
; END FUNCTION thunk_265f00
0x265f05: INT3 ; original byte CC, padding
0x265f06: INT3 ; original byte CC, padding
0x265f07: INT3 ; original byte CC, padding

; FUNCTION thunk_265f08 [0x265f08, 0x265f0c] | file +0x800 | ev_4a3d68654cb86cabcd329a43c71f0fce03f29fb5842108f0b2d34544c0e9902d
thunk_265f08:
0x265f08: JMP 0x00abd930
; END FUNCTION thunk_265f08
0x265f0d: INT3 ; original byte CC, padding
0x265f0e: INT3 ; original byte CC, padding
0x265f0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f10 [0x265f10, 0x265f14] | file +0x808 | ev_660c54ded613992dab25244ea16008eaafa9d5e79b9cf48de63fec28375f1716
thunk_265f10:
0x265f10: JMP 0x006be5c0
; END FUNCTION thunk_265f10
0x265f15: INT3 ; original byte CC, padding
0x265f16: INT3 ; original byte CC, padding
0x265f17: INT3 ; original byte CC, padding

; FUNCTION thunk_265f18 [0x265f18, 0x265f1c] | file +0x810 | ev_15b54fa76534d52deb873287223794be86b404d5facfe580439958524b83ae50
thunk_265f18:
0x265f18: JMP 0x006be800
; END FUNCTION thunk_265f18
0x265f1d: INT3 ; original byte CC, padding
0x265f1e: INT3 ; original byte CC, padding
0x265f1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f20 [0x265f20, 0x265f24] | file +0x818 | ev_afc3f4e0d4ec43c8cc6a116e19a7e52381c8ef5e786ddb343a6f23efaab97fda
thunk_265f20:
0x265f20: JMP 0x00a90e10
; END FUNCTION thunk_265f20
0x265f25: INT3 ; original byte CC, padding
0x265f26: INT3 ; original byte CC, padding
0x265f27: INT3 ; original byte CC, padding

; FUNCTION thunk_265f28 [0x265f28, 0x265f2c] | file +0x820 | ev_9554eb5c1b3cacc00bfb98e60ea7963298dc3f5f36e79f3bc6a971a0cf819738
thunk_265f28:
0x265f28: JMP 0x004a2de0
; END FUNCTION thunk_265f28
0x265f2d: INT3 ; original byte CC, padding
0x265f2e: INT3 ; original byte CC, padding
0x265f2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f30 [0x265f30, 0x265f34] | file +0x828 | ev_166a9b8a86592e83f4fb0f60fcac35a44507e80e51f768c7d42f07b667cfdb97
thunk_265f30:
0x265f30: JMP 0x00abdad0
; END FUNCTION thunk_265f30
0x265f35: INT3 ; original byte CC, padding
0x265f36: INT3 ; original byte CC, padding
0x265f37: INT3 ; original byte CC, padding

; FUNCTION thunk_265f38 [0x265f38, 0x265f3c] | file +0x830 | ev_9d6132a5187a9c01a46635876dc1bcee476c5ffc93037fc4a301ce043d948ba3
thunk_265f38:
0x265f38: JMP 0x00a37660
; END FUNCTION thunk_265f38
0x265f3d: INT3 ; original byte CC, padding
0x265f3e: INT3 ; original byte CC, padding
0x265f3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f40 [0x265f40, 0x265f44] | file +0x838 | ev_3d107f6f1eaf2f4090a9431586134de3e3b751f954de14e4d0a0f6bf88ce19b3
thunk_265f40:
0x265f40: JMP 0x00abe1c0
; END FUNCTION thunk_265f40
0x265f45: INT3 ; original byte CC, padding
0x265f46: INT3 ; original byte CC, padding
0x265f47: INT3 ; original byte CC, padding

; FUNCTION thunk_265f48 [0x265f48, 0x265f4c] | file +0x840 | ev_90e30bd2294293ce2a3416705c0cd745a1d6ba504f8bf45f007ccdacd3dfae05
thunk_265f48:
0x265f48: JMP 0x00abe7b0
; END FUNCTION thunk_265f48
0x265f4d: INT3 ; original byte CC, padding
0x265f4e: INT3 ; original byte CC, padding
0x265f4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f50 [0x265f50, 0x265f54] | file +0x848 | ev_7a6c201331064d4f27c60fe9598670d33c09a953fe0624a08f78c3e1d95d47ae
thunk_265f50:
0x265f50: JMP 0x009f81f0
; END FUNCTION thunk_265f50
0x265f55: INT3 ; original byte CC, padding
0x265f56: INT3 ; original byte CC, padding
0x265f57: INT3 ; original byte CC, padding

; FUNCTION thunk_265f58 [0x265f58, 0x265f5c] | file +0x850 | ev_a1eb78dbbdea733c5de2d066d4df609278988e5e0cd5eb75ce20ed31a730dfcc
thunk_265f58:
0x265f58: JMP 0x00be9510
; END FUNCTION thunk_265f58
0x265f5d: INT3 ; original byte CC, padding
0x265f5e: INT3 ; original byte CC, padding
0x265f5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f60 [0x265f60, 0x265f64] | file +0x858 | ev_3ce5dde8008e04c265e5bf4d50b808fd7dde164f1b953bc506e8957fea941364
thunk_265f60:
0x265f60: JMP 0x009a7d10
; END FUNCTION thunk_265f60
0x265f65: INT3 ; original byte CC, padding
0x265f66: INT3 ; original byte CC, padding
0x265f67: INT3 ; original byte CC, padding

; FUNCTION thunk_265f68 [0x265f68, 0x265f6c] | file +0x860 | ev_30fb1503914bfcc9ed442526904c06863c13c21f71c813cb207a809a8b26e288
thunk_265f68:
0x265f68: JMP 0x009a9560
; END FUNCTION thunk_265f68
0x265f6d: INT3 ; original byte CC, padding
0x265f6e: INT3 ; original byte CC, padding
0x265f6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f70 [0x265f70, 0x265f74] | file +0x868 | ev_5a722f62fadb8a29429713bcc4bb02986a139904c60356d3956a39654cd442c6
thunk_265f70:
0x265f70: JMP 0x009a9e10
; END FUNCTION thunk_265f70
0x265f75: INT3 ; original byte CC, padding
0x265f76: INT3 ; original byte CC, padding
0x265f77: INT3 ; original byte CC, padding

; FUNCTION thunk_265f78 [0x265f78, 0x265f7c] | file +0x870 | ev_bcf43827b5c2e17a463acbcf525c45f60b468982552d619865a6bfe7665a37ba
thunk_265f78:
0x265f78: JMP 0x009a9f40
; END FUNCTION thunk_265f78
0x265f7d: INT3 ; original byte CC, padding
0x265f7e: INT3 ; original byte CC, padding
0x265f7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f80 [0x265f80, 0x265f84] | file +0x878 | ev_dd33df4d2f9001ee6ac780697739b18182526436a92e50b0414b4999641f292f
thunk_265f80:
0x265f80: JMP 0x008fb440
; END FUNCTION thunk_265f80
0x265f85: INT3 ; original byte CC, padding
0x265f86: INT3 ; original byte CC, padding
0x265f87: INT3 ; original byte CC, padding

; FUNCTION thunk_265f88 [0x265f88, 0x265f8c] | file +0x880 | ev_ba2dc3f034d56072bd875df79ad909a59c7c7208e8624ef6ffed97aa89dffa93
thunk_265f88:
0x265f88: JMP 0x004a31a0
; END FUNCTION thunk_265f88
0x265f8d: INT3 ; original byte CC, padding
0x265f8e: INT3 ; original byte CC, padding
0x265f8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f90 [0x265f90, 0x265f94] | file +0x888 | ev_095469638dfbce825802a80d7715201dbce0a7c679a97b6a1a02cf82121354f8
thunk_265f90:
0x265f90: JMP 0x00abe8b0
; END FUNCTION thunk_265f90
0x265f95: INT3 ; original byte CC, padding
0x265f96: INT3 ; original byte CC, padding
0x265f97: INT3 ; original byte CC, padding

; FUNCTION thunk_265f98 [0x265f98, 0x265f9c] | file +0x890 | ev_fb01c7296a796c2556b1d847b82e434772757b61df9e17d6c416e7579607cada
thunk_265f98:
0x265f98: JMP 0x009ab1f0
; END FUNCTION thunk_265f98
0x265f9d: INT3 ; original byte CC, padding
0x265f9e: INT3 ; original byte CC, padding
0x265f9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa0 [0x265fa0, 0x265fa4] | file +0x898 | ev_a2e5f09fdea58579b0b34f882641d1c11784819e6375326f32636cf81033081a
thunk_265fa0:
0x265fa0: JMP 0x00abb980
; END FUNCTION thunk_265fa0
0x265fa5: INT3 ; original byte CC, padding
0x265fa6: INT3 ; original byte CC, padding
0x265fa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa8 [0x265fa8, 0x265fac] | file +0x8a0 | ev_007d1966682d3fb2830ab3ff5fd5f30a8b0c7a994a7cf0ab704ace1290990328
thunk_265fa8:
0x265fa8: JMP 0x006f92e0
; END FUNCTION thunk_265fa8
0x265fad: INT3 ; original byte CC, padding
0x265fae: INT3 ; original byte CC, padding
0x265faf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb0 [0x265fb0, 0x265fb4] | file +0x8a8 | ev_b5e3fe99e245a1f4fcac38bb44ae8ede96ce62ba89baa6e030602ac74cd4e2aa
thunk_265fb0:
0x265fb0: JMP 0x00434da0
; END FUNCTION thunk_265fb0
0x265fb5: INT3 ; original byte CC, padding
0x265fb6: INT3 ; original byte CC, padding
0x265fb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb8 [0x265fb8, 0x265fbc] | file +0x8b0 | ev_7672c80ba3199670ff9accf5f0a035019deb6746b16a3408477b03c96a6c5a59
thunk_265fb8:
0x265fb8: JMP 0x00434db0
; END FUNCTION thunk_265fb8
0x265fbd: INT3 ; original byte CC, padding
0x265fbe: INT3 ; original byte CC, padding
0x265fbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc0 [0x265fc0, 0x265fc4] | file +0x8b8 | ev_8e2240493a12bdc4b99dadf1ed7df42990082653e92f2ff14062831045d343e0
thunk_265fc0:
0x265fc0: JMP 0x00434dc0
; END FUNCTION thunk_265fc0
0x265fc5: INT3 ; original byte CC, padding
0x265fc6: INT3 ; original byte CC, padding
0x265fc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc8 [0x265fc8, 0x265fcc] | file +0x8c0 | ev_5bc36022326d27a478db45be2056e64d81fcc7129c079daca457659d2408596e
thunk_265fc8:
0x265fc8: JMP 0x00437d90
; END FUNCTION thunk_265fc8
0x265fcd: INT3 ; original byte CC, padding
0x265fce: INT3 ; original byte CC, padding
0x265fcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd0 [0x265fd0, 0x265fd4] | file +0x8c8 | ev_085d5e1e35ff8b5e66880ad7c2e04e4467175a4f31f04ebb7d9393cf13d3f1b3
thunk_265fd0:
0x265fd0: JMP 0x00438280
; END FUNCTION thunk_265fd0
0x265fd5: INT3 ; original byte CC, padding
0x265fd6: INT3 ; original byte CC, padding
0x265fd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd8 [0x265fd8, 0x265fdc] | file +0x8d0 | ev_4c12611f4973bb95e6930c4a8e7ef5dbbee03d57b570547f98eb8d209fab5390
thunk_265fd8:
0x265fd8: JMP 0x00ae6690
; END FUNCTION thunk_265fd8
0x265fdd: INT3 ; original byte CC, padding
0x265fde: INT3 ; original byte CC, padding
0x265fdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe0 [0x265fe0, 0x265fe4] | file +0x8d8 | ev_bf6dcc0bad4786ad10277760d33efbdb7edba577f48cb79630de67009f81ffcf
thunk_265fe0:
0x265fe0: JMP 0x00ae6580
; END FUNCTION thunk_265fe0
0x265fe5: INT3 ; original byte CC, padding
0x265fe6: INT3 ; original byte CC, padding
0x265fe7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe8 [0x265fe8, 0x265fec] | file +0x8e0 | ev_71ecfb830571598653e281d3aff5b493d821d784e85e4c6587c26283338629ed
thunk_265fe8:
0x265fe8: JMP 0x004490d0
; END FUNCTION thunk_265fe8
0x265fed: INT3 ; original byte CC, padding
0x265fee: INT3 ; original byte CC, padding
0x265fef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff0 [0x265ff0, 0x265ff4] | file +0x8e8 | ev_20d51f9828264b13131e9cc56afd8f93012bd4f3f0874f592b9469011c13f2d0
thunk_265ff0:
0x265ff0: JMP 0x000a6dc0
; END FUNCTION thunk_265ff0
0x265ff5: INT3 ; original byte CC, padding
0x265ff6: INT3 ; original byte CC, padding
0x265ff7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff8 [0x265ff8, 0x265ffc] | file +0x8f0 | ev_beeb742ebbf9feeea40159b7e4e9da77f11e0cb72de20fa239ab2205a287db21
thunk_265ff8:
0x265ff8: JMP 0x0044aa70
; END FUNCTION thunk_265ff8
0x265ffd: INT3 ; original byte CC, padding
0x265ffe: INT3 ; original byte CC, padding
0x265fff: INT3 ; original byte CC, padding

; FUNCTION thunk_266000 [0x266000, 0x266004] | file +0x8f8 | ev_13271d488428427b098ed29297bd6f0d51a9592c4538b98664e46709e6fc2237
thunk_266000:
0x266000: JMP 0x009b6110
; END FUNCTION thunk_266000
0x266005: INT3 ; original byte CC, padding
0x266006: INT3 ; original byte CC, padding
0x266007: INT3 ; original byte CC, padding

; FUNCTION thunk_266008 [0x266008, 0x26600c] | file +0x900 | ev_75bd3fb8ec5fe183e20e5f97247dd25019c7d16cd04af1302ee4213661395ea0
thunk_266008:
0x266008: JMP 0x000a7670
; END FUNCTION thunk_266008
0x26600d: INT3 ; original byte CC, padding
0x26600e: INT3 ; original byte CC, padding
0x26600f: INT3 ; original byte CC, padding

; FUNCTION thunk_266010 [0x266010, 0x266014] | file +0x908 | ev_9241eefa311a80deb03ac0f658ff745e258a28a4f5240ccd14c8c8025756bf71
thunk_266010:
0x266010: JMP 0x000a7850
; END FUNCTION thunk_266010
0x266015: INT3 ; original byte CC, padding
0x266016: INT3 ; original byte CC, padding
0x266017: INT3 ; original byte CC, padding

; FUNCTION thunk_266018 [0x266018, 0x26601c] | file +0x910 | ev_77e192304c9e51060989921f10742631b6c86945dea766a66cde5a5603ae5a03
thunk_266018:
0x266018: JMP 0x000a7880
; END FUNCTION thunk_266018
0x26601d: INT3 ; original byte CC, padding
0x26601e: INT3 ; original byte CC, padding
0x26601f: INT3 ; original byte CC, padding

; FUNCTION thunk_266020 [0x266020, 0x266024] | file +0x918 | ev_08817f0e48324fa1734eebf5afd693d461d4f25faa9a57614305dbeec79fe7c5
thunk_266020:
0x266020: JMP 0x00452040
; END FUNCTION thunk_266020
0x266025: INT3 ; original byte CC, padding
0x266026: INT3 ; original byte CC, padding
0x266027: INT3 ; original byte CC, padding

; FUNCTION thunk_266028 [0x266028, 0x26602c] | file +0x920 | ev_1e5a04d67b16d2fa526870e464a7a9b92615f08e45de21b528d6a0e169950e95
thunk_266028:
0x266028: JMP 0x00454cc0
; END FUNCTION thunk_266028
0x26602d: INT3 ; original byte CC, padding
0x26602e: INT3 ; original byte CC, padding
0x26602f: INT3 ; original byte CC, padding

; FUNCTION thunk_266030 [0x266030, 0x266034] | file +0x928 | ev_cc10ac34cdc34cc724edd95074b755226bea7e251a7b28ab616c70c7e7e3b6f6
thunk_266030:
0x266030: JMP 0x00457820
; END FUNCTION thunk_266030
0x266035: INT3 ; original byte CC, padding
0x266036: INT3 ; original byte CC, padding
0x266037: INT3 ; original byte CC, padding

; FUNCTION thunk_266038 [0x266038, 0x26603c] | file +0x930 | ev_67aa9e5fd76f1c965fc090011e512499a3a3b198c77aab350e1d0473784fea18
thunk_266038:
0x266038: JMP 0x0046df70
; END FUNCTION thunk_266038
0x26603d: INT3 ; original byte CC, padding
0x26603e: INT3 ; original byte CC, padding
0x26603f: INT3 ; original byte CC, padding

; FUNCTION thunk_266040 [0x266040, 0x266044] | file +0x938 | ev_0284f5842ab359d45c0563372236b145cdde7902ac94bd430f6a223a9830dcd7
thunk_266040:
0x266040: JMP 0x0046e080
; END FUNCTION thunk_266040
0x266045: INT3 ; original byte CC, padding
0x266046: INT3 ; original byte CC, padding
0x266047: INT3 ; original byte CC, padding

; FUNCTION thunk_266048 [0x266048, 0x26604c] | file +0x940 | ev_274829a26a30245653849082cc72e6e35fed236ce0bbdb3ec6faab0eada81538
thunk_266048:
0x266048: JMP 0x00472990
; END FUNCTION thunk_266048
0x26604d: INT3 ; original byte CC, padding
0x26604e: INT3 ; original byte CC, padding
0x26604f: INT3 ; original byte CC, padding

; FUNCTION thunk_266050 [0x266050, 0x266054] | file +0x948 | ev_ba4f7a680946cc24f7d64ad866a978721163a825432c7cf1640b506b2eb8784d
thunk_266050:
0x266050: JMP 0x004733b0
; END FUNCTION thunk_266050
0x266055: INT3 ; original byte CC, padding
0x266056: INT3 ; original byte CC, padding
0x266057: INT3 ; original byte CC, padding

; FUNCTION thunk_266058 [0x266058, 0x26605c] | file +0x950 | ev_8d6f5eab901c31a67905fdcd53e3dc1c0fbc315b09039f6f12e50ade27b3174e
thunk_266058:
0x266058: JMP 0x004738b0
; END FUNCTION thunk_266058
0x26605d: INT3 ; original byte CC, padding
0x26605e: INT3 ; original byte CC, padding
0x26605f: INT3 ; original byte CC, padding

; FUNCTION thunk_266060 [0x266060, 0x266064] | file +0x958 | ev_e8b4123b0dba35e5d807682900886d6e11de80f9778dd14c6f7aaba6269b6938
thunk_266060:
0x266060: JMP 0x00474250
; END FUNCTION thunk_266060
0x266065: INT3 ; original byte CC, padding
0x266066: INT3 ; original byte CC, padding
0x266067: INT3 ; original byte CC, padding

; FUNCTION thunk_266068 [0x266068, 0x26606c] | file +0x960 | ev_f75afc0429bb5c477bea05f362dc59833ce7113d6a65211ba6ab62563bdc61ad
thunk_266068:
0x266068: JMP 0x00474db0
; END FUNCTION thunk_266068
0x26606d: INT3 ; original byte CC, padding
0x26606e: INT3 ; original byte CC, padding
0x26606f: INT3 ; original byte CC, padding

; FUNCTION thunk_266070 [0x266070, 0x266074] | file +0x968 | ev_f2aa6b1b31f49271e828c16308725efe4f855d10cb85de9cff13f6cdbda35fb3
thunk_266070:
0x266070: JMP 0x0047cff0
; END FUNCTION thunk_266070
0x266075: INT3 ; original byte CC, padding
0x266076: INT3 ; original byte CC, padding
0x266077: INT3 ; original byte CC, padding

; FUNCTION thunk_266078 [0x266078, 0x26607c] | file +0x970 | ev_51642329c1bbde0e93e8dec02d8735898e1286b91137062d76126033999a3d32
thunk_266078:
0x266078: JMP 0x0021dff0
; END FUNCTION thunk_266078
0x26607d: INT3 ; original byte CC, padding
0x26607e: INT3 ; original byte CC, padding
0x26607f: INT3 ; original byte CC, padding

; FUNCTION thunk_266080 [0x266080, 0x266084] | file +0x978 | ev_813edcb664f5a4436816b054fe42fdbf47ba1bcffa004d50477f7cf091d814be
thunk_266080:
0x266080: JMP 0x00490300
; END FUNCTION thunk_266080
0x266085: INT3 ; original byte CC, padding
0x266086: INT3 ; original byte CC, padding
0x266087: INT3 ; original byte CC, padding

; FUNCTION thunk_266088 [0x266088, 0x26608c] | file +0x980 | ev_bb9d9eb4c7788123aa96c895346d74ee3fcfb19ec4015518bd51902322271c89
thunk_266088:
0x266088: JMP 0x00490db0
; END FUNCTION thunk_266088
0x26608d: INT3 ; original byte CC, padding
0x26608e: INT3 ; original byte CC, padding
0x26608f: INT3 ; original byte CC, padding

; FUNCTION thunk_266090 [0x266090, 0x266094] | file +0x988 | ev_5f37661cb7d598c9dc86a7cefc47d3cf985f370da26ca037d619cb73a5ca4b8e
thunk_266090:
0x266090: JMP 0x00497fb0
; END FUNCTION thunk_266090
0x266095: INT3 ; original byte CC, padding
0x266096: INT3 ; original byte CC, padding
0x266097: INT3 ; original byte CC, padding

; FUNCTION thunk_266098 [0x266098, 0x26609c] | file +0x990 | ev_228fbdbd5af4919e2970004de3681f60847a1febed9f5d2595709cbb8462d11b
thunk_266098:
0x266098: JMP 0x00497fe0
; END FUNCTION thunk_266098
0x26609d: INT3 ; original byte CC, padding
0x26609e: INT3 ; original byte CC, padding
0x26609f: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a0 [0x2660a0, 0x2660a4] | file +0x998 | ev_ed6831e278bd783f3be5cb487656b3e4fbd09e14c5253eef5c2f3bd4fd69d74e
thunk_2660a0:
0x2660a0: JMP 0x00498630
; END FUNCTION thunk_2660a0
0x2660a5: INT3 ; original byte CC, padding
0x2660a6: INT3 ; original byte CC, padding
0x2660a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a8 [0x2660a8, 0x2660ac] | file +0x9a0 | ev_c8ed06089cd894204da39e1cac0194ac9499dfa20bfb4873e4db9564a46f5e29
thunk_2660a8:
0x2660a8: JMP 0x00498640
; END FUNCTION thunk_2660a8
0x2660ad: INT3 ; original byte CC, padding
0x2660ae: INT3 ; original byte CC, padding
0x2660af: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b0 [0x2660b0, 0x2660b4] | file +0x9a8 | ev_2504a752eb3543760284d7669f69d99c6776905f0b697402ee78f8025cb45d24
thunk_2660b0:
0x2660b0: JMP 0x008f7bc0
; END FUNCTION thunk_2660b0
0x2660b5: INT3 ; original byte CC, padding
0x2660b6: INT3 ; original byte CC, padding
0x2660b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b8 [0x2660b8, 0x2660bc] | file +0x9b0 | ev_e75168b4c23bf70efaf2133494a544d5d58e397acbb367674bb96a93020a891b
thunk_2660b8:
0x2660b8: JMP 0x008f6800
; END FUNCTION thunk_2660b8
0x2660bd: INT3 ; original byte CC, padding
0x2660be: INT3 ; original byte CC, padding
0x2660bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c0 [0x2660c0, 0x2660c4] | file +0x9b8 | ev_da7e97c369a81ea579dcdd4063c45b34ce659b954f7474a798c98d18f5072f48
thunk_2660c0:
0x2660c0: JMP 0x008f7420
; END FUNCTION thunk_2660c0
0x2660c5: INT3 ; original byte CC, padding
0x2660c6: INT3 ; original byte CC, padding
0x2660c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c8 [0x2660c8, 0x2660cc] | file +0x9c0 | ev_757ca60740b8f73bb6ff2a575203849b790702722e8d4687c36fb07a63dc9d6a
thunk_2660c8:
0x2660c8: JMP 0x008f9f80
; END FUNCTION thunk_2660c8
0x2660cd: INT3 ; original byte CC, padding
0x2660ce: INT3 ; original byte CC, padding
0x2660cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d0 [0x2660d0, 0x2660d4] | file +0x9c8 | ev_b14e0cde435fef81d6524b07ab25a64c832dfa4e07ec4813d36cb68c5a2542e6
thunk_2660d0:
0x2660d0: JMP 0x005df350
; END FUNCTION thunk_2660d0
0x2660d5: INT3 ; original byte CC, padding
0x2660d6: INT3 ; original byte CC, padding
0x2660d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d8 [0x2660d8, 0x2660dc] | file +0x9d0 | ev_695ca4375c51c495d91c54720b2ee5edbe4646386d7bdf42b6f1f7f1096ab7aa
thunk_2660d8:
0x2660d8: JMP 0x005df820
; END FUNCTION thunk_2660d8
0x2660dd: INT3 ; original byte CC, padding
0x2660de: INT3 ; original byte CC, padding
0x2660df: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e0 [0x2660e0, 0x2660e4] | file +0x9d8 | ev_7b89d84bc17a972cb085dda05242e82715a0d3c4e9b5c80e1d1a10d3cf703d8e
thunk_2660e0:
0x2660e0: JMP 0x00a34ce0
; END FUNCTION thunk_2660e0
0x2660e5: INT3 ; original byte CC, padding
0x2660e6: INT3 ; original byte CC, padding
0x2660e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e8 [0x2660e8, 0x2660ec] | file +0x9e0 | ev_e88176bc6d92c2a8a7349783a3ea17eb1596a47cc8519ecba94f4b20c0525334
thunk_2660e8:
0x2660e8: JMP 0x005e84a0
; END FUNCTION thunk_2660e8
0x2660ed: INT3 ; original byte CC, padding
0x2660ee: INT3 ; original byte CC, padding
0x2660ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f0 [0x2660f0, 0x2660f4] | file +0x9e8 | ev_338488211248baab7b79b0818ed3b67f3ca1443ece0ee1265a6eecf7dd0d3ecd
thunk_2660f0:
0x2660f0: JMP 0x008f81f0
; END FUNCTION thunk_2660f0
0x2660f5: INT3 ; original byte CC, padding
0x2660f6: INT3 ; original byte CC, padding
0x2660f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f8 [0x2660f8, 0x2660fc] | file +0x9f0 | ev_7967a6f62a6c6d7ec9772ad9b5eac8becd562619cecab980b52874d1b54dca4b
thunk_2660f8:
0x2660f8: JMP 0x008f9410
; END FUNCTION thunk_2660f8
0x2660fd: INT3 ; original byte CC, padding
0x2660fe: INT3 ; original byte CC, padding
0x2660ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266100 [0x266100, 0x266104] | file +0x9f8 | ev_849951bba96cef9609da76002488e8a1d20f07ec9230cefd95bfb3ad861b36a1
thunk_266100:
0x266100: JMP 0x008fc3f0
; END FUNCTION thunk_266100
0x266105: INT3 ; original byte CC, padding
0x266106: INT3 ; original byte CC, padding
0x266107: INT3 ; original byte CC, padding

; FUNCTION thunk_266108 [0x266108, 0x26610c] | file +0xa00 | ev_1e6da3dff07fe59402a80c14648d04826df148070707dd9c0ef6a4e1fd74fafd
thunk_266108:
0x266108: JMP 0x008f6c90
; END FUNCTION thunk_266108
0x26610d: INT3 ; original byte CC, padding
0x26610e: INT3 ; original byte CC, padding
0x26610f: INT3 ; original byte CC, padding

; FUNCTION thunk_266110 [0x266110, 0x266114] | file +0xa08 | ev_d2c807990d94f945e00cd701e68c26292cb1e2009d73f8f84b655ea38e88c052
thunk_266110:
0x266110: JMP 0x00cb1a10
; END FUNCTION thunk_266110
0x266115: INT3 ; original byte CC, padding
0x266116: INT3 ; original byte CC, padding
0x266117: INT3 ; original byte CC, padding

; FUNCTION thunk_266118 [0x266118, 0x26611c] | file +0xa10 | ev_53472b939b20ba25a57ab4d91660139c63e4a4ba8839cddb43837794fa57e6e5
thunk_266118:
0x266118: JMP 0x00ab83a0
; END FUNCTION thunk_266118
0x26611d: INT3 ; original byte CC, padding
0x26611e: INT3 ; original byte CC, padding
0x26611f: INT3 ; original byte CC, padding

; FUNCTION thunk_266120 [0x266120, 0x266124] | file +0xa18 | ev_e3874429a2cd73930fad18d5594175104a6647df9411fdc9fdaba20f544869ac
thunk_266120:
0x266120: JMP 0x00ab83b0
; END FUNCTION thunk_266120
0x266125: INT3 ; original byte CC, padding
0x266126: INT3 ; original byte CC, padding
0x266127: INT3 ; original byte CC, padding

; FUNCTION thunk_266128 [0x266128, 0x26612c] | file +0xa20 | ev_9c8c416f951cb9e26ea8daf6254d67a2a2cb5f1e29a81b93155052ba74848071
thunk_266128:
0x266128: JMP 0x008fa1c0
; END FUNCTION thunk_266128
0x26612d: INT3 ; original byte CC, padding
0x26612e: INT3 ; original byte CC, padding
0x26612f: INT3 ; original byte CC, padding

; FUNCTION thunk_266130 [0x266130, 0x266134] | file +0xa28 | ev_f75fd383e35d1954533ca22638803f3c72f6a82546cd3a8ceccad79fa1daf4b7
thunk_266130:
0x266130: JMP 0x008f7b40
; END FUNCTION thunk_266130
0x266135: INT3 ; original byte CC, padding
0x266136: INT3 ; original byte CC, padding
0x266137: INT3 ; original byte CC, padding

; FUNCTION thunk_266138 [0x266138, 0x26613c] | file +0xa30 | ev_8207120065dabc5b19c2f962cda8ae9f598c7325173c735e6d269bcccae85a15
thunk_266138:
0x266138: JMP 0x004a0960
; END FUNCTION thunk_266138
0x26613d: INT3 ; original byte CC, padding
0x26613e: INT3 ; original byte CC, padding
0x26613f: INT3 ; original byte CC, padding

; FUNCTION thunk_266140 [0x266140, 0x266144] | file +0xa38 | ev_6d7cc7b56a7cd224e4e1ca39aa3c2a2d97be8d247b1b879fbe064c464bd07514
thunk_266140:
0x266140: JMP 0x00729780
; END FUNCTION thunk_266140
0x266145: INT3 ; original byte CC, padding
0x266146: INT3 ; original byte CC, padding
0x266147: INT3 ; original byte CC, padding

; FUNCTION thunk_266148 [0x266148, 0x26614c] | file +0xa40 | ev_62c7b086c5573b195bb72867047d219ff493c01e81f65173fdda18ed43941bca
thunk_266148:
0x266148: JMP 0x00729790
; END FUNCTION thunk_266148
0x26614d: INT3 ; original byte CC, padding
0x26614e: INT3 ; original byte CC, padding
0x26614f: INT3 ; original byte CC, padding

; FUNCTION thunk_266150 [0x266150, 0x266154] | file +0xa48 | ev_efe9729a0a63c617fe6c009276ba9db0563058f4462ea9ff1bd507ed71a70a62
thunk_266150:
0x266150: JMP 0x007297a0
; END FUNCTION thunk_266150
0x266155: INT3 ; original byte CC, padding
0x266156: INT3 ; original byte CC, padding
0x266157: INT3 ; original byte CC, padding

; FUNCTION thunk_266158 [0x266158, 0x26615c] | file +0xa50 | ev_b0621322d51d31fb36c314eb23a97a956aceffc0a88da9f9970a8a68d289a159
thunk_266158:
0x266158: JMP 0x006bb590
; END FUNCTION thunk_266158
0x26615d: INT3 ; original byte CC, padding
0x26615e: INT3 ; original byte CC, padding
0x26615f: INT3 ; original byte CC, padding

; FUNCTION thunk_266160 [0x266160, 0x266164] | file +0xa58 | ev_fcc1bfa009ab0ece3e52445710d3c3b56a294709c05cf127ebc6989ec52073a0
thunk_266160:
0x266160: JMP 0x00ab8da0
; END FUNCTION thunk_266160
0x266165: INT3 ; original byte CC, padding
0x266166: INT3 ; original byte CC, padding
0x266167: INT3 ; original byte CC, padding

; FUNCTION thunk_266168 [0x266168, 0x26616c] | file +0xa60 | ev_85fe954f6e700c0007bf50bcb5abe7fa8945362eb645e2117df19c1cb45cfd0f
thunk_266168:
0x266168: JMP 0x008fa170
; END FUNCTION thunk_266168
0x26616d: INT3 ; original byte CC, padding
0x26616e: INT3 ; original byte CC, padding
0x26616f: INT3 ; original byte CC, padding

; FUNCTION thunk_266170 [0x266170, 0x266174] | file +0xa68 | ev_c890e498bbcc6f8ac6e3e30792c03ca2289ba3e9f242a390489aa6aea5228cf5
thunk_266170:
0x266170: JMP 0x00b7f0c0
; END FUNCTION thunk_266170
0x266175: INT3 ; original byte CC, padding
0x266176: INT3 ; original byte CC, padding
0x266177: INT3 ; original byte CC, padding

; FUNCTION thunk_266178 [0x266178, 0x26617c] | file +0xa70 | ev_e1430f65ea8ac5404922d82f740706346a0b3b614afea6cb0d6d4ab94bd94f4d
thunk_266178:
0x266178: JMP 0x00b7f100
; END FUNCTION thunk_266178
0x26617d: INT3 ; original byte CC, padding
0x26617e: INT3 ; original byte CC, padding
0x26617f: INT3 ; original byte CC, padding

; FUNCTION thunk_266180 [0x266180, 0x266184] | file +0xa78 | ev_fd48f8dae2e01b6715b9a25b9598a63851195089c4d557d8e15a01f560b938a8
thunk_266180:
0x266180: JMP 0x008f9cf0
; END FUNCTION thunk_266180
0x266185: INT3 ; original byte CC, padding
0x266186: INT3 ; original byte CC, padding
0x266187: INT3 ; original byte CC, padding

; FUNCTION thunk_266188 [0x266188, 0x26618c] | file +0xa80 | ev_544cba46ca25c52016b06b1336491047811985c85719c88aca599bb88ca2fe9e
thunk_266188:
0x266188: JMP 0x008fa740
; END FUNCTION thunk_266188
0x26618d: INT3 ; original byte CC, padding
0x26618e: INT3 ; original byte CC, padding
0x26618f: INT3 ; original byte CC, padding

; FUNCTION thunk_266190 [0x266190, 0x266194] | file +0xa88 | ev_c59a83c527ec2c14aefac1b9685ab1f5033a1302df2ae7c904635b8c49564da7
thunk_266190:
0x266190: JMP 0x00552b70
; END FUNCTION thunk_266190
0x266195: INT3 ; original byte CC, padding
0x266196: INT3 ; original byte CC, padding
0x266197: INT3 ; original byte CC, padding

; FUNCTION thunk_266198 [0x266198, 0x26619c] | file +0xa90 | ev_48793e7f58ef9e0f869d5bf7e4197a1365c5204a853d9f6e86f272e062ecad5f
thunk_266198:
0x266198: JMP 0x00552bf0
; END FUNCTION thunk_266198
0x26619d: INT3 ; original byte CC, padding
0x26619e: INT3 ; original byte CC, padding
0x26619f: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a0 [0x2661a0, 0x2661a4] | file +0xa98 | ev_21f6a74ead4cf7febff2d4196b2a7986d4cd72a85ab83c1e027b9eb014c9db41
thunk_2661a0:
0x2661a0: JMP 0x00552c50
; END FUNCTION thunk_2661a0
0x2661a5: INT3 ; original byte CC, padding
0x2661a6: INT3 ; original byte CC, padding
0x2661a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a8 [0x2661a8, 0x2661ac] | file +0xaa0 | ev_08c7efec6159a4231f725feeb2ae4667652444949af05bfad614ed486cc10726
thunk_2661a8:
0x2661a8: JMP 0x00552c80
; END FUNCTION thunk_2661a8
0x2661ad: INT3 ; original byte CC, padding
0x2661ae: INT3 ; original byte CC, padding
0x2661af: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b0 [0x2661b0, 0x2661b4] | file +0xaa8 | ev_e62aa65b183e4f6ea7ab3b5cd9bfe757dfa71a58a3191566234425bdfd6b468c
thunk_2661b0:
0x2661b0: JMP 0x00552cb0
; END FUNCTION thunk_2661b0
0x2661b5: INT3 ; original byte CC, padding
0x2661b6: INT3 ; original byte CC, padding
0x2661b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b8 [0x2661b8, 0x2661bc] | file +0xab0 | ev_59a4649b3a618147c0f8e7d991262dccbb38b62bab46745d9dc86f95ee01c0f8
thunk_2661b8:
0x2661b8: JMP 0x00552ce0
; END FUNCTION thunk_2661b8
0x2661bd: INT3 ; original byte CC, padding
0x2661be: INT3 ; original byte CC, padding
0x2661bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c0 [0x2661c0, 0x2661c4] | file +0xab8 | ev_6ab3dee911315061b49dc3807ba7a64a017fe2ef5e7edcc67e0a8b25af23a042
thunk_2661c0:
0x2661c0: JMP 0x00b7e800
; END FUNCTION thunk_2661c0
0x2661c5: INT3 ; original byte CC, padding
0x2661c6: INT3 ; original byte CC, padding
0x2661c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c8 [0x2661c8, 0x2661cc] | file +0xac0 | ev_255f396dca8f49de3450f7d86252eaee6b5c42959e9628c715fbd35c890e38e7
thunk_2661c8:
0x2661c8: JMP 0x00b7ebe0
; END FUNCTION thunk_2661c8
0x2661cd: INT3 ; original byte CC, padding
0x2661ce: INT3 ; original byte CC, padding
0x2661cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d0 [0x2661d0, 0x2661d4] | file +0xac8 | ev_c9d1cac1498546eeeab2fce1f6faafc853cb664e949cc88c10d0bee8e3abeb57
thunk_2661d0:
0x2661d0: JMP 0x00b7ef70
; END FUNCTION thunk_2661d0
0x2661d5: INT3 ; original byte CC, padding
0x2661d6: INT3 ; original byte CC, padding
0x2661d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d8 [0x2661d8, 0x2661dc] | file +0xad0 | ev_0b00bb178d5769719b66fc3253ea231d0f2d95e28ca0c9c7dde96e4f42e76c33
thunk_2661d8:
0x2661d8: JMP 0x00c06d30
; END FUNCTION thunk_2661d8
0x2661dd: INT3 ; original byte CC, padding
0x2661de: INT3 ; original byte CC, padding
0x2661df: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e0 [0x2661e0, 0x2661e4] | file +0xad8 | ev_498718fb310bd1eb2b790209f3a3d38511b8173ce987d8063b228403a1c56ad7
thunk_2661e0:
0x2661e0: JMP 0x00792690
; END FUNCTION thunk_2661e0
0x2661e5: INT3 ; original byte CC, padding
0x2661e6: INT3 ; original byte CC, padding
0x2661e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e8 [0x2661e8, 0x2661ec] | file +0xae0 | ev_8a8290c5607724f7392ee63f16aadf7e18422517ed6a4e904e9edc27d524cc6b
thunk_2661e8:
0x2661e8: JMP 0x005e8b20
; END FUNCTION thunk_2661e8
0x2661ed: INT3 ; original byte CC, padding
0x2661ee: INT3 ; original byte CC, padding
0x2661ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f0 [0x2661f0, 0x2661f4] | file +0xae8 | ev_8c1ed7bc8853604e5acf55448a86e622f5ce0b7e72c7ce4cb732a0f49b42d130
thunk_2661f0:
0x2661f0: JMP 0x00552d10
; END FUNCTION thunk_2661f0
0x2661f5: INT3 ; original byte CC, padding
0x2661f6: INT3 ; original byte CC, padding
0x2661f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f8 [0x2661f8, 0x2661fc] | file +0xaf0 | ev_5dd1aefd4eafac7c3e2c0dd0b2f9a465137289585f5cde83e19c612c55283277
thunk_2661f8:
0x2661f8: JMP 0x00b7f160
; END FUNCTION thunk_2661f8
0x2661fd: INT3 ; original byte CC, padding
0x2661fe: INT3 ; original byte CC, padding
0x2661ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266200 [0x266200, 0x266204] | file +0xaf8 | ev_757ed4e16199c82a0c607920c217f95085b37f8a6717d7dbb7978116461ae164
thunk_266200:
0x266200: JMP 0x005de250
; END FUNCTION thunk_266200
0x266205: INT3 ; original byte CC, padding
0x266206: INT3 ; original byte CC, padding
0x266207: INT3 ; original byte CC, padding

; FUNCTION thunk_266208 [0x266208, 0x26620c] | file +0xb00 | ev_a91a98e2442ba222b625021ef2f015620cb04418f3424570d5a614e1076c3fcb
thunk_266208:
0x266208: JMP 0x00a54a30
; END FUNCTION thunk_266208
0x26620d: INT3 ; original byte CC, padding
0x26620e: INT3 ; original byte CC, padding
0x26620f: INT3 ; original byte CC, padding

; FUNCTION thunk_266210 [0x266210, 0x266214] | file +0xb08 | ev_62abc88f2ffa6f5a0735a3c380225d00d1cc5230fe6196dbd4554708b105ba38
thunk_266210:
0x266210: JMP 0x00a54a40
; END FUNCTION thunk_266210
0x266215: INT3 ; original byte CC, padding
0x266216: INT3 ; original byte CC, padding
0x266217: INT3 ; original byte CC, padding

; FUNCTION thunk_266218 [0x266218, 0x26621c] | file +0xb10 | ev_316646bb0eb8fd79801320346e50eaec76dfa54cb81513b797abe9e2b4888da0
thunk_266218:
0x266218: JMP 0x00a54a50
; END FUNCTION thunk_266218
0x26621d: INT3 ; original byte CC, padding
0x26621e: INT3 ; original byte CC, padding
0x26621f: INT3 ; original byte CC, padding

; FUNCTION thunk_266220 [0x266220, 0x266224] | file +0xb18 | ev_4a106cd82fbe8c86da526794caa3df2f7d5aef9eaae4cff41d637e9c2cd824be
thunk_266220:
0x266220: JMP 0x00a54a60
; END FUNCTION thunk_266220
0x266225: INT3 ; original byte CC, padding
0x266226: INT3 ; original byte CC, padding
0x266227: INT3 ; original byte CC, padding

; FUNCTION thunk_266228 [0x266228, 0x26622c] | file +0xb20 | ev_351475a479b8e03694262bc8dcef5bbd2294aeaff31eeaa55316389e51414995
thunk_266228:
0x266228: JMP 0x00a54a80
; END FUNCTION thunk_266228
0x26622d: INT3 ; original byte CC, padding
0x26622e: INT3 ; original byte CC, padding
0x26622f: INT3 ; original byte CC, padding

; FUNCTION thunk_266230 [0x266230, 0x266234] | file +0xb28 | ev_068172e45f643e23c2637d51152a476b51dec1fd8b501c50c998a097591390c2
thunk_266230:
0x266230: JMP 0x00a54a90
; END FUNCTION thunk_266230
0x266235: INT3 ; original byte CC, padding
0x266236: INT3 ; original byte CC, padding
0x266237: INT3 ; original byte CC, padding

; FUNCTION thunk_266238 [0x266238, 0x26623c] | file +0xb30 | ev_dfc19b0d494a5652a47ade31009b1e4c990f00087fde5e625a98a44c96cf0818
thunk_266238:
0x266238: JMP 0x008f9720
; END FUNCTION thunk_266238
0x26623d: INT3 ; original byte CC, padding
0x26623e: INT3 ; original byte CC, padding
0x26623f: INT3 ; original byte CC, padding

; FUNCTION thunk_266240 [0x266240, 0x266244] | file +0xb38 | ev_c4b0a4d54127ab7bacb8213d7c83b00ba3119ecb6a1ed4bcefb4af04d714bff9
thunk_266240:
0x266240: JMP 0x00a54ab0
; END FUNCTION thunk_266240
0x266245: INT3 ; original byte CC, padding
0x266246: INT3 ; original byte CC, padding
0x266247: INT3 ; original byte CC, padding

; FUNCTION thunk_266248 [0x266248, 0x26624c] | file +0xb40 | ev_3955365d4f354d375284caa65baa7fdc58b06cbf43962a43f4403daf1e6ca121
thunk_266248:
0x266248: JMP 0x008f64e0
; END FUNCTION thunk_266248
0x26624d: INT3 ; original byte CC, padding
0x26624e: INT3 ; original byte CC, padding
0x26624f: INT3 ; original byte CC, padding

; FUNCTION thunk_266250 [0x266250, 0x266254] | file +0xb48 | ev_f96adbdce6189ddf520dc792bf796a549b63d30d28bf78afb120432ba46da586
thunk_266250:
0x266250: JMP 0x008f5ef0
; END FUNCTION thunk_266250
0x266255: INT3 ; original byte CC, padding
0x266256: INT3 ; original byte CC, padding
0x266257: INT3 ; original byte CC, padding

; FUNCTION thunk_266258 [0x266258, 0x26625c] | file +0xb50 | ev_1b34325666d3c9c6d915c324fbccf4635988b46d93e5a9c542d2c00f603b09aa
thunk_266258:
0x266258: JMP 0x00a54a20
; END FUNCTION thunk_266258
0x26625d: INT3 ; original byte CC, padding
0x26625e: INT3 ; original byte CC, padding
0x26625f: INT3 ; original byte CC, padding

; FUNCTION thunk_266260 [0x266260, 0x266264] | file +0xb58 | ev_4d1b8a3331344e715a72a250a7d7161a2ccd108eb7ebf2facdfab957a5a66bb3
thunk_266260:
0x266260: JMP 0x00a54a70
; END FUNCTION thunk_266260
0x266265: INT3 ; original byte CC, padding
0x266266: INT3 ; original byte CC, padding
0x266267: INT3 ; original byte CC, padding

; FUNCTION thunk_266268 [0x266268, 0x26626c] | file +0xb60 | ev_22e4db3caf86ff04a9eee13f105b1058dc4863b54bce4a01374f8889e8a30600
thunk_266268:
0x266268: JMP 0x00a54aa0
; END FUNCTION thunk_266268
0x26626d: INT3 ; original byte CC, padding
0x26626e: INT3 ; original byte CC, padding
0x26626f: INT3 ; original byte CC, padding

; FUNCTION thunk_266270 [0x266270, 0x266274] | file +0xb68 | ev_890be6f1c7920f0033104ee575247e1908f0c97280a687224b3a7da85c57310a
thunk_266270:
0x266270: JMP 0x006e54d0
; END FUNCTION thunk_266270
0x266275: INT3 ; original byte CC, padding
0x266276: INT3 ; original byte CC, padding
0x266277: INT3 ; original byte CC, padding

; FUNCTION thunk_266278 [0x266278, 0x26627c] | file +0xb70 | ev_38a9d23e776f221c1f5b721b4f7c272ef04b2b40606ad30cb41ed2f6fe414c12
thunk_266278:
0x266278: JMP 0x00b7f4b0
; END FUNCTION thunk_266278
0x26627d: INT3 ; original byte CC, padding
0x26627e: INT3 ; original byte CC, padding
0x26627f: INT3 ; original byte CC, padding

; FUNCTION thunk_266280 [0x266280, 0x266284] | file +0xb78 | ev_2f26b0745ccafe1db376effabe7a0a78b79d483ba1574dca7a4e24346f526141
thunk_266280:
0x266280: JMP 0x0083d660
; END FUNCTION thunk_266280
0x266285: INT3 ; original byte CC, padding
0x266286: INT3 ; original byte CC, padding
0x266287: INT3 ; original byte CC, padding

; FUNCTION thunk_266288 [0x266288, 0x26628c] | file +0xb80 | ev_f9d0bb27935ce47d742649223a7e2e81d68bc42ed16701b18f269579e25bb4e0
thunk_266288:
0x266288: JMP 0x0083d7c0
; END FUNCTION thunk_266288
0x26628d: INT3 ; original byte CC, padding
0x26628e: INT3 ; original byte CC, padding
0x26628f: INT3 ; original byte CC, padding

; FUNCTION thunk_266290 [0x266290, 0x266294] | file +0xb88 | ev_a1a078ae92c7980fc788d3c99d9298c6590db02a5982d9127f09f838f9409650
thunk_266290:
0x266290: JMP 0x0083dab0
; END FUNCTION thunk_266290
0x266295: INT3 ; original byte CC, padding
0x266296: INT3 ; original byte CC, padding
0x266297: INT3 ; original byte CC, padding

; FUNCTION thunk_266298 [0x266298, 0x26629c] | file +0xb90 | ev_a78e29a1ea04bf6d30594d3b19849395bc30b22f59337d3f40a121a6320dc5ab
thunk_266298:
0x266298: JMP 0x0083de80
; END FUNCTION thunk_266298
0x26629d: INT3 ; original byte CC, padding
0x26629e: INT3 ; original byte CC, padding
0x26629f: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a0 [0x2662a0, 0x2662a4] | file +0xb98 | ev_155d45ce5e405802c8aeeaba1343bdef4231a636cf536cf310fc69c4c61f7313
thunk_2662a0:
0x2662a0: JMP 0x008f9c80
; END FUNCTION thunk_2662a0
0x2662a5: INT3 ; original byte CC, padding
0x2662a6: INT3 ; original byte CC, padding
0x2662a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a8 [0x2662a8, 0x2662ac] | file +0xba0 | ev_bd1796ad561e4782dded9a21477730f4bdf304f5dabc5868b80761969759fad6
thunk_2662a8:
0x2662a8: JMP 0x008fa110
; END FUNCTION thunk_2662a8
0x2662ad: INT3 ; original byte CC, padding
0x2662ae: INT3 ; original byte CC, padding
0x2662af: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b0 [0x2662b0, 0x2662b4] | file +0xba8 | ev_0480d28ab6222af2b93e4fd113f16ba734ff8878a8f42b06d5158480225cf901
thunk_2662b0:
0x2662b0: JMP 0x008f91b0
; END FUNCTION thunk_2662b0
0x2662b5: INT3 ; original byte CC, padding
0x2662b6: INT3 ; original byte CC, padding
0x2662b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b8 [0x2662b8, 0x2662bc] | file +0xbb0 | ev_1c690d03a8e9640305178c7da5cb0928be57685cc88733f8570a0a2b2d1e3e1e
thunk_2662b8:
0x2662b8: JMP 0x008fa4f0
; END FUNCTION thunk_2662b8
0x2662bd: INT3 ; original byte CC, padding
0x2662be: INT3 ; original byte CC, padding
0x2662bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c0 [0x2662c0, 0x2662c4] | file +0xbb8 | ev_719922efa405ef9eca04e783fe6e621ff2a66e1ad1adbeffd20ce01bd1b0ed53
thunk_2662c0:
0x2662c0: JMP 0x008f8090
; END FUNCTION thunk_2662c0
0x2662c5: INT3 ; original byte CC, padding
0x2662c6: INT3 ; original byte CC, padding
0x2662c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c8 [0x2662c8, 0x2662cc] | file +0xbc0 | ev_a91a6620a8b9164f6f8704cd2c44855feabb5aee9594bdae24707f232e57d539
thunk_2662c8:
0x2662c8: JMP 0x008fbb80
; END FUNCTION thunk_2662c8
0x2662cd: INT3 ; original byte CC, padding
0x2662ce: INT3 ; original byte CC, padding
0x2662cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d0 [0x2662d0, 0x2662d4] | file +0xbc8 | ev_a29cf940ec7347209b1f1e1e1df6ed80e1b76b49b50c65175eeb8dbb2f48f37d
thunk_2662d0:
0x2662d0: JMP 0x008f7b80
; END FUNCTION thunk_2662d0
0x2662d5: INT3 ; original byte CC, padding
0x2662d6: INT3 ; original byte CC, padding
0x2662d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d8 [0x2662d8, 0x2662dc] | file +0xbd0 | ev_1b6cc0fa753ccd5b1d7037a0c83ca39e8938cd8ce9dae47fdab2114c3a3f30a0
thunk_2662d8:
0x2662d8: JMP 0x008f7890
; END FUNCTION thunk_2662d8
0x2662dd: INT3 ; original byte CC, padding
0x2662de: INT3 ; original byte CC, padding
0x2662df: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e0 [0x2662e0, 0x2662e4] | file +0xbd8 | ev_3f3429b265d0817f87fde71c226edb3414a5e56742e62e83e7ba9c5eb129e695
thunk_2662e0:
0x2662e0: JMP 0x008fb8a0
; END FUNCTION thunk_2662e0
0x2662e5: INT3 ; original byte CC, padding
0x2662e6: INT3 ; original byte CC, padding
0x2662e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e8 [0x2662e8, 0x2662ec] | file +0xbe0 | ev_5fc1e1d8cefa479de1df321dd78e3e0fcec232438431dd18a61fa054ab7b3e6a
thunk_2662e8:
0x2662e8: JMP 0x008f8510
; END FUNCTION thunk_2662e8
0x2662ed: INT3 ; original byte CC, padding
0x2662ee: INT3 ; original byte CC, padding
0x2662ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f0 [0x2662f0, 0x2662f4] | file +0xbe8 | ev_069bad0ed13080f7e9635297f56d86b4d2e1c4617a1fe0b1e4cf75f1ccc2c916
thunk_2662f0:
0x2662f0: JMP 0x008f8800
; END FUNCTION thunk_2662f0
0x2662f5: INT3 ; original byte CC, padding
0x2662f6: INT3 ; original byte CC, padding
0x2662f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f8 [0x2662f8, 0x2662fc] | file +0xbf0 | ev_d3234eeed367638025138ce92a20673c4286efccda25b5770c0733c2eb4a83e4
thunk_2662f8:
0x2662f8: JMP 0x0049b080
; END FUNCTION thunk_2662f8
0x2662fd: INT3 ; original byte CC, padding
0x2662fe: INT3 ; original byte CC, padding
0x2662ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266300 [0x266300, 0x266304] | file +0xbf8 | ev_75056b65a1d2bedd343eb1adcf1cef2a1c0fda4e054c7388d54dbd2caba2e0b9
thunk_266300:
0x266300: JMP 0x0049b090
; END FUNCTION thunk_266300
0x266305: INT3 ; original byte CC, padding
0x266306: INT3 ; original byte CC, padding
0x266307: INT3 ; original byte CC, padding

; FUNCTION thunk_266308 [0x266308, 0x26630c] | file +0xc00 | ev_91ea1293d69e9c30d64b99d8801790056e6736a65b95aea27ec12055f57b1083
thunk_266308:
0x266308: JMP 0x0055fa50
; END FUNCTION thunk_266308
0x26630d: INT3 ; original byte CC, padding
0x26630e: INT3 ; original byte CC, padding
0x26630f: INT3 ; original byte CC, padding

; FUNCTION thunk_266310 [0x266310, 0x266314] | file +0xc08 | ev_bf5a4d512d418182601ed746a6835acf3eb5afe4f7852dfadc904c056465c94b
thunk_266310:
0x266310: JMP 0x00c34870
; END FUNCTION thunk_266310
0x266315: INT3 ; original byte CC, padding
0x266316: INT3 ; original byte CC, padding
0x266317: INT3 ; original byte CC, padding

; FUNCTION thunk_266318 [0x266318, 0x26631c] | file +0xc10 | ev_208b12d33f8755d90604b90a10a2c17d58b0947f24fd776ac8b17d17f6313ee8
thunk_266318:
0x266318: JMP 0x007dccf0
; END FUNCTION thunk_266318
0x26631d: INT3 ; original byte CC, padding
0x26631e: INT3 ; original byte CC, padding
0x26631f: INT3 ; original byte CC, padding

; FUNCTION thunk_266320 [0x266320, 0x266324] | file +0xc18 | ev_dd4ca9088204fa7e974a87d0b009a8ebc2fd2759fb8b63a52a185ba34cf8eb29
thunk_266320:
0x266320: JMP 0x007dcd00
; END FUNCTION thunk_266320
0x266325: INT3 ; original byte CC, padding
0x266326: INT3 ; original byte CC, padding
0x266327: INT3 ; original byte CC, padding

; FUNCTION thunk_266328 [0x266328, 0x26632c] | file +0xc20 | ev_69848362de2103bd5cf50d86ad439e274738f701958fe202143e54df6f1453c8
thunk_266328:
0x266328: JMP 0x007dcd10
; END FUNCTION thunk_266328
0x26632d: INT3 ; original byte CC, padding
0x26632e: INT3 ; original byte CC, padding
0x26632f: INT3 ; original byte CC, padding

; FUNCTION thunk_266330 [0x266330, 0x266334] | file +0xc28 | ev_a9629abec3308aca2457491628273649a887f0f033e06071bf19d59e7c25aeb6
thunk_266330:
0x266330: JMP 0x007dcd20
; END FUNCTION thunk_266330
0x266335: INT3 ; original byte CC, padding
0x266336: INT3 ; original byte CC, padding
0x266337: INT3 ; original byte CC, padding

; FUNCTION thunk_266338 [0x266338, 0x26633c] | file +0xc30 | ev_2c9fc9579a5e8f0951e68ec4ee69f8bab5819987d27b92dac0e5ca9ab7aa9585
thunk_266338:
0x266338: JMP 0x007dcd30
; END FUNCTION thunk_266338
0x26633d: INT3 ; original byte CC, padding
0x26633e: INT3 ; original byte CC, padding
0x26633f: INT3 ; original byte CC, padding

; FUNCTION thunk_266340 [0x266340, 0x266344] | file +0xc38 | ev_28d00ff55ee14bddc3a396e9c941f0914c680d54e45f0e7d0a0fe6bcaf0abdfd
thunk_266340:
0x266340: JMP 0x005a6c90
; END FUNCTION thunk_266340
0x266345: INT3 ; original byte CC, padding
0x266346: INT3 ; original byte CC, padding
0x266347: INT3 ; original byte CC, padding

; FUNCTION thunk_266348 [0x266348, 0x26634c] | file +0xc40 | ev_a0a92a8617b94cc57cf896b02840e085453db69e9b9b89b42fd08675b520d877
thunk_266348:
0x266348: JMP 0x005a7300
; END FUNCTION thunk_266348
0x26634d: INT3 ; original byte CC, padding
0x26634e: INT3 ; original byte CC, padding
0x26634f: INT3 ; original byte CC, padding

; FUNCTION thunk_266350 [0x266350, 0x266354] | file +0xc48 | ev_0a57f3bca0315a687f07d3f9b7f70316f45c7906a2d0cf0fa17dc9062c3dee7c
thunk_266350:
0x266350: JMP 0x005a7610
; END FUNCTION thunk_266350
0x266355: INT3 ; original byte CC, padding
0x266356: INT3 ; original byte CC, padding
0x266357: INT3 ; original byte CC, padding

; FUNCTION thunk_266358 [0x266358, 0x26635c] | file +0xc50 | ev_af4fded32a25b1dd2506f0fa8d3a6fe561debf05b2f66c733b119322209b6aaf
thunk_266358:
0x266358: JMP 0x005a7900
; END FUNCTION thunk_266358
0x26635d: INT3 ; original byte CC, padding
0x26635e: INT3 ; original byte CC, padding
0x26635f: INT3 ; original byte CC, padding

; FUNCTION thunk_266360 [0x266360, 0x266364] | file +0xc58 | ev_9c6af11e7c8dd305336c3838898236fd05099b0aa65104622374b160736ab5b6
thunk_266360:
0x266360: JMP 0x00c9c830
; END FUNCTION thunk_266360
0x266365: INT3 ; original byte CC, padding
0x266366: INT3 ; original byte CC, padding
0x266367: INT3 ; original byte CC, padding

; FUNCTION thunk_266368 [0x266368, 0x26636c] | file +0xc60 | ev_87f009c7ed6a037fc6a2e695d59a03270e62b3b2b19528404427fdbc1ab4ee9e
thunk_266368:
0x266368: JMP 0x005a7f00
; END FUNCTION thunk_266368
0x26636d: INT3 ; original byte CC, padding
0x26636e: INT3 ; original byte CC, padding
0x26636f: INT3 ; original byte CC, padding

; FUNCTION thunk_266370 [0x266370, 0x266374] | file +0xc68 | ev_3070545cbae7a2801f820e3271e277b6b50e272261694c2bd8e9e12e4aae5233
thunk_266370:
0x266370: JMP 0x005a8070
; END FUNCTION thunk_266370
0x266375: INT3 ; original byte CC, padding
0x266376: INT3 ; original byte CC, padding
0x266377: INT3 ; original byte CC, padding

; FUNCTION thunk_266378 [0x266378, 0x26637c] | file +0xc70 | ev_ca921bb3120b8324a1de915ed3013883e4fa47822426fb4cd29d45496c86f8d4
thunk_266378:
0x266378: JMP 0x00be8480
; END FUNCTION thunk_266378
0x26637d: INT3 ; original byte CC, padding
0x26637e: INT3 ; original byte CC, padding
0x26637f: INT3 ; original byte CC, padding

; FUNCTION thunk_266380 [0x266380, 0x266384] | file +0xc78 | ev_a8a021cff5d62e81b20c04597b03ae061b60365d11847b3152df272cc8acdd6f
thunk_266380:
0x266380: JMP 0x0049b0a0
; END FUNCTION thunk_266380
0x266385: INT3 ; original byte CC, padding
0x266386: INT3 ; original byte CC, padding
0x266387: INT3 ; original byte CC, padding

; FUNCTION thunk_266388 [0x266388, 0x26638c] | file +0xc80 | ev_2997099199ab42db19428062e874712cd6df17198b3e9050eab123c8e272e909
thunk_266388:
0x266388: JMP 0x0049b0c0
; END FUNCTION thunk_266388
0x26638d: INT3 ; original byte CC, padding
0x26638e: INT3 ; original byte CC, padding
0x26638f: INT3 ; original byte CC, padding

; FUNCTION thunk_266390 [0x266390, 0x266394] | file +0xc88 | ev_b65bf17266f25edcb08139f6c59009a5ffaaa52228678f32ef1ea053d7b820ea
thunk_266390:
0x266390: JMP 0x0049b0d0
; END FUNCTION thunk_266390
0x266395: INT3 ; original byte CC, padding
0x266396: INT3 ; original byte CC, padding
0x266397: INT3 ; original byte CC, padding

; FUNCTION thunk_266398 [0x266398, 0x26639c] | file +0xc90 | ev_4bf27f9aa04b2929a3570e0657827ba247a75006d293b78e64abaff44da59012
thunk_266398:
0x266398: JMP 0x0049b0e0
; END FUNCTION thunk_266398
0x26639d: INT3 ; original byte CC, padding
0x26639e: INT3 ; original byte CC, padding
0x26639f: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a0 [0x2663a0, 0x2663a4] | file +0xc98 | ev_67bb7eec5a2d6bdffe57a922696a5236cd5e44e0462ecd023f1a1790e17462b7
thunk_2663a0:
0x2663a0: JMP 0x0049b0f0
; END FUNCTION thunk_2663a0
0x2663a5: INT3 ; original byte CC, padding
0x2663a6: INT3 ; original byte CC, padding
0x2663a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a8 [0x2663a8, 0x2663ac] | file +0xca0 | ev_68a25a408bff8ab52323616e1566b09b1bdfef1050073934b37bcd78f8bff273
thunk_2663a8:
0x2663a8: JMP 0x00530720
; END FUNCTION thunk_2663a8
0x2663ad: INT3 ; original byte CC, padding
0x2663ae: INT3 ; original byte CC, padding
0x2663af: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b0 [0x2663b0, 0x2663b4] | file +0xca8 | ev_83ae655e96cd90c09eb9dc0ce6bd23f77ef191df92f56a0d59db6f4464af597e
thunk_2663b0:
0x2663b0: JMP 0x00531670
; END FUNCTION thunk_2663b0
0x2663b5: INT3 ; original byte CC, padding
0x2663b6: INT3 ; original byte CC, padding
0x2663b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b8 [0x2663b8, 0x2663bc] | file +0xcb0 | ev_1afdd0cffa8bf6b0d345f517b61d8ebdb86433a05beb859e3375a00d0567815c
thunk_2663b8:
0x2663b8: JMP 0x008f96f0
; END FUNCTION thunk_2663b8
0x2663bd: INT3 ; original byte CC, padding
0x2663be: INT3 ; original byte CC, padding
0x2663bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c0 [0x2663c0, 0x2663c4] | file +0xcb8 | ev_a2681b835dabbb2bbe1018977711d8e7a6b25088c1c3b1bd12d40314ae174cdd
thunk_2663c0:
0x2663c0: JMP 0x00531230
; END FUNCTION thunk_2663c0
0x2663c5: INT3 ; original byte CC, padding
0x2663c6: INT3 ; original byte CC, padding
0x2663c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c8 [0x2663c8, 0x2663cc] | file +0xcc0 | ev_1202d226e0b0dc8c3cdef6d838d3717b0e0b43e88f3997d1a0aa7e109050b457
thunk_2663c8:
0x2663c8: JMP 0x00802df0
; END FUNCTION thunk_2663c8
0x2663cd: INT3 ; original byte CC, padding
0x2663ce: INT3 ; original byte CC, padding
0x2663cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d0 [0x2663d0, 0x2663d4] | file +0xcc8 | ev_22ff5ff4908294967385a694e23aaac6ac0ea8916a63f1fa973d669ba6fb8df0
thunk_2663d0:
0x2663d0: JMP 0x00b7f140
; END FUNCTION thunk_2663d0
0x2663d5: INT3 ; original byte CC, padding
0x2663d6: INT3 ; original byte CC, padding
0x2663d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d8 [0x2663d8, 0x2663dc] | file +0xcd0 | ev_34a23c6ea3b7a2d859dc68cf0179d2e6e3f54574cdd2132544206387c29aa21e
thunk_2663d8:
0x2663d8: JMP 0x00ae35e0
; END FUNCTION thunk_2663d8
0x2663dd: INT3 ; original byte CC, padding
0x2663de: INT3 ; original byte CC, padding
0x2663df: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e0 [0x2663e0, 0x2663e4] | file +0xcd8 | ev_5cb448dfe07b9a4edd1fcf0107805a9bd7ea03b9d2747e2e94001efd67a9feb3
thunk_2663e0:
0x2663e0: JMP 0x004eee20
; END FUNCTION thunk_2663e0
0x2663e5: INT3 ; original byte CC, padding
0x2663e6: INT3 ; original byte CC, padding
0x2663e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e8 [0x2663e8, 0x2663ec] | file +0xce0 | ev_197bd45d13ebaabd9a99bf7238e2da2d83a7c121b47a589578b35369fae3ff3b
thunk_2663e8:
0x2663e8: JMP 0x008fab10
; END FUNCTION thunk_2663e8
0x2663ed: INT3 ; original byte CC, padding
0x2663ee: INT3 ; original byte CC, padding
0x2663ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f0 [0x2663f0, 0x2663f4] | file +0xce8 | ev_390cff6484046a0500dd687e1027f4b3ccfb2934b44486aa755a95431a7fe4a2
thunk_2663f0:
0x2663f0: JMP 0x008fae30
; END FUNCTION thunk_2663f0
0x2663f5: INT3 ; original byte CC, padding
0x2663f6: INT3 ; original byte CC, padding
0x2663f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f8 [0x2663f8, 0x2663fc] | file +0xcf0 | ev_3c5fc25132a91f686abd292661e26aae09b02682ce5c53c831b4f6f03827049a
thunk_2663f8:
0x2663f8: JMP 0x009c9220
; END FUNCTION thunk_2663f8
0x2663fd: INT3 ; original byte CC, padding
0x2663fe: INT3 ; original byte CC, padding
0x2663ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266400 [0x266400, 0x266404] | file +0xcf8 | ev_57db6d921f8026b55dc8e147118e9d9cb10f40830fcbb9a59701387c437a9d1b
thunk_266400:
0x266400: JMP 0x009c9100
; END FUNCTION thunk_266400
0x266405: INT3 ; original byte CC, padding
0x266406: INT3 ; original byte CC, padding
0x266407: INT3 ; original byte CC, padding

; FUNCTION thunk_266408 [0x266408, 0x26640c] | file +0xd00 | ev_d0a17fb65beb653cf741b97d5f412cf3674a53cfab34f587c8e6b0c6abb9c4c8
thunk_266408:
0x266408: JMP 0x00642310
; END FUNCTION thunk_266408
0x26640d: INT3 ; original byte CC, padding
0x26640e: INT3 ; original byte CC, padding
0x26640f: INT3 ; original byte CC, padding

; FUNCTION thunk_266410 [0x266410, 0x266414] | file +0xd08 | ev_9fc7135a6d4d0bcf4f8046fe5a5ef91b770aeba84442b46d8339d885842b2c6b
thunk_266410:
0x266410: JMP 0x00642820
; END FUNCTION thunk_266410
0x266415: INT3 ; original byte CC, padding
0x266416: INT3 ; original byte CC, padding
0x266417: INT3 ; original byte CC, padding

; FUNCTION thunk_266418 [0x266418, 0x26641c] | file +0xd10 | ev_2b57d9748536f30d1ad30c74b67122f3d29f2da19d2d2c776b1e549e6b375495
thunk_266418:
0x266418: JMP 0x006436e0
; END FUNCTION thunk_266418
0x26641d: INT3 ; original byte CC, padding
0x26641e: INT3 ; original byte CC, padding
0x26641f: INT3 ; original byte CC, padding

; FUNCTION thunk_266420 [0x266420, 0x266424] | file +0xd18 | ev_5731453af60ee21737f0a19f8df3841abc1185e5f887c5a2651f9da56f35dd45
thunk_266420:
0x266420: JMP 0x006438d0
; END FUNCTION thunk_266420
0x266425: INT3 ; original byte CC, padding
0x266426: INT3 ; original byte CC, padding
0x266427: INT3 ; original byte CC, padding

; FUNCTION thunk_266428 [0x266428, 0x26642c] | file +0xd20 | ev_e36675918b3af93a0ba702a21607e01ed6c6402aec3ced61dede9f937ad73f86
thunk_266428:
0x266428: JMP 0x00643c60
; END FUNCTION thunk_266428
0x26642d: INT3 ; original byte CC, padding
0x26642e: INT3 ; original byte CC, padding
0x26642f: INT3 ; original byte CC, padding

; FUNCTION thunk_266430 [0x266430, 0x266434] | file +0xd28 | ev_6a04f2314e3bd552a5cfa9f286543184288bcceb388acd83f0f89386e77844c5
thunk_266430:
0x266430: JMP 0x009f8290
; END FUNCTION thunk_266430
0x266435: INT3 ; original byte CC, padding
0x266436: INT3 ; original byte CC, padding
0x266437: INT3 ; original byte CC, padding

; FUNCTION thunk_266438 [0x266438, 0x26643c] | file +0xd30 | ev_f0f29b9b58193821f977a76d6075531fc649104ed3ff9888e799ce9604452c14
thunk_266438:
0x266438: JMP 0x009fbb70
; END FUNCTION thunk_266438
0x26643d: INT3 ; original byte CC, padding
0x26643e: INT3 ; original byte CC, padding
0x26643f: INT3 ; original byte CC, padding

; FUNCTION thunk_266440 [0x266440, 0x266444] | file +0xd38 | ev_127a5173d91f5372221bc3d6a59f5ee274647c47100ccb53d2c9971e8f04095e
thunk_266440:
0x266440: JMP 0x00a45280
; END FUNCTION thunk_266440
0x266445: INT3 ; original byte CC, padding
0x266446: INT3 ; original byte CC, padding
0x266447: INT3 ; original byte CC, padding

; FUNCTION thunk_266448 [0x266448, 0x26644c] | file +0xd40 | ev_9f62465d050ae1689681c25f188166de765fef7a456d5df8e48326754e89d912
thunk_266448:
0x266448: JMP 0x00c87ca0
; END FUNCTION thunk_266448
0x26644d: INT3 ; original byte CC, padding
0x26644e: INT3 ; original byte CC, padding
0x26644f: INT3 ; original byte CC, padding

; FUNCTION thunk_266450 [0x266450, 0x266454] | file +0xd48 | ev_c67e3645f3916bc52308fafa2c022bb81b0d570232e6162a3b5bf0e618b49e6f
thunk_266450:
0x266450: JMP 0x009ff000
; END FUNCTION thunk_266450
0x266455: INT3 ; original byte CC, padding
0x266456: INT3 ; original byte CC, padding
0x266457: INT3 ; original byte CC, padding

; FUNCTION thunk_266458 [0x266458, 0x26645c] | file +0xd50 | ev_9094c60b8bf24caf27dfc6ca1cc5af5d2c0cc59d23e15835384bc32a6ebbb651
thunk_266458:
0x266458: JMP 0x00a00780
; END FUNCTION thunk_266458
0x26645d: INT3 ; original byte CC, padding
0x26645e: INT3 ; original byte CC, padding
0x26645f: INT3 ; original byte CC, padding

; FUNCTION thunk_266460 [0x266460, 0x266464] | file +0xd58 | ev_f967dc0dce327888fc081cf3a60385a6c81a79c39a438c911569b99b2c2970f7
thunk_266460:
0x266460: JMP 0x00a007e0
; END FUNCTION thunk_266460
0x266465: INT3 ; original byte CC, padding
0x266466: INT3 ; original byte CC, padding
0x266467: INT3 ; original byte CC, padding

; FUNCTION thunk_266468 [0x266468, 0x26646c] | file +0xd60 | ev_5bb2a3a4b48b10f438f6bfd412e4c2aacf8034f0398d15e36164eea11ac8baaa
thunk_266468:
0x266468: JMP 0x00abe830
; END FUNCTION thunk_266468
0x26646d: INT3 ; original byte CC, padding
0x26646e: INT3 ; original byte CC, padding
0x26646f: INT3 ; original byte CC, padding

; FUNCTION thunk_266470 [0x266470, 0x266474] | file +0xd68 | ev_be306a0fec488868836f0d090ee9360688d8f3815794a95290c9258d1f5c9a52
thunk_266470:
0x266470: JMP 0x009fcf30
; END FUNCTION thunk_266470
0x266475: INT3 ; original byte CC, padding
0x266476: INT3 ; original byte CC, padding
0x266477: INT3 ; original byte CC, padding

; FUNCTION thunk_266478 [0x266478, 0x26647c] | file +0xd70 | ev_922487f426c1b9f1e6487c6527a855ee8b87c562dc258ff108f54fe5ecbe0a5e
thunk_266478:
0x266478: JMP 0x005f0fc0
; END FUNCTION thunk_266478
0x26647d: INT3 ; original byte CC, padding
0x26647e: INT3 ; original byte CC, padding
0x26647f: INT3 ; original byte CC, padding

; FUNCTION thunk_266480 [0x266480, 0x266484] | file +0xd78 | ev_c8ec32f779da850e6799cd8600e705890b09ee79ea421903c0972a20aa3691d5
thunk_266480:
0x266480: JMP 0x008f73f0
; END FUNCTION thunk_266480
0x266485: INT3 ; original byte CC, padding
0x266486: INT3 ; original byte CC, padding
0x266487: INT3 ; original byte CC, padding

; FUNCTION thunk_266488 [0x266488, 0x26648c] | file +0xd80 | ev_0e6780b3ab0518de85ec8cb1b1a41b5328048b27e3d70609480c76c9a729a658
thunk_266488:
0x266488: JMP 0x004f7250
; END FUNCTION thunk_266488
0x26648d: INT3 ; original byte CC, padding
0x26648e: INT3 ; original byte CC, padding
0x26648f: INT3 ; original byte CC, padding

; FUNCTION thunk_266490 [0x266490, 0x266494] | file +0xd88 | ev_eac6950051720ccdf0ce61f974ce273efefff7871ba9f2c6388e5a8e3a8cf4ee
thunk_266490:
0x266490: JMP 0x009fdad0
; END FUNCTION thunk_266490
0x266495: INT3 ; original byte CC, padding
0x266496: INT3 ; original byte CC, padding
0x266497: INT3 ; original byte CC, padding

; FUNCTION thunk_266498 [0x266498, 0x26649c] | file +0xd90 | ev_ff1c155e08e26d495cf8504aee29f9999b292832e20c7561fa400036d5c41bfd
thunk_266498:
0x266498: JMP 0x009fddb0
; END FUNCTION thunk_266498
0x26649d: INT3 ; original byte CC, padding
0x26649e: INT3 ; original byte CC, padding
0x26649f: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a0 [0x2664a0, 0x2664a4] | file +0xd98 | ev_9afec5667fabacf37cd58916e41fef67ff924e46b1463d99a0f4bf58efef7597
thunk_2664a0:
0x2664a0: JMP 0x009fdf10
; END FUNCTION thunk_2664a0
0x2664a5: INT3 ; original byte CC, padding
0x2664a6: INT3 ; original byte CC, padding
0x2664a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a8 [0x2664a8, 0x2664ac] | file +0xda0 | ev_0c5f34727f071eb6c339e4b79622768bdaf09dbe3f4ed379509e311c30490ac2
thunk_2664a8:
0x2664a8: JMP 0x006444d0
; END FUNCTION thunk_2664a8
0x2664ad: INT3 ; original byte CC, padding
0x2664ae: INT3 ; original byte CC, padding
0x2664af: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b0 [0x2664b0, 0x2664b4] | file +0xda8 | ev_d48bdaa2800476d452e672b45b77e9cd08abbf106a93632ad6021e777d43d1c0
thunk_2664b0:
0x2664b0: JMP 0x00650fd0
; END FUNCTION thunk_2664b0
0x2664b5: INT3 ; original byte CC, padding
0x2664b6: INT3 ; original byte CC, padding
0x2664b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b8 [0x2664b8, 0x2664bc] | file +0xdb0 | ev_ee3d8784b8bce47b4bda93ac32d92f80e18d040dbbb0f7e18230bda96f0e6a06
thunk_2664b8:
0x2664b8: JMP 0x009fea30
; END FUNCTION thunk_2664b8
0x2664bd: INT3 ; original byte CC, padding
0x2664be: INT3 ; original byte CC, padding
0x2664bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c0 [0x2664c0, 0x2664c4] | file +0xdb8 | ev_80e8082dd778c1359f914df823d4e82cdf37fdd7e497c6fd37e38b496a711883
thunk_2664c0:
0x2664c0: JMP 0x004f7940
; END FUNCTION thunk_2664c0
0x2664c5: INT3 ; original byte CC, padding
0x2664c6: INT3 ; original byte CC, padding
0x2664c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c8 [0x2664c8, 0x2664cc] | file +0xdc0 | ev_f002307638dc8b0656c4f4fc065ba5bf1a73cbb551ca6838d6c478ff89f08933
thunk_2664c8:
0x2664c8: JMP 0x00ab8ae0
; END FUNCTION thunk_2664c8
0x2664cd: INT3 ; original byte CC, padding
0x2664ce: INT3 ; original byte CC, padding
0x2664cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d0 [0x2664d0, 0x2664d4] | file +0xdc8 | ev_4cb91d7ac1a88bfa50ffc18582852cbc35933f3b7c1cd09cef419b49abf1ceae
thunk_2664d0:
0x2664d0: JMP 0x00abb660
; END FUNCTION thunk_2664d0
0x2664d5: INT3 ; original byte CC, padding
0x2664d6: INT3 ; original byte CC, padding
0x2664d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d8 [0x2664d8, 0x2664dc] | file +0xdd0 | ev_93971fce626806f71b48fa88650de2f3e837cbbf7a1a5b1a01c24609d7685e42
thunk_2664d8:
0x2664d8: JMP 0x009fe260
; END FUNCTION thunk_2664d8
0x2664dd: INT3 ; original byte CC, padding
0x2664de: INT3 ; original byte CC, padding
0x2664df: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e0 [0x2664e0, 0x2664e4] | file +0xdd8 | ev_0637971ec956a822522a0d24e1a2b33abdcc31e6e0968b663d4594b931fb59c6
thunk_2664e0:
0x2664e0: JMP 0x009fe4e0
; END FUNCTION thunk_2664e0
0x2664e5: INT3 ; original byte CC, padding
0x2664e6: INT3 ; original byte CC, padding
0x2664e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e8 [0x2664e8, 0x2664ec] | file +0xde0 | ev_96f2eb78d44e2be90df1bfac8907de11a07fd1c20a137c512007f0794700cec0
thunk_2664e8:
0x2664e8: JMP 0x009fe630
; END FUNCTION thunk_2664e8
0x2664ed: INT3 ; original byte CC, padding
0x2664ee: INT3 ; original byte CC, padding
0x2664ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f0 [0x2664f0, 0x2664f4] | file +0xde8 | ev_d07160a37d230e28275e29ea7fc0ead6f9f93e14db0a551c24c70ee037fe8547
thunk_2664f0:
0x2664f0: JMP 0x00798330
; END FUNCTION thunk_2664f0
0x2664f5: INT3 ; original byte CC, padding
0x2664f6: INT3 ; original byte CC, padding
0x2664f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f8 [0x2664f8, 0x2664fc] | file +0xdf0 | ev_9d7c483a683c8982d49d9799eceee79a3cdf2e18a6b44d8f5196a2a5583aee1a
thunk_2664f8:
0x2664f8: JMP 0x00abd000
; END FUNCTION thunk_2664f8
0x2664fd: INT3 ; original byte CC, padding
0x2664fe: INT3 ; original byte CC, padding
0x2664ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266500 [0x266500, 0x266504] | file +0xdf8 | ev_c07731e10bb7a1e470f23c0481586c9a79f74361b124421bf746e95b99a5ae93
thunk_266500:
0x266500: JMP 0x000fc890
; END FUNCTION thunk_266500
0x266505: INT3 ; original byte CC, padding
0x266506: INT3 ; original byte CC, padding
0x266507: INT3 ; original byte CC, padding

; FUNCTION thunk_266508 [0x266508, 0x26650c] | file +0xe00 | ev_1e6f012c63f03e4c7afa6e0683fef2ded8312a616632d2bc042c027e9cf07565
thunk_266508:
0x266508: JMP 0x0049f090
; END FUNCTION thunk_266508
0x26650d: INT3 ; original byte CC, padding
0x26650e: INT3 ; original byte CC, padding
0x26650f: INT3 ; original byte CC, padding

; FUNCTION thunk_266510 [0x266510, 0x266514] | file +0xe08 | ev_dee16371c42076c27084c7b50a89913f1c7863ce6228e387f88210c14185bb3a
thunk_266510:
0x266510: JMP 0x0049f200
; END FUNCTION thunk_266510
0x266515: INT3 ; original byte CC, padding
0x266516: INT3 ; original byte CC, padding
0x266517: INT3 ; original byte CC, padding

; FUNCTION thunk_266518 [0x266518, 0x26651c] | file +0xe10 | ev_a058a528785a3cc58198c17c8dc1925048f41e95131251d68285c6b501aafcf4
thunk_266518:
0x266518: JMP 0x004c0590
; END FUNCTION thunk_266518
0x26651d: INT3 ; original byte CC, padding
0x26651e: INT3 ; original byte CC, padding
0x26651f: INT3 ; original byte CC, padding

; FUNCTION thunk_266520 [0x266520, 0x266524] | file +0xe18 | ev_9c4b34282938bf36e1ebd5dfb17568acc7f2ae9dc7d37ca8532f66102dcc05f5
thunk_266520:
0x266520: JMP 0x004c05b0
; END FUNCTION thunk_266520
0x266525: INT3 ; original byte CC, padding
0x266526: INT3 ; original byte CC, padding
0x266527: INT3 ; original byte CC, padding

; FUNCTION thunk_266528 [0x266528, 0x26652c] | file +0xe20 | ev_510b5e50d52f5d207b82eef585db3edfcdd3041c8ffd642236f3957145d64a8f
thunk_266528:
0x266528: JMP 0x000a9430
; END FUNCTION thunk_266528
0x26652d: INT3 ; original byte CC, padding
0x26652e: INT3 ; original byte CC, padding
0x26652f: INT3 ; original byte CC, padding

; FUNCTION thunk_266530 [0x266530, 0x266534] | file +0xe28 | ev_3a5134362781c6d2c668f7e3314cc6a65b2f5285c575ecca40cd49d5040c24c1
thunk_266530:
0x266530: JMP 0x004ca350
; END FUNCTION thunk_266530
0x266535: INT3 ; original byte CC, padding
0x266536: INT3 ; original byte CC, padding
0x266537: INT3 ; original byte CC, padding

; FUNCTION thunk_266538 [0x266538, 0x26653c] | file +0xe30 | ev_8f8bff6001bcc400d3026e1885d9d081268397ec60954c6f57d10812e981a85e
thunk_266538:
0x266538: JMP 0x004caa40
; END FUNCTION thunk_266538
0x26653d: INT3 ; original byte CC, padding
0x26653e: INT3 ; original byte CC, padding
0x26653f: INT3 ; original byte CC, padding

; FUNCTION thunk_266540 [0x266540, 0x266544] | file +0xe38 | ev_d62a46be2c40b28d5f4aa8189bfefe8245f83f992b2d039b6320fa7b30c2cb03
thunk_266540:
0x266540: JMP 0x000aa510
; END FUNCTION thunk_266540
0x266545: INT3 ; original byte CC, padding
0x266546: INT3 ; original byte CC, padding
0x266547: INT3 ; original byte CC, padding

; FUNCTION thunk_266548 [0x266548, 0x26654c] | file +0xe40 | ev_4f04853bf68c590f0c12431b9a942d2d53521c34c9c89c2a5ff51e8aa24f25a9
thunk_266548:
0x266548: JMP 0x004d51d0
; END FUNCTION thunk_266548
0x26654d: INT3 ; original byte CC, padding
0x26654e: INT3 ; original byte CC, padding
0x26654f: INT3 ; original byte CC, padding

; FUNCTION thunk_266550 [0x266550, 0x266554] | file +0xe48 | ev_48c24e846bbea721b69c29780cba7eca1dd5efc88062c725a2b36e5eedc146cb
thunk_266550:
0x266550: JMP 0x008111b0
; END FUNCTION thunk_266550
0x266555: INT3 ; original byte CC, padding
0x266556: INT3 ; original byte CC, padding
0x266557: INT3 ; original byte CC, padding

; FUNCTION thunk_266558 [0x266558, 0x26655c] | file +0xe50 | ev_52e069bbab5228f4e691ccbf934368856bb89a90b72181270e08558cfea35f8a
thunk_266558:
0x266558: JMP 0x0001ae90
; END FUNCTION thunk_266558
0x26655d: INT3 ; original byte CC, padding
0x26655e: INT3 ; original byte CC, padding
0x26655f: INT3 ; original byte CC, padding

; FUNCTION thunk_266560 [0x266560, 0x266564] | file +0xe58 | ev_e91e51e4026fb5d054d11b40d42ef31bf3a18612cafbb880f2af3b25c4b6eb5d
thunk_266560:
0x266560: JMP 0x004f0030
; END FUNCTION thunk_266560
0x266565: INT3 ; original byte CC, padding
0x266566: INT3 ; original byte CC, padding
0x266567: INT3 ; original byte CC, padding

; FUNCTION thunk_266568 [0x266568, 0x26656c] | file +0xe60 | ev_aeae8c8acd7deace89e69e155c6a30e5941f3f2f11ad32f21f70ce92f24451b7
thunk_266568:
0x266568: JMP 0x004fbbd0
; END FUNCTION thunk_266568
0x26656d: INT3 ; original byte CC, padding
0x26656e: INT3 ; original byte CC, padding
0x26656f: INT3 ; original byte CC, padding

; FUNCTION thunk_266570 [0x266570, 0x266574] | file +0xe68 | ev_79da496439052e9f20d766207934d2c884760604dc1329284f73b2992d92df31
thunk_266570:
0x266570: JMP 0x0050ced0
; END FUNCTION thunk_266570
0x266575: INT3 ; original byte CC, padding
0x266576: INT3 ; original byte CC, padding
0x266577: INT3 ; original byte CC, padding

; FUNCTION thunk_266578 [0x266578, 0x26657c] | file +0xe70 | ev_964d4b815a68973efd6e7497a577ce655d463705de549f248cde2a68066a59df
thunk_266578:
0x266578: JMP 0x0050cee0
; END FUNCTION thunk_266578
0x26657d: INT3 ; original byte CC, padding
0x26657e: INT3 ; original byte CC, padding
0x26657f: INT3 ; original byte CC, padding

; FUNCTION thunk_266580 [0x266580, 0x266584] | file +0xe78 | ev_aefa1f19195c0d79f1651ddb2f1a627ca1439c9bf20aac8cc008d0961a79170e
thunk_266580:
0x266580: JMP 0x0050cf30
; END FUNCTION thunk_266580
0x266585: INT3 ; original byte CC, padding
0x266586: INT3 ; original byte CC, padding
0x266587: INT3 ; original byte CC, padding

; FUNCTION thunk_266588 [0x266588, 0x26658c] | file +0xe80 | ev_b61af5a573168b66efe96561016fef3eeca97db1adbc8414497d0cb29ba0d7a0
thunk_266588:
0x266588: JMP 0x0050cf70
; END FUNCTION thunk_266588
0x26658d: INT3 ; original byte CC, padding
0x26658e: INT3 ; original byte CC, padding
0x26658f: INT3 ; original byte CC, padding

; FUNCTION thunk_266590 [0x266590, 0x266594] | file +0xe88 | ev_380bd567410144f9738e47feb993c3d6b679a6af88094979e1d777b20bb9580b
thunk_266590:
0x266590: JMP 0x0050cfb0
; END FUNCTION thunk_266590
0x266595: INT3 ; original byte CC, padding
0x266596: INT3 ; original byte CC, padding
0x266597: INT3 ; original byte CC, padding

; FUNCTION thunk_266598 [0x266598, 0x26659c] | file +0xe90 | ev_5868fd4afe999e7d1aafb7358aece988818e1a7228a241c440d4dad25303d370
thunk_266598:
0x266598: JMP 0x0050cfe0
; END FUNCTION thunk_266598
0x26659d: INT3 ; original byte CC, padding
0x26659e: INT3 ; original byte CC, padding
0x26659f: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a0 [0x2665a0, 0x2665a4] | file +0xe98 | ev_1d3af3466642591fb9ae548773fa77f270dfa1e30126c5557abfe8798a26ea1e
thunk_2665a0:
0x2665a0: JMP 0x0051e4d0
; END FUNCTION thunk_2665a0
0x2665a5: INT3 ; original byte CC, padding
0x2665a6: INT3 ; original byte CC, padding
0x2665a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a8 [0x2665a8, 0x2665ac] | file +0xea0 | ev_632d3b384b31fc7b5fe70b62f0039def1d96dbfe25f77005039f00d57bcd942f
thunk_2665a8:
0x2665a8: JMP 0x0051ef60
; END FUNCTION thunk_2665a8
0x2665ad: INT3 ; original byte CC, padding
0x2665ae: INT3 ; original byte CC, padding
0x2665af: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b0 [0x2665b0, 0x2665b4] | file +0xea8 | ev_94edde6bfb8961eb7e729bdd77dd0bf926b17201e8338e7cb1020119fa0f2234
thunk_2665b0:
0x2665b0: JMP 0x0051f000
; END FUNCTION thunk_2665b0
0x2665b5: INT3 ; original byte CC, padding
0x2665b6: INT3 ; original byte CC, padding
0x2665b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b8 [0x2665b8, 0x2665bc] | file +0xeb0 | ev_f2e9166c9f386acb417d242b86be346cf51f95e0d63976665a57af55744197ea
thunk_2665b8:
0x2665b8: JMP 0x0051f0b0
; END FUNCTION thunk_2665b8
0x2665bd: INT3 ; original byte CC, padding
0x2665be: INT3 ; original byte CC, padding
0x2665bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c0 [0x2665c0, 0x2665c4] | file +0xeb8 | ev_9407f2080d4104ecd0eaff2585ea6744706bbd910f81860ffc7e9ba4d938f5e3
thunk_2665c0:
0x2665c0: JMP 0x0051f2e0
; END FUNCTION thunk_2665c0
0x2665c5: INT3 ; original byte CC, padding
0x2665c6: INT3 ; original byte CC, padding
0x2665c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c8 [0x2665c8, 0x2665cc] | file +0xec0 | ev_6c6f0cc089b1226a7d6726d9e43a828973723387ff0e9e1f51a32e4aab932f5b
thunk_2665c8:
0x2665c8: JMP 0x0051f670
; END FUNCTION thunk_2665c8
0x2665cd: INT3 ; original byte CC, padding
0x2665ce: INT3 ; original byte CC, padding
0x2665cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d0 [0x2665d0, 0x2665d4] | file +0xec8 | ev_de593e95b52c6954e7b5a8bdf1fb7eb8da68f265b88d3ee5ca370c7dbbf35a50
thunk_2665d0:
0x2665d0: JMP 0x0051fee0
; END FUNCTION thunk_2665d0
0x2665d5: INT3 ; original byte CC, padding
0x2665d6: INT3 ; original byte CC, padding
0x2665d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d8 [0x2665d8, 0x2665dc] | file +0xed0 | ev_4b6c006f374d6f4364ae18785bffb8f9246c17dd08eccb325d682318cb34ba97
thunk_2665d8:
0x2665d8: JMP 0x00536400
; END FUNCTION thunk_2665d8
0x2665dd: INT3 ; original byte CC, padding
0x2665de: INT3 ; original byte CC, padding
0x2665df: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e0 [0x2665e0, 0x2665e4] | file +0xed8 | ev_1d5df3f7cc5b94434a0bcdd6c8bd3650cf445e8eb753129dbf8f5e0f70a0eb1d
thunk_2665e0:
0x2665e0: JMP 0x00544ca0
; END FUNCTION thunk_2665e0
0x2665e5: INT3 ; original byte CC, padding
0x2665e6: INT3 ; original byte CC, padding
0x2665e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e8 [0x2665e8, 0x2665ec] | file +0xee0 | ev_0d9fc998f59eb9321b785945f66f8959c5918c8ad836154bb965bd9d2296264a
thunk_2665e8:
0x2665e8: JMP 0x005468f0
; END FUNCTION thunk_2665e8
0x2665ed: INT3 ; original byte CC, padding
0x2665ee: INT3 ; original byte CC, padding
0x2665ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f0 [0x2665f0, 0x2665f4] | file +0xee8 | ev_b116196a64488efd9c1b72ae3c533266522eda4a8fbb1b6e79e2733335a24e78
thunk_2665f0:
0x2665f0: JMP 0x000b1630
; END FUNCTION thunk_2665f0
0x2665f5: INT3 ; original byte CC, padding
0x2665f6: INT3 ; original byte CC, padding
0x2665f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665f8 [0x2665f8, 0x2665fc] | file +0xef0 | ev_3b702acb66c6b631c54492df6681303acc0017b9df69368f5a242ed562b21de5
thunk_2665f8:
0x2665f8: JMP 0x000b1fb0
; END FUNCTION thunk_2665f8
0x2665fd: INT3 ; original byte CC, padding
0x2665fe: INT3 ; original byte CC, padding
0x2665ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266600 [0x266600, 0x266604] | file +0xef8 | ev_1e07f001454166a3d1932f149491dd8e8ad0f746dbb751dbb62e05df4eb73cec
thunk_266600:
0x266600: JMP 0x0055bf40
; END FUNCTION thunk_266600
0x266605: INT3 ; original byte CC, padding
0x266606: INT3 ; original byte CC, padding
0x266607: INT3 ; original byte CC, padding

; FUNCTION thunk_266608 [0x266608, 0x26660c] | file +0xf00 | ev_fdaa12aca219d327f7b7013a4ac2ce6fb1668e6c95796c879ae08ad0a9a4d14c
thunk_266608:
0x266608: JMP 0x0055c030
; END FUNCTION thunk_266608
0x26660d: INT3 ; original byte CC, padding
0x26660e: INT3 ; original byte CC, padding
0x26660f: INT3 ; original byte CC, padding

; FUNCTION thunk_266610 [0x266610, 0x266614] | file +0xf08 | ev_cb7af76482977ad5099e10759b4f36bd807a74c02238ba70d09d477b0787d1b8
thunk_266610:
0x266610: JMP 0x0055c050
; END FUNCTION thunk_266610
0x266615: INT3 ; original byte CC, padding
0x266616: INT3 ; original byte CC, padding
0x266617: INT3 ; original byte CC, padding

; FUNCTION thunk_266618 [0x266618, 0x26661c] | file +0xf10 | ev_2bd9ac4e5e57f7adc97febe9846d1970db4ebd1190c8f9d8982c660d0253753e
thunk_266618:
0x266618: JMP 0x0056e200
; END FUNCTION thunk_266618
0x26661d: INT3 ; original byte CC, padding
0x26661e: INT3 ; original byte CC, padding
0x26661f: INT3 ; original byte CC, padding

; FUNCTION thunk_266620 [0x266620, 0x266624] | file +0xf18 | ev_593b98f7dc50a27a5588c48f4c17f1866befccab7662293c7e2333a3d50a6f4b
thunk_266620:
0x266620: JMP 0x0057f4a0
; END FUNCTION thunk_266620
0x266625: INT3 ; original byte CC, padding
0x266626: INT3 ; original byte CC, padding
0x266627: INT3 ; original byte CC, padding

; FUNCTION thunk_266628 [0x266628, 0x26662c] | file +0xf20 | ev_c5b83f0108bf44ae90930b50d0263279ff36467be223d600ced8fc96d2ee7929
thunk_266628:
0x266628: JMP 0x009945e0
; END FUNCTION thunk_266628
0x26662d: INT3 ; original byte CC, padding
0x26662e: INT3 ; original byte CC, padding
0x26662f: INT3 ; original byte CC, padding

; FUNCTION thunk_266630 [0x266630, 0x266634] | file +0xf28 | ev_5cf6d423437e99ddbb8cd8e4b40d39012dc65b942cb0c1269e98656d4e28ed42
thunk_266630:
0x266630: JMP 0x00585950
; END FUNCTION thunk_266630
0x266635: INT3 ; original byte CC, padding
0x266636: INT3 ; original byte CC, padding
0x266637: INT3 ; original byte CC, padding

; FUNCTION thunk_266638 [0x266638, 0x26663c] | file +0xf30 | ev_d3864fbae4a854bea158517502d07e2c640eed4f08054721bfa77e8437796a78
thunk_266638:
0x266638: JMP 0x00599820
; END FUNCTION thunk_266638
0x26663d: INT3 ; original byte CC, padding
0x26663e: INT3 ; original byte CC, padding
0x26663f: INT3 ; original byte CC, padding

; FUNCTION thunk_266640 [0x266640, 0x266644] | file +0xf38 | ev_0cf72c58a29aa48fdbeb3fe7471ccca3f55d02275a6b8e57bc8b493e93cc1983
thunk_266640:
0x266640: JMP 0x0059a3e0
; END FUNCTION thunk_266640
0x266645: INT3 ; original byte CC, padding
0x266646: INT3 ; original byte CC, padding
0x266647: INT3 ; original byte CC, padding

; FUNCTION thunk_266648 [0x266648, 0x26664c] | file +0xf40 | ev_88f8129ae070b59174d6629166daaf3cda09a413acdfd11e27c52697cea4e330
thunk_266648:
0x266648: JMP 0x0059a530
; END FUNCTION thunk_266648
0x26664d: INT3 ; original byte CC, padding
0x26664e: INT3 ; original byte CC, padding
0x26664f: INT3 ; original byte CC, padding

; FUNCTION thunk_266650 [0x266650, 0x266654] | file +0xf48 | ev_29da0dc73a44fd6dd2fd8d2091508c58564f4dc190a01efc2144843c6eda23f0
thunk_266650:
0x266650: JMP 0x0059a700
; END FUNCTION thunk_266650
0x266655: INT3 ; original byte CC, padding
0x266656: INT3 ; original byte CC, padding
0x266657: INT3 ; original byte CC, padding

; FUNCTION thunk_266658 [0x266658, 0x26665c] | file +0xf50 | ev_059a725bfe974d6b155fb60d27a08b661ebed71bef5f0cce2b6d74d7843196d6
thunk_266658:
0x266658: JMP 0x0059a7d0
; END FUNCTION thunk_266658
0x26665d: INT3 ; original byte CC, padding
0x26665e: INT3 ; original byte CC, padding
0x26665f: INT3 ; original byte CC, padding

; FUNCTION thunk_266660 [0x266660, 0x266664] | file +0xf58 | ev_aa770d9229105e8de9473b32c45eeab911e8040c7ead3a62086c8d81c0d63057
thunk_266660:
0x266660: JMP 0x0059aa50
; END FUNCTION thunk_266660
0x266665: INT3 ; original byte CC, padding
0x266666: INT3 ; original byte CC, padding
0x266667: INT3 ; original byte CC, padding

; FUNCTION thunk_266668 [0x266668, 0x26666c] | file +0xf60 | ev_5d8df5e689d73705cbe7911573c11e59f4c9dd14d7742265fe52131f8ffed6b8
thunk_266668:
0x266668: JMP 0x0059ab60
; END FUNCTION thunk_266668
0x26666d: INT3 ; original byte CC, padding
0x26666e: INT3 ; original byte CC, padding
0x26666f: INT3 ; original byte CC, padding

; FUNCTION thunk_266670 [0x266670, 0x266674] | file +0xf68 | ev_7497aa6f9391ccfe9f178de8d2e7b33b9d2692702e8fa5c686d888375be21115
thunk_266670:
0x266670: JMP 0x0059ac60
; END FUNCTION thunk_266670
0x266675: INT3 ; original byte CC, padding
0x266676: INT3 ; original byte CC, padding
0x266677: INT3 ; original byte CC, padding

; FUNCTION thunk_266678 [0x266678, 0x26667c] | file +0xf70 | ev_fd4b2d5033671b632bd9ee613bf95e7cf74b995cf067e25317f6f7a4520daf2e
thunk_266678:
0x266678: JMP 0x005dbed0
; END FUNCTION thunk_266678
0x26667d: INT3 ; original byte CC, padding
0x26667e: INT3 ; original byte CC, padding
0x26667f: INT3 ; original byte CC, padding

; FUNCTION thunk_266680 [0x266680, 0x266684] | file +0xf78 | ev_004be00b548657d12bea0e98f33bf3f7a871049b0855b14afdbb795e680d4ad8
thunk_266680:
0x266680: JMP 0x005eb720
; END FUNCTION thunk_266680
0x266685: INT3 ; original byte CC, padding
0x266686: INT3 ; original byte CC, padding
0x266687: INT3 ; original byte CC, padding

; FUNCTION thunk_266688 [0x266688, 0x26668c] | file +0xf80 | ev_c2162fb02fda50b640447f399c71ba268fd1992045f11f539a8a435a1ca274d1
thunk_266688:
0x266688: JMP 0x005ec030
; END FUNCTION thunk_266688
0x26668d: INT3 ; original byte CC, padding
0x26668e: INT3 ; original byte CC, padding
0x26668f: INT3 ; original byte CC, padding

; FUNCTION thunk_266690 [0x266690, 0x266694] | file +0xf88 | ev_eba0a4a74aa12436710862f2312ae575bf8a217d97a1ddb3ccb9c80335d6bd81
thunk_266690:
0x266690: JMP 0x005ecad0
; END FUNCTION thunk_266690
0x266695: INT3 ; original byte CC, padding
0x266696: INT3 ; original byte CC, padding
0x266697: INT3 ; original byte CC, padding

; FUNCTION thunk_266698 [0x266698, 0x26669c] | file +0xf90 | ev_5fda6a92c9d55295ca631a21884e06a3cc98de9725e3b4f37061e33c265cc0b4
thunk_266698:
0x266698: JMP 0x005ed440
; END FUNCTION thunk_266698
0x26669d: INT3 ; original byte CC, padding
0x26669e: INT3 ; original byte CC, padding
0x26669f: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a0 [0x2666a0, 0x2666a4] | file +0xf98 | ev_5f098f7d02fc4507b375d5517da227a6c9a7e570c92a3cf19b16b6907dea6e73
thunk_2666a0:
0x2666a0: JMP 0x005edb30
; END FUNCTION thunk_2666a0
0x2666a5: INT3 ; original byte CC, padding
0x2666a6: INT3 ; original byte CC, padding
0x2666a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666a8 [0x2666a8, 0x2666ac] | file +0xfa0 | ev_368ebdf88ad88722afc8583b9a3f7b89ca149ef8151b207eaf213873b8d1b44b
thunk_2666a8:
0x2666a8: JMP 0x0014e280
; END FUNCTION thunk_2666a8
0x2666ad: INT3 ; original byte CC, padding
0x2666ae: INT3 ; original byte CC, padding
0x2666af: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b0 [0x2666b0, 0x2666b4] | file +0xfa8 | ev_f48e2b21b39a7345cb8d6ccb11d68b5ddef61b23b3541819fb5f1f578f38f5fa
thunk_2666b0:
0x2666b0: JMP 0x005f18b0
; END FUNCTION thunk_2666b0
0x2666b5: INT3 ; original byte CC, padding
0x2666b6: INT3 ; original byte CC, padding
0x2666b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666b8 [0x2666b8, 0x2666bc] | file +0xfb0 | ev_ac4f1a25a415e295b1ecdd613c8acebed207e1359f2d047e975a29135068af7a
thunk_2666b8:
0x2666b8: JMP 0x005f2b30
; END FUNCTION thunk_2666b8
0x2666bd: INT3 ; original byte CC, padding
0x2666be: INT3 ; original byte CC, padding
0x2666bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c0 [0x2666c0, 0x2666c4] | file +0xfb8 | ev_656228c91f4b9d17f428d6dad119fc03036809e7293dbd512e9704dab45f5346
thunk_2666c0:
0x2666c0: JMP 0x005fd0c0
; END FUNCTION thunk_2666c0
0x2666c5: INT3 ; original byte CC, padding
0x2666c6: INT3 ; original byte CC, padding
0x2666c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666c8 [0x2666c8, 0x2666cc] | file +0xfc0 | ev_f9890d98733cf5b105bc535a06caf9e4dbe5739cb70df00f29ea69a52a7ae404
thunk_2666c8:
0x2666c8: JMP 0x00600680
; END FUNCTION thunk_2666c8
0x2666cd: INT3 ; original byte CC, padding
0x2666ce: INT3 ; original byte CC, padding
0x2666cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d0 [0x2666d0, 0x2666d4] | file +0xfc8 | ev_5346064d60c1151772b5afcfea264e91ea0405ef3932ec33cb4e4f8798d67ef7
thunk_2666d0:
0x2666d0: JMP 0x00600f40
; END FUNCTION thunk_2666d0
0x2666d5: INT3 ; original byte CC, padding
0x2666d6: INT3 ; original byte CC, padding
0x2666d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666d8 [0x2666d8, 0x2666dc] | file +0xfd0 | ev_f9366c8d734402c7bab13a139c6dd2e19a457b89a3715396d93d2b8f4fa6c02f
thunk_2666d8:
0x2666d8: JMP 0x00ae64a0
; END FUNCTION thunk_2666d8
0x2666dd: INT3 ; original byte CC, padding
0x2666de: INT3 ; original byte CC, padding
0x2666df: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e0 [0x2666e0, 0x2666e4] | file +0xfd8 | ev_921888daae08e4063aa4b63cfe29da6024b44a8fdb1f332ac4026f152cd8408b
thunk_2666e0:
0x2666e0: JMP 0x0062daa0
; END FUNCTION thunk_2666e0
0x2666e5: INT3 ; original byte CC, padding
0x2666e6: INT3 ; original byte CC, padding
0x2666e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666e8 [0x2666e8, 0x2666ec] | file +0xfe0 | ev_b0ff6d81c0fda4a8690f4254c60494f3808bb2250b25c2646544d04989de6408
thunk_2666e8:
0x2666e8: JMP 0x006302d0
; END FUNCTION thunk_2666e8
0x2666ed: INT3 ; original byte CC, padding
0x2666ee: INT3 ; original byte CC, padding
0x2666ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f0 [0x2666f0, 0x2666f4] | file +0xfe8 | ev_fd18711d0a9cd1dc3c94bc30c0b90d2b0bf5a17834c0b37539f53fc9b04bada5
thunk_2666f0:
0x2666f0: JMP 0x00634f10
; END FUNCTION thunk_2666f0
0x2666f5: INT3 ; original byte CC, padding
0x2666f6: INT3 ; original byte CC, padding
0x2666f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2666f8 [0x2666f8, 0x2666fc] | file +0xff0 | ev_b2d0914c0bf11ca8a6b63ad73c28879ba8112411cc44b55c9158e1f31f6828d2
thunk_2666f8:
0x2666f8: JMP 0x0063f520
; END FUNCTION thunk_2666f8
0x2666fd: INT3 ; original byte CC, padding
0x2666fe: INT3 ; original byte CC, padding
0x2666ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266700 [0x266700, 0x266704] | file +0xff8 | ev_b3b8a09dd69c726029958431264c4518e87b5c6333736040e5583e3ffa5cfb33
thunk_266700:
0x266700: JMP 0x006579b0
; END FUNCTION thunk_266700
0x266705: INT3 ; original byte CC, padding
0x266706: INT3 ; original byte CC, padding
0x266707: INT3 ; original byte CC, padding



; ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_EXT_FUN_003af8e0 RVA 0x265708 | Evidence ev_719a817fad8756d6ec35956743113e97eb79ebb9e3e168c17c198f4b1dfe51a9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_668.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
<EXTERNAL>::thunk_EXT_FUN_003af8e0:
0x265708: JMP 0x003af8e0


; ===== TARGET: handler_668_body RVA 0x3af8e0 | Evidence ev_fc99bb6787dcc738c22b502b69849b8ff29b74271f0148f9f1c3836ea0a00f8d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_668.support.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handlers_b_support.elf SHA256 2b4ed3a3b88bdc0018718feb8e7ce9ce648fd045fa4512fac963c78239d66301 =====
handler_668_body:
0x3af8e0: PUSH RBP
0x3af8e1: MOV RBP, RSP
0x3af8e4: XOR ESI, ESI
0x3af8e6: POP RBP
0x3af8e7: JMP 0x00265760


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): handler_650_651_nosys_body RVA 0x5620e0 | Evidence ev_d3bc602c2586b12228e23650aa2a3b4c6f855acfc2f0888aecc081fca0243cc6 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_nosys.functions/0x5620e0.json | Source /tmp/handlers-a/context.elf SHA256 e50f48d9ed939fec51c4f6fdf27ccd27c17f070a4162880470aa7bb609f504a0 =====
handler_650_651_nosys_body:
0x5620e0: PUSH RBP
0x5620e1: MOV RBP, RSP
0x5620e4: PUSH R15
0x5620e6: PUSH R14
0x5620e8: PUSH R12
0x5620ea: PUSH RBX
0x5620eb: SUB RSP, 0x80
0x5620f2: LEA R12, [0x391c310]
0x5620f9: MOV EBX, 0x148
0x5620fe: MOV R14, RDI
0x562101: XOR ESI, ESI
0x562103: XOR EDX, EDX
0x562105: XOR ECX, ECX
0x562107: MOV RAX, qword ptr [R12]
0x56210b: MOV qword ptr [RBP + -0x28], RAX
0x56210f: ADD RBX, qword ptr [RDI + 0x8]
0x562113: MOV RDI, RBX
0x562116: CALL 0x004c6a00
0x56211b: LEA R15, [RBP + -0x98]
0x562122: MOV ESI, 0x70
0x562127: MOV RDI, R15
0x56212a: CALL 0x00258ff0
0x56212f: MOV dword ptr [RBP + -0x88], 0xc
0x562139: MOV dword ptr [RBP + -0x80], 0x10006
0x562140: MOV RSI, R14
0x562143: MOV EDX, 0xc
0x562148: MOV RCX, R15
0x56214b: MOV RDI, qword ptr [R14 + 0x8]
0x56214f: CALL 0x00560540
0x562154: MOV RDI, RBX
0x562157: XOR ESI, ESI
0x562159: XOR EDX, EDX
0x56215b: XOR ECX, ECX
0x56215d: CALL 0x004c6fa0
0x562162: MOV RAX, qword ptr [R12]
0x562166: CMP RAX, qword ptr [RBP + -0x28]
0x56216a: JNZ 0x00562181
0x56216c: MOV EAX, 0x4e
0x562171: ADD RSP, 0x80
0x562178: POP RBX
0x562179: POP R12
0x56217b: POP R14
0x56217d: POP R15
0x56217f: POP RBP
0x562180: RET
0x562181: CALL 0x006fd6b0
0x562186: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): adjacent_560540 RVA 0x560540 | Evidence ev_81d91fc02d2da7a03b70e167dcf730885ffa6b4960cc9fa24a9f7ba9a6464e1d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_nosys.functions/0x560540.json | Source /tmp/handlers-a/context.elf SHA256 e50f48d9ed939fec51c4f6fdf27ccd27c17f070a4162880470aa7bb609f504a0 =====
adjacent_560540:
0x560540: PUSH RBP
0x560541: MOV RBP, RSP
0x560544: PUSH R15
0x560546: PUSH R14
0x560548: PUSH R13
0x56054a: PUSH R12
0x56054c: PUSH RBX
0x56054d: SUB RSP, 0x98
0x560554: LEA R15, [0x391c310]
0x56055b: LEA R12D, [RDX + -0x1]
0x56055f: MOV RAX, qword ptr [R15]
0x560562: MOV qword ptr [RBP + -0x30], RAX
0x560566: CMP R12D, 0x80
0x56056d: JNC 0x00560fa6
0x560573: CMP dword ptr [RDI + 0xb8], 0x2
0x56057a: MOV RBX, RDI
0x56057d: JNZ 0x005605ac
0x56057f: XOR R13D, R13D
0x560582: TEST RCX, RCX
0x560585: JZ 0x0056091e
0x56058b: MOV EAX, dword ptr [RCX + 0x60]
0x56058e: AND EAX, 0x6
0x560591: CMP EAX, 0x4
0x560594: JNZ 0x0056091e
0x56059a: MOV RDI, qword ptr [0x035ab098]
0x5605a1: XOR R13D, R13D
0x5605a4: MOV RSI, RCX
0x5605a7: JMP 0x00560769
0x5605ac: TEST byte ptr [RBX + 0xb1], 0x8
0x5605b3: MOV R14, RSI
0x5605b6: MOV qword ptr [RBP + -0xb0], RCX
0x5605bd: JNZ 0x005605d4
0x5605bf: TEST byte ptr [RBX + 0x562], 0x2
0x5605c6: MOV EAX, 0x9
0x5605cb: CMOVZ EAX, EDX
0x5605ce: LEA R12D, [RAX + -0x1]
0x5605d2: MOV EDX, EAX
0x5605d4: MOV RDI, qword ptr [RBX + 0xb40]
0x5605db: MOV R13, qword ptr [RBX + 0xa8]
0x5605e2: MOV ESI, EDX
0x5605e4: MOV qword ptr [RBP + -0x88], RDX
0x5605eb: MOV EDX, 0x1
0x5605f0: OR ESI, 0x8000000
0x5605f6: CALL 0x00313d50
0x5605fb: XOR EAX, EAX
0x5605fd: CMP R12D, 0x1e
0x560601: JA 0x00560610
0x560603: MOV EAX, R12D
0x560606: LEA RCX, [0x15925c0]
0x56060d: MOV EAX, dword ptr [RCX + RAX*0x4]
0x560610: MOV dword ptr [RBP + -0x90], EAX
0x560616: TEST R14, R14
0x560619: JZ 0x00560627
0x56061b: LEA RAX, [R14 + 0xa0]
0x560622: JMP 0x005606d8
0x560627: CMP dword ptr [RBP + -0x88], 0x9
0x56062e: JNZ 0x00560650
0x560630: MOV RAX, qword ptr [RBX + 0x10]
0x560634: TEST RAX, RAX
0x560637: JZ 0x00560650
0x560639: NOP dword ptr [RAX]
0x560640: AND byte ptr [RAX + 0x2c0], 0xfe
0x560647: MOV RAX, qword ptr [RAX + 0x10]
0x56064b: TEST RAX, RAX
0x56064e: JNZ 0x00560640
0x560650: MOV R14, qword ptr GS:[0x0]
0x560659: CMP qword ptr [R14 + 0x8], RBX
0x56065d: JNZ 0x00560673
0x56065f: MOV EAX, R12D
0x560662: SHR EAX, 0x5
0x560665: MOV EAX, dword ptr [R14 + RAX*0x4 + 0x3b0]
0x56066d: BT EAX, R12D
0x560671: JNC 0x005606d1
0x560673: MOV RAX, qword ptr [RBX + 0x10]
0x560677: TEST RAX, RAX
0x56067a: JZ 0x005606ce
0x56067c: MOV ECX, R12D
0x56067f: MOV EDX, 0x1
0x560684: MOV R14, RAX
0x560687: SHR ECX, 0x5
0x56068a: SHLX EDX, EDX, R12D
0x56068f: JMP 0x005606a9
0x5606a0: MOV R14, qword ptr [R14 + 0x10]
0x5606a4: TEST R14, R14
0x5606a7: JZ 0x005606c9
0x5606a9: TEST dword ptr [R14 + RCX*0x4 + 0x3b0], EDX
0x5606b1: JNZ 0x005606a0
0x5606b3: TEST byte ptr [R14 + 0x2c0], 0x1
0x5606bb: JNZ 0x005606a0
0x5606bd: TEST byte ptr [R14 + 0xe8], 0x20
0x5606c5: JNZ 0x005606a0
0x5606c7: JMP 0x005606d1
0x5606c9: MOV R14, RAX
0x5606cc: JMP 0x005606d1
0x5606ce: XOR R14D, R14D
0x5606d1: LEA RAX, [RBX + 0x1b8]
0x5606d8: MOV RDI, qword ptr [0x01ad6bf8]
0x5606df: MOV qword ptr [RBP + -0xa0], RAX
0x5606e6: TEST RDI, RDI
0x5606e9: JNZ 0x00560f2f
0x5606ef: LEA R15, [R13 + 0xcc0]
0x5606f6: XOR ESI, ESI
0x5606f8: XOR EDX, EDX
0x5606fa: XOR ECX, ECX
0x5606fc: MOV RDI, R15
0x5606ff: CALL 0x004c6a00
0x560704: MOV EAX, R12D
0x560707: SHR EAX, 0x5
0x56070a: MOV ECX, dword ptr [R13 + RAX*0x4 + 0xc50]
0x560712: BT ECX, R12D
0x560716: JNC 0x00560775
0x560718: MOV RDI, qword ptr [0x01ad6cb8]
0x56071f: TEST RDI, RDI
0x560722: JNZ 0x00560f6e
0x560728: MOV RDI, R15
0x56072b: XOR R13D, R13D
0x56072e: XOR ESI, ESI
0x560730: XOR EDX, EDX
0x560732: XOR ECX, ECX
0x560734: CALL 0x004c6fa0
0x560739: MOV RSI, qword ptr [RBP + -0xb0]
0x560740: TEST RSI, RSI
0x560743: JZ 0x0056084a
0x560749: MOV EAX, dword ptr [RSI + 0x60]
0x56074c: LEA R15, [0x391c310]
0x560753: AND EAX, 0x6
0x560756: CMP EAX, 0x4
0x560759: JNZ 0x0056091e
0x56075f: MOV RDI, qword ptr [0x035ab098]
0x560766: XOR R13D, R13D
0x560769: XOR EDX, EDX
0x56076b: CALL 0x0043c0c0
0x560770: JMP 0x0056091e
0x560775: MOV EDX, dword ptr [R14 + RAX*0x4 + 0x3b0]
0x56077d: MOV ECX, 0x1
0x560782: SHLX ESI, ECX, R12D
0x560787: MOV dword ptr [RBP + -0xb4], EDX
0x56078d: TEST EDX, ESI
0x56078f: JZ 0x005607ac
0x560791: MOV ECX, 0x3
0x560796: MOV dword ptr [RBP + -0x98], 0x0
0x5607a0: MOV dword ptr [RBP + -0x94], 0x0
0x5607aa: JMP 0x005607ca
0x5607ac: XOR ECX, ECX
0x5607ae: TEST dword ptr [R13 + RAX*0x4 + 0xc60], ESI
0x5607b6: SETNZ CL
0x5607b9: SETZ DL
0x5607bc: MOV dword ptr [RBP + -0x94], ECX
0x5607c2: ADD ECX, ECX
0x5607c4: MOV dword ptr [RBP + -0x98], EDX
0x5607ca: MOV qword ptr [RBP + -0xa8], RCX
0x5607d1: MOV EAX, dword ptr [R13 + RAX*0x4 + 0xc10]
0x5607d9: MOV RDI, R15
0x5607dc: MOV dword ptr [RBP + -0xb8], ESI
0x5607e2: AND EAX, ESI
0x5607e4: CMP EAX, 0x1
0x5607e7: SETNC byte ptr [RBP + -0x89]
0x5607ee: XOR ESI, ESI
0x5607f0: XOR EDX, EDX
0x5607f2: XOR ECX, ECX
0x5607f4: CALL 0x004c6fa0
0x5607f9: MOV EAX, dword ptr [RBP + -0x90]
0x5607ff: TEST AL, 0x20
0x560801: JNZ 0x00560856
0x560803: TEST AL, 0x4
0x560805: JZ 0x005608f6
0x56080b: TEST byte ptr [RBP + -0x90], 0x8
0x560812: JZ 0x00560a4f
0x560818: MOV RAX, qword ptr [RBX + 0xb38]
0x56081f: MOV ECX, dword ptr [RBP + -0x98]
0x560825: CMP dword ptr [RAX + 0x2c], 0x0
0x560829: SETNZ AL
0x56082c: XOR CL, 0x1
0x56082f: OR CL, AL
0x560831: JNZ 0x00560a4f
0x560837: MOV RSI, qword ptr [RBP + -0xb0]
0x56083e: XOR R13D, R13D
0x560841: TEST RSI, RSI
0x560844: JNZ 0x00560749
0x56084a: LEA R15, [0x391c310]
0x560851: JMP 0x0056091e
0x560856: LEA RAX, [RBP + -0x50]
0x56085a: LEA RDI, [RBX + 0x1b8]
0x560861: LEA RSI, [RBP + -0x70]
0x560865: LEA RDX, [RBP + -0x80]
0x560869: MOV qword ptr [RBP + -0x78], 0x0
0x560871: MOV qword ptr [RBP + -0x70], 0x0
0x560879: MOV qword ptr [RBP + -0x68], 0x0
0x560881: MOV qword ptr [RBP + -0x60], 0x0
0x560889: MOV qword ptr [RBP + -0x58], 0x0
0x560891: MOV qword ptr [RBP + -0x50], 0x0
0x560899: MOV qword ptr [RBP + -0x80], 0x330000
0x5608a1: MOV qword ptr [RBP + -0x48], RAX
0x5608a5: MOV qword ptr [RBP + -0x40], 0x0
0x5608ad: MOV dword ptr [RBP + -0x38], 0x1
0x5608b4: CALL 0x00562560
0x5608b9: MOV R12, qword ptr [RBX + 0x10]
0x5608bd: TEST R12, R12
0x5608c0: JZ 0x005608ed
0x5608c2: LEA R15, [RBP + -0x70]
0x5608c6: LEA R13, [RBP + -0x80]
0x5608ca: NOP word ptr [RAX + RAX*0x1]
0x5608d0: LEA RDI, [R12 + 0xa0]
0x5608d8: MOV RSI, R15
0x5608db: MOV RDX, R13
0x5608de: CALL 0x00562560
0x5608e3: MOV R12, qword ptr [R12 + 0x10]
0x5608e8: TEST R12, R12
0x5608eb: JNZ 0x005608d0
0x5608ed: LEA RDI, [RBP + -0x70]
0x5608f1: CALL 0x0055c4e0
0x5608f6: MOV RDI, qword ptr [RBP + -0xa0]
0x5608fd: MOV RDX, qword ptr [RBP + -0xb0]
0x560904: MOV RSI, qword ptr [RBP + -0x88]
0x56090b: CALL 0x005612a0
0x560910: LEA R15, [0x391c310]
0x560917: MOV R13D, EAX
0x56091a: TEST EAX, EAX
0x56091c: JZ 0x00560940
0x56091e: MOV RAX, qword ptr [R15]
0x560921: CMP RAX, qword ptr [RBP + -0x30]
0x560925: JNZ 0x00560fe2
0x56092b: MOV EAX, R13D
0x56092e: ADD RSP, 0x98
0x560935: POP RBX
0x560936: POP R12
0x560938: POP R13
0x56093a: POP R14
0x56093c: POP R15
0x56093e: POP RBP
0x56093f: RET
0x560940: MOV RDI, R14
0x560943: CALL 0x0055cf70
0x560948: MOV EAX, dword ptr [RBP + -0xb4]
0x56094e: TEST dword ptr [RBP + -0xb8], EAX
0x560954: JZ 0x0056096b
0x560956: XOR R13D, R13D
0x560959: TEST byte ptr [RBP + -0x90], 0x20
0x560960: JZ 0x0056091e
0x560962: TEST byte ptr [RBX + 0xb2], 0x2
0x560969: JZ 0x0056091e
0x56096b: XOR R12D, R12D
0x56096e: MOVZX EAX, byte ptr [RBP + -0x89]
0x560975: CMP dword ptr [RBP + -0x88], 0x9
0x56097c: MOV R12B, AL
0x56097f: JNZ 0x0056099e
0x560981: LEA RDI, [RBX + 0x380]
0x560988: MOV dword ptr [RBX + 0x378], 0x0
0x560992: MOV byte ptr [RBX + 0x380], 0x0
0x560999: CALL 0x00c06910
0x56099e: MOV RCX, qword ptr [RBX + 0x560]
0x5609a5: TEST CL, 0x2
0x5609a8: JNZ 0x005609b1
0x5609aa: AND byte ptr [RBX + 0xb2], 0xfb
0x5609b1: CMP dword ptr [RBP + -0x88], 0x9
0x5609b8: LEA R12D, [R12 + R12*0x4 + -0x1]
0x5609bd: JNZ 0x00560b53
0x5609c3: MOV R15, qword ptr [RBX + 0x10]
0x5609c7: TEST R15, R15
0x5609ca: JZ 0x00560a15
0x5609cc: LEA R13, [0x12b5611]
0x5609d3: NOP dword ptr CS:[RAX + RAX*0x1]
0x5609e0: MOV RDI, R15
0x5609e3: MOV RDX, R13
0x5609e6: MOV ECX, 0x95a
0x5609eb: XOR ESI, ESI
0x5609ed: CALL 0x004c78b0
0x5609f2: MOV RDI, R15
0x5609f5: CALL 0x006f93a0
0x5609fa: MOV RDI, qword ptr [R15]
0x5609fd: XOR ESI, ESI
0x5609ff: XOR EDX, EDX
0x560a01: XOR ECX, ECX
0x560a03: ADD RDI, 0x18
0x560a07: CALL 0x004c7520
0x560a0c: MOV R15, qword ptr [R15 + 0x10]
0x560a10: TEST R15, R15
0x560a13: JNZ 0x005609e0
0x560a15: MOV EAX, dword ptr [RBX + 0xb0]
0x560a1b: TEST EAX, 0xe0000
0x560a20: JZ 0x00560be5
0x560a26: LEA R15, [0x391c310]
0x560a2d: MOV RSI, qword ptr [RBP + -0x88]
0x560a34: TEST EAX, 0x800
0x560a39: JNZ 0x00560d5f
0x560a3f: AND EAX, 0xfffdf7ff
0x560a44: MOV dword ptr [RBX + 0xb0], EAX
0x560a4a: JMP 0x00560db6
0x560a4f: LEA RAX, [RBP + -0x50]
0x560a53: LEA RDI, [RBX + 0x1b8]
0x560a5a: LEA RSI, [RBP + -0x70]
0x560a5e: LEA RDX, [RBP + -0x80]
0x560a62: MOV qword ptr [RBP + -0x78], 0x0
0x560a6a: MOV qword ptr [RBP + -0x70], 0x0
0x560a72: MOV qword ptr [RBP + -0x68], 0x0
0x560a7a: MOV qword ptr [RBP + -0x60], 0x0
0x560a82: MOV qword ptr [RBP + -0x58], 0x0
0x560a8a: MOV qword ptr [RBP + -0x50], 0x0
0x560a92: MOV qword ptr [RBP + -0x80], 0x40000
0x560a9a: MOV qword ptr [RBP + -0x48], RAX
0x560a9e: MOV qword ptr [RBP + -0x40], 0x0
0x560aa6: MOV dword ptr [RBP + -0x38], 0x1
0x560aad: CALL 0x00562560
0x560ab2: MOV R12, qword ptr [RBX + 0x10]
0x560ab6: TEST R12, R12
0x560ab9: JZ 0x00560aed
0x560abb: LEA R15, [RBP + -0x70]
0x560abf: LEA R13, [RBP + -0x80]
0x560ac3: NOP dword ptr CS:[RAX + RAX*0x1]
0x560ad0: LEA RDI, [R12 + 0xa0]
0x560ad8: MOV RSI, R15
0x560adb: MOV RDX, R13
0x560ade: CALL 0x00562560
0x560ae3: MOV R12, qword ptr [R12 + 0x10]
0x560ae8: TEST R12, R12
0x560aeb: JNZ 0x00560ad0
0x560aed: LEA RDI, [RBP + -0x70]
0x560af1: CALL 0x0055c4e0
0x560af6: MOV EAX, dword ptr [RBX + 0xb0]
0x560afc: TEST EAX, 0x10000
0x560b01: JZ 0x005608f6
0x560b07: AND EAX, 0xfffeffff
0x560b0c: MOV R15D, 0x148
0x560b12: XOR ESI, ESI
0x560b14: XOR EDX, EDX
0x560b16: XOR ECX, ECX
0x560b18: MOV dword ptr [RBX + 0xb0], EAX
0x560b1e: MOV RDI, qword ptr [RBX + 0xe0]
0x560b25: ADD RDI, R15
0x560b28: CALL 0x004c6a00
0x560b2d: MOV RDI, qword ptr [RBX + 0x1b0]
0x560b34: CALL 0x0055c390
0x560b39: ADD R15, qword ptr [RBX + 0xe0]
0x560b40: XOR ESI, ESI
0x560b42: XOR EDX, EDX
0x560b44: XOR ECX, ECX
0x560b46: MOV RDI, R15
0x560b49: CALL 0x004c6fa0
0x560b4e: JMP 0x005608f6
0x560b53: MOV EAX, dword ptr [RBX + 0xb0]
0x560b59: MOV EDX, dword ptr [RBP + -0x90]
0x560b5f: TEST EAX, 0xe0000
0x560b64: JZ 0x00560bfb
0x560b6a: TEST DL, 0x20
0x560b6d: JNZ 0x00560c57
0x560b73: TEST DL, 0x4
0x560b76: JNZ 0x00560d67
0x560b7c: ADD RBX, 0x38
0x560b80: XOR R13D, R13D
0x560b83: XOR ESI, ESI
0x560b85: XOR EDX, EDX
0x560b87: XOR ECX, ECX
0x560b89: MOV RDI, RBX
0x560b8c: CALL 0x004c7190
0x560b91: LEA RDX, [0x12b5611]
0x560b98: MOV RDI, R14
0x560b9b: MOV ECX, 0x9cb
0x560ba0: XOR ESI, ESI
0x560ba2: CALL 0x004c78b0
0x560ba7: CMP qword ptr [R14 + 0xf8], 0x0
0x560baf: JZ 0x00560bc0
0x560bb1: MOV EAX, dword ptr [R14 + 0xe4]
0x560bb8: TEST AL, 0x8
0x560bba: JNZ 0x00560e1d
0x560bc0: MOV RDI, qword ptr [R14]
0x560bc3: XOR ESI, ESI
0x560bc5: XOR EDX, EDX
0x560bc7: XOR ECX, ECX
0x560bc9: ADD RDI, 0x18
0x560bcd: CALL 0x004c7520
0x560bd2: MOV RDI, RBX
0x560bd5: XOR ESI, ESI
0x560bd7: XOR EDX, EDX
0x560bd9: XOR ECX, ECX
0x560bdb: CALL 0x004c7520
0x560be0: JMP 0x0056091e
0x560be5: LEA R15, [0x391c310]
0x560bec: MOV RSI, qword ptr [RBP + -0x88]
0x560bf3: MOV EDX, dword ptr [RBP + -0x90]
0x560bf9: JMP 0x00560c02
0x560bfb: MOV RSI, qword ptr [RBP + -0x88]
0x560c02: CMP dword ptr [RBX + 0xb8], 0x1
0x560c09: JNZ 0x00560c46
0x560c0b: MOV ESI, dword ptr [RBP + -0x94]
0x560c11: TEST EAX, 0x800
0x560c16: SETZ CL
0x560c19: NOT SIL
0x560c1c: TEST SIL, CL
0x560c1f: JNZ 0x00560d48
0x560c25: MOV RDX, qword ptr [RBP + -0xa8]
0x560c2c: MOV RDI, R14
0x560c2f: MOV ECX, R12D
0x560c32: MOV RSI, qword ptr [RBP + -0x88]
0x560c39: CALL 0x00561470
0x560c3e: XOR R13D, R13D
0x560c41: JMP 0x0056091e
0x560c46: MOV RDI, qword ptr [RBP + -0xa0]
0x560c4d: CALL 0x0055c620
0x560c52: JMP 0x00560d5f
0x560c57: MOV EDX, EAX
0x560c59: SHR ECX, 0x1
0x560c5b: SHR EDX, 0xb
0x560c5e: AND EDX, ECX
0x560c60: TEST DL, 0x1
0x560c63: JNZ 0x00560d5f
0x560c69: LEA R15, [RBX + 0x38]
0x560c6d: AND EAX, 0xfffdffff
0x560c72: XOR ESI, ESI
0x560c74: XOR EDX, EDX
0x560c76: XOR ECX, ECX
0x560c78: MOV RDI, R15
0x560c7b: MOV dword ptr [RBX + 0xb0], EAX
0x560c81: CALL 0x004c7190
0x560c86: MOV EAX, dword ptr [RBX + 0xb48]
0x560c8c: CMP EAX, dword ptr [RBX + 0x3a0]
0x560c92: JNZ 0x00560d03
0x560c94: MOV RDI, R15
0x560c97: XOR ESI, ESI
0x560c99: XOR EDX, EDX
0x560c9b: XOR ECX, ECX
0x560c9d: CALL 0x004c7520
0x560ca2: OR byte ptr [RBX + 0xb2], 0x1
0x560ca9: MOV dword ptr [RBX + 0xa30], 0x13
0x560cb3: MOV R13D, 0x148
0x560cb9: XOR ESI, ESI
0x560cbb: XOR EDX, EDX
0x560cbd: XOR ECX, ECX
0x560cbf: MOV RDI, qword ptr [RBX + 0xe0]
0x560cc6: ADD RDI, R13
0x560cc9: CALL 0x004c6a00
0x560cce: MOV RDI, RBX
0x560cd1: MOV ESI, 0x6
0x560cd6: MOV EDX, 0x13
0x560cdb: CALL 0x00561f10
0x560ce0: ADD R13, qword ptr [RBX + 0xe0]
0x560ce7: XOR ESI, ESI
0x560ce9: XOR EDX, EDX
0x560ceb: XOR ECX, ECX
0x560ced: MOV RDI, R13
0x560cf0: CALL 0x004c6fa0
0x560cf5: MOV RDI, R15
0x560cf8: XOR ESI, ESI
0x560cfa: XOR EDX, EDX
0x560cfc: XOR ECX, ECX
0x560cfe: CALL 0x004c7190
0x560d03: CMP byte ptr [RBP + -0x98], 0x0
0x560d0a: JZ 0x00560d98
0x560d10: MOV RDI, RBX
0x560d13: CALL 0x00b91ed0
0x560d18: MOV RDI, R15
0x560d1b: XOR R13D, R13D
0x560d1e: XOR ESI, ESI
0x560d20: XOR EDX, EDX
0x560d22: XOR ECX, ECX
0x560d24: CALL 0x004c7520
0x560d29: MOV RDI, qword ptr [RBP + -0xa0]
0x560d30: MOV RSI, qword ptr [RBP + -0x88]
0x560d37: CALL 0x0055c620
0x560d3c: LEA R15, [0x391c310]
0x560d43: JMP 0x0056091e
0x560d48: MOV RSI, qword ptr [RBP + -0x88]
0x560d4f: TEST DL, 0x4
0x560d52: JZ 0x00560db6
0x560d54: TEST EAX, 0x2010
0x560d59: JZ 0x00560e97
0x560d5f: XOR R13D, R13D
0x560d62: JMP 0x0056091e
0x560d67: XOR R13D, R13D
0x560d6a: TEST EAX, 0x800
0x560d6f: JNZ 0x0056091e
0x560d75: MOV RDI, qword ptr [RBP + -0xa0]
0x560d7c: OR EAX, 0x20000
0x560d81: MOV RSI, qword ptr [RBP + -0x88]
0x560d88: MOV dword ptr [RBX + 0xb0], EAX
0x560d8e: CALL 0x0055c620
0x560d93: JMP 0x0056091e
0x560d98: CMP byte ptr [RBP + -0x94], 0x0
0x560d9f: JZ 0x00560df8
0x560da1: MOV RDI, R15
0x560da4: XOR ESI, ESI
0x560da6: XOR EDX, EDX
0x560da8: XOR ECX, ECX
0x560daa: CALL 0x004c7520
0x560daf: MOV RSI, qword ptr [RBP + -0x88]
0x560db6: MOV RDX, qword ptr [RBP + -0xa8]
0x560dbd: MOV RDI, R14
0x560dc0: MOV ECX, R12D
0x560dc3: MOV R13, RSI
0x560dc6: CALL 0x00561470
0x560dcb: LEA R15, [RBX + 0x38]
0x560dcf: XOR ESI, ESI
0x560dd1: XOR EDX, EDX
0x560dd3: XOR ECX, ECX
0x560dd5: MOV RDI, R15
0x560dd8: CALL 0x004c7190
0x560ddd: CMP R13D, 0x9
0x560de1: JNZ 0x00560df8
0x560de3: MOV RDI, RBX
0x560de6: CALL 0x00b921e0
0x560deb: MOV RDI, RBX
0x560dee: MOV RSI, R14
0x560df1: CALL 0x00b92070
0x560df6: JMP 0x00560e00
0x560df8: MOV RDI, RBX
0x560dfb: CALL 0x00b91ed0
0x560e00: MOV RDI, R15
0x560e03: XOR R13D, R13D
0x560e06: XOR ESI, ESI
0x560e08: XOR EDX, EDX
0x560e0a: XOR ECX, ECX
0x560e0c: CALL 0x004c7520
0x560e11: LEA R15, [0x391c310]
0x560e18: JMP 0x0056091e
0x560e1d: MOV ECX, dword ptr [R14 + 0xe8]
0x560e24: TEST CL, 0x20
0x560e27: JZ 0x00560e4c
0x560e29: AND ECX, 0xffffffdf
0x560e2c: MOV dword ptr [R14 + 0xe8], ECX
0x560e33: JNZ 0x00560e40
0x560e35: MOV dword ptr [R14 + 0x400], 0x2
0x560e40: OR EAX, 0x80000800
0x560e45: MOV dword ptr [R14 + 0xe4], EAX
0x560e4c: MOV RDI, R14
0x560e4f: MOV ESI, R12D
0x560e52: CALL 0x00c1b3e0
0x560e57: MOV RDI, qword ptr [R14]
0x560e5a: MOV R15D, EAX
0x560e5d: XOR R13D, R13D
0x560e60: XOR ESI, ESI
0x560e62: XOR EDX, EDX
0x560e64: XOR ECX, ECX
0x560e66: ADD RDI, 0x18
0x560e6a: CALL 0x004c7520
0x560e6f: MOV RDI, RBX
0x560e72: XOR ESI, ESI
0x560e74: XOR EDX, EDX
0x560e76: XOR ECX, ECX
0x560e78: CALL 0x004c7520
0x560e7d: TEST R15D, R15D
0x560e80: JZ 0x0056084a
0x560e86: CALL 0x0053acf0
0x560e8b: LEA R15, [0x391c310]
0x560e92: JMP 0x0056091e
0x560e97: LEA R15, [RBX + 0x38]
0x560e9b: OR EAX, 0x20000
0x560ea0: XOR EDX, EDX
0x560ea2: XOR ECX, ECX
0x560ea4: MOV RDI, R15
0x560ea7: MOV dword ptr [RBX + 0xb0], EAX
0x560ead: MOV dword ptr [RBX + 0xa30], ESI
0x560eb3: XOR ESI, ESI
0x560eb5: CALL 0x004c7190
0x560eba: MOV RDI, R14
0x560ebd: MOV RSI, RBX
0x560ec0: CALL 0x00561730
0x560ec5: MOV R14D, EAX
0x560ec8: MOV EAX, dword ptr [RBX + 0xb48]
0x560ece: CMP EAX, dword ptr [RBX + 0x3a0]
0x560ed4: JNZ 0x00560f04
0x560ed6: MOV RDI, RBX
0x560ed9: CALL 0x005619e0
0x560ede: MOV RDI, R15
0x560ee1: XOR ESI, ESI
0x560ee3: XOR EDX, EDX
0x560ee5: XOR ECX, ECX
0x560ee7: CALL 0x004c7520
0x560eec: MOV RDI, RBX
0x560eef: CALL 0x00a91ce0
0x560ef4: MOV ESI, dword ptr [RBX + 0xa30]
0x560efa: MOV RDI, RBX
0x560efd: CALL 0x0055c820
0x560f02: JMP 0x00560f12
0x560f04: MOV RDI, R15
0x560f07: XOR ESI, ESI
0x560f09: XOR EDX, EDX
0x560f0b: XOR ECX, ECX
0x560f0d: CALL 0x004c7520
0x560f12: LEA R15, [0x391c310]
0x560f19: XOR R13D, R13D
0x560f1c: TEST R14D, R14D
0x560f1f: JZ 0x0056091e
0x560f25: CALL 0x0053acf0
0x560f2a: JMP 0x0056091e
0x560f2f: LEA RAX, [0x1a9bf28]
0x560f36: MOV R15, qword ptr [RAX]
0x560f39: LEA RAX, [0x2681e8]
0x560f40: SUB RAX, R15
0x560f43: ROR RAX, 0x3
0x560f47: CMP RAX, 0x1
0x560f4b: MOV RAX, qword ptr [RBP + -0x88]
0x560f52: JA 0x00560fe9
0x560f58: MOV ECX, EAX
0x560f5a: MOV RSI, R14
0x560f5d: MOV RDX, RBX
0x560f60: XOR R8D, R8D
0x560f63: XOR R9D, R9D
0x560f66: CALL R15
0x560f69: JMP 0x005606ef
0x560f6e: LEA RAX, [0x1a9bf28]
0x560f75: MOV R13, qword ptr [RAX]
0x560f78: LEA RAX, [0x2681e8]
0x560f7f: SUB RAX, R13
0x560f82: ROR RAX, 0x3
0x560f86: CMP RAX, 0x1
0x560f8a: JA 0x0056100b
0x560f8c: MOV ECX, dword ptr [RBP + -0x88]
0x560f92: MOV RSI, R14
0x560f95: MOV RDX, RBX
0x560f98: XOR R8D, R8D
0x560f9b: XOR R9D, R9D
0x560f9e: CALL R13
0x560fa1: JMP 0x00560728
0x560fa6: MOV R14, RDX
0x560fa9: CALL 0x007f1950
0x560fae: LEA RBX, [0x12a11e7]
0x560fb5: MOVSXD RDX, R14D
0x560fb8: LEA RDI, [0x560fa6]
0x560fbf: MOV RSI, RBX
0x560fc2: CALL 0x007f2010
0x560fc7: LEA RSI, [0x137158a]
0x560fce: MOV EDI, 0x2b
0x560fd3: MOV RDX, RBX
0x560fd6: MOV ECX, R14D
0x560fd9: XOR EAX, EAX
0x560fdb: CALL 0x00c9aa10
0x560fe0: UD2
0x560fe2: CALL 0x006fd6b0
0x560fe7: UD2
0x560fe9: LEA RDI, [0x1ad72e0]
0x560ff0: MOV RSI, R15
0x560ff3: CALL 0x0044f8c0
0x560ff8: MOV RAX, qword ptr [RBP + -0x88]
0x560fff: MOV RDI, qword ptr [0x01ad6bf8]
0x561006: JMP 0x00560f58
0x56100b: LEA RDI, [0x1ad7300]
0x561012: MOV RSI, R13
0x561015: CALL 0x0044f8c0
0x56101a: MOV RDI, qword ptr [0x01ad6cb8]
0x561021: JMP 0x00560f8c


; ===== SUPPLEMENTAL GNU objdump full linear disassembly of every original4096 input byte =====
; Source raw file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_668.bin
; This is independent linear decoding, not REA function discovery; padding/data may decode as instructions.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_668.bin:     file format binary


Disassembly of section .data:

0000000000265708 <.data>:
  265708:	e9 d3 a1 14 00       	jmp    0x3af8e0
  26570d:	cc                   	int3
  26570e:	cc                   	int3
  26570f:	cc                   	int3
  265710:	e9 db a1 14 00       	jmp    0x3af8f0
  265715:	cc                   	int3
  265716:	cc                   	int3
  265717:	cc                   	int3
  265718:	e9 e3 a1 14 00       	jmp    0x3af900
  26571d:	cc                   	int3
  26571e:	cc                   	int3
  26571f:	cc                   	int3
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


; ===== SUPPLEMENTAL GNU objdump FULL original target-window bytes =====
; Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_668.body.bin SHA256 bf7bea36eaeeb8b15814ec092045c42b1504acf8f95a59bbf58025d740584c56
; RVA 0x3af8e0; size16384 bytes. This linear decode may include adjacent code/data and is not a REA boundary claim.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_668.body.bin:     file format binary


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
