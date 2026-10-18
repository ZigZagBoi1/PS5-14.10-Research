; Handler 649: Module-record selector query
; REA6.7.0/Ghidra12.1.4, static analysis; RVAs, not runtime addresses.
; Original4KB SHA256 c91696f14a12fd28bbdcf30162c156afb6291017349ac6560fbf2aa788b42763, entry 0x2655e8, tail target0x34cfa0.
; Runtime VA=0xffffffff8a9c0000+RVA. Analyst-inferred names/types are not original source.

; COMPLETE ORIGINAL INPUT WINDOW: handler_649.bin, 4096 bytes
; SHA256 c91696f14a12fd28bbdcf30162c156afb6291017349ac6560fbf2aa788b42763; file offset zero = kernel RVA 0x2655e8.
; REA 6.7.0 / Ghidra 12.1.4 procedure_assembly disassembled every JMP below.
; Each function range is its five-byte tail-JMP; three CC padding bytes follow.
; INT3 padding is decoded from verified original bytes; GNU full-byte listing is supplied separately.
; Evidence source: byte-identical slice of raw_union.bin; evidence IDs per procedure.

; FUNCTION thunk_2655e8 [0x2655e8, 0x2655ec] | file +0x0 | ev_d04f42a05898d8bd4b8960e81b16dbdc885ee891feec0db2bbbd6745a734b881
thunk_2655e8:
0x2655e8: JMP 0x0034cfa0
; END FUNCTION thunk_2655e8
0x2655ed: INT3 ; original byte CC, padding
0x2655ee: INT3 ; original byte CC, padding
0x2655ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2655f0 [0x2655f0, 0x2655f4] | file +0x8 | ev_a583b0b1a1b77d4401d93efdb7fdc69ed43822c0ccfbc9d84a83cae5c1067db6
thunk_2655f0:
0x2655f0: JMP 0x0037caa0
; END FUNCTION thunk_2655f0
0x2655f5: INT3 ; original byte CC, padding
0x2655f6: INT3 ; original byte CC, padding
0x2655f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2655f8 [0x2655f8, 0x2655fc] | file +0x10 | ev_5972dda5b00da72808982c8d711bb5bff9fffa07aeeb6cfdeb909c109d128315
thunk_2655f8:
0x2655f8: JMP 0x0037cb20
; END FUNCTION thunk_2655f8
0x2655fd: INT3 ; original byte CC, padding
0x2655fe: INT3 ; original byte CC, padding
0x2655ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265600 [0x265600, 0x265604] | file +0x18 | ev_8ff1316c7a4e64179e85baffffd024e42fadc1fe73aae463a4e5c3e6409c1afc
thunk_265600:
0x265600: JMP 0x0037ec40
; END FUNCTION thunk_265600
0x265605: INT3 ; original byte CC, padding
0x265606: INT3 ; original byte CC, padding
0x265607: INT3 ; original byte CC, padding

; FUNCTION thunk_265608 [0x265608, 0x26560c] | file +0x20 | ev_e532461b9c87f5f7609d71aa5c26ea1fa782ee7a6a5bc6691c1d3cbee0d557d1
thunk_265608:
0x265608: JMP 0x0037fa90
; END FUNCTION thunk_265608
0x26560d: INT3 ; original byte CC, padding
0x26560e: INT3 ; original byte CC, padding
0x26560f: INT3 ; original byte CC, padding

; FUNCTION thunk_265610 [0x265610, 0x265614] | file +0x28 | ev_7dbb4d99ff69671662f6b3799f461d45a8e60d8aadd5d44c5ded7270eb1afebf
thunk_265610:
0x265610: JMP 0x0037faa0
; END FUNCTION thunk_265610
0x265615: INT3 ; original byte CC, padding
0x265616: INT3 ; original byte CC, padding
0x265617: INT3 ; original byte CC, padding

; FUNCTION thunk_265618 [0x265618, 0x26561c] | file +0x30 | ev_00e874f5ec55b08ab1e90458551cc980df9fd7e6cac1c963c0000dbfc5e3cd2d
thunk_265618:
0x265618: JMP 0x0037fbc0
; END FUNCTION thunk_265618
0x26561d: INT3 ; original byte CC, padding
0x26561e: INT3 ; original byte CC, padding
0x26561f: INT3 ; original byte CC, padding

; FUNCTION thunk_265620 [0x265620, 0x265624] | file +0x38 | ev_b27291283b87566ebbf7402b46548974c36fb0a5669365bafd2af714a6da1a43
thunk_265620:
0x265620: JMP 0x0037fc70
; END FUNCTION thunk_265620
0x265625: INT3 ; original byte CC, padding
0x265626: INT3 ; original byte CC, padding
0x265627: INT3 ; original byte CC, padding

; FUNCTION thunk_265628 [0x265628, 0x26562c] | file +0x40 | ev_d57b5a725c90110c6e5b9a32b9fa69d662be87ba05bc19f321ddcef413e11870
thunk_265628:
0x265628: JMP 0x0037fc90
; END FUNCTION thunk_265628
0x26562d: INT3 ; original byte CC, padding
0x26562e: INT3 ; original byte CC, padding
0x26562f: INT3 ; original byte CC, padding

; FUNCTION thunk_265630 [0x265630, 0x265634] | file +0x48 | ev_46b1d35f9c7f7b763b35faf4b2cb7326aaef1746f3be8719d673dc85ad8b9ed8
thunk_265630:
0x265630: JMP 0x0037fd70
; END FUNCTION thunk_265630
0x265635: INT3 ; original byte CC, padding
0x265636: INT3 ; original byte CC, padding
0x265637: INT3 ; original byte CC, padding

; FUNCTION thunk_265638 [0x265638, 0x26563c] | file +0x50 | ev_ded72901a04864b5314aa55188fcf32ed509f53882971d5d485e088198909f72
thunk_265638:
0x265638: JMP 0x0037fd80
; END FUNCTION thunk_265638
0x26563d: INT3 ; original byte CC, padding
0x26563e: INT3 ; original byte CC, padding
0x26563f: INT3 ; original byte CC, padding

; FUNCTION thunk_265640 [0x265640, 0x265644] | file +0x58 | ev_032c15880de00d704df86f91ddb4dd549390ff43b06954783dfb05ae33c656a4
thunk_265640:
0x265640: JMP 0x00380260
; END FUNCTION thunk_265640
0x265645: INT3 ; original byte CC, padding
0x265646: INT3 ; original byte CC, padding
0x265647: INT3 ; original byte CC, padding

; FUNCTION thunk_265648 [0x265648, 0x26564c] | file +0x60 | ev_9a9940b367a2d434f043d987327963484706a7c35d52889e196df8cd8d4953c9
thunk_265648:
0x265648: JMP 0x00380760
; END FUNCTION thunk_265648
0x26564d: INT3 ; original byte CC, padding
0x26564e: INT3 ; original byte CC, padding
0x26564f: INT3 ; original byte CC, padding

; FUNCTION thunk_265650 [0x265650, 0x265654] | file +0x68 | ev_9f0def260481557902a1cd7fb54a56718b9221f3dd58c97820cf9f6a4f9085b6
thunk_265650:
0x265650: JMP 0x00380c90
; END FUNCTION thunk_265650
0x265655: INT3 ; original byte CC, padding
0x265656: INT3 ; original byte CC, padding
0x265657: INT3 ; original byte CC, padding

; FUNCTION thunk_265658 [0x265658, 0x26565c] | file +0x70 | ev_a822354efe7fca8962e45d7586031032de48afa47b4b3ef905b9f0c5abce4dc0
thunk_265658:
0x265658: JMP 0x00381140
; END FUNCTION thunk_265658
0x26565d: INT3 ; original byte CC, padding
0x26565e: INT3 ; original byte CC, padding
0x26565f: INT3 ; original byte CC, padding

; FUNCTION thunk_265660 [0x265660, 0x265664] | file +0x78 | ev_46b96ebed1fd2c2ddf1bdcc4b65ad190c22b31aa6c05e2867e1033d05d5c6a9f
thunk_265660:
0x265660: JMP 0x00381230
; END FUNCTION thunk_265660
0x265665: INT3 ; original byte CC, padding
0x265666: INT3 ; original byte CC, padding
0x265667: INT3 ; original byte CC, padding

; FUNCTION thunk_265668 [0x265668, 0x26566c] | file +0x80 | ev_50d2fc3a7d8fab4abcc03d4dc91f823b43793aa59ba4a13ce1a133fd9550970f
thunk_265668:
0x265668: JMP 0x00381330
; END FUNCTION thunk_265668
0x26566d: INT3 ; original byte CC, padding
0x26566e: INT3 ; original byte CC, padding
0x26566f: INT3 ; original byte CC, padding

; FUNCTION thunk_265670 [0x265670, 0x265674] | file +0x88 | ev_52b0d1e59f807fe153e1c36fe7cffc36424474d9b7125cbbf21c95af359229e5
thunk_265670:
0x265670: JMP 0x00381430
; END FUNCTION thunk_265670
0x265675: INT3 ; original byte CC, padding
0x265676: INT3 ; original byte CC, padding
0x265677: INT3 ; original byte CC, padding

; FUNCTION thunk_265678 [0x265678, 0x26567c] | file +0x90 | ev_90f27185bc0396128019a8eb015d78728f68be97c3d5f19a60b1ac13d70f46c7
thunk_265678:
0x265678: JMP 0x00381900
; END FUNCTION thunk_265678
0x26567d: INT3 ; original byte CC, padding
0x26567e: INT3 ; original byte CC, padding
0x26567f: INT3 ; original byte CC, padding

; FUNCTION thunk_265680 [0x265680, 0x265684] | file +0x98 | ev_3cc54f03858cf10549e3643f93fcc7212ae0c23ca647b90059b3b6175d3816cc
thunk_265680:
0x265680: JMP 0x003819f0
; END FUNCTION thunk_265680
0x265685: INT3 ; original byte CC, padding
0x265686: INT3 ; original byte CC, padding
0x265687: INT3 ; original byte CC, padding

; FUNCTION thunk_265688 [0x265688, 0x26568c] | file +0xa0 | ev_43f7f36df2779a9a1e50bfd9cc73e276dd78c156abbd2d36260b312a00612f38
thunk_265688:
0x265688: JMP 0x00381a10
; END FUNCTION thunk_265688
0x26568d: INT3 ; original byte CC, padding
0x26568e: INT3 ; original byte CC, padding
0x26568f: INT3 ; original byte CC, padding

; FUNCTION thunk_265690 [0x265690, 0x265694] | file +0xa8 | ev_cc8d59b63f127c42e47d0fdb641bb0453566ae62fa911d6df68e619a95b8ed62
thunk_265690:
0x265690: JMP 0x00381af0
; END FUNCTION thunk_265690
0x265695: INT3 ; original byte CC, padding
0x265696: INT3 ; original byte CC, padding
0x265697: INT3 ; original byte CC, padding

; FUNCTION thunk_265698 [0x265698, 0x26569c] | file +0xb0 | ev_252e45b17cc1ee0b1d1595451cca0b16c65c057bba1160a7315e261d9388374b
thunk_265698:
0x265698: JMP 0x00381e70
; END FUNCTION thunk_265698
0x26569d: INT3 ; original byte CC, padding
0x26569e: INT3 ; original byte CC, padding
0x26569f: INT3 ; original byte CC, padding

; FUNCTION thunk_2656a0 [0x2656a0, 0x2656a4] | file +0xb8 | ev_99c7624a168e538f6280896f1c2e9f5f0fc759c375b2dc6094e9ae80fcd2d1bb
thunk_2656a0:
0x2656a0: JMP 0x00382280
; END FUNCTION thunk_2656a0
0x2656a5: INT3 ; original byte CC, padding
0x2656a6: INT3 ; original byte CC, padding
0x2656a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656a8 [0x2656a8, 0x2656ac] | file +0xc0 | ev_4ccd85983d473ecbf1be16a517252cbf47ed884f400a76029b693a6982832e66
thunk_2656a8:
0x2656a8: JMP 0x00382480
; END FUNCTION thunk_2656a8
0x2656ad: INT3 ; original byte CC, padding
0x2656ae: INT3 ; original byte CC, padding
0x2656af: INT3 ; original byte CC, padding

; FUNCTION thunk_2656b0 [0x2656b0, 0x2656b4] | file +0xc8 | ev_b4c7378155e1869861aea18bd21c7165afa04ef19d1e6142864a19faccd622e6
thunk_2656b0:
0x2656b0: JMP 0x00382590
; END FUNCTION thunk_2656b0
0x2656b5: INT3 ; original byte CC, padding
0x2656b6: INT3 ; original byte CC, padding
0x2656b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656b8 [0x2656b8, 0x2656bc] | file +0xd0 | ev_ef0fa7476e30d003032ec3edc8d22189f985dc0e224da3a36c4d56354f2ea4ff
thunk_2656b8:
0x2656b8: JMP 0x00382a60
; END FUNCTION thunk_2656b8
0x2656bd: INT3 ; original byte CC, padding
0x2656be: INT3 ; original byte CC, padding
0x2656bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2656c0 [0x2656c0, 0x2656c4] | file +0xd8 | ev_3d29a0bceadcf1c9026875f0b00049d0c3a0a19ff77db6026d2147f1494fcc4f
thunk_2656c0:
0x2656c0: JMP 0x00383120
; END FUNCTION thunk_2656c0
0x2656c5: INT3 ; original byte CC, padding
0x2656c6: INT3 ; original byte CC, padding
0x2656c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656c8 [0x2656c8, 0x2656cc] | file +0xe0 | ev_6509d1d0b3bc88941cc429dbbabea8512da76a0c9176eb4c6403802b02bdfd32
thunk_2656c8:
0x2656c8: JMP 0x003835b0
; END FUNCTION thunk_2656c8
0x2656cd: INT3 ; original byte CC, padding
0x2656ce: INT3 ; original byte CC, padding
0x2656cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2656d0 [0x2656d0, 0x2656d4] | file +0xe8 | ev_b09732798b8219c326cf8e746d2bb94629bf7c9c7656fab1b50b1a12a13d7714
thunk_2656d0:
0x2656d0: JMP 0x003837f0
; END FUNCTION thunk_2656d0
0x2656d5: INT3 ; original byte CC, padding
0x2656d6: INT3 ; original byte CC, padding
0x2656d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656d8 [0x2656d8, 0x2656dc] | file +0xf0 | ev_0e56407053a5d4093c5bfd1b973f5d0874fb4bc1fe0e52c7ea9e54f575242e1f
thunk_2656d8:
0x2656d8: JMP 0x00383800
; END FUNCTION thunk_2656d8
0x2656dd: INT3 ; original byte CC, padding
0x2656de: INT3 ; original byte CC, padding
0x2656df: INT3 ; original byte CC, padding

; FUNCTION thunk_2656e0 [0x2656e0, 0x2656e4] | file +0xf8 | ev_7503b2fa859c9d0e4642ab19ed425a8035ccf51b94fe362963147005584afc34
thunk_2656e0:
0x2656e0: JMP 0x0038a2a0
; END FUNCTION thunk_2656e0
0x2656e5: INT3 ; original byte CC, padding
0x2656e6: INT3 ; original byte CC, padding
0x2656e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656e8 [0x2656e8, 0x2656ec] | file +0x100 | ev_837feaf04ffb74158744d7ea0d7d53b3da9448d769e6f3f3ade6c216e9452bd8
thunk_2656e8:
0x2656e8: JMP 0x003ef380
; END FUNCTION thunk_2656e8
0x2656ed: INT3 ; original byte CC, padding
0x2656ee: INT3 ; original byte CC, padding
0x2656ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2656f0 [0x2656f0, 0x2656f4] | file +0x108 | ev_018891b17eb2eaba28cb20355a3236beb3c0192f9110dc20df1baf2778f42f34
thunk_2656f0:
0x2656f0: JMP 0x003a60e0
; END FUNCTION thunk_2656f0
0x2656f5: INT3 ; original byte CC, padding
0x2656f6: INT3 ; original byte CC, padding
0x2656f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656f8 [0x2656f8, 0x2656fc] | file +0x110 | ev_640fefc2deaa24bb5083fc4750cb11729edd91835a3c189a01bbd7348445e8d3
thunk_2656f8:
0x2656f8: JMP 0x003aeb00
; END FUNCTION thunk_2656f8
0x2656fd: INT3 ; original byte CC, padding
0x2656fe: INT3 ; original byte CC, padding
0x2656ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265700 [0x265700, 0x265704] | file +0x118 | ev_0fb1c1111094d4f95aeb3879b22865c21e89c9041b0379467a3b95cea62e35be
thunk_265700:
0x265700: JMP 0x003aebf0
; END FUNCTION thunk_265700
0x265705: INT3 ; original byte CC, padding
0x265706: INT3 ; original byte CC, padding
0x265707: INT3 ; original byte CC, padding

; FUNCTION thunk_265708 [0x265708, 0x26570c] | file +0x120 | ev_b6bdfcb7fa6b476800c032a87f312ce12794bc79da48eebe5d32541e885939e1
thunk_265708:
0x265708: JMP 0x003af8e0
; END FUNCTION thunk_265708
0x26570d: INT3 ; original byte CC, padding
0x26570e: INT3 ; original byte CC, padding
0x26570f: INT3 ; original byte CC, padding

; FUNCTION thunk_265710 [0x265710, 0x265714] | file +0x128 | ev_a7bbccaa887f1dc74dd5a20eceae5368575f08b1d5ecd8282f6df24e299ce536
thunk_265710:
0x265710: JMP 0x003af8f0
; END FUNCTION thunk_265710
0x265715: INT3 ; original byte CC, padding
0x265716: INT3 ; original byte CC, padding
0x265717: INT3 ; original byte CC, padding

; FUNCTION thunk_265718 [0x265718, 0x26571c] | file +0x130 | ev_38789675eca62443741b8e1bab095e841cecf87a00496a78c4bf3372253bc2b2
thunk_265718:
0x265718: JMP 0x003af900
; END FUNCTION thunk_265718
0x26571d: INT3 ; original byte CC, padding
0x26571e: INT3 ; original byte CC, padding
0x26571f: INT3 ; original byte CC, padding

; FUNCTION thunk_265720 [0x265720, 0x265724] | file +0x138 | ev_663b0a68a7b3c2be7c9493c0aead17e89f76910d56519503799ba2ffda9209d0
thunk_265720:
0x265720: JMP 0x003b01f0
; END FUNCTION thunk_265720
0x265725: INT3 ; original byte CC, padding
0x265726: INT3 ; original byte CC, padding
0x265727: INT3 ; original byte CC, padding

; FUNCTION thunk_265728 [0x265728, 0x26572c] | file +0x140 | ev_d69bbc7a859c476d6141155d3b2d923da60bf9e3f5f4355d77f3bcedce013985
thunk_265728:
0x265728: JMP 0x003b0fb0
; END FUNCTION thunk_265728
0x26572d: INT3 ; original byte CC, padding
0x26572e: INT3 ; original byte CC, padding
0x26572f: INT3 ; original byte CC, padding

; FUNCTION thunk_265730 [0x265730, 0x265734] | file +0x148 | ev_cf4a0758f2319cf7845c9debebe9582bfd69286eb3a26b66f296653aa9038eb8
thunk_265730:
0x265730: JMP 0x003b1670
; END FUNCTION thunk_265730
0x265735: INT3 ; original byte CC, padding
0x265736: INT3 ; original byte CC, padding
0x265737: INT3 ; original byte CC, padding

; FUNCTION thunk_265738 [0x265738, 0x26573c] | file +0x150 | ev_92ce22eed051fe8e75b8bc76827733d13e499e4d8d596bf46af0d7d5c1429ef3
thunk_265738:
0x265738: JMP 0x003b1680
; END FUNCTION thunk_265738
0x26573d: INT3 ; original byte CC, padding
0x26573e: INT3 ; original byte CC, padding
0x26573f: INT3 ; original byte CC, padding

; FUNCTION thunk_265740 [0x265740, 0x265744] | file +0x158 | ev_33530924e7685bff9fddd82f68a628a756c5337ce46b62cbd6d38d80f5fa6096
thunk_265740:
0x265740: JMP 0x003b2060
; END FUNCTION thunk_265740
0x265745: INT3 ; original byte CC, padding
0x265746: INT3 ; original byte CC, padding
0x265747: INT3 ; original byte CC, padding

; FUNCTION thunk_265748 [0x265748, 0x26574c] | file +0x160 | ev_de67cf534443a31bebab6a25bf45f5fd82945002817eb37fa40aaff619e6d23a
thunk_265748:
0x265748: JMP 0x003b28d0
; END FUNCTION thunk_265748
0x26574d: INT3 ; original byte CC, padding
0x26574e: INT3 ; original byte CC, padding
0x26574f: INT3 ; original byte CC, padding

; FUNCTION thunk_265750 [0x265750, 0x265754] | file +0x168 | ev_132234fcaf537fa6a42b874d00a2e1aad642c7a28a779da7ebbeaa20c0874aaa
thunk_265750:
0x265750: JMP 0x003b2d50
; END FUNCTION thunk_265750
0x265755: INT3 ; original byte CC, padding
0x265756: INT3 ; original byte CC, padding
0x265757: INT3 ; original byte CC, padding

; FUNCTION thunk_265758 [0x265758, 0x26575c] | file +0x170 | ev_068558a7684bdcceb36c61662c628b8e88ef07ac65492f923014b5c82b93fade
thunk_265758:
0x265758: JMP 0x003b3090
; END FUNCTION thunk_265758
0x26575d: INT3 ; original byte CC, padding
0x26575e: INT3 ; original byte CC, padding
0x26575f: INT3 ; original byte CC, padding

; FUNCTION thunk_265760 [0x265760, 0x265764] | file +0x178 | ev_bd63dc1cd6837db427a1056eb97158fe259206066faca40c28dcf7934f20ba4d
thunk_265760:
0x265760: JMP 0x005620e0
; END FUNCTION thunk_265760
0x265765: INT3 ; original byte CC, padding
0x265766: INT3 ; original byte CC, padding
0x265767: INT3 ; original byte CC, padding

; FUNCTION thunk_265768 [0x265768, 0x26576c] | file +0x180 | ev_1d901a1b7fdb0a3a9f237abaa418c80c2b2fea99395acd4e1fbac26e3445716b
thunk_265768:
0x265768: JMP 0x003b6020
; END FUNCTION thunk_265768
0x26576d: INT3 ; original byte CC, padding
0x26576e: INT3 ; original byte CC, padding
0x26576f: INT3 ; original byte CC, padding

; FUNCTION thunk_265770 [0x265770, 0x265774] | file +0x188 | ev_b6804c0eb21d9151919aae4a42f9c0cfc063fb2f53e6396e6dc77cbac8e2a1ba
thunk_265770:
0x265770: JMP 0x003b6240
; END FUNCTION thunk_265770
0x265775: INT3 ; original byte CC, padding
0x265776: INT3 ; original byte CC, padding
0x265777: INT3 ; original byte CC, padding

; FUNCTION thunk_265778 [0x265778, 0x26577c] | file +0x190 | ev_34f74d2743a15a04b1f71fa6f65bd4bd17e95b886cba7359e78b5faeff6c856d
thunk_265778:
0x265778: JMP 0x003c1e10
; END FUNCTION thunk_265778
0x26577d: INT3 ; original byte CC, padding
0x26577e: INT3 ; original byte CC, padding
0x26577f: INT3 ; original byte CC, padding

; FUNCTION thunk_265780 [0x265780, 0x265784] | file +0x198 | ev_10c0daa579f734a4a7decbb86d19d366ccc650fa23eb00375ad24032a5e6e0b8
thunk_265780:
0x265780: JMP 0x003c2240
; END FUNCTION thunk_265780
0x265785: INT3 ; original byte CC, padding
0x265786: INT3 ; original byte CC, padding
0x265787: INT3 ; original byte CC, padding

; FUNCTION thunk_265788 [0x265788, 0x26578c] | file +0x1a0 | ev_f3de7310226151c0183fe0d6a12e4162a8775d55c90b0d1ecb962e5e74c27fbf
thunk_265788:
0x265788: JMP 0x0012f7e0
; END FUNCTION thunk_265788
0x26578d: INT3 ; original byte CC, padding
0x26578e: INT3 ; original byte CC, padding
0x26578f: INT3 ; original byte CC, padding

; FUNCTION thunk_265790 [0x265790, 0x265794] | file +0x1a8 | ev_ce96bb8ef60d99823c5763a8166e15725e79734fa2c841d7a584703f32adc295
thunk_265790:
0x265790: JMP 0x003ce150
; END FUNCTION thunk_265790
0x265795: INT3 ; original byte CC, padding
0x265796: INT3 ; original byte CC, padding
0x265797: INT3 ; original byte CC, padding

; FUNCTION thunk_265798 [0x265798, 0x26579c] | file +0x1b0 | ev_0f8dc4e185eda329d0f5b8a0e374280c6e3304d1ed60a8d7d32f05850edf66e6
thunk_265798:
0x265798: JMP 0x003d52b0
; END FUNCTION thunk_265798
0x26579d: INT3 ; original byte CC, padding
0x26579e: INT3 ; original byte CC, padding
0x26579f: INT3 ; original byte CC, padding

; FUNCTION thunk_2657a0 [0x2657a0, 0x2657a4] | file +0x1b8 | ev_e2f761a65fdd84dab59b1b13e22a3b855068bf5d9a5be19d82c77854c4429308
thunk_2657a0:
0x2657a0: JMP 0x003e5aa0
; END FUNCTION thunk_2657a0
0x2657a5: INT3 ; original byte CC, padding
0x2657a6: INT3 ; original byte CC, padding
0x2657a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657a8 [0x2657a8, 0x2657ac] | file +0x1c0 | ev_6697810b038fc1b12c4d4c9a9b0dd049ff025f425f50042e871cec4631353f94
thunk_2657a8:
0x2657a8: JMP 0x003e5ad0
; END FUNCTION thunk_2657a8
0x2657ad: INT3 ; original byte CC, padding
0x2657ae: INT3 ; original byte CC, padding
0x2657af: INT3 ; original byte CC, padding

; FUNCTION thunk_2657b0 [0x2657b0, 0x2657b4] | file +0x1c8 | ev_ebf7b57120fb86445774a5dca464139125d8f4d01fa8fb9287d3638ebaef2c34
thunk_2657b0:
0x2657b0: JMP 0x003e5af0
; END FUNCTION thunk_2657b0
0x2657b5: INT3 ; original byte CC, padding
0x2657b6: INT3 ; original byte CC, padding
0x2657b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657b8 [0x2657b8, 0x2657bc] | file +0x1d0 | ev_f18742952a9bc02a461e135a15fb6ef707ecbaf16ba12b4da18dbdae79073308
thunk_2657b8:
0x2657b8: JMP 0x003ec340
; END FUNCTION thunk_2657b8
0x2657bd: INT3 ; original byte CC, padding
0x2657be: INT3 ; original byte CC, padding
0x2657bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2657c0 [0x2657c0, 0x2657c4] | file +0x1d8 | ev_91f732a1a4e63f6a6eb155545811fa0e43b164dacb291025c69d8da804414ace
thunk_2657c0:
0x2657c0: JMP 0x003f05c0
; END FUNCTION thunk_2657c0
0x2657c5: INT3 ; original byte CC, padding
0x2657c6: INT3 ; original byte CC, padding
0x2657c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657c8 [0x2657c8, 0x2657cc] | file +0x1e0 | ev_c7b98d7ba8ab37f6d1800ccac069f4d56bde69cdec76707b570744d7e7dc1d69
thunk_2657c8:
0x2657c8: JMP 0x003f2810
; END FUNCTION thunk_2657c8
0x2657cd: INT3 ; original byte CC, padding
0x2657ce: INT3 ; original byte CC, padding
0x2657cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2657d0 [0x2657d0, 0x2657d4] | file +0x1e8 | ev_4f51d5c363cf402cd2db4e9f992362fbab4776f0ecbd528c24eb13344bbd3dca
thunk_2657d0:
0x2657d0: JMP 0x003f2b60
; END FUNCTION thunk_2657d0
0x2657d5: INT3 ; original byte CC, padding
0x2657d6: INT3 ; original byte CC, padding
0x2657d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657d8 [0x2657d8, 0x2657dc] | file +0x1f0 | ev_1fa68ba64ca0d7c70f430e815cb0b0f22e75fe57ded1c269a505586d5c58f4d2
thunk_2657d8:
0x2657d8: JMP 0x0050ce20
; END FUNCTION thunk_2657d8
0x2657dd: INT3 ; original byte CC, padding
0x2657de: INT3 ; original byte CC, padding
0x2657df: INT3 ; original byte CC, padding

; FUNCTION thunk_2657e0 [0x2657e0, 0x2657e4] | file +0x1f8 | ev_cdf4533c696eba4277540c786b459e9ea015d47fce9d5d76f4a652cb6ac58172
thunk_2657e0:
0x2657e0: JMP 0x003f3f90
; END FUNCTION thunk_2657e0
0x2657e5: INT3 ; original byte CC, padding
0x2657e6: INT3 ; original byte CC, padding
0x2657e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657e8 [0x2657e8, 0x2657ec] | file +0x200 | ev_374afdf2cce64a46acab5a174134a7f968029c9c59d14d6742cd560ce5213f23
thunk_2657e8:
0x2657e8: JMP 0x00409790
; END FUNCTION thunk_2657e8
0x2657ed: INT3 ; original byte CC, padding
0x2657ee: INT3 ; original byte CC, padding
0x2657ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2657f0 [0x2657f0, 0x2657f4] | file +0x208 | ev_58e9f1700ab212c7bbdd085f1ce9a5bdbaedb7fab614a122c69f2a9c6762e1bd
thunk_2657f0:
0x2657f0: JMP 0x00be7240
; END FUNCTION thunk_2657f0
0x2657f5: INT3 ; original byte CC, padding
0x2657f6: INT3 ; original byte CC, padding
0x2657f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657f8 [0x2657f8, 0x2657fc] | file +0x210 | ev_f6bc973f7dcabf9e89f903c9e2bf5dbf21259650a2b611915c1164b66fa72741
thunk_2657f8:
0x2657f8: JMP 0x00cb1390
; END FUNCTION thunk_2657f8
0x2657fd: INT3 ; original byte CC, padding
0x2657fe: INT3 ; original byte CC, padding
0x2657ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265800 [0x265800, 0x265804] | file +0x218 | ev_21b84e85838248825fd2de74126e431447c58868f9b80275e73f098e74c945cf
thunk_265800:
0x265800: JMP 0x004ec000
; END FUNCTION thunk_265800
0x265805: INT3 ; original byte CC, padding
0x265806: INT3 ; original byte CC, padding
0x265807: INT3 ; original byte CC, padding

; FUNCTION thunk_265808 [0x265808, 0x26580c] | file +0x220 | ev_ed36ff2d496580222b1f83b896dfddfaf483e38fce8c3c285a7c9581d5ef186f
thunk_265808:
0x265808: JMP 0x004ec560
; END FUNCTION thunk_265808
0x26580d: INT3 ; original byte CC, padding
0x26580e: INT3 ; original byte CC, padding
0x26580f: INT3 ; original byte CC, padding

; FUNCTION thunk_265810 [0x265810, 0x265814] | file +0x228 | ev_89727ec834a0cfe20eb32510eb9c2eae50ce027f3e6a558042ad62d7e27d8e1b
thunk_265810:
0x265810: JMP 0x008f6e00
; END FUNCTION thunk_265810
0x265815: INT3 ; original byte CC, padding
0x265816: INT3 ; original byte CC, padding
0x265817: INT3 ; original byte CC, padding

; FUNCTION thunk_265818 [0x265818, 0x26581c] | file +0x230 | ev_eefb66ff0c291781258b8a7b7ae899d7e3dcf66c5c651f06811347f6134cff7e
thunk_265818:
0x265818: JMP 0x0072bf00
; END FUNCTION thunk_265818
0x26581d: INT3 ; original byte CC, padding
0x26581e: INT3 ; original byte CC, padding
0x26581f: INT3 ; original byte CC, padding

; FUNCTION thunk_265820 [0x265820, 0x265824] | file +0x238 | ev_b01c8ded1e53f1229648a8fc823292f76ba1e191912f08da40a003017916d032
thunk_265820:
0x265820: JMP 0x00be8290
; END FUNCTION thunk_265820
0x265825: INT3 ; original byte CC, padding
0x265826: INT3 ; original byte CC, padding
0x265827: INT3 ; original byte CC, padding

; FUNCTION thunk_265828 [0x265828, 0x26582c] | file +0x240 | ev_e877aa9a22237e98d7eb06a87171e8dc74a5766852423ce01502627d2dfb95bb
thunk_265828:
0x265828: JMP 0x008f8550
; END FUNCTION thunk_265828
0x26582d: INT3 ; original byte CC, padding
0x26582e: INT3 ; original byte CC, padding
0x26582f: INT3 ; original byte CC, padding

; FUNCTION thunk_265830 [0x265830, 0x265834] | file +0x248 | ev_ba7051f63021a6fd1c6284d1f82b4898b77f53988089d8426c18b784cb611820
thunk_265830:
0x265830: JMP 0x008f6b20
; END FUNCTION thunk_265830
0x265835: INT3 ; original byte CC, padding
0x265836: INT3 ; original byte CC, padding
0x265837: INT3 ; original byte CC, padding

; FUNCTION thunk_265838 [0x265838, 0x26583c] | file +0x250 | ev_29e270b89c7ed4c79f5d94bb4bd94f9805dda1cdee86aa988991baafe5cab9bf
thunk_265838:
0x265838: JMP 0x008f9b40
; END FUNCTION thunk_265838
0x26583d: INT3 ; original byte CC, padding
0x26583e: INT3 ; original byte CC, padding
0x26583f: INT3 ; original byte CC, padding

; FUNCTION thunk_265840 [0x265840, 0x265844] | file +0x258 | ev_2286b3dda1e7e72b42d6a92a0a0aefa2f61011e9c731cefc24e2698890829772
thunk_265840:
0x265840: JMP 0x005329e0
; END FUNCTION thunk_265840
0x265845: INT3 ; original byte CC, padding
0x265846: INT3 ; original byte CC, padding
0x265847: INT3 ; original byte CC, padding

; FUNCTION thunk_265848 [0x265848, 0x26584c] | file +0x260 | ev_01217ef4807cb3458c4e52bd4cc87292cea659508dadb94fb69d13110186d725
thunk_265848:
0x265848: JMP 0x005321e0
; END FUNCTION thunk_265848
0x26584d: INT3 ; original byte CC, padding
0x26584e: INT3 ; original byte CC, padding
0x26584f: INT3 ; original byte CC, padding

; FUNCTION thunk_265850 [0x265850, 0x265854] | file +0x268 | ev_6d5fd951eb8cbb265a712cc176037c10716ffd34adb58ee287e6ce7605307018
thunk_265850:
0x265850: JMP 0x005328d0
; END FUNCTION thunk_265850
0x265855: INT3 ; original byte CC, padding
0x265856: INT3 ; original byte CC, padding
0x265857: INT3 ; original byte CC, padding

; FUNCTION thunk_265858 [0x265858, 0x26585c] | file +0x270 | ev_5090551b84c0f978635bfd1de6823dd5bef2c93d319a2411da7d400cedf97693
thunk_265858:
0x265858: JMP 0x00531080
; END FUNCTION thunk_265858
0x26585d: INT3 ; original byte CC, padding
0x26585e: INT3 ; original byte CC, padding
0x26585f: INT3 ; original byte CC, padding

; FUNCTION thunk_265860 [0x265860, 0x265864] | file +0x278 | ev_01c5c090c8cdb41592a81f1781d3f81583f8dd4d4fe769363a8450c7d1f7a771
thunk_265860:
0x265860: JMP 0x00533310
; END FUNCTION thunk_265860
0x265865: INT3 ; original byte CC, padding
0x265866: INT3 ; original byte CC, padding
0x265867: INT3 ; original byte CC, padding

; FUNCTION thunk_265868 [0x265868, 0x26586c] | file +0x280 | ev_c24a1e048aeb103df20b0435af6b29a74f5df513f9f5c72aaa03666f01eb6fdc
thunk_265868:
0x265868: JMP 0x00533030
; END FUNCTION thunk_265868
0x26586d: INT3 ; original byte CC, padding
0x26586e: INT3 ; original byte CC, padding
0x26586f: INT3 ; original byte CC, padding

; FUNCTION thunk_265870 [0x265870, 0x265874] | file +0x288 | ev_76ba314b67213efa76858206a61bcd4163406a9f26e42af0d8698645842db016
thunk_265870:
0x265870: JMP 0x008f8be0
; END FUNCTION thunk_265870
0x265875: INT3 ; original byte CC, padding
0x265876: INT3 ; original byte CC, padding
0x265877: INT3 ; original byte CC, padding

; FUNCTION thunk_265878 [0x265878, 0x26587c] | file +0x290 | ev_896c34d770fdd0c212052502dd983d487250108abf025f4f05b524748fb80c86
thunk_265878:
0x265878: JMP 0x008f95b0
; END FUNCTION thunk_265878
0x26587d: INT3 ; original byte CC, padding
0x26587e: INT3 ; original byte CC, padding
0x26587f: INT3 ; original byte CC, padding

; FUNCTION thunk_265880 [0x265880, 0x265884] | file +0x298 | ev_f8863d096867a30cdba9addd987914e5d320e078b4aade3ac9e818e1f98319d5
thunk_265880:
0x265880: JMP 0x008f9760
; END FUNCTION thunk_265880
0x265885: INT3 ; original byte CC, padding
0x265886: INT3 ; original byte CC, padding
0x265887: INT3 ; original byte CC, padding

; FUNCTION thunk_265888 [0x265888, 0x26588c] | file +0x2a0 | ev_85141131e97cdc037a66618a2dab05c4883afdef7550bb962d7c3b1108406661
thunk_265888:
0x265888: JMP 0x008f5d20
; END FUNCTION thunk_265888
0x26588d: INT3 ; original byte CC, padding
0x26588e: INT3 ; original byte CC, padding
0x26588f: INT3 ; original byte CC, padding

; FUNCTION thunk_265890 [0x265890, 0x265894] | file +0x2a8 | ev_5ede924fc5154e62e37e7bf8c3f811e88e9b2faec58b249284bb80f0fb48025b
thunk_265890:
0x265890: JMP 0x0055f5b0
; END FUNCTION thunk_265890
0x265895: INT3 ; original byte CC, padding
0x265896: INT3 ; original byte CC, padding
0x265897: INT3 ; original byte CC, padding

; FUNCTION thunk_265898 [0x265898, 0x26589c] | file +0x2b0 | ev_a23d17f391f4d36d97e50a18a5186539d45e2bed5fc87ffe4a0dcc4d6db07939
thunk_265898:
0x265898: JMP 0x00729d80
; END FUNCTION thunk_265898
0x26589d: INT3 ; original byte CC, padding
0x26589e: INT3 ; original byte CC, padding
0x26589f: INT3 ; original byte CC, padding

; FUNCTION thunk_2658a0 [0x2658a0, 0x2658a4] | file +0x2b8 | ev_b7a1dccb9d6a6d2325e92a7739fa6f321de83fb32cf43179dc7d2b1beed1ac61
thunk_2658a0:
0x2658a0: JMP 0x00802d90
; END FUNCTION thunk_2658a0
0x2658a5: INT3 ; original byte CC, padding
0x2658a6: INT3 ; original byte CC, padding
0x2658a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658a8 [0x2658a8, 0x2658ac] | file +0x2c0 | ev_b19515a52787f810c0fc8a150c253edf5a09f1ecb6685c5ddb19a7fcbd31e7f0
thunk_2658a8:
0x2658a8: JMP 0x0045e4d0
; END FUNCTION thunk_2658a8
0x2658ad: INT3 ; original byte CC, padding
0x2658ae: INT3 ; original byte CC, padding
0x2658af: INT3 ; original byte CC, padding

; FUNCTION thunk_2658b0 [0x2658b0, 0x2658b4] | file +0x2c8 | ev_5b2cef43eb0f5d13ddd9c2fd9b7fa4dd2b081756fab4a5992d820a192c878767
thunk_2658b0:
0x2658b0: JMP 0x0055f400
; END FUNCTION thunk_2658b0
0x2658b5: INT3 ; original byte CC, padding
0x2658b6: INT3 ; original byte CC, padding
0x2658b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658b8 [0x2658b8, 0x2658bc] | file +0x2d0 | ev_17fe6fbebe1335a99ecaeac06f571ba24b9ad7de60e42acf82b9b228106d6104
thunk_2658b8:
0x2658b8: JMP 0x004ecf40
; END FUNCTION thunk_2658b8
0x2658bd: INT3 ; original byte CC, padding
0x2658be: INT3 ; original byte CC, padding
0x2658bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2658c0 [0x2658c0, 0x2658c4] | file +0x2d8 | ev_eee7a1b6ecdce4e0b77d92dfc20a43dc2782e75827d3f98726902e4b96738d77
thunk_2658c0:
0x2658c0: JMP 0x007e4810
; END FUNCTION thunk_2658c0
0x2658c5: INT3 ; original byte CC, padding
0x2658c6: INT3 ; original byte CC, padding
0x2658c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658c8 [0x2658c8, 0x2658cc] | file +0x2e0 | ev_845ed6badef4ae9ef77ba2e779a2375a56564fca34ec6fbcd0911725b268c459
thunk_2658c8:
0x2658c8: JMP 0x008fc490
; END FUNCTION thunk_2658c8
0x2658cd: INT3 ; original byte CC, padding
0x2658ce: INT3 ; original byte CC, padding
0x2658cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2658d0 [0x2658d0, 0x2658d4] | file +0x2e8 | ev_d1b9e0d38d6434e6a73c7cd5580db593062890703035603def4048e5f0f70516
thunk_2658d0:
0x2658d0: JMP 0x006e2dc0
; END FUNCTION thunk_2658d0
0x2658d5: INT3 ; original byte CC, padding
0x2658d6: INT3 ; original byte CC, padding
0x2658d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658d8 [0x2658d8, 0x2658dc] | file +0x2f0 | ev_ef22b085ea6deaa05e80e7ecc0348d6d86c49968e69baffefc4836914656a99f
thunk_2658d8:
0x2658d8: JMP 0x00ab8af0
; END FUNCTION thunk_2658d8
0x2658dd: INT3 ; original byte CC, padding
0x2658de: INT3 ; original byte CC, padding
0x2658df: INT3 ; original byte CC, padding

; FUNCTION thunk_2658e0 [0x2658e0, 0x2658e4] | file +0x2f8 | ev_4f526ca80fe3367a5a614419397741f41bb8b497bda0c49a4d7663d093a8a633
thunk_2658e0:
0x2658e0: JMP 0x00ab8bb0
; END FUNCTION thunk_2658e0
0x2658e5: INT3 ; original byte CC, padding
0x2658e6: INT3 ; original byte CC, padding
0x2658e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658e8 [0x2658e8, 0x2658ec] | file +0x300 | ev_6df4f33e4cce4fbceedd1cb5393b063a0eedd64e4998eb6e45e4de8a5ac03640
thunk_2658e8:
0x2658e8: JMP 0x00ab8d20
; END FUNCTION thunk_2658e8
0x2658ed: INT3 ; original byte CC, padding
0x2658ee: INT3 ; original byte CC, padding
0x2658ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2658f0 [0x2658f0, 0x2658f4] | file +0x308 | ev_890257df8433a0b7603458bc3bad772ae2bbe8da754402853cc8349d35c35c69
thunk_2658f0:
0x2658f0: JMP 0x00ab8e00
; END FUNCTION thunk_2658f0
0x2658f5: INT3 ; original byte CC, padding
0x2658f6: INT3 ; original byte CC, padding
0x2658f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658f8 [0x2658f8, 0x2658fc] | file +0x310 | ev_fccee6840eafe44da8599577bb9231c256a751d24cfad1a211d736e7cc16a240
thunk_2658f8:
0x2658f8: JMP 0x00ab8ec0
; END FUNCTION thunk_2658f8
0x2658fd: INT3 ; original byte CC, padding
0x2658fe: INT3 ; original byte CC, padding
0x2658ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265900 [0x265900, 0x265904] | file +0x318 | ev_c4d18df255e8b78afdffc056ebfd253100811ec71a1ccc354048d17e93f0b70a
thunk_265900:
0x265900: JMP 0x006bccc0
; END FUNCTION thunk_265900
0x265905: INT3 ; original byte CC, padding
0x265906: INT3 ; original byte CC, padding
0x265907: INT3 ; original byte CC, padding

; FUNCTION thunk_265908 [0x265908, 0x26590c] | file +0x320 | ev_1d8c648b8c949bddfa542a680881a2b6d34989bc252b7c050d7498240ee980e3
thunk_265908:
0x265908: JMP 0x006bca20
; END FUNCTION thunk_265908
0x26590d: INT3 ; original byte CC, padding
0x26590e: INT3 ; original byte CC, padding
0x26590f: INT3 ; original byte CC, padding

; FUNCTION thunk_265910 [0x265910, 0x265914] | file +0x328 | ev_2fbce8ef0f6b1d956a901b81cb57c9f16ae0b93127324c46ac5e0c8dc797f3fb
thunk_265910:
0x265910: JMP 0x007299f0
; END FUNCTION thunk_265910
0x265915: INT3 ; original byte CC, padding
0x265916: INT3 ; original byte CC, padding
0x265917: INT3 ; original byte CC, padding

; FUNCTION thunk_265918 [0x265918, 0x26591c] | file +0x330 | ev_51a7fedd9d37821417b557dbf67683f2594f508d9320da3f13e506d0066051e8
thunk_265918:
0x265918: JMP 0x00729a40
; END FUNCTION thunk_265918
0x26591d: INT3 ; original byte CC, padding
0x26591e: INT3 ; original byte CC, padding
0x26591f: INT3 ; original byte CC, padding

; FUNCTION thunk_265920 [0x265920, 0x265924] | file +0x338 | ev_c39c0d1fff985a45fbc3bd1198cf1b0ecd31692fb4a457f2d3a91762a9715145
thunk_265920:
0x265920: JMP 0x00729dc0
; END FUNCTION thunk_265920
0x265925: INT3 ; original byte CC, padding
0x265926: INT3 ; original byte CC, padding
0x265927: INT3 ; original byte CC, padding

; FUNCTION thunk_265928 [0x265928, 0x26592c] | file +0x340 | ev_6ed115f20180546ca451c6a4143e4cbcf49238cec1d7281f9c760435a3f48a16
thunk_265928:
0x265928: JMP 0x004ee4b0
; END FUNCTION thunk_265928
0x26592d: INT3 ; original byte CC, padding
0x26592e: INT3 ; original byte CC, padding
0x26592f: INT3 ; original byte CC, padding

; FUNCTION thunk_265930 [0x265930, 0x265934] | file +0x348 | ev_168128ab332fee133851c8c2c0dfed0372d386808a7ee24636fca3e8f350e72b
thunk_265930:
0x265930: JMP 0x008fb430
; END FUNCTION thunk_265930
0x265935: INT3 ; original byte CC, padding
0x265936: INT3 ; original byte CC, padding
0x265937: INT3 ; original byte CC, padding

; FUNCTION thunk_265938 [0x265938, 0x26593c] | file +0x350 | ev_c519c25eba1520b948eb17ada921ff130548b371bb9e749cd1a8197150ae7c7e
thunk_265938:
0x265938: JMP 0x0049ff80
; END FUNCTION thunk_265938
0x26593d: INT3 ; original byte CC, padding
0x26593e: INT3 ; original byte CC, padding
0x26593f: INT3 ; original byte CC, padding

; FUNCTION thunk_265940 [0x265940, 0x265944] | file +0x358 | ev_b31257a300ab503ae550e8b75e4beed9089c4d8aeff2ef13c06811b5f847cdcf
thunk_265940:
0x265940: JMP 0x0052f8f0
; END FUNCTION thunk_265940
0x265945: INT3 ; original byte CC, padding
0x265946: INT3 ; original byte CC, padding
0x265947: INT3 ; original byte CC, padding

; FUNCTION thunk_265948 [0x265948, 0x26594c] | file +0x360 | ev_6a0bec579f7db081777d62e5e84debe5bdb67589729a3712805f516afce5c16d
thunk_265948:
0x265948: JMP 0x00531260
; END FUNCTION thunk_265948
0x26594d: INT3 ; original byte CC, padding
0x26594e: INT3 ; original byte CC, padding
0x26594f: INT3 ; original byte CC, padding

; FUNCTION thunk_265950 [0x265950, 0x265954] | file +0x368 | ev_4ce2255d03764bdadf7c883b0fef92a89073cd0f77961ad7c78a4b7f395b1148
thunk_265950:
0x265950: JMP 0x0052fce0
; END FUNCTION thunk_265950
0x265955: INT3 ; original byte CC, padding
0x265956: INT3 ; original byte CC, padding
0x265957: INT3 ; original byte CC, padding

; FUNCTION thunk_265958 [0x265958, 0x26595c] | file +0x370 | ev_46ac121cd15ec4f1eef7e953216a00693eb003f1b8f3a51d54159f9c8db904ba
thunk_265958:
0x265958: JMP 0x0049fcf0
; END FUNCTION thunk_265958
0x26595d: INT3 ; original byte CC, padding
0x26595e: INT3 ; original byte CC, padding
0x26595f: INT3 ; original byte CC, padding

; FUNCTION thunk_265960 [0x265960, 0x265964] | file +0x378 | ev_58f2dc23be3ba21d60623d9e300f14eff0866f1b9d61326b6f93f17a5fe0e31d
thunk_265960:
0x265960: JMP 0x0052fd00
; END FUNCTION thunk_265960
0x265965: INT3 ; original byte CC, padding
0x265966: INT3 ; original byte CC, padding
0x265967: INT3 ; original byte CC, padding

; FUNCTION thunk_265968 [0x265968, 0x26596c] | file +0x380 | ev_7edf4937f75b34607d7282f661231292fd6b0e1043adabcdb3cec2032a84ae52
thunk_265968:
0x265968: JMP 0x0052fe00
; END FUNCTION thunk_265968
0x26596d: INT3 ; original byte CC, padding
0x26596e: INT3 ; original byte CC, padding
0x26596f: INT3 ; original byte CC, padding

; FUNCTION thunk_265970 [0x265970, 0x265974] | file +0x388 | ev_a61179069aea9d46cde19c9c505ec477bfafb1f1307b2ecb9a5dd4481f9599b0
thunk_265970:
0x265970: JMP 0x00530480
; END FUNCTION thunk_265970
0x265975: INT3 ; original byte CC, padding
0x265976: INT3 ; original byte CC, padding
0x265977: INT3 ; original byte CC, padding

; FUNCTION thunk_265978 [0x265978, 0x26597c] | file +0x390 | ev_8f68cf96d5c5641edab50be0cecfebf44ffa93a70f88e3e350a9ed6c39d0444f
thunk_265978:
0x265978: JMP 0x00532bc0
; END FUNCTION thunk_265978
0x26597d: INT3 ; original byte CC, padding
0x26597e: INT3 ; original byte CC, padding
0x26597f: INT3 ; original byte CC, padding

; FUNCTION thunk_265980 [0x265980, 0x265984] | file +0x398 | ev_96bd70da6010511498989cf153467883d54c72197753f7d56914e6848963c666
thunk_265980:
0x265980: JMP 0x005307d0
; END FUNCTION thunk_265980
0x265985: INT3 ; original byte CC, padding
0x265986: INT3 ; original byte CC, padding
0x265987: INT3 ; original byte CC, padding

; FUNCTION thunk_265988 [0x265988, 0x26598c] | file +0x3a0 | ev_ad263442a4957628c3651d02ff31caf3ff123d91ac6e612316130ef55a06fc41
thunk_265988:
0x265988: JMP 0x0052fae0
; END FUNCTION thunk_265988
0x26598d: INT3 ; original byte CC, padding
0x26598e: INT3 ; original byte CC, padding
0x26598f: INT3 ; original byte CC, padding

; FUNCTION thunk_265990 [0x265990, 0x265994] | file +0x3a8 | ev_6ddca225a8844f0a956e72eb36adca2fe53bd90a89eff3a53ef68aef49eda57d
thunk_265990:
0x265990: JMP 0x0072c140
; END FUNCTION thunk_265990
0x265995: INT3 ; original byte CC, padding
0x265996: INT3 ; original byte CC, padding
0x265997: INT3 ; original byte CC, padding

; FUNCTION thunk_265998 [0x265998, 0x26599c] | file +0x3b0 | ev_65c2b3b478763fa59180871059f420c13f43e74bbb5db32ea6e8a3ba14aed9c9
thunk_265998:
0x265998: JMP 0x006bc800
; END FUNCTION thunk_265998
0x26599d: INT3 ; original byte CC, padding
0x26599e: INT3 ; original byte CC, padding
0x26599f: INT3 ; original byte CC, padding

; FUNCTION thunk_2659a0 [0x2659a0, 0x2659a4] | file +0x3b8 | ev_3737c135be6511a09efc868cc07a5c07499ffae8ae300ed846470a34637263b2
thunk_2659a0:
0x2659a0: JMP 0x004a1ba0
; END FUNCTION thunk_2659a0
0x2659a5: INT3 ; original byte CC, padding
0x2659a6: INT3 ; original byte CC, padding
0x2659a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659a8 [0x2659a8, 0x2659ac] | file +0x3c0 | ev_1c8053eb5bc3aa09b01e0bc4d2c28858562f68c983c137ac0e898b243011a3f4
thunk_2659a8:
0x2659a8: JMP 0x00532cd0
; END FUNCTION thunk_2659a8
0x2659ad: INT3 ; original byte CC, padding
0x2659ae: INT3 ; original byte CC, padding
0x2659af: INT3 ; original byte CC, padding

; FUNCTION thunk_2659b0 [0x2659b0, 0x2659b4] | file +0x3c8 | ev_1a5b353552123c0d975b18fde8275291d3bc26fef98318c05a592f13ef508e30
thunk_2659b0:
0x2659b0: JMP 0x004ec2c0
; END FUNCTION thunk_2659b0
0x2659b5: INT3 ; original byte CC, padding
0x2659b6: INT3 ; original byte CC, padding
0x2659b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659b8 [0x2659b8, 0x2659bc] | file +0x3d0 | ev_ed5e8fd16ab4df76ed7f71c3c304a25e832678c51f3912fc41e30f28750c643e
thunk_2659b8:
0x2659b8: JMP 0x004ec8e0
; END FUNCTION thunk_2659b8
0x2659bd: INT3 ; original byte CC, padding
0x2659be: INT3 ; original byte CC, padding
0x2659bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2659c0 [0x2659c0, 0x2659c4] | file +0x3d8 | ev_42388928d43dbee314a6c1ce3245c8d49c8390da3c4bc594fb5aaddafc070ab7
thunk_2659c0:
0x2659c0: JMP 0x006bc8d0
; END FUNCTION thunk_2659c0
0x2659c5: INT3 ; original byte CC, padding
0x2659c6: INT3 ; original byte CC, padding
0x2659c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659c8 [0x2659c8, 0x2659cc] | file +0x3e0 | ev_aa1de99500333816fe82e6a0e9e23204b7b21bb793b90cf9923a4574ffd80d7c
thunk_2659c8:
0x2659c8: JMP 0x008f9d40
; END FUNCTION thunk_2659c8
0x2659cd: INT3 ; original byte CC, padding
0x2659ce: INT3 ; original byte CC, padding
0x2659cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2659d0 [0x2659d0, 0x2659d4] | file +0x3e8 | ev_d7c4da6f51e0244008bec03e69af471e068616e27e56eaaba7cd17e57aee7856
thunk_2659d0:
0x2659d0: JMP 0x0052fe70
; END FUNCTION thunk_2659d0
0x2659d5: INT3 ; original byte CC, padding
0x2659d6: INT3 ; original byte CC, padding
0x2659d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659d8 [0x2659d8, 0x2659dc] | file +0x3f0 | ev_d812c2321b5e8acb07f8f189c4f83d49099c0d10ab687c950cf9040645c78369
thunk_2659d8:
0x2659d8: JMP 0x008fb450
; END FUNCTION thunk_2659d8
0x2659dd: INT3 ; original byte CC, padding
0x2659de: INT3 ; original byte CC, padding
0x2659df: INT3 ; original byte CC, padding

; FUNCTION thunk_2659e0 [0x2659e0, 0x2659e4] | file +0x3f8 | ev_eeaf3a8beaaed8e90f29f246e32ffa9b14bf76351f9c7cdd7b75a5907064074e
thunk_2659e0:
0x2659e0: JMP 0x0072e590
; END FUNCTION thunk_2659e0
0x2659e5: INT3 ; original byte CC, padding
0x2659e6: INT3 ; original byte CC, padding
0x2659e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659e8 [0x2659e8, 0x2659ec] | file +0x400 | ev_93e5bf490834f1047815cb55d92a50b3522304ffe4de081ae3e2a6297c559350
thunk_2659e8:
0x2659e8: JMP 0x00531b30
; END FUNCTION thunk_2659e8
0x2659ed: INT3 ; original byte CC, padding
0x2659ee: INT3 ; original byte CC, padding
0x2659ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2659f0 [0x2659f0, 0x2659f4] | file +0x408 | ev_57eee56aad063f12744228690ca7ce45177d557dbda4f1cfc4949d59a3dd76f2
thunk_2659f0:
0x2659f0: JMP 0x00532af0
; END FUNCTION thunk_2659f0
0x2659f5: INT3 ; original byte CC, padding
0x2659f6: INT3 ; original byte CC, padding
0x2659f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659f8 [0x2659f8, 0x2659fc] | file +0x410 | ev_db6ed9d2e0cae311a8d595ad0e20575d70be3c6634b7afa4daa42c7afdd41d1c
thunk_2659f8:
0x2659f8: JMP 0x00531720
; END FUNCTION thunk_2659f8
0x2659fd: INT3 ; original byte CC, padding
0x2659fe: INT3 ; original byte CC, padding
0x2659ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265a00 [0x265a00, 0x265a04] | file +0x418 | ev_b9362fe323a442adbbe22eddd8cb779a87e9f35aa42d1392c2f78475a282a46c
thunk_265a00:
0x265a00: JMP 0x008fb8e0
; END FUNCTION thunk_265a00
0x265a05: INT3 ; original byte CC, padding
0x265a06: INT3 ; original byte CC, padding
0x265a07: INT3 ; original byte CC, padding

; FUNCTION thunk_265a08 [0x265a08, 0x265a0c] | file +0x420 | ev_e101e165d55e3c023ea9702dfff16f6e79246d887abaaf2a48215537ac448782
thunk_265a08:
0x265a08: JMP 0x008fbbc0
; END FUNCTION thunk_265a08
0x265a0d: INT3 ; original byte CC, padding
0x265a0e: INT3 ; original byte CC, padding
0x265a0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a10 [0x265a10, 0x265a14] | file +0x428 | ev_ab047a2ffd77c7fb21b69d50e06b794aa9de69186983e5cd51eb5c80a01023a4
thunk_265a10:
0x265a10: JMP 0x008fa310
; END FUNCTION thunk_265a10
0x265a15: INT3 ; original byte CC, padding
0x265a16: INT3 ; original byte CC, padding
0x265a17: INT3 ; original byte CC, padding

; FUNCTION thunk_265a18 [0x265a18, 0x265a1c] | file +0x430 | ev_457281366867d82ba2e84e2eeef2531b31b5cda653fa8dea15200204f38ec3dc
thunk_265a18:
0x265a18: JMP 0x0047b030
; END FUNCTION thunk_265a18
0x265a1d: INT3 ; original byte CC, padding
0x265a1e: INT3 ; original byte CC, padding
0x265a1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a20 [0x265a20, 0x265a24] | file +0x438 | ev_4cb9f4b02ac3982206479c7a415db43ef9663b9930a274e8917298018a4f8c09
thunk_265a20:
0x265a20: JMP 0x008f8e20
; END FUNCTION thunk_265a20
0x265a25: INT3 ; original byte CC, padding
0x265a26: INT3 ; original byte CC, padding
0x265a27: INT3 ; original byte CC, padding

; FUNCTION thunk_265a28 [0x265a28, 0x265a2c] | file +0x440 | ev_6aeeb89ab9fdd62d9997b8bb32c9bed71748578a672c0ba09686d984be5a9bdc
thunk_265a28:
0x265a28: JMP 0x0072c150
; END FUNCTION thunk_265a28
0x265a2d: INT3 ; original byte CC, padding
0x265a2e: INT3 ; original byte CC, padding
0x265a2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a30 [0x265a30, 0x265a34] | file +0x448 | ev_be064326b7431503cdcb02908a7217e744357b729e72e1614dc1328bc1ea66b1
thunk_265a30:
0x265a30: JMP 0x008f9260
; END FUNCTION thunk_265a30
0x265a35: INT3 ; original byte CC, padding
0x265a36: INT3 ; original byte CC, padding
0x265a37: INT3 ; original byte CC, padding

; FUNCTION thunk_265a38 [0x265a38, 0x265a3c] | file +0x450 | ev_eb91a911fcc71da70f30352af205783637b459c9f8d67b0eed63722a8d86b1cf
thunk_265a38:
0x265a38: JMP 0x008f9310
; END FUNCTION thunk_265a38
0x265a3d: INT3 ; original byte CC, padding
0x265a3e: INT3 ; original byte CC, padding
0x265a3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a40 [0x265a40, 0x265a44] | file +0x458 | ev_a3a52775b98c6fc5df9d7b69dd708e06229385519208b8f9465b77c8a0e0b83d
thunk_265a40:
0x265a40: JMP 0x0072c3e0
; END FUNCTION thunk_265a40
0x265a45: INT3 ; original byte CC, padding
0x265a46: INT3 ; original byte CC, padding
0x265a47: INT3 ; original byte CC, padding

; FUNCTION thunk_265a48 [0x265a48, 0x265a4c] | file +0x460 | ev_96925a78451c47ba5cdc7f70b51a7168ab595113055ce5d9d6b7261f687e8714
thunk_265a48:
0x265a48: JMP 0x004a13e0
; END FUNCTION thunk_265a48
0x265a4d: INT3 ; original byte CC, padding
0x265a4e: INT3 ; original byte CC, padding
0x265a4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a50 [0x265a50, 0x265a54] | file +0x468 | ev_06598b27113e0dd15bfe1ee2bc7d1d3b941c688d483dbbb8500b929308de0685
thunk_265a50:
0x265a50: JMP 0x004a0c30
; END FUNCTION thunk_265a50
0x265a55: INT3 ; original byte CC, padding
0x265a56: INT3 ; original byte CC, padding
0x265a57: INT3 ; original byte CC, padding

; FUNCTION thunk_265a58 [0x265a58, 0x265a5c] | file +0x470 | ev_ee56e932effb8cd11abcdecf19d018c0439a597586b5af12955784334c9c2e4c
thunk_265a58:
0x265a58: JMP 0x008fbbe0
; END FUNCTION thunk_265a58
0x265a5d: INT3 ; original byte CC, padding
0x265a5e: INT3 ; original byte CC, padding
0x265a5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a60 [0x265a60, 0x265a64] | file +0x478 | ev_c95aaa86727ffe60a4df1d510d7c3093e8db94cd313c902d93a5997623489575
thunk_265a60:
0x265a60: JMP 0x005581e0
; END FUNCTION thunk_265a60
0x265a65: INT3 ; original byte CC, padding
0x265a66: INT3 ; original byte CC, padding
0x265a67: INT3 ; original byte CC, padding

; FUNCTION thunk_265a68 [0x265a68, 0x265a6c] | file +0x480 | ev_a0b1537d4bc5be6705b058b5985864a5157864850b1bd21bf57c9b2325380cf6
thunk_265a68:
0x265a68: JMP 0x00ab9450
; END FUNCTION thunk_265a68
0x265a6d: INT3 ; original byte CC, padding
0x265a6e: INT3 ; original byte CC, padding
0x265a6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a70 [0x265a70, 0x265a74] | file +0x488 | ev_e362c6c038b8a2de4031260263b33b300becdbb2a86e2dc2d06b1a513f67a290
thunk_265a70:
0x265a70: JMP 0x00ab9710
; END FUNCTION thunk_265a70
0x265a75: INT3 ; original byte CC, padding
0x265a76: INT3 ; original byte CC, padding
0x265a77: INT3 ; original byte CC, padding

; FUNCTION thunk_265a78 [0x265a78, 0x265a7c] | file +0x490 | ev_495d3038041b1a058b06ff2e731663ea4085c3483dad60be8c277ec4650ae131
thunk_265a78:
0x265a78: JMP 0x008fa8e0
; END FUNCTION thunk_265a78
0x265a7d: INT3 ; original byte CC, padding
0x265a7e: INT3 ; original byte CC, padding
0x265a7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a80 [0x265a80, 0x265a84] | file +0x498 | ev_01494b260f43259ae66379dfaa4ec3220cf27d283f5fa293cc9016f999ef5a95
thunk_265a80:
0x265a80: JMP 0x004ee550
; END FUNCTION thunk_265a80
0x265a85: INT3 ; original byte CC, padding
0x265a86: INT3 ; original byte CC, padding
0x265a87: INT3 ; original byte CC, padding

; FUNCTION thunk_265a88 [0x265a88, 0x265a8c] | file +0x4a0 | ev_44497fb3e04c8f7d5d0ac5c7e05dd2da54ffa2c8543f7248613743fa2124e22e
thunk_265a88:
0x265a88: JMP 0x008fc810
; END FUNCTION thunk_265a88
0x265a8d: INT3 ; original byte CC, padding
0x265a8e: INT3 ; original byte CC, padding
0x265a8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a90 [0x265a90, 0x265a94] | file +0x4a8 | ev_9ae732fc69c6cc412b0330c58f2d0bb51a78ab4d537f32b719ec38209eac178a
thunk_265a90:
0x265a90: JMP 0x008fc820
; END FUNCTION thunk_265a90
0x265a95: INT3 ; original byte CC, padding
0x265a96: INT3 ; original byte CC, padding
0x265a97: INT3 ; original byte CC, padding

; FUNCTION thunk_265a98 [0x265a98, 0x265a9c] | file +0x4b0 | ev_703f3a9a7f45ff25eec1878f102b43f3b14214814250fb5f5c02f5bb7cae1c1b
thunk_265a98:
0x265a98: JMP 0x006bb670
; END FUNCTION thunk_265a98
0x265a9d: INT3 ; original byte CC, padding
0x265a9e: INT3 ; original byte CC, padding
0x265a9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265aa0 [0x265aa0, 0x265aa4] | file +0x4b8 | ev_74184725994ed2974629c910264ae0ce707c4aedf51a50f3a0ed2fdb4811bafd
thunk_265aa0:
0x265aa0: JMP 0x006bbd20
; END FUNCTION thunk_265aa0
0x265aa5: INT3 ; original byte CC, padding
0x265aa6: INT3 ; original byte CC, padding
0x265aa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265aa8 [0x265aa8, 0x265aac] | file +0x4c0 | ev_e9fefd27bc7e8195f87b57be11e34664c183dddbdafa1971b6354208ba73289c
thunk_265aa8:
0x265aa8: JMP 0x006bc030
; END FUNCTION thunk_265aa8
0x265aad: INT3 ; original byte CC, padding
0x265aae: INT3 ; original byte CC, padding
0x265aaf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ab0 [0x265ab0, 0x265ab4] | file +0x4c8 | ev_d6bb2d3864dfa8653d8b0a1a1a301a0ec61fc622efb8ed1a8c716a6616500d8c
thunk_265ab0:
0x265ab0: JMP 0x006bd570
; END FUNCTION thunk_265ab0
0x265ab5: INT3 ; original byte CC, padding
0x265ab6: INT3 ; original byte CC, padding
0x265ab7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ab8 [0x265ab8, 0x265abc] | file +0x4d0 | ev_da8086beb71b8289e8a89ced618b14099f0e550d9c8b00b77e86342eb26afc6b
thunk_265ab8:
0x265ab8: JMP 0x006bdfa0
; END FUNCTION thunk_265ab8
0x265abd: INT3 ; original byte CC, padding
0x265abe: INT3 ; original byte CC, padding
0x265abf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ac0 [0x265ac0, 0x265ac4] | file +0x4d8 | ev_a7a4b472e4d5050be1e8b517eb6b54f185b39ba3a423190aeff61c75a894d6a6
thunk_265ac0:
0x265ac0: JMP 0x006bdfb0
; END FUNCTION thunk_265ac0
0x265ac5: INT3 ; original byte CC, padding
0x265ac6: INT3 ; original byte CC, padding
0x265ac7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ac8 [0x265ac8, 0x265acc] | file +0x4e0 | ev_f5662ab849c8da53ecae1ad0eeaddb1df22fad5b85181d96d1a93b3c3137080b
thunk_265ac8:
0x265ac8: JMP 0x006be1d0
; END FUNCTION thunk_265ac8
0x265acd: INT3 ; original byte CC, padding
0x265ace: INT3 ; original byte CC, padding
0x265acf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ad0 [0x265ad0, 0x265ad4] | file +0x4e8 | ev_a83086b17cb41202f8a783e29293a14cf7083aef07c71243350a67baf6a55783
thunk_265ad0:
0x265ad0: JMP 0x006be370
; END FUNCTION thunk_265ad0
0x265ad5: INT3 ; original byte CC, padding
0x265ad6: INT3 ; original byte CC, padding
0x265ad7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ad8 [0x265ad8, 0x265adc] | file +0x4f0 | ev_8b313a4cd4e03d138294806bc1259185344520a276b48d244c4a89477c4c787c
thunk_265ad8:
0x265ad8: JMP 0x006bc4e0
; END FUNCTION thunk_265ad8
0x265add: INT3 ; original byte CC, padding
0x265ade: INT3 ; original byte CC, padding
0x265adf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ae0 [0x265ae0, 0x265ae4] | file +0x4f8 | ev_f30b4d187411d67d73401e1457f57a54727fc2e9e0ff00e7587ba82b85313d03
thunk_265ae0:
0x265ae0: JMP 0x00cb1ab0
; END FUNCTION thunk_265ae0
0x265ae5: INT3 ; original byte CC, padding
0x265ae6: INT3 ; original byte CC, padding
0x265ae7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ae8 [0x265ae8, 0x265aec] | file +0x500 | ev_afba907846997d56d0b1e5c1e415974c601de5cf6166c57a19b6f6715465b552
thunk_265ae8:
0x265ae8: JMP 0x008fc390
; END FUNCTION thunk_265ae8
0x265aed: INT3 ; original byte CC, padding
0x265aee: INT3 ; original byte CC, padding
0x265aef: INT3 ; original byte CC, padding

; FUNCTION thunk_265af0 [0x265af0, 0x265af4] | file +0x508 | ev_cd81f5026adc4e739b1631c6db8bc6dfcb618f6a8d7556dd3134662e421e165f
thunk_265af0:
0x265af0: JMP 0x004ec4e0
; END FUNCTION thunk_265af0
0x265af5: INT3 ; original byte CC, padding
0x265af6: INT3 ; original byte CC, padding
0x265af7: INT3 ; original byte CC, padding

; FUNCTION thunk_265af8 [0x265af8, 0x265afc] | file +0x510 | ev_3a07c8c9cac85f4902d53fd0bdeb88f36620f674b725f543cc5ddc1cfe02744f
thunk_265af8:
0x265af8: JMP 0x004ecc70
; END FUNCTION thunk_265af8
0x265afd: INT3 ; original byte CC, padding
0x265afe: INT3 ; original byte CC, padding
0x265aff: INT3 ; original byte CC, padding

; FUNCTION thunk_265b00 [0x265b00, 0x265b04] | file +0x518 | ev_3421d95e17cc4a1925878bcf237c85a181496eb13254fc09214051717e3bf956
thunk_265b00:
0x265b00: JMP 0x00b7e960
; END FUNCTION thunk_265b00
0x265b05: INT3 ; original byte CC, padding
0x265b06: INT3 ; original byte CC, padding
0x265b07: INT3 ; original byte CC, padding

; FUNCTION thunk_265b08 [0x265b08, 0x265b0c] | file +0x520 | ev_75fd94589e78a26fe265113c01ec72d5cc7b39e10c9ab4703526f635bb918b90
thunk_265b08:
0x265b08: JMP 0x00ab9580
; END FUNCTION thunk_265b08
0x265b0d: INT3 ; original byte CC, padding
0x265b0e: INT3 ; original byte CC, padding
0x265b0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b10 [0x265b10, 0x265b14] | file +0x528 | ev_af1b623e4e48ac4d33130b6c322bad5504b08c7fcfd69f2794de5fdd99e36ba2
thunk_265b10:
0x265b10: JMP 0x00ab9690
; END FUNCTION thunk_265b10
0x265b15: INT3 ; original byte CC, padding
0x265b16: INT3 ; original byte CC, padding
0x265b17: INT3 ; original byte CC, padding

; FUNCTION thunk_265b18 [0x265b18, 0x265b1c] | file +0x530 | ev_6f08de602f743b11af2a3ca81a92e66b4599a09ea231bf06d2b2b6b3b5eaaca6
thunk_265b18:
0x265b18: JMP 0x005a3a60
; END FUNCTION thunk_265b18
0x265b1d: INT3 ; original byte CC, padding
0x265b1e: INT3 ; original byte CC, padding
0x265b1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b20 [0x265b20, 0x265b24] | file +0x538 | ev_c564b04ab0134458f3ec21037b36c3c93539d25c908e0ad6ca22354547c06438
thunk_265b20:
0x265b20: JMP 0x005a3b50
; END FUNCTION thunk_265b20
0x265b25: INT3 ; original byte CC, padding
0x265b26: INT3 ; original byte CC, padding
0x265b27: INT3 ; original byte CC, padding

; FUNCTION thunk_265b28 [0x265b28, 0x265b2c] | file +0x540 | ev_5affb35aa9906b7dce9056179ac6876de7facd3be39c71c34d941337286ca5a6
thunk_265b28:
0x265b28: JMP 0x005a3c60
; END FUNCTION thunk_265b28
0x265b2d: INT3 ; original byte CC, padding
0x265b2e: INT3 ; original byte CC, padding
0x265b2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b30 [0x265b30, 0x265b34] | file +0x548 | ev_c7936173b4efa1a6af8d0aa07fef51e96aec939bed94b875ebdf5c5837764184
thunk_265b30:
0x265b30: JMP 0x005a3d80
; END FUNCTION thunk_265b30
0x265b35: INT3 ; original byte CC, padding
0x265b36: INT3 ; original byte CC, padding
0x265b37: INT3 ; original byte CC, padding

; FUNCTION thunk_265b38 [0x265b38, 0x265b3c] | file +0x550 | ev_0e76e0fad593dfb982ea3a62cc569e5ea657347adda0b8922d71b521086b1c2b
thunk_265b38:
0x265b38: JMP 0x005a3e70
; END FUNCTION thunk_265b38
0x265b3d: INT3 ; original byte CC, padding
0x265b3e: INT3 ; original byte CC, padding
0x265b3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b40 [0x265b40, 0x265b44] | file +0x558 | ev_f1fc0fe618834671b18566b6c97f93eb32d77f7ff6bc3a5c418a0488c6417721
thunk_265b40:
0x265b40: JMP 0x005a3e90
; END FUNCTION thunk_265b40
0x265b45: INT3 ; original byte CC, padding
0x265b46: INT3 ; original byte CC, padding
0x265b47: INT3 ; original byte CC, padding

; FUNCTION thunk_265b48 [0x265b48, 0x265b4c] | file +0x560 | ev_297e4ad1506e4fa588be7ffb3cc64d2c156a60c7398949f2861c53f18d5b17d2
thunk_265b48:
0x265b48: JMP 0x005a3ef0
; END FUNCTION thunk_265b48
0x265b4d: INT3 ; original byte CC, padding
0x265b4e: INT3 ; original byte CC, padding
0x265b4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b50 [0x265b50, 0x265b54] | file +0x568 | ev_957aacb527787eb0bbe4be89cd09cb9d646bdb0b0eef73532724401411d3f83f
thunk_265b50:
0x265b50: JMP 0x005a3f50
; END FUNCTION thunk_265b50
0x265b55: INT3 ; original byte CC, padding
0x265b56: INT3 ; original byte CC, padding
0x265b57: INT3 ; original byte CC, padding

; FUNCTION thunk_265b58 [0x265b58, 0x265b5c] | file +0x570 | ev_cdf8cfb3dbfa1c991b88c6fb6c622969311bf5929ddd06d485acb7358d3b157f
thunk_265b58:
0x265b58: JMP 0x0055ddc0
; END FUNCTION thunk_265b58
0x265b5d: INT3 ; original byte CC, padding
0x265b5e: INT3 ; original byte CC, padding
0x265b5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b60 [0x265b60, 0x265b64] | file +0x578 | ev_ff82123b8e6c256e78638c22fe7f10d74d0dfa36b00ec56cab6d9ea3a0aa3319
thunk_265b60:
0x265b60: JMP 0x0055ed70
; END FUNCTION thunk_265b60
0x265b65: INT3 ; original byte CC, padding
0x265b66: INT3 ; original byte CC, padding
0x265b67: INT3 ; original byte CC, padding

; FUNCTION thunk_265b68 [0x265b68, 0x265b6c] | file +0x580 | ev_741b6004488946980cd7fb46c8ac97d67f459efd27fe6f2f52fb1230a023caee
thunk_265b68:
0x265b68: JMP 0x0055ec90
; END FUNCTION thunk_265b68
0x265b6d: INT3 ; original byte CC, padding
0x265b6e: INT3 ; original byte CC, padding
0x265b6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b70 [0x265b70, 0x265b74] | file +0x588 | ev_a80907af4d4322c151a28c2e6b435566f63b91608759d6b7eed94f2c1d82e756
thunk_265b70:
0x265b70: JMP 0x0055e550
; END FUNCTION thunk_265b70
0x265b75: INT3 ; original byte CC, padding
0x265b76: INT3 ; original byte CC, padding
0x265b77: INT3 ; original byte CC, padding

; FUNCTION thunk_265b78 [0x265b78, 0x265b7c] | file +0x590 | ev_fdf4707818758567a82e30ec2143b122d38d08eb7ed927cd231371fdc7e00e94
thunk_265b78:
0x265b78: JMP 0x0055e680
; END FUNCTION thunk_265b78
0x265b7d: INT3 ; original byte CC, padding
0x265b7e: INT3 ; original byte CC, padding
0x265b7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b80 [0x265b80, 0x265b84] | file +0x598 | ev_799415689b58e85117b40d602cd6f0ae72c9367f920780d6dac67533b8fab27b
thunk_265b80:
0x265b80: JMP 0x00abbd80
; END FUNCTION thunk_265b80
0x265b85: INT3 ; original byte CC, padding
0x265b86: INT3 ; original byte CC, padding
0x265b87: INT3 ; original byte CC, padding

; FUNCTION thunk_265b88 [0x265b88, 0x265b8c] | file +0x5a0 | ev_f76ebe4feb3b350240ced19a248ba11b57b55594dfd79f35b9487d256cc6a04d
thunk_265b88:
0x265b88: JMP 0x008340e0
; END FUNCTION thunk_265b88
0x265b8d: INT3 ; original byte CC, padding
0x265b8e: INT3 ; original byte CC, padding
0x265b8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b90 [0x265b90, 0x265b94] | file +0x5a8 | ev_e804e814208779b292184c09528d5b06b191b5e662769ad648d37c00fa89bdff
thunk_265b90:
0x265b90: JMP 0x008f6120
; END FUNCTION thunk_265b90
0x265b95: INT3 ; original byte CC, padding
0x265b96: INT3 ; original byte CC, padding
0x265b97: INT3 ; original byte CC, padding

; FUNCTION thunk_265b98 [0x265b98, 0x265b9c] | file +0x5b0 | ev_8e023189980448d6df30dad824c60fca8197963af4cd274e52ca66e3592e2094
thunk_265b98:
0x265b98: JMP 0x00c42f00
; END FUNCTION thunk_265b98
0x265b9d: INT3 ; original byte CC, padding
0x265b9e: INT3 ; original byte CC, padding
0x265b9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ba0 [0x265ba0, 0x265ba4] | file +0x5b8 | ev_14db88a56f2d598b9fe53ff7e638f60ded442f1493152fa12749722dc00d28f1
thunk_265ba0:
0x265ba0: JMP 0x00c43010
; END FUNCTION thunk_265ba0
0x265ba5: INT3 ; original byte CC, padding
0x265ba6: INT3 ; original byte CC, padding
0x265ba7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ba8 [0x265ba8, 0x265bac] | file +0x5c0 | ev_32b9f7cf53a0920034e238f86f0960da31d0a690a74474aa4d053cbe623c8890
thunk_265ba8:
0x265ba8: JMP 0x00c43170
; END FUNCTION thunk_265ba8
0x265bad: INT3 ; original byte CC, padding
0x265bae: INT3 ; original byte CC, padding
0x265baf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bb0 [0x265bb0, 0x265bb4] | file +0x5c8 | ev_d4fef26238f87cdb8b610f00be41942cd7a349cc61e68316a81cb39b0b1c2fce
thunk_265bb0:
0x265bb0: JMP 0x00c434a0
; END FUNCTION thunk_265bb0
0x265bb5: INT3 ; original byte CC, padding
0x265bb6: INT3 ; original byte CC, padding
0x265bb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bb8 [0x265bb8, 0x265bbc] | file +0x5d0 | ev_4b8412f013e4a4161e3b194fda8f6cb9c414b2af1de1c4afbc24c0ea4644503e
thunk_265bb8:
0x265bb8: JMP 0x00c42760
; END FUNCTION thunk_265bb8
0x265bbd: INT3 ; original byte CC, padding
0x265bbe: INT3 ; original byte CC, padding
0x265bbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bc0 [0x265bc0, 0x265bc4] | file +0x5d8 | ev_542f037da7f8c1fbbbbe4388bc2a8965614ae5b299d19f951ab10f851c55470f
thunk_265bc0:
0x265bc0: JMP 0x00c42b90
; END FUNCTION thunk_265bc0
0x265bc5: INT3 ; original byte CC, padding
0x265bc6: INT3 ; original byte CC, padding
0x265bc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bc8 [0x265bc8, 0x265bcc] | file +0x5e0 | ev_2abf1503fb82f595215032a28e2b77328058162fd3991569beaaaa185103b9d0
thunk_265bc8:
0x265bc8: JMP 0x00c42bc0
; END FUNCTION thunk_265bc8
0x265bcd: INT3 ; original byte CC, padding
0x265bce: INT3 ; original byte CC, padding
0x265bcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bd0 [0x265bd0, 0x265bd4] | file +0x5e8 | ev_387932b9517a57a82c27fdbdcbf9e370a164e0a05fff89ca14b8746cdc73bab3
thunk_265bd0:
0x265bd0: JMP 0x00c434c0
; END FUNCTION thunk_265bd0
0x265bd5: INT3 ; original byte CC, padding
0x265bd6: INT3 ; original byte CC, padding
0x265bd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bd8 [0x265bd8, 0x265bdc] | file +0x5f0 | ev_26ee89d746438e99e644a6e16f3f2b9c9ff970be35a07e54a2046ea564c57865
thunk_265bd8:
0x265bd8: JMP 0x00c43620
; END FUNCTION thunk_265bd8
0x265bdd: INT3 ; original byte CC, padding
0x265bde: INT3 ; original byte CC, padding
0x265bdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265be0 [0x265be0, 0x265be4] | file +0x5f8 | ev_0d9cd2755c606972ae8da0395a90246782c03e5283edfa37f3d50fb9cae6a53a
thunk_265be0:
0x265be0: JMP 0x0055d0c0
; END FUNCTION thunk_265be0
0x265be5: INT3 ; original byte CC, padding
0x265be6: INT3 ; original byte CC, padding
0x265be7: INT3 ; original byte CC, padding

; FUNCTION thunk_265be8 [0x265be8, 0x265bec] | file +0x600 | ev_a8aa7da9f0f61c34383d7c33eac6c441db1c5fc2aa8b978bdcf95961ef7abd04
thunk_265be8:
0x265be8: JMP 0x00a07280
; END FUNCTION thunk_265be8
0x265bed: INT3 ; original byte CC, padding
0x265bee: INT3 ; original byte CC, padding
0x265bef: INT3 ; original byte CC, padding

; FUNCTION thunk_265bf0 [0x265bf0, 0x265bf4] | file +0x608 | ev_679c3d1f43637f11cd7695c288b451925ec6002f64d269f54c771928525841a5
thunk_265bf0:
0x265bf0: JMP 0x00c37860
; END FUNCTION thunk_265bf0
0x265bf5: INT3 ; original byte CC, padding
0x265bf6: INT3 ; original byte CC, padding
0x265bf7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bf8 [0x265bf8, 0x265bfc] | file +0x610 | ev_be190519692c8275063e286d6fffd6a64efe639bb6af22a923b4fd232f4105db
thunk_265bf8:
0x265bf8: JMP 0x00c37970
; END FUNCTION thunk_265bf8
0x265bfd: INT3 ; original byte CC, padding
0x265bfe: INT3 ; original byte CC, padding
0x265bff: INT3 ; original byte CC, padding

; FUNCTION thunk_265c00 [0x265c00, 0x265c04] | file +0x618 | ev_376b188e787a152b612ae47a3648a443bb8a8cfcaff267f96a1ec4874ac9450a
thunk_265c00:
0x265c00: JMP 0x00c37a20
; END FUNCTION thunk_265c00
0x265c05: INT3 ; original byte CC, padding
0x265c06: INT3 ; original byte CC, padding
0x265c07: INT3 ; original byte CC, padding

; FUNCTION thunk_265c08 [0x265c08, 0x265c0c] | file +0x620 | ev_f434a76a40f2b0300bd3a5e9385326262ff52dd8d7886dc762ba81360a2ddf87
thunk_265c08:
0x265c08: JMP 0x0055deb0
; END FUNCTION thunk_265c08
0x265c0d: INT3 ; original byte CC, padding
0x265c0e: INT3 ; original byte CC, padding
0x265c0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c10 [0x265c10, 0x265c14] | file +0x628 | ev_931e459cfa2bc89ce67e5db8224a8c392853e680b03a61f1c4b53790ccfef13e
thunk_265c10:
0x265c10: JMP 0x00437cf0
; END FUNCTION thunk_265c10
0x265c15: INT3 ; original byte CC, padding
0x265c16: INT3 ; original byte CC, padding
0x265c17: INT3 ; original byte CC, padding

; FUNCTION thunk_265c18 [0x265c18, 0x265c1c] | file +0x630 | ev_438aeee9179dc8a6bb52273c75cf0e13486940563f28b22cd10ca70617ffdc84
thunk_265c18:
0x265c18: JMP 0x004383f0
; END FUNCTION thunk_265c18
0x265c1d: INT3 ; original byte CC, padding
0x265c1e: INT3 ; original byte CC, padding
0x265c1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c20 [0x265c20, 0x265c24] | file +0x638 | ev_4c312f6e9064ce367f20897f87104b54edcf7a4040d829ac34ce64a41d5cccef
thunk_265c20:
0x265c20: JMP 0x004383c0
; END FUNCTION thunk_265c20
0x265c25: INT3 ; original byte CC, padding
0x265c26: INT3 ; original byte CC, padding
0x265c27: INT3 ; original byte CC, padding

; FUNCTION thunk_265c28 [0x265c28, 0x265c2c] | file +0x640 | ev_0ab289f3bd62320e6566baa85db7e1202ddfc9373809b3e3b041b9f8ffd735c7
thunk_265c28:
0x265c28: JMP 0x00438560
; END FUNCTION thunk_265c28
0x265c2d: INT3 ; original byte CC, padding
0x265c2e: INT3 ; original byte CC, padding
0x265c2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c30 [0x265c30, 0x265c34] | file +0x648 | ev_bb6054e8c6fb2f121bcafd7a5c5ec8cff8a0d4c62a9156a3ea7fba134abf1536
thunk_265c30:
0x265c30: JMP 0x00c433f0
; END FUNCTION thunk_265c30
0x265c35: INT3 ; original byte CC, padding
0x265c36: INT3 ; original byte CC, padding
0x265c37: INT3 ; original byte CC, padding

; FUNCTION thunk_265c38 [0x265c38, 0x265c3c] | file +0x650 | ev_1696320a0b23b1fbe9014e786637c3aa0ebe7eb95ac14323feb57d182773a829
thunk_265c38:
0x265c38: JMP 0x004388c0
; END FUNCTION thunk_265c38
0x265c3d: INT3 ; original byte CC, padding
0x265c3e: INT3 ; original byte CC, padding
0x265c3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c40 [0x265c40, 0x265c44] | file +0x658 | ev_91a591a481a2b0fa31e530f862c8de090450922e52945aee314f278a55712a96
thunk_265c40:
0x265c40: JMP 0x00438ab0
; END FUNCTION thunk_265c40
0x265c45: INT3 ; original byte CC, padding
0x265c46: INT3 ; original byte CC, padding
0x265c47: INT3 ; original byte CC, padding

; FUNCTION thunk_265c48 [0x265c48, 0x265c4c] | file +0x660 | ev_709ff95251ab30ee92ca67ec919accb694556039b483a052b3e048988602a70c
thunk_265c48:
0x265c48: JMP 0x00552c20
; END FUNCTION thunk_265c48
0x265c4d: INT3 ; original byte CC, padding
0x265c4e: INT3 ; original byte CC, padding
0x265c4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c50 [0x265c50, 0x265c54] | file +0x668 | ev_4eafb23dc2edda248c508804926a68aac0c3aea458e04a43c2944debfa602ca4
thunk_265c50:
0x265c50: JMP 0x00437de0
; END FUNCTION thunk_265c50
0x265c55: INT3 ; original byte CC, padding
0x265c56: INT3 ; original byte CC, padding
0x265c57: INT3 ; original byte CC, padding

; FUNCTION thunk_265c58 [0x265c58, 0x265c5c] | file +0x670 | ev_cc3a07b8d71a1d4520dc7a3471d16d389cb9a545dbea33c1f9ead630c8c24e8c
thunk_265c58:
0x265c58: JMP 0x0055fc20
; END FUNCTION thunk_265c58
0x265c5d: INT3 ; original byte CC, padding
0x265c5e: INT3 ; original byte CC, padding
0x265c5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c60 [0x265c60, 0x265c64] | file +0x678 | ev_a9da2e1f21296d36267a024dc9f6baa872bd760111b710b4e17e73fab083ee82
thunk_265c60:
0x265c60: JMP 0x00438b60
; END FUNCTION thunk_265c60
0x265c65: INT3 ; original byte CC, padding
0x265c66: INT3 ; original byte CC, padding
0x265c67: INT3 ; original byte CC, padding

; FUNCTION thunk_265c68 [0x265c68, 0x265c6c] | file +0x680 | ev_ade79c344fa8f9813a509184257a796302ce52c97d848f153069b605de1f1255
thunk_265c68:
0x265c68: JMP 0x004a0400
; END FUNCTION thunk_265c68
0x265c6d: INT3 ; original byte CC, padding
0x265c6e: INT3 ; original byte CC, padding
0x265c6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c70 [0x265c70, 0x265c74] | file +0x688 | ev_93839e631c81c2700fc2f343594258766f1e42358948e7d0d9f8d4bac559696a
thunk_265c70:
0x265c70: JMP 0x004ec120
; END FUNCTION thunk_265c70
0x265c75: INT3 ; original byte CC, padding
0x265c76: INT3 ; original byte CC, padding
0x265c77: INT3 ; original byte CC, padding

; FUNCTION thunk_265c78 [0x265c78, 0x265c7c] | file +0x690 | ev_10871a7c7ae092e887b02fb009ac16eb48ee7f55f6163c265dcb6fb32f10ebcd
thunk_265c78:
0x265c78: JMP 0x004ec740
; END FUNCTION thunk_265c78
0x265c7d: INT3 ; original byte CC, padding
0x265c7e: INT3 ; original byte CC, padding
0x265c7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c80 [0x265c80, 0x265c84] | file +0x698 | ev_0e11dae06b7985255741a13a2e75201ff96088ebbdc4cb6c011b2b4b9d93dddc
thunk_265c80:
0x265c80: JMP 0x00ab83c0
; END FUNCTION thunk_265c80
0x265c85: INT3 ; original byte CC, padding
0x265c86: INT3 ; original byte CC, padding
0x265c87: INT3 ; original byte CC, padding

; FUNCTION thunk_265c88 [0x265c88, 0x265c8c] | file +0x6a0 | ev_ca4309404d7e3f813e8c3bdf066f86347e96654cb670f2fc40c3d6f4e27ed389
thunk_265c88:
0x265c88: JMP 0x008f8ab0
; END FUNCTION thunk_265c88
0x265c8d: INT3 ; original byte CC, padding
0x265c8e: INT3 ; original byte CC, padding
0x265c8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c90 [0x265c90, 0x265c94] | file +0x6a8 | ev_bda1c7672eafac7c695ffd553b29b18e662a3681aa39f879c1bb0c52ae1c896d
thunk_265c90:
0x265c90: JMP 0x008fafa0
; END FUNCTION thunk_265c90
0x265c95: INT3 ; original byte CC, padding
0x265c96: INT3 ; original byte CC, padding
0x265c97: INT3 ; original byte CC, padding

; FUNCTION thunk_265c98 [0x265c98, 0x265c9c] | file +0x6b0 | ev_78454f2614f7a8c5aa0ce1cc9f62c1aa06794fd78c8d46cb05f945f619e752d6
thunk_265c98:
0x265c98: JMP 0x004ecf20
; END FUNCTION thunk_265c98
0x265c9d: INT3 ; original byte CC, padding
0x265c9e: INT3 ; original byte CC, padding
0x265c9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ca0 [0x265ca0, 0x265ca4] | file +0x6b8 | ev_260b63cf8aaa76d66b218e0f85b6398abb5808a76e2f61128df3ff7e757ecae0
thunk_265ca0:
0x265ca0: JMP 0x004386f0
; END FUNCTION thunk_265ca0
0x265ca5: INT3 ; original byte CC, padding
0x265ca6: INT3 ; original byte CC, padding
0x265ca7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ca8 [0x265ca8, 0x265cac] | file +0x6c0 | ev_ff272acd78e9f5676eecf4bdd04b9434bee5314e6ff5aa418a1d299d01201bb5
thunk_265ca8:
0x265ca8: JMP 0x0080d740
; END FUNCTION thunk_265ca8
0x265cad: INT3 ; original byte CC, padding
0x265cae: INT3 ; original byte CC, padding
0x265caf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cb0 [0x265cb0, 0x265cb4] | file +0x6c8 | ev_6f1a3bda27ebdb29a3f400241102983207b2bfad15583ecd4555d9330af029ed
thunk_265cb0:
0x265cb0: JMP 0x0080dbd0
; END FUNCTION thunk_265cb0
0x265cb5: INT3 ; original byte CC, padding
0x265cb6: INT3 ; original byte CC, padding
0x265cb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cb8 [0x265cb8, 0x265cbc] | file +0x6d0 | ev_e1fa139b401f6c9470b4fa81c12a54c9a5f32c84d99ca333038c5ed29ad90765
thunk_265cb8:
0x265cb8: JMP 0x0083d830
; END FUNCTION thunk_265cb8
0x265cbd: INT3 ; original byte CC, padding
0x265cbe: INT3 ; original byte CC, padding
0x265cbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cc0 [0x265cc0, 0x265cc4] | file +0x6d8 | ev_a8e7b48f6f0f8d93bd1602d0953c8af3f8fdd570ad0089e5fd0e55eab5ed37b8
thunk_265cc0:
0x265cc0: JMP 0x0083de60
; END FUNCTION thunk_265cc0
0x265cc5: INT3 ; original byte CC, padding
0x265cc6: INT3 ; original byte CC, padding
0x265cc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cc8 [0x265cc8, 0x265ccc] | file +0x6e0 | ev_88c2cc843bca285bfdccb1db75a05ab3b1a284ae03f9a895638b74e0eddca2ac
thunk_265cc8:
0x265cc8: JMP 0x0083e320
; END FUNCTION thunk_265cc8
0x265ccd: INT3 ; original byte CC, padding
0x265cce: INT3 ; original byte CC, padding
0x265ccf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cd0 [0x265cd0, 0x265cd4] | file +0x6e8 | ev_f750b507c4e2d19e5d98f168eeeb8418fecfabdb7a02fc8699620ec54d8bdb56
thunk_265cd0:
0x265cd0: JMP 0x008f6e50
; END FUNCTION thunk_265cd0
0x265cd5: INT3 ; original byte CC, padding
0x265cd6: INT3 ; original byte CC, padding
0x265cd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cd8 [0x265cd8, 0x265cdc] | file +0x6f0 | ev_6eeb7e7ddd34548c87c2bdde79cfe3f25d5b61dd128d96f044c33c798a9b1c6c
thunk_265cd8:
0x265cd8: JMP 0x0049b0b0
; END FUNCTION thunk_265cd8
0x265cdd: INT3 ; original byte CC, padding
0x265cde: INT3 ; original byte CC, padding
0x265cdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ce0 [0x265ce0, 0x265ce4] | file +0x6f8 | ev_955b59f34dcc82d326f8019b5a4ef7d192713861deb00f603f64834614e2f0db
thunk_265ce0:
0x265ce0: JMP 0x004ed3c0
; END FUNCTION thunk_265ce0
0x265ce5: INT3 ; original byte CC, padding
0x265ce6: INT3 ; original byte CC, padding
0x265ce7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ce8 [0x265ce8, 0x265cec] | file +0x700 | ev_ddd096685219d6ca376c0ace419e984924567abf06917bc2cdfb8084533d37cf
thunk_265ce8:
0x265ce8: JMP 0x00af0040
; END FUNCTION thunk_265ce8
0x265ced: INT3 ; original byte CC, padding
0x265cee: INT3 ; original byte CC, padding
0x265cef: INT3 ; original byte CC, padding

; FUNCTION thunk_265cf0 [0x265cf0, 0x265cf4] | file +0x708 | ev_eb3f8a47c49ea4c24498ce29ef78200d49662ce3715f6d19d2959697e1e145d3
thunk_265cf0:
0x265cf0: JMP 0x00705880
; END FUNCTION thunk_265cf0
0x265cf5: INT3 ; original byte CC, padding
0x265cf6: INT3 ; original byte CC, padding
0x265cf7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cf8 [0x265cf8, 0x265cfc] | file +0x710 | ev_11ce4b2a7e8dafd791795576150b7e1fbf7fc1d3e8daa84958e281d2f2f0500a
thunk_265cf8:
0x265cf8: JMP 0x00705c60
; END FUNCTION thunk_265cf8
0x265cfd: INT3 ; original byte CC, padding
0x265cfe: INT3 ; original byte CC, padding
0x265cff: INT3 ; original byte CC, padding

; FUNCTION thunk_265d00 [0x265d00, 0x265d04] | file +0x718 | ev_da3f4081ffd1cca782d99510df16611df388a87eebce2f5108c2fa7c8173b36a
thunk_265d00:
0x265d00: JMP 0x004f65f0
; END FUNCTION thunk_265d00
0x265d05: INT3 ; original byte CC, padding
0x265d06: INT3 ; original byte CC, padding
0x265d07: INT3 ; original byte CC, padding

; FUNCTION thunk_265d08 [0x265d08, 0x265d0c] | file +0x720 | ev_91f3053d25aad314c50b29f764dc1a5ac85bdd695d16fb9c87e18cc475c3e9f0
thunk_265d08:
0x265d08: JMP 0x004f6a70
; END FUNCTION thunk_265d08
0x265d0d: INT3 ; original byte CC, padding
0x265d0e: INT3 ; original byte CC, padding
0x265d0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d10 [0x265d10, 0x265d14] | file +0x728 | ev_141bedc32617e72efe65c1855a21c5bc10119939626978056e0e307ade7c92a3
thunk_265d10:
0x265d10: JMP 0x00bafa80
; END FUNCTION thunk_265d10
0x265d15: INT3 ; original byte CC, padding
0x265d16: INT3 ; original byte CC, padding
0x265d17: INT3 ; original byte CC, padding

; FUNCTION thunk_265d18 [0x265d18, 0x265d1c] | file +0x730 | ev_b24101c8493214775072a4b243b882c271212957cc7bac7568a9482b23581da1
thunk_265d18:
0x265d18: JMP 0x00bafcf0
; END FUNCTION thunk_265d18
0x265d1d: INT3 ; original byte CC, padding
0x265d1e: INT3 ; original byte CC, padding
0x265d1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d20 [0x265d20, 0x265d24] | file +0x738 | ev_3f2696dc3468757284ec2bbccc5407f8851ad569f6a2098b096e4c156360a8f2
thunk_265d20:
0x265d20: JMP 0x00bb0330
; END FUNCTION thunk_265d20
0x265d25: INT3 ; original byte CC, padding
0x265d26: INT3 ; original byte CC, padding
0x265d27: INT3 ; original byte CC, padding

; FUNCTION thunk_265d28 [0x265d28, 0x265d2c] | file +0x740 | ev_9e1a530419c38b63f1c5c7f52f378f12933697777c29a2da5b9ab03f35a25121
thunk_265d28:
0x265d28: JMP 0x00bb0490
; END FUNCTION thunk_265d28
0x265d2d: INT3 ; original byte CC, padding
0x265d2e: INT3 ; original byte CC, padding
0x265d2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d30 [0x265d30, 0x265d34] | file +0x748 | ev_017269beca73fffa4d0e24415f9e851d880f86cbab93db9eca9ee4b129e29848
thunk_265d30:
0x265d30: JMP 0x00bafe50
; END FUNCTION thunk_265d30
0x265d35: INT3 ; original byte CC, padding
0x265d36: INT3 ; original byte CC, padding
0x265d37: INT3 ; original byte CC, padding

; FUNCTION thunk_265d38 [0x265d38, 0x265d3c] | file +0x750 | ev_7e8aa0703fa40d1dc25c26b650facf9165e8413fb00e01a9cb67b371c16e4761
thunk_265d38:
0x265d38: JMP 0x00bb0030
; END FUNCTION thunk_265d38
0x265d3d: INT3 ; original byte CC, padding
0x265d3e: INT3 ; original byte CC, padding
0x265d3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d40 [0x265d40, 0x265d44] | file +0x758 | ev_c6bd5b3b4689c932c0734de76323ffb6e492cd71b7f45059a8ee63b1b8c956c9
thunk_265d40:
0x265d40: JMP 0x00bb0150
; END FUNCTION thunk_265d40
0x265d45: INT3 ; original byte CC, padding
0x265d46: INT3 ; original byte CC, padding
0x265d47: INT3 ; original byte CC, padding

; FUNCTION thunk_265d48 [0x265d48, 0x265d4c] | file +0x760 | ev_139615a2fdde2cf350858d9f99c761a3bffb85be8daeae5c86b4510bc7b09c47
thunk_265d48:
0x265d48: JMP 0x00bb01d0
; END FUNCTION thunk_265d48
0x265d4d: INT3 ; original byte CC, padding
0x265d4e: INT3 ; original byte CC, padding
0x265d4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d50 [0x265d50, 0x265d54] | file +0x768 | ev_8e719955e834476320223e8cef9d48b6df5226ae75bcb7e95f0b800f19159d18
thunk_265d50:
0x265d50: JMP 0x00bb0280
; END FUNCTION thunk_265d50
0x265d55: INT3 ; original byte CC, padding
0x265d56: INT3 ; original byte CC, padding
0x265d57: INT3 ; original byte CC, padding

; FUNCTION thunk_265d58 [0x265d58, 0x265d5c] | file +0x770 | ev_572d12d696e0f9e3cebbf9442f0836c3e6d0e75fa7911b310cd02e3443ebaddd
thunk_265d58:
0x265d58: JMP 0x00aba540
; END FUNCTION thunk_265d58
0x265d5d: INT3 ; original byte CC, padding
0x265d5e: INT3 ; original byte CC, padding
0x265d5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d60 [0x265d60, 0x265d64] | file +0x778 | ev_cd34b10aeff44368d17a22690ff8671d8217d50f3346247d9fa38371455636fe
thunk_265d60:
0x265d60: JMP 0x00abbe60
; END FUNCTION thunk_265d60
0x265d65: INT3 ; original byte CC, padding
0x265d66: INT3 ; original byte CC, padding
0x265d67: INT3 ; original byte CC, padding

; FUNCTION thunk_265d68 [0x265d68, 0x265d6c] | file +0x780 | ev_ee7d3692358008761769bce5e91ce6601167a43b7111c85cc4784ff8ad6d3bde
thunk_265d68:
0x265d68: JMP 0x00c16020
; END FUNCTION thunk_265d68
0x265d6d: INT3 ; original byte CC, padding
0x265d6e: INT3 ; original byte CC, padding
0x265d6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d70 [0x265d70, 0x265d74] | file +0x788 | ev_853d03a7b64b35632fb036feb750d9f78ec2536e8b530ba4ab6afc35d8f1d24d
thunk_265d70:
0x265d70: JMP 0x00c16270
; END FUNCTION thunk_265d70
0x265d75: INT3 ; original byte CC, padding
0x265d76: INT3 ; original byte CC, padding
0x265d77: INT3 ; original byte CC, padding

; FUNCTION thunk_265d78 [0x265d78, 0x265d7c] | file +0x790 | ev_470381e6a7ac04b89f9f77aa051e4885ac56ec195c7b436ac9ad7c5e0046851e
thunk_265d78:
0x265d78: JMP 0x00c16720
; END FUNCTION thunk_265d78
0x265d7d: INT3 ; original byte CC, padding
0x265d7e: INT3 ; original byte CC, padding
0x265d7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d80 [0x265d80, 0x265d84] | file +0x798 | ev_b3a359056b1cc38b9cfdd428c2a96dceba507535f64dfe81267ffcc5df21a579
thunk_265d80:
0x265d80: JMP 0x00c16880
; END FUNCTION thunk_265d80
0x265d85: INT3 ; original byte CC, padding
0x265d86: INT3 ; original byte CC, padding
0x265d87: INT3 ; original byte CC, padding

; FUNCTION thunk_265d88 [0x265d88, 0x265d8c] | file +0x7a0 | ev_cda830d9a5b4a90b869dad8f56aaf69560ea49a89ebde10424aa99d79655dcef
thunk_265d88:
0x265d88: JMP 0x00c163d0
; END FUNCTION thunk_265d88
0x265d8d: INT3 ; original byte CC, padding
0x265d8e: INT3 ; original byte CC, padding
0x265d8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d90 [0x265d90, 0x265d94] | file +0x7a8 | ev_4ea4d752366a09794902acd3fe0b4bd1ce883c98227d2b06608bfaf43c6cf3ac
thunk_265d90:
0x265d90: JMP 0x00c164f0
; END FUNCTION thunk_265d90
0x265d95: INT3 ; original byte CC, padding
0x265d96: INT3 ; original byte CC, padding
0x265d97: INT3 ; original byte CC, padding

; FUNCTION thunk_265d98 [0x265d98, 0x265d9c] | file +0x7b0 | ev_67145635d96053dc90aef304f72ee68efa38f57d726896667daf6347ff26cf97
thunk_265d98:
0x265d98: JMP 0x00c165d0
; END FUNCTION thunk_265d98
0x265d9d: INT3 ; original byte CC, padding
0x265d9e: INT3 ; original byte CC, padding
0x265d9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265da0 [0x265da0, 0x265da4] | file +0x7b8 | ev_b269cf020b1a2b49192d23123b900d40fdfd1262e814a7c11b1158bf584f301e
thunk_265da0:
0x265da0: JMP 0x00c16660
; END FUNCTION thunk_265da0
0x265da5: INT3 ; original byte CC, padding
0x265da6: INT3 ; original byte CC, padding
0x265da7: INT3 ; original byte CC, padding

; FUNCTION thunk_265da8 [0x265da8, 0x265dac] | file +0x7c0 | ev_8b66b6a15fdc1e32825941008d7389a84c5f3bfab207a8160af754f27c44ec26
thunk_265da8:
0x265da8: JMP 0x00ac7240
; END FUNCTION thunk_265da8
0x265dad: INT3 ; original byte CC, padding
0x265dae: INT3 ; original byte CC, padding
0x265daf: INT3 ; original byte CC, padding

; FUNCTION thunk_265db0 [0x265db0, 0x265db4] | file +0x7c8 | ev_caa1cbb55e05df95cb7a1c0ce004a24f59594389be3f808e779476ba59b0e12d
thunk_265db0:
0x265db0: JMP 0x00ac73c0
; END FUNCTION thunk_265db0
0x265db5: INT3 ; original byte CC, padding
0x265db6: INT3 ; original byte CC, padding
0x265db7: INT3 ; original byte CC, padding

; FUNCTION thunk_265db8 [0x265db8, 0x265dbc] | file +0x7d0 | ev_f72dc88d903f73c825320375b4c5b23400d62ed612ceea71d002d5806cc18bd5
thunk_265db8:
0x265db8: JMP 0x00abc510
; END FUNCTION thunk_265db8
0x265dbd: INT3 ; original byte CC, padding
0x265dbe: INT3 ; original byte CC, padding
0x265dbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265dc0 [0x265dc0, 0x265dc4] | file +0x7d8 | ev_df8ffb00941eaaf1b014b9d6c1debb830d74d4b57a56dfe8ab7727dd09742b59
thunk_265dc0:
0x265dc0: JMP 0x004f5e60
; END FUNCTION thunk_265dc0
0x265dc5: INT3 ; original byte CC, padding
0x265dc6: INT3 ; original byte CC, padding
0x265dc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265dc8 [0x265dc8, 0x265dcc] | file +0x7e0 | ev_b994f7e6a252748c518087af66f7152ad8d94eabf90061c7d242006164705cd4
thunk_265dc8:
0x265dc8: JMP 0x00602fe0
; END FUNCTION thunk_265dc8
0x265dcd: INT3 ; original byte CC, padding
0x265dce: INT3 ; original byte CC, padding
0x265dcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265dd0 [0x265dd0, 0x265dd4] | file +0x7e8 | ev_b9500ecd1e28f4f0264d22e68110cfb13a646405f1b50760c958118427d85260
thunk_265dd0:
0x265dd0: JMP 0x00603260
; END FUNCTION thunk_265dd0
0x265dd5: INT3 ; original byte CC, padding
0x265dd6: INT3 ; original byte CC, padding
0x265dd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265dd8 [0x265dd8, 0x265ddc] | file +0x7f0 | ev_7425e6bc0085d8c1456a00d22cd5d65cd23b05743dad6a46e24781fb3e860bda
thunk_265dd8:
0x265dd8: JMP 0x006034e0
; END FUNCTION thunk_265dd8
0x265ddd: INT3 ; original byte CC, padding
0x265dde: INT3 ; original byte CC, padding
0x265ddf: INT3 ; original byte CC, padding

; FUNCTION thunk_265de0 [0x265de0, 0x265de4] | file +0x7f8 | ev_c756130153707d47e6f24f71ad62949a6e53f64ef061495df5aa42fa423d1347
thunk_265de0:
0x265de0: JMP 0x00603710
; END FUNCTION thunk_265de0
0x265de5: INT3 ; original byte CC, padding
0x265de6: INT3 ; original byte CC, padding
0x265de7: INT3 ; original byte CC, padding

; FUNCTION thunk_265de8 [0x265de8, 0x265dec] | file +0x800 | ev_dd794267e63b1a5d75db5ef8f5a9ec6ac215c996345f89df19f48e44500dbd91
thunk_265de8:
0x265de8: JMP 0x006039d0
; END FUNCTION thunk_265de8
0x265ded: INT3 ; original byte CC, padding
0x265dee: INT3 ; original byte CC, padding
0x265def: INT3 ; original byte CC, padding

; FUNCTION thunk_265df0 [0x265df0, 0x265df4] | file +0x808 | ev_53445b4101b0607d7f53ee9f9b9f829a516dfcc063bd5e9678540b6141875405
thunk_265df0:
0x265df0: JMP 0x00abac50
; END FUNCTION thunk_265df0
0x265df5: INT3 ; original byte CC, padding
0x265df6: INT3 ; original byte CC, padding
0x265df7: INT3 ; original byte CC, padding

; FUNCTION thunk_265df8 [0x265df8, 0x265dfc] | file +0x810 | ev_9053ea6113d1fcbce07ea7bc6c773a1d6f872daaa256ef7f8d5d773b8df8a05f
thunk_265df8:
0x265df8: JMP 0x008fc610
; END FUNCTION thunk_265df8
0x265dfd: INT3 ; original byte CC, padding
0x265dfe: INT3 ; original byte CC, padding
0x265dff: INT3 ; original byte CC, padding

; FUNCTION thunk_265e00 [0x265e00, 0x265e04] | file +0x818 | ev_2d379c587a389af961b4e370bc502d7a019631a3244916178756499037519ad1
thunk_265e00:
0x265e00: JMP 0x004e1a70
; END FUNCTION thunk_265e00
0x265e05: INT3 ; original byte CC, padding
0x265e06: INT3 ; original byte CC, padding
0x265e07: INT3 ; original byte CC, padding

; FUNCTION thunk_265e08 [0x265e08, 0x265e0c] | file +0x820 | ev_722615ccce74c58107e60906b1e967da2cf0d8bcd78bf5b3a5b0de5a214caa92
thunk_265e08:
0x265e08: JMP 0x00abc5f0
; END FUNCTION thunk_265e08
0x265e0d: INT3 ; original byte CC, padding
0x265e0e: INT3 ; original byte CC, padding
0x265e0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e10 [0x265e10, 0x265e14] | file +0x828 | ev_37aca5cf7d1c28c8bf849e9f04e45dfb04b41d726aaf5258a5d30105bdb04598
thunk_265e10:
0x265e10: JMP 0x00a367e0
; END FUNCTION thunk_265e10
0x265e15: INT3 ; original byte CC, padding
0x265e16: INT3 ; original byte CC, padding
0x265e17: INT3 ; original byte CC, padding

; FUNCTION thunk_265e18 [0x265e18, 0x265e1c] | file +0x830 | ev_43884718e58292c832ea8a998b28d3eebdf76b31de0e8e8b295848bcb18f19c2
thunk_265e18:
0x265e18: JMP 0x00ca0630
; END FUNCTION thunk_265e18
0x265e1d: INT3 ; original byte CC, padding
0x265e1e: INT3 ; original byte CC, padding
0x265e1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e20 [0x265e20, 0x265e24] | file +0x838 | ev_d1bafefb5ca66c2b59f724e32941436f01a1d668cb2dcf44bb98e501c91513bb
thunk_265e20:
0x265e20: JMP 0x00a368e0
; END FUNCTION thunk_265e20
0x265e25: INT3 ; original byte CC, padding
0x265e26: INT3 ; original byte CC, padding
0x265e27: INT3 ; original byte CC, padding

; FUNCTION thunk_265e28 [0x265e28, 0x265e2c] | file +0x840 | ev_76740d04bd0fa44e04809a29e736e4d4de8c1aa42303e07fba3012a1ad03f667
thunk_265e28:
0x265e28: JMP 0x0072ecc0
; END FUNCTION thunk_265e28
0x265e2d: INT3 ; original byte CC, padding
0x265e2e: INT3 ; original byte CC, padding
0x265e2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e30 [0x265e30, 0x265e34] | file +0x848 | ev_5b470392df3096545b35171d8830430e529dc2885ed7fd63673b636ec696f9f9
thunk_265e30:
0x265e30: JMP 0x004f7370
; END FUNCTION thunk_265e30
0x265e35: INT3 ; original byte CC, padding
0x265e36: INT3 ; original byte CC, padding
0x265e37: INT3 ; original byte CC, padding

; FUNCTION thunk_265e38 [0x265e38, 0x265e3c] | file +0x850 | ev_6f9f1ce71e9ea4c394db6586515d83d76fa68b271bc3da58988e7910cbc2fb54
thunk_265e38:
0x265e38: JMP 0x00a36b00
; END FUNCTION thunk_265e38
0x265e3d: INT3 ; original byte CC, padding
0x265e3e: INT3 ; original byte CC, padding
0x265e3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e40 [0x265e40, 0x265e44] | file +0x858 | ev_ef143793367f3451c5a8e0bdc8eb37f1f6c13b48c2e7c0e098d30077555b904d
thunk_265e40:
0x265e40: JMP 0x00a36b90
; END FUNCTION thunk_265e40
0x265e45: INT3 ; original byte CC, padding
0x265e46: INT3 ; original byte CC, padding
0x265e47: INT3 ; original byte CC, padding

; FUNCTION thunk_265e48 [0x265e48, 0x265e4c] | file +0x860 | ev_2f42ab8d4c7f316be09068c535ab8450158592cf54991840e19304610d5a1d07
thunk_265e48:
0x265e48: JMP 0x00abc710
; END FUNCTION thunk_265e48
0x265e4d: INT3 ; original byte CC, padding
0x265e4e: INT3 ; original byte CC, padding
0x265e4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e50 [0x265e50, 0x265e54] | file +0x868 | ev_85c7b01fc12753dce03c87eee1509d51a78a63de5f53132f6e6614707b3c8db5
thunk_265e50:
0x265e50: JMP 0x005a7f60
; END FUNCTION thunk_265e50
0x265e55: INT3 ; original byte CC, padding
0x265e56: INT3 ; original byte CC, padding
0x265e57: INT3 ; original byte CC, padding

; FUNCTION thunk_265e58 [0x265e58, 0x265e5c] | file +0x870 | ev_df8ea304f646c11a583b14aae4ca1a483f4782e1e9354dce034d074761991e9d
thunk_265e58:
0x265e58: JMP 0x00a36bc0
; END FUNCTION thunk_265e58
0x265e5d: INT3 ; original byte CC, padding
0x265e5e: INT3 ; original byte CC, padding
0x265e5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e60 [0x265e60, 0x265e64] | file +0x878 | ev_6198524f60231153a0e06f7b2780b66fc77694781b03b7891c043a5d885ab756
thunk_265e60:
0x265e60: JMP 0x00abca10
; END FUNCTION thunk_265e60
0x265e65: INT3 ; original byte CC, padding
0x265e66: INT3 ; original byte CC, padding
0x265e67: INT3 ; original byte CC, padding

; FUNCTION thunk_265e68 [0x265e68, 0x265e6c] | file +0x880 | ev_8623a41ef8f18a1433f4d8d8d8c4ae56a20bc22464b1afdd5e3060271c537bb3
thunk_265e68:
0x265e68: JMP 0x00abcc00
; END FUNCTION thunk_265e68
0x265e6d: INT3 ; original byte CC, padding
0x265e6e: INT3 ; original byte CC, padding
0x265e6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e70 [0x265e70, 0x265e74] | file +0x888 | ev_4b8b732890c7585fee162dd206d6db0bca27e0c19731e4fc6697ccd7f847c1bf
thunk_265e70:
0x265e70: JMP 0x00438c90
; END FUNCTION thunk_265e70
0x265e75: INT3 ; original byte CC, padding
0x265e76: INT3 ; original byte CC, padding
0x265e77: INT3 ; original byte CC, padding

; FUNCTION thunk_265e78 [0x265e78, 0x265e7c] | file +0x890 | ev_1768279b2851f65325ade262735a2b5161d0b00c0cb0153a8119e17cfac138e3
thunk_265e78:
0x265e78: JMP 0x008d2570
; END FUNCTION thunk_265e78
0x265e7d: INT3 ; original byte CC, padding
0x265e7e: INT3 ; original byte CC, padding
0x265e7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e80 [0x265e80, 0x265e84] | file +0x898 | ev_4d0dc7aa1e73570e5e303d05b62b42265a0a127393c36cc0ffb723f7e92ae586
thunk_265e80:
0x265e80: JMP 0x00abd0f0
; END FUNCTION thunk_265e80
0x265e85: INT3 ; original byte CC, padding
0x265e86: INT3 ; original byte CC, padding
0x265e87: INT3 ; original byte CC, padding

; FUNCTION thunk_265e88 [0x265e88, 0x265e8c] | file +0x8a0 | ev_327b227bd6c213499654b0860aa855d48da53a03261343aaf271ac55682e0e1b
thunk_265e88:
0x265e88: JMP 0x00a37650
; END FUNCTION thunk_265e88
0x265e8d: INT3 ; original byte CC, padding
0x265e8e: INT3 ; original byte CC, padding
0x265e8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e90 [0x265e90, 0x265e94] | file +0x8a8 | ev_c570d0bb05504dfdb65b965e7ab8343f01e31ce22848c7beb6085619a0f039d1
thunk_265e90:
0x265e90: JMP 0x00abd430
; END FUNCTION thunk_265e90
0x265e95: INT3 ; original byte CC, padding
0x265e96: INT3 ; original byte CC, padding
0x265e97: INT3 ; original byte CC, padding

; FUNCTION thunk_265e98 [0x265e98, 0x265e9c] | file +0x8b0 | ev_9f8fcd7e7582e90f4ae8d10d3700626945970635f835f002c08ae61b8aef4e2c
thunk_265e98:
0x265e98: JMP 0x007dcd40
; END FUNCTION thunk_265e98
0x265e9d: INT3 ; original byte CC, padding
0x265e9e: INT3 ; original byte CC, padding
0x265e9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ea0 [0x265ea0, 0x265ea4] | file +0x8b8 | ev_5d32621c61a283e9ed381e98bbdc04f8f8e60e693addd2854e40ea89656581d7
thunk_265ea0:
0x265ea0: JMP 0x008d25a0
; END FUNCTION thunk_265ea0
0x265ea5: INT3 ; original byte CC, padding
0x265ea6: INT3 ; original byte CC, padding
0x265ea7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ea8 [0x265ea8, 0x265eac] | file +0x8c0 | ev_581d77043fca64b9008dbb77b35ef67701738522ff4a29c87647c8175679d453
thunk_265ea8:
0x265ea8: JMP 0x00abd4f0
; END FUNCTION thunk_265ea8
0x265ead: INT3 ; original byte CC, padding
0x265eae: INT3 ; original byte CC, padding
0x265eaf: INT3 ; original byte CC, padding

; FUNCTION thunk_265eb0 [0x265eb0, 0x265eb4] | file +0x8c8 | ev_98633b69352d8d9e092c2f8a57ed6c394087995b60f18753830b9031469b16fb
thunk_265eb0:
0x265eb0: JMP 0x00603c90
; END FUNCTION thunk_265eb0
0x265eb5: INT3 ; original byte CC, padding
0x265eb6: INT3 ; original byte CC, padding
0x265eb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265eb8 [0x265eb8, 0x265ebc] | file +0x8d0 | ev_cab9ba7fa07157798e9f5cadc43dcf8c8285cfde5e57ed64baa9330bdb4b3364
thunk_265eb8:
0x265eb8: JMP 0x00604cf0
; END FUNCTION thunk_265eb8
0x265ebd: INT3 ; original byte CC, padding
0x265ebe: INT3 ; original byte CC, padding
0x265ebf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ec0 [0x265ec0, 0x265ec4] | file +0x8d8 | ev_cac1613c2427686035e9e95ee09e19b96ec40c6b3c8b1ebaece49035e0658fe3
thunk_265ec0:
0x265ec0: JMP 0x004a2850
; END FUNCTION thunk_265ec0
0x265ec5: INT3 ; original byte CC, padding
0x265ec6: INT3 ; original byte CC, padding
0x265ec7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ec8 [0x265ec8, 0x265ecc] | file +0x8e0 | ev_b54802e9cb78880b4fcd87bbbf1e79334bfe9d710c70defaf9d16dcf467d49e5
thunk_265ec8:
0x265ec8: JMP 0x00abd540
; END FUNCTION thunk_265ec8
0x265ecd: INT3 ; original byte CC, padding
0x265ece: INT3 ; original byte CC, padding
0x265ecf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ed0 [0x265ed0, 0x265ed4] | file +0x8e8 | ev_b4dff738d0aa6573e8ba8ee944a868d36f40233c03506de9cd019889e249d2ae
thunk_265ed0:
0x265ed0: JMP 0x0091c640
; END FUNCTION thunk_265ed0
0x265ed5: INT3 ; original byte CC, padding
0x265ed6: INT3 ; original byte CC, padding
0x265ed7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ed8 [0x265ed8, 0x265edc] | file +0x8f0 | ev_2ca4a5aae0e3cb568cb359f5a033eb6c099fe6e02d90047fe6e63bfdb4e4e39a
thunk_265ed8:
0x265ed8: JMP 0x0091cc70
; END FUNCTION thunk_265ed8
0x265edd: INT3 ; original byte CC, padding
0x265ede: INT3 ; original byte CC, padding
0x265edf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ee0 [0x265ee0, 0x265ee4] | file +0x8f8 | ev_d6cb9b9d3c6df35bf074ba1290f1451b1704e84cbd4f89e4635d0a2f9a7f33cf
thunk_265ee0:
0x265ee0: JMP 0x00438e30
; END FUNCTION thunk_265ee0
0x265ee5: INT3 ; original byte CC, padding
0x265ee6: INT3 ; original byte CC, padding
0x265ee7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ee8 [0x265ee8, 0x265eec] | file +0x900 | ev_17e3eae79b71b98f1e0494ebf42f465c42d9d98f8fe67f6e80e7a8148ca93d38
thunk_265ee8:
0x265ee8: JMP 0x00439070
; END FUNCTION thunk_265ee8
0x265eed: INT3 ; original byte CC, padding
0x265eee: INT3 ; original byte CC, padding
0x265eef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ef0 [0x265ef0, 0x265ef4] | file +0x908 | ev_3d7f77fcd4287dd192f950799646d851d1d0457ce890de81f01f63e41251b5ee
thunk_265ef0:
0x265ef0: JMP 0x00439150
; END FUNCTION thunk_265ef0
0x265ef5: INT3 ; original byte CC, padding
0x265ef6: INT3 ; original byte CC, padding
0x265ef7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ef8 [0x265ef8, 0x265efc] | file +0x910 | ev_a4235e90b5a1ccc8ef061ee289bbbd9ef9237b96b7d7228147c2913d89618ad1
thunk_265ef8:
0x265ef8: JMP 0x004393a0
; END FUNCTION thunk_265ef8
0x265efd: INT3 ; original byte CC, padding
0x265efe: INT3 ; original byte CC, padding
0x265eff: INT3 ; original byte CC, padding

; FUNCTION thunk_265f00 [0x265f00, 0x265f04] | file +0x918 | ev_23d77d4e06bbb9201cb88289fdc0b83e75b775d8a447532847bc445292f7ab97
thunk_265f00:
0x265f00: JMP 0x006be4d0
; END FUNCTION thunk_265f00
0x265f05: INT3 ; original byte CC, padding
0x265f06: INT3 ; original byte CC, padding
0x265f07: INT3 ; original byte CC, padding

; FUNCTION thunk_265f08 [0x265f08, 0x265f0c] | file +0x920 | ev_4a3d68654cb86cabcd329a43c71f0fce03f29fb5842108f0b2d34544c0e9902d
thunk_265f08:
0x265f08: JMP 0x00abd930
; END FUNCTION thunk_265f08
0x265f0d: INT3 ; original byte CC, padding
0x265f0e: INT3 ; original byte CC, padding
0x265f0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f10 [0x265f10, 0x265f14] | file +0x928 | ev_660c54ded613992dab25244ea16008eaafa9d5e79b9cf48de63fec28375f1716
thunk_265f10:
0x265f10: JMP 0x006be5c0
; END FUNCTION thunk_265f10
0x265f15: INT3 ; original byte CC, padding
0x265f16: INT3 ; original byte CC, padding
0x265f17: INT3 ; original byte CC, padding

; FUNCTION thunk_265f18 [0x265f18, 0x265f1c] | file +0x930 | ev_15b54fa76534d52deb873287223794be86b404d5facfe580439958524b83ae50
thunk_265f18:
0x265f18: JMP 0x006be800
; END FUNCTION thunk_265f18
0x265f1d: INT3 ; original byte CC, padding
0x265f1e: INT3 ; original byte CC, padding
0x265f1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f20 [0x265f20, 0x265f24] | file +0x938 | ev_afc3f4e0d4ec43c8cc6a116e19a7e52381c8ef5e786ddb343a6f23efaab97fda
thunk_265f20:
0x265f20: JMP 0x00a90e10
; END FUNCTION thunk_265f20
0x265f25: INT3 ; original byte CC, padding
0x265f26: INT3 ; original byte CC, padding
0x265f27: INT3 ; original byte CC, padding

; FUNCTION thunk_265f28 [0x265f28, 0x265f2c] | file +0x940 | ev_9554eb5c1b3cacc00bfb98e60ea7963298dc3f5f36e79f3bc6a971a0cf819738
thunk_265f28:
0x265f28: JMP 0x004a2de0
; END FUNCTION thunk_265f28
0x265f2d: INT3 ; original byte CC, padding
0x265f2e: INT3 ; original byte CC, padding
0x265f2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f30 [0x265f30, 0x265f34] | file +0x948 | ev_166a9b8a86592e83f4fb0f60fcac35a44507e80e51f768c7d42f07b667cfdb97
thunk_265f30:
0x265f30: JMP 0x00abdad0
; END FUNCTION thunk_265f30
0x265f35: INT3 ; original byte CC, padding
0x265f36: INT3 ; original byte CC, padding
0x265f37: INT3 ; original byte CC, padding

; FUNCTION thunk_265f38 [0x265f38, 0x265f3c] | file +0x950 | ev_9d6132a5187a9c01a46635876dc1bcee476c5ffc93037fc4a301ce043d948ba3
thunk_265f38:
0x265f38: JMP 0x00a37660
; END FUNCTION thunk_265f38
0x265f3d: INT3 ; original byte CC, padding
0x265f3e: INT3 ; original byte CC, padding
0x265f3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f40 [0x265f40, 0x265f44] | file +0x958 | ev_3d107f6f1eaf2f4090a9431586134de3e3b751f954de14e4d0a0f6bf88ce19b3
thunk_265f40:
0x265f40: JMP 0x00abe1c0
; END FUNCTION thunk_265f40
0x265f45: INT3 ; original byte CC, padding
0x265f46: INT3 ; original byte CC, padding
0x265f47: INT3 ; original byte CC, padding

; FUNCTION thunk_265f48 [0x265f48, 0x265f4c] | file +0x960 | ev_90e30bd2294293ce2a3416705c0cd745a1d6ba504f8bf45f007ccdacd3dfae05
thunk_265f48:
0x265f48: JMP 0x00abe7b0
; END FUNCTION thunk_265f48
0x265f4d: INT3 ; original byte CC, padding
0x265f4e: INT3 ; original byte CC, padding
0x265f4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f50 [0x265f50, 0x265f54] | file +0x968 | ev_7a6c201331064d4f27c60fe9598670d33c09a953fe0624a08f78c3e1d95d47ae
thunk_265f50:
0x265f50: JMP 0x009f81f0
; END FUNCTION thunk_265f50
0x265f55: INT3 ; original byte CC, padding
0x265f56: INT3 ; original byte CC, padding
0x265f57: INT3 ; original byte CC, padding

; FUNCTION thunk_265f58 [0x265f58, 0x265f5c] | file +0x970 | ev_a1eb78dbbdea733c5de2d066d4df609278988e5e0cd5eb75ce20ed31a730dfcc
thunk_265f58:
0x265f58: JMP 0x00be9510
; END FUNCTION thunk_265f58
0x265f5d: INT3 ; original byte CC, padding
0x265f5e: INT3 ; original byte CC, padding
0x265f5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f60 [0x265f60, 0x265f64] | file +0x978 | ev_3ce5dde8008e04c265e5bf4d50b808fd7dde164f1b953bc506e8957fea941364
thunk_265f60:
0x265f60: JMP 0x009a7d10
; END FUNCTION thunk_265f60
0x265f65: INT3 ; original byte CC, padding
0x265f66: INT3 ; original byte CC, padding
0x265f67: INT3 ; original byte CC, padding

; FUNCTION thunk_265f68 [0x265f68, 0x265f6c] | file +0x980 | ev_30fb1503914bfcc9ed442526904c06863c13c21f71c813cb207a809a8b26e288
thunk_265f68:
0x265f68: JMP 0x009a9560
; END FUNCTION thunk_265f68
0x265f6d: INT3 ; original byte CC, padding
0x265f6e: INT3 ; original byte CC, padding
0x265f6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f70 [0x265f70, 0x265f74] | file +0x988 | ev_5a722f62fadb8a29429713bcc4bb02986a139904c60356d3956a39654cd442c6
thunk_265f70:
0x265f70: JMP 0x009a9e10
; END FUNCTION thunk_265f70
0x265f75: INT3 ; original byte CC, padding
0x265f76: INT3 ; original byte CC, padding
0x265f77: INT3 ; original byte CC, padding

; FUNCTION thunk_265f78 [0x265f78, 0x265f7c] | file +0x990 | ev_bcf43827b5c2e17a463acbcf525c45f60b468982552d619865a6bfe7665a37ba
thunk_265f78:
0x265f78: JMP 0x009a9f40
; END FUNCTION thunk_265f78
0x265f7d: INT3 ; original byte CC, padding
0x265f7e: INT3 ; original byte CC, padding
0x265f7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f80 [0x265f80, 0x265f84] | file +0x998 | ev_dd33df4d2f9001ee6ac780697739b18182526436a92e50b0414b4999641f292f
thunk_265f80:
0x265f80: JMP 0x008fb440
; END FUNCTION thunk_265f80
0x265f85: INT3 ; original byte CC, padding
0x265f86: INT3 ; original byte CC, padding
0x265f87: INT3 ; original byte CC, padding

; FUNCTION thunk_265f88 [0x265f88, 0x265f8c] | file +0x9a0 | ev_ba2dc3f034d56072bd875df79ad909a59c7c7208e8624ef6ffed97aa89dffa93
thunk_265f88:
0x265f88: JMP 0x004a31a0
; END FUNCTION thunk_265f88
0x265f8d: INT3 ; original byte CC, padding
0x265f8e: INT3 ; original byte CC, padding
0x265f8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f90 [0x265f90, 0x265f94] | file +0x9a8 | ev_095469638dfbce825802a80d7715201dbce0a7c679a97b6a1a02cf82121354f8
thunk_265f90:
0x265f90: JMP 0x00abe8b0
; END FUNCTION thunk_265f90
0x265f95: INT3 ; original byte CC, padding
0x265f96: INT3 ; original byte CC, padding
0x265f97: INT3 ; original byte CC, padding

; FUNCTION thunk_265f98 [0x265f98, 0x265f9c] | file +0x9b0 | ev_fb01c7296a796c2556b1d847b82e434772757b61df9e17d6c416e7579607cada
thunk_265f98:
0x265f98: JMP 0x009ab1f0
; END FUNCTION thunk_265f98
0x265f9d: INT3 ; original byte CC, padding
0x265f9e: INT3 ; original byte CC, padding
0x265f9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa0 [0x265fa0, 0x265fa4] | file +0x9b8 | ev_a2e5f09fdea58579b0b34f882641d1c11784819e6375326f32636cf81033081a
thunk_265fa0:
0x265fa0: JMP 0x00abb980
; END FUNCTION thunk_265fa0
0x265fa5: INT3 ; original byte CC, padding
0x265fa6: INT3 ; original byte CC, padding
0x265fa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa8 [0x265fa8, 0x265fac] | file +0x9c0 | ev_007d1966682d3fb2830ab3ff5fd5f30a8b0c7a994a7cf0ab704ace1290990328
thunk_265fa8:
0x265fa8: JMP 0x006f92e0
; END FUNCTION thunk_265fa8
0x265fad: INT3 ; original byte CC, padding
0x265fae: INT3 ; original byte CC, padding
0x265faf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb0 [0x265fb0, 0x265fb4] | file +0x9c8 | ev_b5e3fe99e245a1f4fcac38bb44ae8ede96ce62ba89baa6e030602ac74cd4e2aa
thunk_265fb0:
0x265fb0: JMP 0x00434da0
; END FUNCTION thunk_265fb0
0x265fb5: INT3 ; original byte CC, padding
0x265fb6: INT3 ; original byte CC, padding
0x265fb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb8 [0x265fb8, 0x265fbc] | file +0x9d0 | ev_7672c80ba3199670ff9accf5f0a035019deb6746b16a3408477b03c96a6c5a59
thunk_265fb8:
0x265fb8: JMP 0x00434db0
; END FUNCTION thunk_265fb8
0x265fbd: INT3 ; original byte CC, padding
0x265fbe: INT3 ; original byte CC, padding
0x265fbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc0 [0x265fc0, 0x265fc4] | file +0x9d8 | ev_8e2240493a12bdc4b99dadf1ed7df42990082653e92f2ff14062831045d343e0
thunk_265fc0:
0x265fc0: JMP 0x00434dc0
; END FUNCTION thunk_265fc0
0x265fc5: INT3 ; original byte CC, padding
0x265fc6: INT3 ; original byte CC, padding
0x265fc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc8 [0x265fc8, 0x265fcc] | file +0x9e0 | ev_5bc36022326d27a478db45be2056e64d81fcc7129c079daca457659d2408596e
thunk_265fc8:
0x265fc8: JMP 0x00437d90
; END FUNCTION thunk_265fc8
0x265fcd: INT3 ; original byte CC, padding
0x265fce: INT3 ; original byte CC, padding
0x265fcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd0 [0x265fd0, 0x265fd4] | file +0x9e8 | ev_085d5e1e35ff8b5e66880ad7c2e04e4467175a4f31f04ebb7d9393cf13d3f1b3
thunk_265fd0:
0x265fd0: JMP 0x00438280
; END FUNCTION thunk_265fd0
0x265fd5: INT3 ; original byte CC, padding
0x265fd6: INT3 ; original byte CC, padding
0x265fd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd8 [0x265fd8, 0x265fdc] | file +0x9f0 | ev_4c12611f4973bb95e6930c4a8e7ef5dbbee03d57b570547f98eb8d209fab5390
thunk_265fd8:
0x265fd8: JMP 0x00ae6690
; END FUNCTION thunk_265fd8
0x265fdd: INT3 ; original byte CC, padding
0x265fde: INT3 ; original byte CC, padding
0x265fdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe0 [0x265fe0, 0x265fe4] | file +0x9f8 | ev_bf6dcc0bad4786ad10277760d33efbdb7edba577f48cb79630de67009f81ffcf
thunk_265fe0:
0x265fe0: JMP 0x00ae6580
; END FUNCTION thunk_265fe0
0x265fe5: INT3 ; original byte CC, padding
0x265fe6: INT3 ; original byte CC, padding
0x265fe7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe8 [0x265fe8, 0x265fec] | file +0xa00 | ev_71ecfb830571598653e281d3aff5b493d821d784e85e4c6587c26283338629ed
thunk_265fe8:
0x265fe8: JMP 0x004490d0
; END FUNCTION thunk_265fe8
0x265fed: INT3 ; original byte CC, padding
0x265fee: INT3 ; original byte CC, padding
0x265fef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff0 [0x265ff0, 0x265ff4] | file +0xa08 | ev_20d51f9828264b13131e9cc56afd8f93012bd4f3f0874f592b9469011c13f2d0
thunk_265ff0:
0x265ff0: JMP 0x000a6dc0
; END FUNCTION thunk_265ff0
0x265ff5: INT3 ; original byte CC, padding
0x265ff6: INT3 ; original byte CC, padding
0x265ff7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff8 [0x265ff8, 0x265ffc] | file +0xa10 | ev_beeb742ebbf9feeea40159b7e4e9da77f11e0cb72de20fa239ab2205a287db21
thunk_265ff8:
0x265ff8: JMP 0x0044aa70
; END FUNCTION thunk_265ff8
0x265ffd: INT3 ; original byte CC, padding
0x265ffe: INT3 ; original byte CC, padding
0x265fff: INT3 ; original byte CC, padding

; FUNCTION thunk_266000 [0x266000, 0x266004] | file +0xa18 | ev_13271d488428427b098ed29297bd6f0d51a9592c4538b98664e46709e6fc2237
thunk_266000:
0x266000: JMP 0x009b6110
; END FUNCTION thunk_266000
0x266005: INT3 ; original byte CC, padding
0x266006: INT3 ; original byte CC, padding
0x266007: INT3 ; original byte CC, padding

; FUNCTION thunk_266008 [0x266008, 0x26600c] | file +0xa20 | ev_75bd3fb8ec5fe183e20e5f97247dd25019c7d16cd04af1302ee4213661395ea0
thunk_266008:
0x266008: JMP 0x000a7670
; END FUNCTION thunk_266008
0x26600d: INT3 ; original byte CC, padding
0x26600e: INT3 ; original byte CC, padding
0x26600f: INT3 ; original byte CC, padding

; FUNCTION thunk_266010 [0x266010, 0x266014] | file +0xa28 | ev_9241eefa311a80deb03ac0f658ff745e258a28a4f5240ccd14c8c8025756bf71
thunk_266010:
0x266010: JMP 0x000a7850
; END FUNCTION thunk_266010
0x266015: INT3 ; original byte CC, padding
0x266016: INT3 ; original byte CC, padding
0x266017: INT3 ; original byte CC, padding

; FUNCTION thunk_266018 [0x266018, 0x26601c] | file +0xa30 | ev_77e192304c9e51060989921f10742631b6c86945dea766a66cde5a5603ae5a03
thunk_266018:
0x266018: JMP 0x000a7880
; END FUNCTION thunk_266018
0x26601d: INT3 ; original byte CC, padding
0x26601e: INT3 ; original byte CC, padding
0x26601f: INT3 ; original byte CC, padding

; FUNCTION thunk_266020 [0x266020, 0x266024] | file +0xa38 | ev_08817f0e48324fa1734eebf5afd693d461d4f25faa9a57614305dbeec79fe7c5
thunk_266020:
0x266020: JMP 0x00452040
; END FUNCTION thunk_266020
0x266025: INT3 ; original byte CC, padding
0x266026: INT3 ; original byte CC, padding
0x266027: INT3 ; original byte CC, padding

; FUNCTION thunk_266028 [0x266028, 0x26602c] | file +0xa40 | ev_1e5a04d67b16d2fa526870e464a7a9b92615f08e45de21b528d6a0e169950e95
thunk_266028:
0x266028: JMP 0x00454cc0
; END FUNCTION thunk_266028
0x26602d: INT3 ; original byte CC, padding
0x26602e: INT3 ; original byte CC, padding
0x26602f: INT3 ; original byte CC, padding

; FUNCTION thunk_266030 [0x266030, 0x266034] | file +0xa48 | ev_cc10ac34cdc34cc724edd95074b755226bea7e251a7b28ab616c70c7e7e3b6f6
thunk_266030:
0x266030: JMP 0x00457820
; END FUNCTION thunk_266030
0x266035: INT3 ; original byte CC, padding
0x266036: INT3 ; original byte CC, padding
0x266037: INT3 ; original byte CC, padding

; FUNCTION thunk_266038 [0x266038, 0x26603c] | file +0xa50 | ev_67aa9e5fd76f1c965fc090011e512499a3a3b198c77aab350e1d0473784fea18
thunk_266038:
0x266038: JMP 0x0046df70
; END FUNCTION thunk_266038
0x26603d: INT3 ; original byte CC, padding
0x26603e: INT3 ; original byte CC, padding
0x26603f: INT3 ; original byte CC, padding

; FUNCTION thunk_266040 [0x266040, 0x266044] | file +0xa58 | ev_0284f5842ab359d45c0563372236b145cdde7902ac94bd430f6a223a9830dcd7
thunk_266040:
0x266040: JMP 0x0046e080
; END FUNCTION thunk_266040
0x266045: INT3 ; original byte CC, padding
0x266046: INT3 ; original byte CC, padding
0x266047: INT3 ; original byte CC, padding

; FUNCTION thunk_266048 [0x266048, 0x26604c] | file +0xa60 | ev_274829a26a30245653849082cc72e6e35fed236ce0bbdb3ec6faab0eada81538
thunk_266048:
0x266048: JMP 0x00472990
; END FUNCTION thunk_266048
0x26604d: INT3 ; original byte CC, padding
0x26604e: INT3 ; original byte CC, padding
0x26604f: INT3 ; original byte CC, padding

; FUNCTION thunk_266050 [0x266050, 0x266054] | file +0xa68 | ev_ba4f7a680946cc24f7d64ad866a978721163a825432c7cf1640b506b2eb8784d
thunk_266050:
0x266050: JMP 0x004733b0
; END FUNCTION thunk_266050
0x266055: INT3 ; original byte CC, padding
0x266056: INT3 ; original byte CC, padding
0x266057: INT3 ; original byte CC, padding

; FUNCTION thunk_266058 [0x266058, 0x26605c] | file +0xa70 | ev_8d6f5eab901c31a67905fdcd53e3dc1c0fbc315b09039f6f12e50ade27b3174e
thunk_266058:
0x266058: JMP 0x004738b0
; END FUNCTION thunk_266058
0x26605d: INT3 ; original byte CC, padding
0x26605e: INT3 ; original byte CC, padding
0x26605f: INT3 ; original byte CC, padding

; FUNCTION thunk_266060 [0x266060, 0x266064] | file +0xa78 | ev_e8b4123b0dba35e5d807682900886d6e11de80f9778dd14c6f7aaba6269b6938
thunk_266060:
0x266060: JMP 0x00474250
; END FUNCTION thunk_266060
0x266065: INT3 ; original byte CC, padding
0x266066: INT3 ; original byte CC, padding
0x266067: INT3 ; original byte CC, padding

; FUNCTION thunk_266068 [0x266068, 0x26606c] | file +0xa80 | ev_f75afc0429bb5c477bea05f362dc59833ce7113d6a65211ba6ab62563bdc61ad
thunk_266068:
0x266068: JMP 0x00474db0
; END FUNCTION thunk_266068
0x26606d: INT3 ; original byte CC, padding
0x26606e: INT3 ; original byte CC, padding
0x26606f: INT3 ; original byte CC, padding

; FUNCTION thunk_266070 [0x266070, 0x266074] | file +0xa88 | ev_f2aa6b1b31f49271e828c16308725efe4f855d10cb85de9cff13f6cdbda35fb3
thunk_266070:
0x266070: JMP 0x0047cff0
; END FUNCTION thunk_266070
0x266075: INT3 ; original byte CC, padding
0x266076: INT3 ; original byte CC, padding
0x266077: INT3 ; original byte CC, padding

; FUNCTION thunk_266078 [0x266078, 0x26607c] | file +0xa90 | ev_51642329c1bbde0e93e8dec02d8735898e1286b91137062d76126033999a3d32
thunk_266078:
0x266078: JMP 0x0021dff0
; END FUNCTION thunk_266078
0x26607d: INT3 ; original byte CC, padding
0x26607e: INT3 ; original byte CC, padding
0x26607f: INT3 ; original byte CC, padding

; FUNCTION thunk_266080 [0x266080, 0x266084] | file +0xa98 | ev_813edcb664f5a4436816b054fe42fdbf47ba1bcffa004d50477f7cf091d814be
thunk_266080:
0x266080: JMP 0x00490300
; END FUNCTION thunk_266080
0x266085: INT3 ; original byte CC, padding
0x266086: INT3 ; original byte CC, padding
0x266087: INT3 ; original byte CC, padding

; FUNCTION thunk_266088 [0x266088, 0x26608c] | file +0xaa0 | ev_bb9d9eb4c7788123aa96c895346d74ee3fcfb19ec4015518bd51902322271c89
thunk_266088:
0x266088: JMP 0x00490db0
; END FUNCTION thunk_266088
0x26608d: INT3 ; original byte CC, padding
0x26608e: INT3 ; original byte CC, padding
0x26608f: INT3 ; original byte CC, padding

; FUNCTION thunk_266090 [0x266090, 0x266094] | file +0xaa8 | ev_5f37661cb7d598c9dc86a7cefc47d3cf985f370da26ca037d619cb73a5ca4b8e
thunk_266090:
0x266090: JMP 0x00497fb0
; END FUNCTION thunk_266090
0x266095: INT3 ; original byte CC, padding
0x266096: INT3 ; original byte CC, padding
0x266097: INT3 ; original byte CC, padding

; FUNCTION thunk_266098 [0x266098, 0x26609c] | file +0xab0 | ev_228fbdbd5af4919e2970004de3681f60847a1febed9f5d2595709cbb8462d11b
thunk_266098:
0x266098: JMP 0x00497fe0
; END FUNCTION thunk_266098
0x26609d: INT3 ; original byte CC, padding
0x26609e: INT3 ; original byte CC, padding
0x26609f: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a0 [0x2660a0, 0x2660a4] | file +0xab8 | ev_ed6831e278bd783f3be5cb487656b3e4fbd09e14c5253eef5c2f3bd4fd69d74e
thunk_2660a0:
0x2660a0: JMP 0x00498630
; END FUNCTION thunk_2660a0
0x2660a5: INT3 ; original byte CC, padding
0x2660a6: INT3 ; original byte CC, padding
0x2660a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a8 [0x2660a8, 0x2660ac] | file +0xac0 | ev_c8ed06089cd894204da39e1cac0194ac9499dfa20bfb4873e4db9564a46f5e29
thunk_2660a8:
0x2660a8: JMP 0x00498640
; END FUNCTION thunk_2660a8
0x2660ad: INT3 ; original byte CC, padding
0x2660ae: INT3 ; original byte CC, padding
0x2660af: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b0 [0x2660b0, 0x2660b4] | file +0xac8 | ev_2504a752eb3543760284d7669f69d99c6776905f0b697402ee78f8025cb45d24
thunk_2660b0:
0x2660b0: JMP 0x008f7bc0
; END FUNCTION thunk_2660b0
0x2660b5: INT3 ; original byte CC, padding
0x2660b6: INT3 ; original byte CC, padding
0x2660b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b8 [0x2660b8, 0x2660bc] | file +0xad0 | ev_e75168b4c23bf70efaf2133494a544d5d58e397acbb367674bb96a93020a891b
thunk_2660b8:
0x2660b8: JMP 0x008f6800
; END FUNCTION thunk_2660b8
0x2660bd: INT3 ; original byte CC, padding
0x2660be: INT3 ; original byte CC, padding
0x2660bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c0 [0x2660c0, 0x2660c4] | file +0xad8 | ev_da7e97c369a81ea579dcdd4063c45b34ce659b954f7474a798c98d18f5072f48
thunk_2660c0:
0x2660c0: JMP 0x008f7420
; END FUNCTION thunk_2660c0
0x2660c5: INT3 ; original byte CC, padding
0x2660c6: INT3 ; original byte CC, padding
0x2660c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c8 [0x2660c8, 0x2660cc] | file +0xae0 | ev_757ca60740b8f73bb6ff2a575203849b790702722e8d4687c36fb07a63dc9d6a
thunk_2660c8:
0x2660c8: JMP 0x008f9f80
; END FUNCTION thunk_2660c8
0x2660cd: INT3 ; original byte CC, padding
0x2660ce: INT3 ; original byte CC, padding
0x2660cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d0 [0x2660d0, 0x2660d4] | file +0xae8 | ev_b14e0cde435fef81d6524b07ab25a64c832dfa4e07ec4813d36cb68c5a2542e6
thunk_2660d0:
0x2660d0: JMP 0x005df350
; END FUNCTION thunk_2660d0
0x2660d5: INT3 ; original byte CC, padding
0x2660d6: INT3 ; original byte CC, padding
0x2660d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d8 [0x2660d8, 0x2660dc] | file +0xaf0 | ev_695ca4375c51c495d91c54720b2ee5edbe4646386d7bdf42b6f1f7f1096ab7aa
thunk_2660d8:
0x2660d8: JMP 0x005df820
; END FUNCTION thunk_2660d8
0x2660dd: INT3 ; original byte CC, padding
0x2660de: INT3 ; original byte CC, padding
0x2660df: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e0 [0x2660e0, 0x2660e4] | file +0xaf8 | ev_7b89d84bc17a972cb085dda05242e82715a0d3c4e9b5c80e1d1a10d3cf703d8e
thunk_2660e0:
0x2660e0: JMP 0x00a34ce0
; END FUNCTION thunk_2660e0
0x2660e5: INT3 ; original byte CC, padding
0x2660e6: INT3 ; original byte CC, padding
0x2660e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e8 [0x2660e8, 0x2660ec] | file +0xb00 | ev_e88176bc6d92c2a8a7349783a3ea17eb1596a47cc8519ecba94f4b20c0525334
thunk_2660e8:
0x2660e8: JMP 0x005e84a0
; END FUNCTION thunk_2660e8
0x2660ed: INT3 ; original byte CC, padding
0x2660ee: INT3 ; original byte CC, padding
0x2660ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f0 [0x2660f0, 0x2660f4] | file +0xb08 | ev_338488211248baab7b79b0818ed3b67f3ca1443ece0ee1265a6eecf7dd0d3ecd
thunk_2660f0:
0x2660f0: JMP 0x008f81f0
; END FUNCTION thunk_2660f0
0x2660f5: INT3 ; original byte CC, padding
0x2660f6: INT3 ; original byte CC, padding
0x2660f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f8 [0x2660f8, 0x2660fc] | file +0xb10 | ev_7967a6f62a6c6d7ec9772ad9b5eac8becd562619cecab980b52874d1b54dca4b
thunk_2660f8:
0x2660f8: JMP 0x008f9410
; END FUNCTION thunk_2660f8
0x2660fd: INT3 ; original byte CC, padding
0x2660fe: INT3 ; original byte CC, padding
0x2660ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266100 [0x266100, 0x266104] | file +0xb18 | ev_849951bba96cef9609da76002488e8a1d20f07ec9230cefd95bfb3ad861b36a1
thunk_266100:
0x266100: JMP 0x008fc3f0
; END FUNCTION thunk_266100
0x266105: INT3 ; original byte CC, padding
0x266106: INT3 ; original byte CC, padding
0x266107: INT3 ; original byte CC, padding

; FUNCTION thunk_266108 [0x266108, 0x26610c] | file +0xb20 | ev_1e6da3dff07fe59402a80c14648d04826df148070707dd9c0ef6a4e1fd74fafd
thunk_266108:
0x266108: JMP 0x008f6c90
; END FUNCTION thunk_266108
0x26610d: INT3 ; original byte CC, padding
0x26610e: INT3 ; original byte CC, padding
0x26610f: INT3 ; original byte CC, padding

; FUNCTION thunk_266110 [0x266110, 0x266114] | file +0xb28 | ev_d2c807990d94f945e00cd701e68c26292cb1e2009d73f8f84b655ea38e88c052
thunk_266110:
0x266110: JMP 0x00cb1a10
; END FUNCTION thunk_266110
0x266115: INT3 ; original byte CC, padding
0x266116: INT3 ; original byte CC, padding
0x266117: INT3 ; original byte CC, padding

; FUNCTION thunk_266118 [0x266118, 0x26611c] | file +0xb30 | ev_53472b939b20ba25a57ab4d91660139c63e4a4ba8839cddb43837794fa57e6e5
thunk_266118:
0x266118: JMP 0x00ab83a0
; END FUNCTION thunk_266118
0x26611d: INT3 ; original byte CC, padding
0x26611e: INT3 ; original byte CC, padding
0x26611f: INT3 ; original byte CC, padding

; FUNCTION thunk_266120 [0x266120, 0x266124] | file +0xb38 | ev_e3874429a2cd73930fad18d5594175104a6647df9411fdc9fdaba20f544869ac
thunk_266120:
0x266120: JMP 0x00ab83b0
; END FUNCTION thunk_266120
0x266125: INT3 ; original byte CC, padding
0x266126: INT3 ; original byte CC, padding
0x266127: INT3 ; original byte CC, padding

; FUNCTION thunk_266128 [0x266128, 0x26612c] | file +0xb40 | ev_9c8c416f951cb9e26ea8daf6254d67a2a2cb5f1e29a81b93155052ba74848071
thunk_266128:
0x266128: JMP 0x008fa1c0
; END FUNCTION thunk_266128
0x26612d: INT3 ; original byte CC, padding
0x26612e: INT3 ; original byte CC, padding
0x26612f: INT3 ; original byte CC, padding

; FUNCTION thunk_266130 [0x266130, 0x266134] | file +0xb48 | ev_f75fd383e35d1954533ca22638803f3c72f6a82546cd3a8ceccad79fa1daf4b7
thunk_266130:
0x266130: JMP 0x008f7b40
; END FUNCTION thunk_266130
0x266135: INT3 ; original byte CC, padding
0x266136: INT3 ; original byte CC, padding
0x266137: INT3 ; original byte CC, padding

; FUNCTION thunk_266138 [0x266138, 0x26613c] | file +0xb50 | ev_8207120065dabc5b19c2f962cda8ae9f598c7325173c735e6d269bcccae85a15
thunk_266138:
0x266138: JMP 0x004a0960
; END FUNCTION thunk_266138
0x26613d: INT3 ; original byte CC, padding
0x26613e: INT3 ; original byte CC, padding
0x26613f: INT3 ; original byte CC, padding

; FUNCTION thunk_266140 [0x266140, 0x266144] | file +0xb58 | ev_6d7cc7b56a7cd224e4e1ca39aa3c2a2d97be8d247b1b879fbe064c464bd07514
thunk_266140:
0x266140: JMP 0x00729780
; END FUNCTION thunk_266140
0x266145: INT3 ; original byte CC, padding
0x266146: INT3 ; original byte CC, padding
0x266147: INT3 ; original byte CC, padding

; FUNCTION thunk_266148 [0x266148, 0x26614c] | file +0xb60 | ev_62c7b086c5573b195bb72867047d219ff493c01e81f65173fdda18ed43941bca
thunk_266148:
0x266148: JMP 0x00729790
; END FUNCTION thunk_266148
0x26614d: INT3 ; original byte CC, padding
0x26614e: INT3 ; original byte CC, padding
0x26614f: INT3 ; original byte CC, padding

; FUNCTION thunk_266150 [0x266150, 0x266154] | file +0xb68 | ev_efe9729a0a63c617fe6c009276ba9db0563058f4462ea9ff1bd507ed71a70a62
thunk_266150:
0x266150: JMP 0x007297a0
; END FUNCTION thunk_266150
0x266155: INT3 ; original byte CC, padding
0x266156: INT3 ; original byte CC, padding
0x266157: INT3 ; original byte CC, padding

; FUNCTION thunk_266158 [0x266158, 0x26615c] | file +0xb70 | ev_b0621322d51d31fb36c314eb23a97a956aceffc0a88da9f9970a8a68d289a159
thunk_266158:
0x266158: JMP 0x006bb590
; END FUNCTION thunk_266158
0x26615d: INT3 ; original byte CC, padding
0x26615e: INT3 ; original byte CC, padding
0x26615f: INT3 ; original byte CC, padding

; FUNCTION thunk_266160 [0x266160, 0x266164] | file +0xb78 | ev_fcc1bfa009ab0ece3e52445710d3c3b56a294709c05cf127ebc6989ec52073a0
thunk_266160:
0x266160: JMP 0x00ab8da0
; END FUNCTION thunk_266160
0x266165: INT3 ; original byte CC, padding
0x266166: INT3 ; original byte CC, padding
0x266167: INT3 ; original byte CC, padding

; FUNCTION thunk_266168 [0x266168, 0x26616c] | file +0xb80 | ev_85fe954f6e700c0007bf50bcb5abe7fa8945362eb645e2117df19c1cb45cfd0f
thunk_266168:
0x266168: JMP 0x008fa170
; END FUNCTION thunk_266168
0x26616d: INT3 ; original byte CC, padding
0x26616e: INT3 ; original byte CC, padding
0x26616f: INT3 ; original byte CC, padding

; FUNCTION thunk_266170 [0x266170, 0x266174] | file +0xb88 | ev_c890e498bbcc6f8ac6e3e30792c03ca2289ba3e9f242a390489aa6aea5228cf5
thunk_266170:
0x266170: JMP 0x00b7f0c0
; END FUNCTION thunk_266170
0x266175: INT3 ; original byte CC, padding
0x266176: INT3 ; original byte CC, padding
0x266177: INT3 ; original byte CC, padding

; FUNCTION thunk_266178 [0x266178, 0x26617c] | file +0xb90 | ev_e1430f65ea8ac5404922d82f740706346a0b3b614afea6cb0d6d4ab94bd94f4d
thunk_266178:
0x266178: JMP 0x00b7f100
; END FUNCTION thunk_266178
0x26617d: INT3 ; original byte CC, padding
0x26617e: INT3 ; original byte CC, padding
0x26617f: INT3 ; original byte CC, padding

; FUNCTION thunk_266180 [0x266180, 0x266184] | file +0xb98 | ev_fd48f8dae2e01b6715b9a25b9598a63851195089c4d557d8e15a01f560b938a8
thunk_266180:
0x266180: JMP 0x008f9cf0
; END FUNCTION thunk_266180
0x266185: INT3 ; original byte CC, padding
0x266186: INT3 ; original byte CC, padding
0x266187: INT3 ; original byte CC, padding

; FUNCTION thunk_266188 [0x266188, 0x26618c] | file +0xba0 | ev_544cba46ca25c52016b06b1336491047811985c85719c88aca599bb88ca2fe9e
thunk_266188:
0x266188: JMP 0x008fa740
; END FUNCTION thunk_266188
0x26618d: INT3 ; original byte CC, padding
0x26618e: INT3 ; original byte CC, padding
0x26618f: INT3 ; original byte CC, padding

; FUNCTION thunk_266190 [0x266190, 0x266194] | file +0xba8 | ev_c59a83c527ec2c14aefac1b9685ab1f5033a1302df2ae7c904635b8c49564da7
thunk_266190:
0x266190: JMP 0x00552b70
; END FUNCTION thunk_266190
0x266195: INT3 ; original byte CC, padding
0x266196: INT3 ; original byte CC, padding
0x266197: INT3 ; original byte CC, padding

; FUNCTION thunk_266198 [0x266198, 0x26619c] | file +0xbb0 | ev_48793e7f58ef9e0f869d5bf7e4197a1365c5204a853d9f6e86f272e062ecad5f
thunk_266198:
0x266198: JMP 0x00552bf0
; END FUNCTION thunk_266198
0x26619d: INT3 ; original byte CC, padding
0x26619e: INT3 ; original byte CC, padding
0x26619f: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a0 [0x2661a0, 0x2661a4] | file +0xbb8 | ev_21f6a74ead4cf7febff2d4196b2a7986d4cd72a85ab83c1e027b9eb014c9db41
thunk_2661a0:
0x2661a0: JMP 0x00552c50
; END FUNCTION thunk_2661a0
0x2661a5: INT3 ; original byte CC, padding
0x2661a6: INT3 ; original byte CC, padding
0x2661a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a8 [0x2661a8, 0x2661ac] | file +0xbc0 | ev_08c7efec6159a4231f725feeb2ae4667652444949af05bfad614ed486cc10726
thunk_2661a8:
0x2661a8: JMP 0x00552c80
; END FUNCTION thunk_2661a8
0x2661ad: INT3 ; original byte CC, padding
0x2661ae: INT3 ; original byte CC, padding
0x2661af: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b0 [0x2661b0, 0x2661b4] | file +0xbc8 | ev_e62aa65b183e4f6ea7ab3b5cd9bfe757dfa71a58a3191566234425bdfd6b468c
thunk_2661b0:
0x2661b0: JMP 0x00552cb0
; END FUNCTION thunk_2661b0
0x2661b5: INT3 ; original byte CC, padding
0x2661b6: INT3 ; original byte CC, padding
0x2661b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b8 [0x2661b8, 0x2661bc] | file +0xbd0 | ev_59a4649b3a618147c0f8e7d991262dccbb38b62bab46745d9dc86f95ee01c0f8
thunk_2661b8:
0x2661b8: JMP 0x00552ce0
; END FUNCTION thunk_2661b8
0x2661bd: INT3 ; original byte CC, padding
0x2661be: INT3 ; original byte CC, padding
0x2661bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c0 [0x2661c0, 0x2661c4] | file +0xbd8 | ev_6ab3dee911315061b49dc3807ba7a64a017fe2ef5e7edcc67e0a8b25af23a042
thunk_2661c0:
0x2661c0: JMP 0x00b7e800
; END FUNCTION thunk_2661c0
0x2661c5: INT3 ; original byte CC, padding
0x2661c6: INT3 ; original byte CC, padding
0x2661c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c8 [0x2661c8, 0x2661cc] | file +0xbe0 | ev_255f396dca8f49de3450f7d86252eaee6b5c42959e9628c715fbd35c890e38e7
thunk_2661c8:
0x2661c8: JMP 0x00b7ebe0
; END FUNCTION thunk_2661c8
0x2661cd: INT3 ; original byte CC, padding
0x2661ce: INT3 ; original byte CC, padding
0x2661cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d0 [0x2661d0, 0x2661d4] | file +0xbe8 | ev_c9d1cac1498546eeeab2fce1f6faafc853cb664e949cc88c10d0bee8e3abeb57
thunk_2661d0:
0x2661d0: JMP 0x00b7ef70
; END FUNCTION thunk_2661d0
0x2661d5: INT3 ; original byte CC, padding
0x2661d6: INT3 ; original byte CC, padding
0x2661d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d8 [0x2661d8, 0x2661dc] | file +0xbf0 | ev_0b00bb178d5769719b66fc3253ea231d0f2d95e28ca0c9c7dde96e4f42e76c33
thunk_2661d8:
0x2661d8: JMP 0x00c06d30
; END FUNCTION thunk_2661d8
0x2661dd: INT3 ; original byte CC, padding
0x2661de: INT3 ; original byte CC, padding
0x2661df: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e0 [0x2661e0, 0x2661e4] | file +0xbf8 | ev_498718fb310bd1eb2b790209f3a3d38511b8173ce987d8063b228403a1c56ad7
thunk_2661e0:
0x2661e0: JMP 0x00792690
; END FUNCTION thunk_2661e0
0x2661e5: INT3 ; original byte CC, padding
0x2661e6: INT3 ; original byte CC, padding
0x2661e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e8 [0x2661e8, 0x2661ec] | file +0xc00 | ev_8a8290c5607724f7392ee63f16aadf7e18422517ed6a4e904e9edc27d524cc6b
thunk_2661e8:
0x2661e8: JMP 0x005e8b20
; END FUNCTION thunk_2661e8
0x2661ed: INT3 ; original byte CC, padding
0x2661ee: INT3 ; original byte CC, padding
0x2661ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f0 [0x2661f0, 0x2661f4] | file +0xc08 | ev_8c1ed7bc8853604e5acf55448a86e622f5ce0b7e72c7ce4cb732a0f49b42d130
thunk_2661f0:
0x2661f0: JMP 0x00552d10
; END FUNCTION thunk_2661f0
0x2661f5: INT3 ; original byte CC, padding
0x2661f6: INT3 ; original byte CC, padding
0x2661f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f8 [0x2661f8, 0x2661fc] | file +0xc10 | ev_5dd1aefd4eafac7c3e2c0dd0b2f9a465137289585f5cde83e19c612c55283277
thunk_2661f8:
0x2661f8: JMP 0x00b7f160
; END FUNCTION thunk_2661f8
0x2661fd: INT3 ; original byte CC, padding
0x2661fe: INT3 ; original byte CC, padding
0x2661ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266200 [0x266200, 0x266204] | file +0xc18 | ev_757ed4e16199c82a0c607920c217f95085b37f8a6717d7dbb7978116461ae164
thunk_266200:
0x266200: JMP 0x005de250
; END FUNCTION thunk_266200
0x266205: INT3 ; original byte CC, padding
0x266206: INT3 ; original byte CC, padding
0x266207: INT3 ; original byte CC, padding

; FUNCTION thunk_266208 [0x266208, 0x26620c] | file +0xc20 | ev_a91a98e2442ba222b625021ef2f015620cb04418f3424570d5a614e1076c3fcb
thunk_266208:
0x266208: JMP 0x00a54a30
; END FUNCTION thunk_266208
0x26620d: INT3 ; original byte CC, padding
0x26620e: INT3 ; original byte CC, padding
0x26620f: INT3 ; original byte CC, padding

; FUNCTION thunk_266210 [0x266210, 0x266214] | file +0xc28 | ev_62abc88f2ffa6f5a0735a3c380225d00d1cc5230fe6196dbd4554708b105ba38
thunk_266210:
0x266210: JMP 0x00a54a40
; END FUNCTION thunk_266210
0x266215: INT3 ; original byte CC, padding
0x266216: INT3 ; original byte CC, padding
0x266217: INT3 ; original byte CC, padding

; FUNCTION thunk_266218 [0x266218, 0x26621c] | file +0xc30 | ev_316646bb0eb8fd79801320346e50eaec76dfa54cb81513b797abe9e2b4888da0
thunk_266218:
0x266218: JMP 0x00a54a50
; END FUNCTION thunk_266218
0x26621d: INT3 ; original byte CC, padding
0x26621e: INT3 ; original byte CC, padding
0x26621f: INT3 ; original byte CC, padding

; FUNCTION thunk_266220 [0x266220, 0x266224] | file +0xc38 | ev_4a106cd82fbe8c86da526794caa3df2f7d5aef9eaae4cff41d637e9c2cd824be
thunk_266220:
0x266220: JMP 0x00a54a60
; END FUNCTION thunk_266220
0x266225: INT3 ; original byte CC, padding
0x266226: INT3 ; original byte CC, padding
0x266227: INT3 ; original byte CC, padding

; FUNCTION thunk_266228 [0x266228, 0x26622c] | file +0xc40 | ev_351475a479b8e03694262bc8dcef5bbd2294aeaff31eeaa55316389e51414995
thunk_266228:
0x266228: JMP 0x00a54a80
; END FUNCTION thunk_266228
0x26622d: INT3 ; original byte CC, padding
0x26622e: INT3 ; original byte CC, padding
0x26622f: INT3 ; original byte CC, padding

; FUNCTION thunk_266230 [0x266230, 0x266234] | file +0xc48 | ev_068172e45f643e23c2637d51152a476b51dec1fd8b501c50c998a097591390c2
thunk_266230:
0x266230: JMP 0x00a54a90
; END FUNCTION thunk_266230
0x266235: INT3 ; original byte CC, padding
0x266236: INT3 ; original byte CC, padding
0x266237: INT3 ; original byte CC, padding

; FUNCTION thunk_266238 [0x266238, 0x26623c] | file +0xc50 | ev_dfc19b0d494a5652a47ade31009b1e4c990f00087fde5e625a98a44c96cf0818
thunk_266238:
0x266238: JMP 0x008f9720
; END FUNCTION thunk_266238
0x26623d: INT3 ; original byte CC, padding
0x26623e: INT3 ; original byte CC, padding
0x26623f: INT3 ; original byte CC, padding

; FUNCTION thunk_266240 [0x266240, 0x266244] | file +0xc58 | ev_c4b0a4d54127ab7bacb8213d7c83b00ba3119ecb6a1ed4bcefb4af04d714bff9
thunk_266240:
0x266240: JMP 0x00a54ab0
; END FUNCTION thunk_266240
0x266245: INT3 ; original byte CC, padding
0x266246: INT3 ; original byte CC, padding
0x266247: INT3 ; original byte CC, padding

; FUNCTION thunk_266248 [0x266248, 0x26624c] | file +0xc60 | ev_3955365d4f354d375284caa65baa7fdc58b06cbf43962a43f4403daf1e6ca121
thunk_266248:
0x266248: JMP 0x008f64e0
; END FUNCTION thunk_266248
0x26624d: INT3 ; original byte CC, padding
0x26624e: INT3 ; original byte CC, padding
0x26624f: INT3 ; original byte CC, padding

; FUNCTION thunk_266250 [0x266250, 0x266254] | file +0xc68 | ev_f96adbdce6189ddf520dc792bf796a549b63d30d28bf78afb120432ba46da586
thunk_266250:
0x266250: JMP 0x008f5ef0
; END FUNCTION thunk_266250
0x266255: INT3 ; original byte CC, padding
0x266256: INT3 ; original byte CC, padding
0x266257: INT3 ; original byte CC, padding

; FUNCTION thunk_266258 [0x266258, 0x26625c] | file +0xc70 | ev_1b34325666d3c9c6d915c324fbccf4635988b46d93e5a9c542d2c00f603b09aa
thunk_266258:
0x266258: JMP 0x00a54a20
; END FUNCTION thunk_266258
0x26625d: INT3 ; original byte CC, padding
0x26625e: INT3 ; original byte CC, padding
0x26625f: INT3 ; original byte CC, padding

; FUNCTION thunk_266260 [0x266260, 0x266264] | file +0xc78 | ev_4d1b8a3331344e715a72a250a7d7161a2ccd108eb7ebf2facdfab957a5a66bb3
thunk_266260:
0x266260: JMP 0x00a54a70
; END FUNCTION thunk_266260
0x266265: INT3 ; original byte CC, padding
0x266266: INT3 ; original byte CC, padding
0x266267: INT3 ; original byte CC, padding

; FUNCTION thunk_266268 [0x266268, 0x26626c] | file +0xc80 | ev_22e4db3caf86ff04a9eee13f105b1058dc4863b54bce4a01374f8889e8a30600
thunk_266268:
0x266268: JMP 0x00a54aa0
; END FUNCTION thunk_266268
0x26626d: INT3 ; original byte CC, padding
0x26626e: INT3 ; original byte CC, padding
0x26626f: INT3 ; original byte CC, padding

; FUNCTION thunk_266270 [0x266270, 0x266274] | file +0xc88 | ev_890be6f1c7920f0033104ee575247e1908f0c97280a687224b3a7da85c57310a
thunk_266270:
0x266270: JMP 0x006e54d0
; END FUNCTION thunk_266270
0x266275: INT3 ; original byte CC, padding
0x266276: INT3 ; original byte CC, padding
0x266277: INT3 ; original byte CC, padding

; FUNCTION thunk_266278 [0x266278, 0x26627c] | file +0xc90 | ev_38a9d23e776f221c1f5b721b4f7c272ef04b2b40606ad30cb41ed2f6fe414c12
thunk_266278:
0x266278: JMP 0x00b7f4b0
; END FUNCTION thunk_266278
0x26627d: INT3 ; original byte CC, padding
0x26627e: INT3 ; original byte CC, padding
0x26627f: INT3 ; original byte CC, padding

; FUNCTION thunk_266280 [0x266280, 0x266284] | file +0xc98 | ev_2f26b0745ccafe1db376effabe7a0a78b79d483ba1574dca7a4e24346f526141
thunk_266280:
0x266280: JMP 0x0083d660
; END FUNCTION thunk_266280
0x266285: INT3 ; original byte CC, padding
0x266286: INT3 ; original byte CC, padding
0x266287: INT3 ; original byte CC, padding

; FUNCTION thunk_266288 [0x266288, 0x26628c] | file +0xca0 | ev_f9d0bb27935ce47d742649223a7e2e81d68bc42ed16701b18f269579e25bb4e0
thunk_266288:
0x266288: JMP 0x0083d7c0
; END FUNCTION thunk_266288
0x26628d: INT3 ; original byte CC, padding
0x26628e: INT3 ; original byte CC, padding
0x26628f: INT3 ; original byte CC, padding

; FUNCTION thunk_266290 [0x266290, 0x266294] | file +0xca8 | ev_a1a078ae92c7980fc788d3c99d9298c6590db02a5982d9127f09f838f9409650
thunk_266290:
0x266290: JMP 0x0083dab0
; END FUNCTION thunk_266290
0x266295: INT3 ; original byte CC, padding
0x266296: INT3 ; original byte CC, padding
0x266297: INT3 ; original byte CC, padding

; FUNCTION thunk_266298 [0x266298, 0x26629c] | file +0xcb0 | ev_a78e29a1ea04bf6d30594d3b19849395bc30b22f59337d3f40a121a6320dc5ab
thunk_266298:
0x266298: JMP 0x0083de80
; END FUNCTION thunk_266298
0x26629d: INT3 ; original byte CC, padding
0x26629e: INT3 ; original byte CC, padding
0x26629f: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a0 [0x2662a0, 0x2662a4] | file +0xcb8 | ev_155d45ce5e405802c8aeeaba1343bdef4231a636cf536cf310fc69c4c61f7313
thunk_2662a0:
0x2662a0: JMP 0x008f9c80
; END FUNCTION thunk_2662a0
0x2662a5: INT3 ; original byte CC, padding
0x2662a6: INT3 ; original byte CC, padding
0x2662a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a8 [0x2662a8, 0x2662ac] | file +0xcc0 | ev_bd1796ad561e4782dded9a21477730f4bdf304f5dabc5868b80761969759fad6
thunk_2662a8:
0x2662a8: JMP 0x008fa110
; END FUNCTION thunk_2662a8
0x2662ad: INT3 ; original byte CC, padding
0x2662ae: INT3 ; original byte CC, padding
0x2662af: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b0 [0x2662b0, 0x2662b4] | file +0xcc8 | ev_0480d28ab6222af2b93e4fd113f16ba734ff8878a8f42b06d5158480225cf901
thunk_2662b0:
0x2662b0: JMP 0x008f91b0
; END FUNCTION thunk_2662b0
0x2662b5: INT3 ; original byte CC, padding
0x2662b6: INT3 ; original byte CC, padding
0x2662b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b8 [0x2662b8, 0x2662bc] | file +0xcd0 | ev_1c690d03a8e9640305178c7da5cb0928be57685cc88733f8570a0a2b2d1e3e1e
thunk_2662b8:
0x2662b8: JMP 0x008fa4f0
; END FUNCTION thunk_2662b8
0x2662bd: INT3 ; original byte CC, padding
0x2662be: INT3 ; original byte CC, padding
0x2662bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c0 [0x2662c0, 0x2662c4] | file +0xcd8 | ev_719922efa405ef9eca04e783fe6e621ff2a66e1ad1adbeffd20ce01bd1b0ed53
thunk_2662c0:
0x2662c0: JMP 0x008f8090
; END FUNCTION thunk_2662c0
0x2662c5: INT3 ; original byte CC, padding
0x2662c6: INT3 ; original byte CC, padding
0x2662c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c8 [0x2662c8, 0x2662cc] | file +0xce0 | ev_a91a6620a8b9164f6f8704cd2c44855feabb5aee9594bdae24707f232e57d539
thunk_2662c8:
0x2662c8: JMP 0x008fbb80
; END FUNCTION thunk_2662c8
0x2662cd: INT3 ; original byte CC, padding
0x2662ce: INT3 ; original byte CC, padding
0x2662cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d0 [0x2662d0, 0x2662d4] | file +0xce8 | ev_a29cf940ec7347209b1f1e1e1df6ed80e1b76b49b50c65175eeb8dbb2f48f37d
thunk_2662d0:
0x2662d0: JMP 0x008f7b80
; END FUNCTION thunk_2662d0
0x2662d5: INT3 ; original byte CC, padding
0x2662d6: INT3 ; original byte CC, padding
0x2662d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d8 [0x2662d8, 0x2662dc] | file +0xcf0 | ev_1b6cc0fa753ccd5b1d7037a0c83ca39e8938cd8ce9dae47fdab2114c3a3f30a0
thunk_2662d8:
0x2662d8: JMP 0x008f7890
; END FUNCTION thunk_2662d8
0x2662dd: INT3 ; original byte CC, padding
0x2662de: INT3 ; original byte CC, padding
0x2662df: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e0 [0x2662e0, 0x2662e4] | file +0xcf8 | ev_3f3429b265d0817f87fde71c226edb3414a5e56742e62e83e7ba9c5eb129e695
thunk_2662e0:
0x2662e0: JMP 0x008fb8a0
; END FUNCTION thunk_2662e0
0x2662e5: INT3 ; original byte CC, padding
0x2662e6: INT3 ; original byte CC, padding
0x2662e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e8 [0x2662e8, 0x2662ec] | file +0xd00 | ev_5fc1e1d8cefa479de1df321dd78e3e0fcec232438431dd18a61fa054ab7b3e6a
thunk_2662e8:
0x2662e8: JMP 0x008f8510
; END FUNCTION thunk_2662e8
0x2662ed: INT3 ; original byte CC, padding
0x2662ee: INT3 ; original byte CC, padding
0x2662ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f0 [0x2662f0, 0x2662f4] | file +0xd08 | ev_069bad0ed13080f7e9635297f56d86b4d2e1c4617a1fe0b1e4cf75f1ccc2c916
thunk_2662f0:
0x2662f0: JMP 0x008f8800
; END FUNCTION thunk_2662f0
0x2662f5: INT3 ; original byte CC, padding
0x2662f6: INT3 ; original byte CC, padding
0x2662f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f8 [0x2662f8, 0x2662fc] | file +0xd10 | ev_d3234eeed367638025138ce92a20673c4286efccda25b5770c0733c2eb4a83e4
thunk_2662f8:
0x2662f8: JMP 0x0049b080
; END FUNCTION thunk_2662f8
0x2662fd: INT3 ; original byte CC, padding
0x2662fe: INT3 ; original byte CC, padding
0x2662ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266300 [0x266300, 0x266304] | file +0xd18 | ev_75056b65a1d2bedd343eb1adcf1cef2a1c0fda4e054c7388d54dbd2caba2e0b9
thunk_266300:
0x266300: JMP 0x0049b090
; END FUNCTION thunk_266300
0x266305: INT3 ; original byte CC, padding
0x266306: INT3 ; original byte CC, padding
0x266307: INT3 ; original byte CC, padding

; FUNCTION thunk_266308 [0x266308, 0x26630c] | file +0xd20 | ev_91ea1293d69e9c30d64b99d8801790056e6736a65b95aea27ec12055f57b1083
thunk_266308:
0x266308: JMP 0x0055fa50
; END FUNCTION thunk_266308
0x26630d: INT3 ; original byte CC, padding
0x26630e: INT3 ; original byte CC, padding
0x26630f: INT3 ; original byte CC, padding

; FUNCTION thunk_266310 [0x266310, 0x266314] | file +0xd28 | ev_bf5a4d512d418182601ed746a6835acf3eb5afe4f7852dfadc904c056465c94b
thunk_266310:
0x266310: JMP 0x00c34870
; END FUNCTION thunk_266310
0x266315: INT3 ; original byte CC, padding
0x266316: INT3 ; original byte CC, padding
0x266317: INT3 ; original byte CC, padding

; FUNCTION thunk_266318 [0x266318, 0x26631c] | file +0xd30 | ev_208b12d33f8755d90604b90a10a2c17d58b0947f24fd776ac8b17d17f6313ee8
thunk_266318:
0x266318: JMP 0x007dccf0
; END FUNCTION thunk_266318
0x26631d: INT3 ; original byte CC, padding
0x26631e: INT3 ; original byte CC, padding
0x26631f: INT3 ; original byte CC, padding

; FUNCTION thunk_266320 [0x266320, 0x266324] | file +0xd38 | ev_dd4ca9088204fa7e974a87d0b009a8ebc2fd2759fb8b63a52a185ba34cf8eb29
thunk_266320:
0x266320: JMP 0x007dcd00
; END FUNCTION thunk_266320
0x266325: INT3 ; original byte CC, padding
0x266326: INT3 ; original byte CC, padding
0x266327: INT3 ; original byte CC, padding

; FUNCTION thunk_266328 [0x266328, 0x26632c] | file +0xd40 | ev_69848362de2103bd5cf50d86ad439e274738f701958fe202143e54df6f1453c8
thunk_266328:
0x266328: JMP 0x007dcd10
; END FUNCTION thunk_266328
0x26632d: INT3 ; original byte CC, padding
0x26632e: INT3 ; original byte CC, padding
0x26632f: INT3 ; original byte CC, padding

; FUNCTION thunk_266330 [0x266330, 0x266334] | file +0xd48 | ev_a9629abec3308aca2457491628273649a887f0f033e06071bf19d59e7c25aeb6
thunk_266330:
0x266330: JMP 0x007dcd20
; END FUNCTION thunk_266330
0x266335: INT3 ; original byte CC, padding
0x266336: INT3 ; original byte CC, padding
0x266337: INT3 ; original byte CC, padding

; FUNCTION thunk_266338 [0x266338, 0x26633c] | file +0xd50 | ev_2c9fc9579a5e8f0951e68ec4ee69f8bab5819987d27b92dac0e5ca9ab7aa9585
thunk_266338:
0x266338: JMP 0x007dcd30
; END FUNCTION thunk_266338
0x26633d: INT3 ; original byte CC, padding
0x26633e: INT3 ; original byte CC, padding
0x26633f: INT3 ; original byte CC, padding

; FUNCTION thunk_266340 [0x266340, 0x266344] | file +0xd58 | ev_28d00ff55ee14bddc3a396e9c941f0914c680d54e45f0e7d0a0fe6bcaf0abdfd
thunk_266340:
0x266340: JMP 0x005a6c90
; END FUNCTION thunk_266340
0x266345: INT3 ; original byte CC, padding
0x266346: INT3 ; original byte CC, padding
0x266347: INT3 ; original byte CC, padding

; FUNCTION thunk_266348 [0x266348, 0x26634c] | file +0xd60 | ev_a0a92a8617b94cc57cf896b02840e085453db69e9b9b89b42fd08675b520d877
thunk_266348:
0x266348: JMP 0x005a7300
; END FUNCTION thunk_266348
0x26634d: INT3 ; original byte CC, padding
0x26634e: INT3 ; original byte CC, padding
0x26634f: INT3 ; original byte CC, padding

; FUNCTION thunk_266350 [0x266350, 0x266354] | file +0xd68 | ev_0a57f3bca0315a687f07d3f9b7f70316f45c7906a2d0cf0fa17dc9062c3dee7c
thunk_266350:
0x266350: JMP 0x005a7610
; END FUNCTION thunk_266350
0x266355: INT3 ; original byte CC, padding
0x266356: INT3 ; original byte CC, padding
0x266357: INT3 ; original byte CC, padding

; FUNCTION thunk_266358 [0x266358, 0x26635c] | file +0xd70 | ev_af4fded32a25b1dd2506f0fa8d3a6fe561debf05b2f66c733b119322209b6aaf
thunk_266358:
0x266358: JMP 0x005a7900
; END FUNCTION thunk_266358
0x26635d: INT3 ; original byte CC, padding
0x26635e: INT3 ; original byte CC, padding
0x26635f: INT3 ; original byte CC, padding

; FUNCTION thunk_266360 [0x266360, 0x266364] | file +0xd78 | ev_9c6af11e7c8dd305336c3838898236fd05099b0aa65104622374b160736ab5b6
thunk_266360:
0x266360: JMP 0x00c9c830
; END FUNCTION thunk_266360
0x266365: INT3 ; original byte CC, padding
0x266366: INT3 ; original byte CC, padding
0x266367: INT3 ; original byte CC, padding

; FUNCTION thunk_266368 [0x266368, 0x26636c] | file +0xd80 | ev_87f009c7ed6a037fc6a2e695d59a03270e62b3b2b19528404427fdbc1ab4ee9e
thunk_266368:
0x266368: JMP 0x005a7f00
; END FUNCTION thunk_266368
0x26636d: INT3 ; original byte CC, padding
0x26636e: INT3 ; original byte CC, padding
0x26636f: INT3 ; original byte CC, padding

; FUNCTION thunk_266370 [0x266370, 0x266374] | file +0xd88 | ev_3070545cbae7a2801f820e3271e277b6b50e272261694c2bd8e9e12e4aae5233
thunk_266370:
0x266370: JMP 0x005a8070
; END FUNCTION thunk_266370
0x266375: INT3 ; original byte CC, padding
0x266376: INT3 ; original byte CC, padding
0x266377: INT3 ; original byte CC, padding

; FUNCTION thunk_266378 [0x266378, 0x26637c] | file +0xd90 | ev_ca921bb3120b8324a1de915ed3013883e4fa47822426fb4cd29d45496c86f8d4
thunk_266378:
0x266378: JMP 0x00be8480
; END FUNCTION thunk_266378
0x26637d: INT3 ; original byte CC, padding
0x26637e: INT3 ; original byte CC, padding
0x26637f: INT3 ; original byte CC, padding

; FUNCTION thunk_266380 [0x266380, 0x266384] | file +0xd98 | ev_a8a021cff5d62e81b20c04597b03ae061b60365d11847b3152df272cc8acdd6f
thunk_266380:
0x266380: JMP 0x0049b0a0
; END FUNCTION thunk_266380
0x266385: INT3 ; original byte CC, padding
0x266386: INT3 ; original byte CC, padding
0x266387: INT3 ; original byte CC, padding

; FUNCTION thunk_266388 [0x266388, 0x26638c] | file +0xda0 | ev_2997099199ab42db19428062e874712cd6df17198b3e9050eab123c8e272e909
thunk_266388:
0x266388: JMP 0x0049b0c0
; END FUNCTION thunk_266388
0x26638d: INT3 ; original byte CC, padding
0x26638e: INT3 ; original byte CC, padding
0x26638f: INT3 ; original byte CC, padding

; FUNCTION thunk_266390 [0x266390, 0x266394] | file +0xda8 | ev_b65bf17266f25edcb08139f6c59009a5ffaaa52228678f32ef1ea053d7b820ea
thunk_266390:
0x266390: JMP 0x0049b0d0
; END FUNCTION thunk_266390
0x266395: INT3 ; original byte CC, padding
0x266396: INT3 ; original byte CC, padding
0x266397: INT3 ; original byte CC, padding

; FUNCTION thunk_266398 [0x266398, 0x26639c] | file +0xdb0 | ev_4bf27f9aa04b2929a3570e0657827ba247a75006d293b78e64abaff44da59012
thunk_266398:
0x266398: JMP 0x0049b0e0
; END FUNCTION thunk_266398
0x26639d: INT3 ; original byte CC, padding
0x26639e: INT3 ; original byte CC, padding
0x26639f: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a0 [0x2663a0, 0x2663a4] | file +0xdb8 | ev_67bb7eec5a2d6bdffe57a922696a5236cd5e44e0462ecd023f1a1790e17462b7
thunk_2663a0:
0x2663a0: JMP 0x0049b0f0
; END FUNCTION thunk_2663a0
0x2663a5: INT3 ; original byte CC, padding
0x2663a6: INT3 ; original byte CC, padding
0x2663a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a8 [0x2663a8, 0x2663ac] | file +0xdc0 | ev_68a25a408bff8ab52323616e1566b09b1bdfef1050073934b37bcd78f8bff273
thunk_2663a8:
0x2663a8: JMP 0x00530720
; END FUNCTION thunk_2663a8
0x2663ad: INT3 ; original byte CC, padding
0x2663ae: INT3 ; original byte CC, padding
0x2663af: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b0 [0x2663b0, 0x2663b4] | file +0xdc8 | ev_83ae655e96cd90c09eb9dc0ce6bd23f77ef191df92f56a0d59db6f4464af597e
thunk_2663b0:
0x2663b0: JMP 0x00531670
; END FUNCTION thunk_2663b0
0x2663b5: INT3 ; original byte CC, padding
0x2663b6: INT3 ; original byte CC, padding
0x2663b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b8 [0x2663b8, 0x2663bc] | file +0xdd0 | ev_1afdd0cffa8bf6b0d345f517b61d8ebdb86433a05beb859e3375a00d0567815c
thunk_2663b8:
0x2663b8: JMP 0x008f96f0
; END FUNCTION thunk_2663b8
0x2663bd: INT3 ; original byte CC, padding
0x2663be: INT3 ; original byte CC, padding
0x2663bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c0 [0x2663c0, 0x2663c4] | file +0xdd8 | ev_a2681b835dabbb2bbe1018977711d8e7a6b25088c1c3b1bd12d40314ae174cdd
thunk_2663c0:
0x2663c0: JMP 0x00531230
; END FUNCTION thunk_2663c0
0x2663c5: INT3 ; original byte CC, padding
0x2663c6: INT3 ; original byte CC, padding
0x2663c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c8 [0x2663c8, 0x2663cc] | file +0xde0 | ev_1202d226e0b0dc8c3cdef6d838d3717b0e0b43e88f3997d1a0aa7e109050b457
thunk_2663c8:
0x2663c8: JMP 0x00802df0
; END FUNCTION thunk_2663c8
0x2663cd: INT3 ; original byte CC, padding
0x2663ce: INT3 ; original byte CC, padding
0x2663cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d0 [0x2663d0, 0x2663d4] | file +0xde8 | ev_22ff5ff4908294967385a694e23aaac6ac0ea8916a63f1fa973d669ba6fb8df0
thunk_2663d0:
0x2663d0: JMP 0x00b7f140
; END FUNCTION thunk_2663d0
0x2663d5: INT3 ; original byte CC, padding
0x2663d6: INT3 ; original byte CC, padding
0x2663d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d8 [0x2663d8, 0x2663dc] | file +0xdf0 | ev_34a23c6ea3b7a2d859dc68cf0179d2e6e3f54574cdd2132544206387c29aa21e
thunk_2663d8:
0x2663d8: JMP 0x00ae35e0
; END FUNCTION thunk_2663d8
0x2663dd: INT3 ; original byte CC, padding
0x2663de: INT3 ; original byte CC, padding
0x2663df: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e0 [0x2663e0, 0x2663e4] | file +0xdf8 | ev_5cb448dfe07b9a4edd1fcf0107805a9bd7ea03b9d2747e2e94001efd67a9feb3
thunk_2663e0:
0x2663e0: JMP 0x004eee20
; END FUNCTION thunk_2663e0
0x2663e5: INT3 ; original byte CC, padding
0x2663e6: INT3 ; original byte CC, padding
0x2663e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e8 [0x2663e8, 0x2663ec] | file +0xe00 | ev_197bd45d13ebaabd9a99bf7238e2da2d83a7c121b47a589578b35369fae3ff3b
thunk_2663e8:
0x2663e8: JMP 0x008fab10
; END FUNCTION thunk_2663e8
0x2663ed: INT3 ; original byte CC, padding
0x2663ee: INT3 ; original byte CC, padding
0x2663ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f0 [0x2663f0, 0x2663f4] | file +0xe08 | ev_390cff6484046a0500dd687e1027f4b3ccfb2934b44486aa755a95431a7fe4a2
thunk_2663f0:
0x2663f0: JMP 0x008fae30
; END FUNCTION thunk_2663f0
0x2663f5: INT3 ; original byte CC, padding
0x2663f6: INT3 ; original byte CC, padding
0x2663f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f8 [0x2663f8, 0x2663fc] | file +0xe10 | ev_3c5fc25132a91f686abd292661e26aae09b02682ce5c53c831b4f6f03827049a
thunk_2663f8:
0x2663f8: JMP 0x009c9220
; END FUNCTION thunk_2663f8
0x2663fd: INT3 ; original byte CC, padding
0x2663fe: INT3 ; original byte CC, padding
0x2663ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266400 [0x266400, 0x266404] | file +0xe18 | ev_57db6d921f8026b55dc8e147118e9d9cb10f40830fcbb9a59701387c437a9d1b
thunk_266400:
0x266400: JMP 0x009c9100
; END FUNCTION thunk_266400
0x266405: INT3 ; original byte CC, padding
0x266406: INT3 ; original byte CC, padding
0x266407: INT3 ; original byte CC, padding

; FUNCTION thunk_266408 [0x266408, 0x26640c] | file +0xe20 | ev_d0a17fb65beb653cf741b97d5f412cf3674a53cfab34f587c8e6b0c6abb9c4c8
thunk_266408:
0x266408: JMP 0x00642310
; END FUNCTION thunk_266408
0x26640d: INT3 ; original byte CC, padding
0x26640e: INT3 ; original byte CC, padding
0x26640f: INT3 ; original byte CC, padding

; FUNCTION thunk_266410 [0x266410, 0x266414] | file +0xe28 | ev_9fc7135a6d4d0bcf4f8046fe5a5ef91b770aeba84442b46d8339d885842b2c6b
thunk_266410:
0x266410: JMP 0x00642820
; END FUNCTION thunk_266410
0x266415: INT3 ; original byte CC, padding
0x266416: INT3 ; original byte CC, padding
0x266417: INT3 ; original byte CC, padding

; FUNCTION thunk_266418 [0x266418, 0x26641c] | file +0xe30 | ev_2b57d9748536f30d1ad30c74b67122f3d29f2da19d2d2c776b1e549e6b375495
thunk_266418:
0x266418: JMP 0x006436e0
; END FUNCTION thunk_266418
0x26641d: INT3 ; original byte CC, padding
0x26641e: INT3 ; original byte CC, padding
0x26641f: INT3 ; original byte CC, padding

; FUNCTION thunk_266420 [0x266420, 0x266424] | file +0xe38 | ev_5731453af60ee21737f0a19f8df3841abc1185e5f887c5a2651f9da56f35dd45
thunk_266420:
0x266420: JMP 0x006438d0
; END FUNCTION thunk_266420
0x266425: INT3 ; original byte CC, padding
0x266426: INT3 ; original byte CC, padding
0x266427: INT3 ; original byte CC, padding

; FUNCTION thunk_266428 [0x266428, 0x26642c] | file +0xe40 | ev_e36675918b3af93a0ba702a21607e01ed6c6402aec3ced61dede9f937ad73f86
thunk_266428:
0x266428: JMP 0x00643c60
; END FUNCTION thunk_266428
0x26642d: INT3 ; original byte CC, padding
0x26642e: INT3 ; original byte CC, padding
0x26642f: INT3 ; original byte CC, padding

; FUNCTION thunk_266430 [0x266430, 0x266434] | file +0xe48 | ev_6a04f2314e3bd552a5cfa9f286543184288bcceb388acd83f0f89386e77844c5
thunk_266430:
0x266430: JMP 0x009f8290
; END FUNCTION thunk_266430
0x266435: INT3 ; original byte CC, padding
0x266436: INT3 ; original byte CC, padding
0x266437: INT3 ; original byte CC, padding

; FUNCTION thunk_266438 [0x266438, 0x26643c] | file +0xe50 | ev_f0f29b9b58193821f977a76d6075531fc649104ed3ff9888e799ce9604452c14
thunk_266438:
0x266438: JMP 0x009fbb70
; END FUNCTION thunk_266438
0x26643d: INT3 ; original byte CC, padding
0x26643e: INT3 ; original byte CC, padding
0x26643f: INT3 ; original byte CC, padding

; FUNCTION thunk_266440 [0x266440, 0x266444] | file +0xe58 | ev_127a5173d91f5372221bc3d6a59f5ee274647c47100ccb53d2c9971e8f04095e
thunk_266440:
0x266440: JMP 0x00a45280
; END FUNCTION thunk_266440
0x266445: INT3 ; original byte CC, padding
0x266446: INT3 ; original byte CC, padding
0x266447: INT3 ; original byte CC, padding

; FUNCTION thunk_266448 [0x266448, 0x26644c] | file +0xe60 | ev_9f62465d050ae1689681c25f188166de765fef7a456d5df8e48326754e89d912
thunk_266448:
0x266448: JMP 0x00c87ca0
; END FUNCTION thunk_266448
0x26644d: INT3 ; original byte CC, padding
0x26644e: INT3 ; original byte CC, padding
0x26644f: INT3 ; original byte CC, padding

; FUNCTION thunk_266450 [0x266450, 0x266454] | file +0xe68 | ev_c67e3645f3916bc52308fafa2c022bb81b0d570232e6162a3b5bf0e618b49e6f
thunk_266450:
0x266450: JMP 0x009ff000
; END FUNCTION thunk_266450
0x266455: INT3 ; original byte CC, padding
0x266456: INT3 ; original byte CC, padding
0x266457: INT3 ; original byte CC, padding

; FUNCTION thunk_266458 [0x266458, 0x26645c] | file +0xe70 | ev_9094c60b8bf24caf27dfc6ca1cc5af5d2c0cc59d23e15835384bc32a6ebbb651
thunk_266458:
0x266458: JMP 0x00a00780
; END FUNCTION thunk_266458
0x26645d: INT3 ; original byte CC, padding
0x26645e: INT3 ; original byte CC, padding
0x26645f: INT3 ; original byte CC, padding

; FUNCTION thunk_266460 [0x266460, 0x266464] | file +0xe78 | ev_f967dc0dce327888fc081cf3a60385a6c81a79c39a438c911569b99b2c2970f7
thunk_266460:
0x266460: JMP 0x00a007e0
; END FUNCTION thunk_266460
0x266465: INT3 ; original byte CC, padding
0x266466: INT3 ; original byte CC, padding
0x266467: INT3 ; original byte CC, padding

; FUNCTION thunk_266468 [0x266468, 0x26646c] | file +0xe80 | ev_5bb2a3a4b48b10f438f6bfd412e4c2aacf8034f0398d15e36164eea11ac8baaa
thunk_266468:
0x266468: JMP 0x00abe830
; END FUNCTION thunk_266468
0x26646d: INT3 ; original byte CC, padding
0x26646e: INT3 ; original byte CC, padding
0x26646f: INT3 ; original byte CC, padding

; FUNCTION thunk_266470 [0x266470, 0x266474] | file +0xe88 | ev_be306a0fec488868836f0d090ee9360688d8f3815794a95290c9258d1f5c9a52
thunk_266470:
0x266470: JMP 0x009fcf30
; END FUNCTION thunk_266470
0x266475: INT3 ; original byte CC, padding
0x266476: INT3 ; original byte CC, padding
0x266477: INT3 ; original byte CC, padding

; FUNCTION thunk_266478 [0x266478, 0x26647c] | file +0xe90 | ev_922487f426c1b9f1e6487c6527a855ee8b87c562dc258ff108f54fe5ecbe0a5e
thunk_266478:
0x266478: JMP 0x005f0fc0
; END FUNCTION thunk_266478
0x26647d: INT3 ; original byte CC, padding
0x26647e: INT3 ; original byte CC, padding
0x26647f: INT3 ; original byte CC, padding

; FUNCTION thunk_266480 [0x266480, 0x266484] | file +0xe98 | ev_c8ec32f779da850e6799cd8600e705890b09ee79ea421903c0972a20aa3691d5
thunk_266480:
0x266480: JMP 0x008f73f0
; END FUNCTION thunk_266480
0x266485: INT3 ; original byte CC, padding
0x266486: INT3 ; original byte CC, padding
0x266487: INT3 ; original byte CC, padding

; FUNCTION thunk_266488 [0x266488, 0x26648c] | file +0xea0 | ev_0e6780b3ab0518de85ec8cb1b1a41b5328048b27e3d70609480c76c9a729a658
thunk_266488:
0x266488: JMP 0x004f7250
; END FUNCTION thunk_266488
0x26648d: INT3 ; original byte CC, padding
0x26648e: INT3 ; original byte CC, padding
0x26648f: INT3 ; original byte CC, padding

; FUNCTION thunk_266490 [0x266490, 0x266494] | file +0xea8 | ev_eac6950051720ccdf0ce61f974ce273efefff7871ba9f2c6388e5a8e3a8cf4ee
thunk_266490:
0x266490: JMP 0x009fdad0
; END FUNCTION thunk_266490
0x266495: INT3 ; original byte CC, padding
0x266496: INT3 ; original byte CC, padding
0x266497: INT3 ; original byte CC, padding

; FUNCTION thunk_266498 [0x266498, 0x26649c] | file +0xeb0 | ev_ff1c155e08e26d495cf8504aee29f9999b292832e20c7561fa400036d5c41bfd
thunk_266498:
0x266498: JMP 0x009fddb0
; END FUNCTION thunk_266498
0x26649d: INT3 ; original byte CC, padding
0x26649e: INT3 ; original byte CC, padding
0x26649f: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a0 [0x2664a0, 0x2664a4] | file +0xeb8 | ev_9afec5667fabacf37cd58916e41fef67ff924e46b1463d99a0f4bf58efef7597
thunk_2664a0:
0x2664a0: JMP 0x009fdf10
; END FUNCTION thunk_2664a0
0x2664a5: INT3 ; original byte CC, padding
0x2664a6: INT3 ; original byte CC, padding
0x2664a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664a8 [0x2664a8, 0x2664ac] | file +0xec0 | ev_0c5f34727f071eb6c339e4b79622768bdaf09dbe3f4ed379509e311c30490ac2
thunk_2664a8:
0x2664a8: JMP 0x006444d0
; END FUNCTION thunk_2664a8
0x2664ad: INT3 ; original byte CC, padding
0x2664ae: INT3 ; original byte CC, padding
0x2664af: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b0 [0x2664b0, 0x2664b4] | file +0xec8 | ev_d48bdaa2800476d452e672b45b77e9cd08abbf106a93632ad6021e777d43d1c0
thunk_2664b0:
0x2664b0: JMP 0x00650fd0
; END FUNCTION thunk_2664b0
0x2664b5: INT3 ; original byte CC, padding
0x2664b6: INT3 ; original byte CC, padding
0x2664b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664b8 [0x2664b8, 0x2664bc] | file +0xed0 | ev_ee3d8784b8bce47b4bda93ac32d92f80e18d040dbbb0f7e18230bda96f0e6a06
thunk_2664b8:
0x2664b8: JMP 0x009fea30
; END FUNCTION thunk_2664b8
0x2664bd: INT3 ; original byte CC, padding
0x2664be: INT3 ; original byte CC, padding
0x2664bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c0 [0x2664c0, 0x2664c4] | file +0xed8 | ev_80e8082dd778c1359f914df823d4e82cdf37fdd7e497c6fd37e38b496a711883
thunk_2664c0:
0x2664c0: JMP 0x004f7940
; END FUNCTION thunk_2664c0
0x2664c5: INT3 ; original byte CC, padding
0x2664c6: INT3 ; original byte CC, padding
0x2664c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664c8 [0x2664c8, 0x2664cc] | file +0xee0 | ev_f002307638dc8b0656c4f4fc065ba5bf1a73cbb551ca6838d6c478ff89f08933
thunk_2664c8:
0x2664c8: JMP 0x00ab8ae0
; END FUNCTION thunk_2664c8
0x2664cd: INT3 ; original byte CC, padding
0x2664ce: INT3 ; original byte CC, padding
0x2664cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d0 [0x2664d0, 0x2664d4] | file +0xee8 | ev_4cb91d7ac1a88bfa50ffc18582852cbc35933f3b7c1cd09cef419b49abf1ceae
thunk_2664d0:
0x2664d0: JMP 0x00abb660
; END FUNCTION thunk_2664d0
0x2664d5: INT3 ; original byte CC, padding
0x2664d6: INT3 ; original byte CC, padding
0x2664d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664d8 [0x2664d8, 0x2664dc] | file +0xef0 | ev_93971fce626806f71b48fa88650de2f3e837cbbf7a1a5b1a01c24609d7685e42
thunk_2664d8:
0x2664d8: JMP 0x009fe260
; END FUNCTION thunk_2664d8
0x2664dd: INT3 ; original byte CC, padding
0x2664de: INT3 ; original byte CC, padding
0x2664df: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e0 [0x2664e0, 0x2664e4] | file +0xef8 | ev_0637971ec956a822522a0d24e1a2b33abdcc31e6e0968b663d4594b931fb59c6
thunk_2664e0:
0x2664e0: JMP 0x009fe4e0
; END FUNCTION thunk_2664e0
0x2664e5: INT3 ; original byte CC, padding
0x2664e6: INT3 ; original byte CC, padding
0x2664e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664e8 [0x2664e8, 0x2664ec] | file +0xf00 | ev_96f2eb78d44e2be90df1bfac8907de11a07fd1c20a137c512007f0794700cec0
thunk_2664e8:
0x2664e8: JMP 0x009fe630
; END FUNCTION thunk_2664e8
0x2664ed: INT3 ; original byte CC, padding
0x2664ee: INT3 ; original byte CC, padding
0x2664ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f0 [0x2664f0, 0x2664f4] | file +0xf08 | ev_d07160a37d230e28275e29ea7fc0ead6f9f93e14db0a551c24c70ee037fe8547
thunk_2664f0:
0x2664f0: JMP 0x00798330
; END FUNCTION thunk_2664f0
0x2664f5: INT3 ; original byte CC, padding
0x2664f6: INT3 ; original byte CC, padding
0x2664f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2664f8 [0x2664f8, 0x2664fc] | file +0xf10 | ev_9d7c483a683c8982d49d9799eceee79a3cdf2e18a6b44d8f5196a2a5583aee1a
thunk_2664f8:
0x2664f8: JMP 0x00abd000
; END FUNCTION thunk_2664f8
0x2664fd: INT3 ; original byte CC, padding
0x2664fe: INT3 ; original byte CC, padding
0x2664ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266500 [0x266500, 0x266504] | file +0xf18 | ev_c07731e10bb7a1e470f23c0481586c9a79f74361b124421bf746e95b99a5ae93
thunk_266500:
0x266500: JMP 0x000fc890
; END FUNCTION thunk_266500
0x266505: INT3 ; original byte CC, padding
0x266506: INT3 ; original byte CC, padding
0x266507: INT3 ; original byte CC, padding

; FUNCTION thunk_266508 [0x266508, 0x26650c] | file +0xf20 | ev_1e6f012c63f03e4c7afa6e0683fef2ded8312a616632d2bc042c027e9cf07565
thunk_266508:
0x266508: JMP 0x0049f090
; END FUNCTION thunk_266508
0x26650d: INT3 ; original byte CC, padding
0x26650e: INT3 ; original byte CC, padding
0x26650f: INT3 ; original byte CC, padding

; FUNCTION thunk_266510 [0x266510, 0x266514] | file +0xf28 | ev_dee16371c42076c27084c7b50a89913f1c7863ce6228e387f88210c14185bb3a
thunk_266510:
0x266510: JMP 0x0049f200
; END FUNCTION thunk_266510
0x266515: INT3 ; original byte CC, padding
0x266516: INT3 ; original byte CC, padding
0x266517: INT3 ; original byte CC, padding

; FUNCTION thunk_266518 [0x266518, 0x26651c] | file +0xf30 | ev_a058a528785a3cc58198c17c8dc1925048f41e95131251d68285c6b501aafcf4
thunk_266518:
0x266518: JMP 0x004c0590
; END FUNCTION thunk_266518
0x26651d: INT3 ; original byte CC, padding
0x26651e: INT3 ; original byte CC, padding
0x26651f: INT3 ; original byte CC, padding

; FUNCTION thunk_266520 [0x266520, 0x266524] | file +0xf38 | ev_9c4b34282938bf36e1ebd5dfb17568acc7f2ae9dc7d37ca8532f66102dcc05f5
thunk_266520:
0x266520: JMP 0x004c05b0
; END FUNCTION thunk_266520
0x266525: INT3 ; original byte CC, padding
0x266526: INT3 ; original byte CC, padding
0x266527: INT3 ; original byte CC, padding

; FUNCTION thunk_266528 [0x266528, 0x26652c] | file +0xf40 | ev_510b5e50d52f5d207b82eef585db3edfcdd3041c8ffd642236f3957145d64a8f
thunk_266528:
0x266528: JMP 0x000a9430
; END FUNCTION thunk_266528
0x26652d: INT3 ; original byte CC, padding
0x26652e: INT3 ; original byte CC, padding
0x26652f: INT3 ; original byte CC, padding

; FUNCTION thunk_266530 [0x266530, 0x266534] | file +0xf48 | ev_3a5134362781c6d2c668f7e3314cc6a65b2f5285c575ecca40cd49d5040c24c1
thunk_266530:
0x266530: JMP 0x004ca350
; END FUNCTION thunk_266530
0x266535: INT3 ; original byte CC, padding
0x266536: INT3 ; original byte CC, padding
0x266537: INT3 ; original byte CC, padding

; FUNCTION thunk_266538 [0x266538, 0x26653c] | file +0xf50 | ev_8f8bff6001bcc400d3026e1885d9d081268397ec60954c6f57d10812e981a85e
thunk_266538:
0x266538: JMP 0x004caa40
; END FUNCTION thunk_266538
0x26653d: INT3 ; original byte CC, padding
0x26653e: INT3 ; original byte CC, padding
0x26653f: INT3 ; original byte CC, padding

; FUNCTION thunk_266540 [0x266540, 0x266544] | file +0xf58 | ev_d62a46be2c40b28d5f4aa8189bfefe8245f83f992b2d039b6320fa7b30c2cb03
thunk_266540:
0x266540: JMP 0x000aa510
; END FUNCTION thunk_266540
0x266545: INT3 ; original byte CC, padding
0x266546: INT3 ; original byte CC, padding
0x266547: INT3 ; original byte CC, padding

; FUNCTION thunk_266548 [0x266548, 0x26654c] | file +0xf60 | ev_4f04853bf68c590f0c12431b9a942d2d53521c34c9c89c2a5ff51e8aa24f25a9
thunk_266548:
0x266548: JMP 0x004d51d0
; END FUNCTION thunk_266548
0x26654d: INT3 ; original byte CC, padding
0x26654e: INT3 ; original byte CC, padding
0x26654f: INT3 ; original byte CC, padding

; FUNCTION thunk_266550 [0x266550, 0x266554] | file +0xf68 | ev_48c24e846bbea721b69c29780cba7eca1dd5efc88062c725a2b36e5eedc146cb
thunk_266550:
0x266550: JMP 0x008111b0
; END FUNCTION thunk_266550
0x266555: INT3 ; original byte CC, padding
0x266556: INT3 ; original byte CC, padding
0x266557: INT3 ; original byte CC, padding

; FUNCTION thunk_266558 [0x266558, 0x26655c] | file +0xf70 | ev_52e069bbab5228f4e691ccbf934368856bb89a90b72181270e08558cfea35f8a
thunk_266558:
0x266558: JMP 0x0001ae90
; END FUNCTION thunk_266558
0x26655d: INT3 ; original byte CC, padding
0x26655e: INT3 ; original byte CC, padding
0x26655f: INT3 ; original byte CC, padding

; FUNCTION thunk_266560 [0x266560, 0x266564] | file +0xf78 | ev_e91e51e4026fb5d054d11b40d42ef31bf3a18612cafbb880f2af3b25c4b6eb5d
thunk_266560:
0x266560: JMP 0x004f0030
; END FUNCTION thunk_266560
0x266565: INT3 ; original byte CC, padding
0x266566: INT3 ; original byte CC, padding
0x266567: INT3 ; original byte CC, padding

; FUNCTION thunk_266568 [0x266568, 0x26656c] | file +0xf80 | ev_aeae8c8acd7deace89e69e155c6a30e5941f3f2f11ad32f21f70ce92f24451b7
thunk_266568:
0x266568: JMP 0x004fbbd0
; END FUNCTION thunk_266568
0x26656d: INT3 ; original byte CC, padding
0x26656e: INT3 ; original byte CC, padding
0x26656f: INT3 ; original byte CC, padding

; FUNCTION thunk_266570 [0x266570, 0x266574] | file +0xf88 | ev_79da496439052e9f20d766207934d2c884760604dc1329284f73b2992d92df31
thunk_266570:
0x266570: JMP 0x0050ced0
; END FUNCTION thunk_266570
0x266575: INT3 ; original byte CC, padding
0x266576: INT3 ; original byte CC, padding
0x266577: INT3 ; original byte CC, padding

; FUNCTION thunk_266578 [0x266578, 0x26657c] | file +0xf90 | ev_964d4b815a68973efd6e7497a577ce655d463705de549f248cde2a68066a59df
thunk_266578:
0x266578: JMP 0x0050cee0
; END FUNCTION thunk_266578
0x26657d: INT3 ; original byte CC, padding
0x26657e: INT3 ; original byte CC, padding
0x26657f: INT3 ; original byte CC, padding

; FUNCTION thunk_266580 [0x266580, 0x266584] | file +0xf98 | ev_aefa1f19195c0d79f1651ddb2f1a627ca1439c9bf20aac8cc008d0961a79170e
thunk_266580:
0x266580: JMP 0x0050cf30
; END FUNCTION thunk_266580
0x266585: INT3 ; original byte CC, padding
0x266586: INT3 ; original byte CC, padding
0x266587: INT3 ; original byte CC, padding

; FUNCTION thunk_266588 [0x266588, 0x26658c] | file +0xfa0 | ev_b61af5a573168b66efe96561016fef3eeca97db1adbc8414497d0cb29ba0d7a0
thunk_266588:
0x266588: JMP 0x0050cf70
; END FUNCTION thunk_266588
0x26658d: INT3 ; original byte CC, padding
0x26658e: INT3 ; original byte CC, padding
0x26658f: INT3 ; original byte CC, padding

; FUNCTION thunk_266590 [0x266590, 0x266594] | file +0xfa8 | ev_380bd567410144f9738e47feb993c3d6b679a6af88094979e1d777b20bb9580b
thunk_266590:
0x266590: JMP 0x0050cfb0
; END FUNCTION thunk_266590
0x266595: INT3 ; original byte CC, padding
0x266596: INT3 ; original byte CC, padding
0x266597: INT3 ; original byte CC, padding

; FUNCTION thunk_266598 [0x266598, 0x26659c] | file +0xfb0 | ev_5868fd4afe999e7d1aafb7358aece988818e1a7228a241c440d4dad25303d370
thunk_266598:
0x266598: JMP 0x0050cfe0
; END FUNCTION thunk_266598
0x26659d: INT3 ; original byte CC, padding
0x26659e: INT3 ; original byte CC, padding
0x26659f: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a0 [0x2665a0, 0x2665a4] | file +0xfb8 | ev_1d3af3466642591fb9ae548773fa77f270dfa1e30126c5557abfe8798a26ea1e
thunk_2665a0:
0x2665a0: JMP 0x0051e4d0
; END FUNCTION thunk_2665a0
0x2665a5: INT3 ; original byte CC, padding
0x2665a6: INT3 ; original byte CC, padding
0x2665a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665a8 [0x2665a8, 0x2665ac] | file +0xfc0 | ev_632d3b384b31fc7b5fe70b62f0039def1d96dbfe25f77005039f00d57bcd942f
thunk_2665a8:
0x2665a8: JMP 0x0051ef60
; END FUNCTION thunk_2665a8
0x2665ad: INT3 ; original byte CC, padding
0x2665ae: INT3 ; original byte CC, padding
0x2665af: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b0 [0x2665b0, 0x2665b4] | file +0xfc8 | ev_94edde6bfb8961eb7e729bdd77dd0bf926b17201e8338e7cb1020119fa0f2234
thunk_2665b0:
0x2665b0: JMP 0x0051f000
; END FUNCTION thunk_2665b0
0x2665b5: INT3 ; original byte CC, padding
0x2665b6: INT3 ; original byte CC, padding
0x2665b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665b8 [0x2665b8, 0x2665bc] | file +0xfd0 | ev_f2e9166c9f386acb417d242b86be346cf51f95e0d63976665a57af55744197ea
thunk_2665b8:
0x2665b8: JMP 0x0051f0b0
; END FUNCTION thunk_2665b8
0x2665bd: INT3 ; original byte CC, padding
0x2665be: INT3 ; original byte CC, padding
0x2665bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c0 [0x2665c0, 0x2665c4] | file +0xfd8 | ev_9407f2080d4104ecd0eaff2585ea6744706bbd910f81860ffc7e9ba4d938f5e3
thunk_2665c0:
0x2665c0: JMP 0x0051f2e0
; END FUNCTION thunk_2665c0
0x2665c5: INT3 ; original byte CC, padding
0x2665c6: INT3 ; original byte CC, padding
0x2665c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665c8 [0x2665c8, 0x2665cc] | file +0xfe0 | ev_6c6f0cc089b1226a7d6726d9e43a828973723387ff0e9e1f51a32e4aab932f5b
thunk_2665c8:
0x2665c8: JMP 0x0051f670
; END FUNCTION thunk_2665c8
0x2665cd: INT3 ; original byte CC, padding
0x2665ce: INT3 ; original byte CC, padding
0x2665cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d0 [0x2665d0, 0x2665d4] | file +0xfe8 | ev_de593e95b52c6954e7b5a8bdf1fb7eb8da68f265b88d3ee5ca370c7dbbf35a50
thunk_2665d0:
0x2665d0: JMP 0x0051fee0
; END FUNCTION thunk_2665d0
0x2665d5: INT3 ; original byte CC, padding
0x2665d6: INT3 ; original byte CC, padding
0x2665d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2665d8 [0x2665d8, 0x2665dc] | file +0xff0 | ev_4b6c006f374d6f4364ae18785bffb8f9246c17dd08eccb325d682318cb34ba97
thunk_2665d8:
0x2665d8: JMP 0x00536400
; END FUNCTION thunk_2665d8
0x2665dd: INT3 ; original byte CC, padding
0x2665de: INT3 ; original byte CC, padding
0x2665df: INT3 ; original byte CC, padding

; FUNCTION thunk_2665e0 [0x2665e0, 0x2665e4] | file +0xff8 | ev_1d5df3f7cc5b94434a0bcdd6c8bd3650cf445e8eb753129dbf8f5e0f70a0eb1d
thunk_2665e0:
0x2665e0: JMP 0x00544ca0
; END FUNCTION thunk_2665e0
0x2665e5: INT3 ; original byte CC, padding
0x2665e6: INT3 ; original byte CC, padding
0x2665e7: INT3 ; original byte CC, padding


; REA RECOVERED BODY AND ANALYSIS-CARRIER CONTEXT
; Every following boundary is Ghidra function-body data; adjacent funcs are not automatically target callees.

; FUNCTION handler_659_body CONTEXT / separate function | ev_66db5dbc6bb440a3c83f47a29715adfde56230b2339e8004128101a6db727409
; Ghidra body: 0x34b790..0x34b7ad
handler_659_body:
0x34b790: PUSH RBP
0x34b791: MOV RBP, RSP
0x34b794: MOV RAX, qword ptr [RSI]
0x34b797: MOV RDI, qword ptr [RDI + 0x8]
0x34b79b: MOV RDX, qword ptr [RSI + 0x8]
0x34b79f: MOV R8, qword ptr [RSI + 0x10]
0x34b7a3: XOR ECX, ECX
0x34b7a5: MOV RSI, RAX
0x34b7a8: POP RBP
0x34b7a9: JMP 0x0034b540
; END FUNCTION handler_659_body

; FUNCTION sys_593 CONTEXT / separate function | ev_d4ee4c062a541622112197cff17ff2497d333c53df925be1b0d19a8fdf9d592c
; Ghidra body: 0x34b7b0..0x34b905
sys_593:
0x34b7b0: PUSH RBP
0x34b7b1: MOV RBP, RSP
0x34b7b4: PUSH R15
0x34b7b6: PUSH R14
0x34b7b8: PUSH R13
0x34b7ba: PUSH R12
0x34b7bc: PUSH RBX
0x34b7bd: SUB RSP, 0x18
0x34b7c1: LEA R13, [0x391c310]
0x34b7c8: MOV RAX, qword ptr [R13]
0x34b7cc: MOV qword ptr [RBP + -0x30], RAX
0x34b7d0: MOV RAX, qword ptr [RDI + 0x8]
0x34b7d4: MOV R14, qword ptr [RAX + 0x3e8]
0x34b7db: TEST R14, R14
0x34b7de: JZ 0x0034b881
0x34b7e4: MOV RAX, qword ptr [R14 + 0x10]
0x34b7e8: CMP qword ptr [RAX + 0x148], 0x0
0x34b7f0: JZ 0x0034b881
0x34b7f6: MOV R15D, dword ptr [RSI]
0x34b7f9: MOV RBX, qword ptr [RSI + 0x8]
0x34b7fd: MOV RDI, qword ptr GS:[0x0]
0x34b806: LEA RSI, [0x1397f3d]
0x34b80d: XOR EDX, EDX
0x34b80f: CALL 0x00c1a3e0
0x34b814: LEA RSI, [RBP + -0x38]
0x34b818: MOV EDX, 0x8
0x34b81d: MOV RDI, RBX
0x34b820: CALL 0x00259280
0x34b825: MOV ECX, EAX
0x34b827: MOV EAX, 0xe
0x34b82c: TEST ECX, ECX
0x34b82e: JNZ 0x0034b8a7
0x34b830: CMP qword ptr [RBP + -0x38], 0x160
0x34b838: MOV EAX, 0x16
0x34b83d: JNZ 0x0034b8a7
0x34b83f: MOV EDI, 0x160
0x34b844: MOV ESI, 0xa
0x34b849: CALL 0x00b2ac60
0x34b84e: MOV RDI, R14
0x34b851: MOV ESI, R15D
0x34b854: MOV EDX, 0x1
0x34b859: MOV RCX, RAX
0x34b85c: MOV R12, RAX
0x34b85f: CALL 0x0034b950
0x34b864: TEST EAX, EAX
0x34b866: JZ 0x0034b8c0
0x34b868: MOV ESI, 0x160
0x34b86d: MOV RDI, R12
0x34b870: MOV EDX, 0xa
0x34b875: CALL 0x00b24250
0x34b87a: MOV EAX, 0x3
0x34b87f: JMP 0x0034b8a7
0x34b881: LEA RDI, [0x128a660]
0x34b888: LEA RDX, [0x12fbd8a]
0x34b88f: LEA RCX, [0x135ae30]
0x34b896: MOV ESI, 0x497
0x34b89b: XOR EAX, EAX
0x34b89d: CALL 0x00b22a30
0x34b8a2: MOV EAX, 0x1
0x34b8a7: MOV RCX, qword ptr [R13]
0x34b8ab: CMP RCX, qword ptr [RBP + -0x30]
0x34b8af: JNZ 0x0034b8ff
0x34b8b1: ADD RSP, 0x18
0x34b8b5: POP RBX
0x34b8b6: POP R12
0x34b8b8: POP R13
0x34b8ba: POP R14
0x34b8bc: POP R15
0x34b8be: POP RBP
0x34b8bf: RET
0x34b8c0: MOV RDI, qword ptr GS:[0x0]
0x34b8c9: LEA RSI, [0x134f297]
0x34b8d0: XOR EDX, EDX
0x34b8d2: CALL 0x00c1a3e0
0x34b8d7: MOV EDX, 0x160
0x34b8dc: MOV RDI, R12
0x34b8df: MOV RSI, RBX
0x34b8e2: CALL 0x002591d0
0x34b8e7: MOV ESI, 0x160
0x34b8ec: MOV RDI, R12
0x34b8ef: MOV EDX, 0xa
0x34b8f4: MOV EBX, EAX
0x34b8f6: CALL 0x00b24250
0x34b8fb: MOV EAX, EBX
0x34b8fd: JMP 0x0034b8a7
0x34b8ff: CALL 0x006fd6b0
0x34b904: UD2
; END FUNCTION sys_593

; FUNCTION sub_34b910 CONTEXT / separate function | ev_122c7d60f5c01bfb6bcb746ff3776dc2e6386029fcd347e7e55c0d1fccebddbb
; Ghidra body: 0x34b910..0x34b947
sub_34b910:
0x34b910: PUSH RBP
0x34b911: MOV RBP, RSP
0x34b914: PUSH R14
0x34b916: PUSH RBX
0x34b917: MOV R14, RDI
0x34b91a: MOV RDI, qword ptr GS:[0x0]
0x34b923: MOV RBX, RSI
0x34b926: LEA RSI, [0x1397f3d]
0x34b92d: XOR EDX, EDX
0x34b92f: CALL 0x00c1a3e0
0x34b934: MOV EDX, 0x4
0x34b939: MOV RDI, R14
0x34b93c: MOV RSI, RBX
0x34b93f: POP RBX
0x34b940: POP R14
0x34b942: POP RBP
0x34b943: JMP 0x00259280
; END FUNCTION sub_34b910

; FUNCTION sub_34b950 CONTEXT / separate function | ev_38e9054f277fec02592d87c23f090fb23de0dd872bec88b9536e118dbbcd1d7f
; Ghidra body: 0x34b950..0x34bbc0, 0x34bbd0..0x34bc53
sub_34b950:
0x34b950: PUSH RBP
0x34b951: MOV RBP, RSP
0x34b954: PUSH R15
0x34b956: PUSH R14
0x34b958: PUSH R13
0x34b95a: PUSH R12
0x34b95c: PUSH RBX
0x34b95d: PUSH RAX
0x34b95e: LEA RBX, [RDI + 0x70]
0x34b962: MOV R15, RDI
0x34b965: MOV R14, RCX
0x34b968: MOV R12D, EDX
0x34b96b: MOV R13D, ESI
0x34b96e: XOR ESI, ESI
0x34b970: XOR EDX, EDX
0x34b972: XOR ECX, ECX
0x34b974: MOV RDI, RBX
0x34b977: CALL 0x00c4bb20
0x34b97c: NOP dword ptr [RAX]
0x34b980: MOV R15, qword ptr [R15]
0x34b983: TEST R15, R15
0x34b986: JZ 0x0034ba69
0x34b98c: CMP R13D, dword ptr [R15 + 0x28]
0x34b990: JNZ 0x0034b980
0x34b992: MOV ESI, 0x160
0x34b997: MOV RDI, R14
0x34b99a: CALL 0x00258ff0
0x34b99f: TEST R12D, R12D
0x34b9a2: JNZ 0x0034b9b8
0x34b9a4: TEST byte ptr [R15 + 0x11d], 0x1
0x34b9ac: MOV R12D, 0x1
0x34b9b2: JNZ 0x0034bb70
0x34b9b8: MOV R12, qword ptr [R15 + 0x8]
0x34b9bc: TEST R12, R12
0x34b9bf: JZ 0x0034ba08
0x34b9c1: MOV ESI, 0x400
0x34b9c6: MOV RDI, R12
0x34b9c9: CALL 0x00444eb0
0x34b9ce: CMP RAX, 0x6
0x34b9d2: JC 0x0034ba08
0x34b9d4: CMP byte ptr [R12], 0x2f
0x34b9d9: JNZ 0x0034ba08
0x34b9db: CMP byte ptr [R12 + 0x1], 0x68
0x34b9e1: JNZ 0x0034ba08
0x34b9e3: CMP byte ptr [R12 + 0x2], 0x6f
0x34b9e9: JNZ 0x0034ba08
0x34b9eb: CMP byte ptr [R12 + 0x3], 0x73
0x34b9f1: JNZ 0x0034ba08
0x34b9f3: CMP byte ptr [R12 + 0x4], 0x74
0x34b9f9: JNZ 0x0034ba08
0x34b9fb: CMP byte ptr [R12 + 0x5], 0x2f
0x34ba01: MOV ESI, 0x5c
0x34ba06: JZ 0x0034ba0d
0x34ba08: MOV ESI, 0x2f
0x34ba0d: MOV R12, qword ptr [R15 + 0x8]
0x34ba11: MOV RDI, R12
0x34ba14: CALL 0x00272200
0x34ba19: LEA RSI, [RAX + 0x1]
0x34ba1d: TEST RAX, RAX
0x34ba20: LEA RDI, [R14 + 0x8]
0x34ba24: MOV EDX, 0x100
0x34ba29: CMOVZ RSI, R12
0x34ba2d: CALL 0x00984440
0x34ba32: MOV EDI, 0x1
0x34ba37: MOV byte ptr [R14 + 0x107], 0x0
0x34ba3f: CALL 0x00b2bb00
0x34ba44: TEST EAX, EAX
0x34ba46: JZ 0x0034ba74
0x34ba48: LEA RDI, [R14 + 0x108]
0x34ba4f: MOV ESI, 0x40
0x34ba54: MOV dword ptr [R14 + 0x148], 0x0
0x34ba5f: CALL 0x00258ff0
0x34ba64: JMP 0x0034bb5b
0x34ba69: MOV R12D, 0x3
0x34ba6f: JMP 0x0034bb70
0x34ba74: MOV EAX, dword ptr [R15 + 0x48]
0x34ba78: CMP EAX, 0x3
0x34ba7b: JZ 0x0034bad8
0x34ba7d: CMP EAX, 0x2
0x34ba80: JNZ 0x0034bb8e
0x34ba86: MOV RAX, qword ptr [R15 + 0x50]
0x34ba8a: MOV RAX, qword ptr [RAX + 0x8]
0x34ba8e: MOV qword ptr [R14 + 0x108], RAX
0x34ba95: MOV RAX, qword ptr [R15 + 0x50]
0x34ba99: MOV EAX, dword ptr [RAX + 0x10]
0x34ba9c: MOV dword ptr [R14 + 0x110], EAX
0x34baa3: MOV dword ptr [R14 + 0x114], 0x5
0x34baae: MOV RAX, qword ptr [R15 + 0x60]
0x34bab2: MOV RAX, qword ptr [RAX + 0x8]
0x34bab6: MOV qword ptr [R14 + 0x118], RAX
0x34babd: MOV RAX, qword ptr [R15 + 0x60]
0x34bac1: MOV EAX, dword ptr [RAX + 0x10]
0x34bac4: MOV dword ptr [R14 + 0x120], EAX
0x34bacb: MOV dword ptr [R14 + 0x124], 0x3
0x34bad6: JMP 0x0034bb50
0x34bad8: MOV RAX, qword ptr [R15 + 0x50]
0x34badc: MOV RAX, qword ptr [RAX + 0x8]
0x34bae0: MOV qword ptr [R14 + 0x108], RAX
0x34bae7: MOV RAX, qword ptr [R15 + 0x50]
0x34baeb: MOV EAX, dword ptr [RAX + 0x10]
0x34baee: MOV dword ptr [R14 + 0x110], EAX
0x34baf5: MOV dword ptr [R14 + 0x114], 0x5
0x34bb00: MOV RAX, qword ptr [R15 + 0x60]
0x34bb04: MOV RAX, qword ptr [RAX + 0x8]
0x34bb08: MOV qword ptr [R14 + 0x118], RAX
0x34bb0f: MOV RAX, qword ptr [R15 + 0x60]
0x34bb13: MOV EAX, dword ptr [RAX + 0x10]
0x34bb16: MOV dword ptr [R14 + 0x120], EAX
0x34bb1d: MOV dword ptr [R14 + 0x124], 0x3
0x34bb28: MOV RAX, qword ptr [R15 + 0x58]
0x34bb2c: MOV RAX, qword ptr [RAX + 0x8]
0x34bb30: MOV qword ptr [R14 + 0x128], RAX
0x34bb37: MOV RAX, qword ptr [R15 + 0x58]
0x34bb3b: MOV EAX, dword ptr [RAX + 0x10]
0x34bb3e: MOV dword ptr [R14 + 0x130], EAX
0x34bb45: MOV dword ptr [R14 + 0x134], 0x1
0x34bb50: MOV EAX, dword ptr [R15 + 0x48]
0x34bb54: MOV dword ptr [R14 + 0x148], EAX
0x34bb5b: ADD R14, 0x14c
0x34bb62: MOV RSI, R15
0x34bb65: MOV RDI, R14
0x34bb68: CALL 0x00b2b740
0x34bb6d: XOR R12D, R12D
0x34bb70: MOV RDI, RBX
0x34bb73: XOR ESI, ESI
0x34bb75: XOR EDX, EDX
0x34bb77: CALL 0x00c4c4b0
0x34bb7c: MOV EAX, R12D
0x34bb7f: ADD RSP, 0x8
0x34bb83: POP RBX
0x34bb84: POP R12
0x34bb86: POP R13
0x34bb88: POP R14
0x34bb8a: POP R15
0x34bb8c: POP RBP
0x34bb8d: RET
0x34bb8e: MOV dword ptr [R14 + 0x148], 0x0
0x34bb99: MOV EAX, dword ptr [R15 + 0x48]
0x34bb9d: TEST EAX, EAX
0x34bb9f: JZ 0x0034bb5b
0x34bba1: CMP EAX, 0x4
0x34bba4: MOV ECX, 0x4
0x34bba9: CMOVC ECX, EAX
0x34bbac: LEA RAX, [R14 + 0x108]
0x34bbb3: XOR EDX, EDX
0x34bbb5: XOR ESI, ESI
0x34bbb7: SHL RCX, 0x3
0x34bbbb: LEA RCX, [RCX + RCX*0x2]
0x34bbbf: JMP 0x0034bbed
0x34bbd0: MOV ESI, dword ptr [R14 + 0x148]
0x34bbd7: ADD RDX, 0x18
0x34bbdb: INC ESI
0x34bbdd: MOV dword ptr [R14 + 0x148], ESI
0x34bbe4: CMP RCX, RDX
0x34bbe7: JZ 0x0034bb5b
0x34bbed: MOV R8, qword ptr [R15 + 0x40]
0x34bbf1: MOV R9D, ESI
0x34bbf4: SHL R9, 0x4
0x34bbf8: LEA RSI, [RAX + R9*0x1]
0x34bbfc: MOV RDI, qword ptr [R8 + RDX*0x1 + 0x8]
0x34bc01: MOV qword ptr [RAX + R9*0x1], RDI
0x34bc05: MOV EDI, dword ptr [R8 + RDX*0x1 + 0x10]
0x34bc0a: MOV dword ptr [RAX + R9*0x1 + 0x8], EDI
0x34bc0f: MOV dword ptr [RAX + R9*0x1 + 0xc], 0x0
0x34bc18: MOV RDI, qword ptr [R8 + RDX*0x1]
0x34bc1c: MOV EDI, dword ptr [RDI + 0xc]
0x34bc1f: AND EDI, 0x1
0x34bc22: MOV dword ptr [RAX + R9*0x1 + 0xc], EDI
0x34bc27: MOV R9, qword ptr [R8 + RDX*0x1]
0x34bc2b: MOV R9D, dword ptr [R9 + 0xc]
0x34bc2f: TEST R9B, 0x2
0x34bc33: JZ 0x0034bc43
0x34bc35: OR EDI, 0x2
0x34bc38: MOV dword ptr [RSI + 0xc], EDI
0x34bc3b: MOV R8, qword ptr [R8 + RDX*0x1]
0x34bc3f: MOV R9D, dword ptr [R8 + 0xc]
0x34bc43: TEST R9B, 0x4
0x34bc47: JZ 0x0034bbd0
0x34bc49: OR EDI, 0x4
0x34bc4c: MOV dword ptr [RSI + 0xc], EDI
0x34bc4f: JMP 0x0034bbd0
; END FUNCTION sub_34b950

; FUNCTION sys_660 CONTEXT / separate function | ev_f9e358c5d256624605272091fac1d6e65f799be58fced44d6a9e3daa27c2c5b7
; Ghidra body: 0x34bc60..0x34bdb1
sys_660:
0x34bc60: PUSH RBP
0x34bc61: MOV RBP, RSP
0x34bc64: PUSH R15
0x34bc66: PUSH R14
0x34bc68: PUSH R13
0x34bc6a: PUSH R12
0x34bc6c: PUSH RBX
0x34bc6d: SUB RSP, 0x18
0x34bc71: LEA R13, [0x391c310]
0x34bc78: MOV RAX, qword ptr [R13]
0x34bc7c: MOV qword ptr [RBP + -0x30], RAX
0x34bc80: MOV RAX, qword ptr [RDI + 0x8]
0x34bc84: MOV R14, qword ptr [RAX + 0x3e8]
0x34bc8b: TEST R14, R14
0x34bc8e: JZ 0x0034bd26
0x34bc94: MOV RAX, qword ptr [R14 + 0x10]
0x34bc98: CMP qword ptr [RAX + 0x148], 0x0
0x34bca0: JZ 0x0034bd26
0x34bca6: MOV R12D, dword ptr [RSI]
0x34bca9: MOV RBX, qword ptr [RSI + 0x8]
0x34bcad: MOV RDI, qword ptr GS:[0x0]
0x34bcb6: LEA RSI, [0x1397f3d]
0x34bcbd: XOR EDX, EDX
0x34bcbf: CALL 0x00c1a3e0
0x34bcc4: LEA RSI, [RBP + -0x38]
0x34bcc8: MOV EDX, 0x8
0x34bccd: MOV RDI, RBX
0x34bcd0: CALL 0x00259280
0x34bcd5: MOV ECX, EAX
0x34bcd7: MOV EAX, 0xe
0x34bcdc: TEST ECX, ECX
0x34bcde: JNZ 0x0034bd4c
0x34bce0: CMP qword ptr [RBP + -0x38], 0x160
0x34bce8: MOV EAX, 0x16
0x34bced: JNZ 0x0034bd4c
0x34bcef: MOV EDI, 0x160
0x34bcf4: MOV ESI, 0xa
0x34bcf9: CALL 0x00b2ac60
0x34bcfe: MOV RDI, R14
0x34bd01: MOV ESI, R12D
0x34bd04: MOV RCX, RAX
0x34bd07: XOR EDX, EDX
0x34bd09: MOV R15, RAX
0x34bd0c: CALL 0x0034b950
0x34bd11: TEST EAX, EAX
0x34bd13: JZ 0x0034bd65
0x34bd15: MOV ESI, 0x160
0x34bd1a: MOV RDI, R15
0x34bd1d: MOV EDX, 0xa
0x34bd22: MOV EBX, EAX
0x34bd24: JMP 0x0034bda2
0x34bd26: LEA RDI, [0x133054a]
0x34bd2d: LEA RDX, [0x12fbd8a]
0x34bd34: LEA RCX, [0x135ae30]
0x34bd3b: MOV ESI, 0x4cb
0x34bd40: XOR EAX, EAX
0x34bd42: CALL 0x00b22a30
0x34bd47: MOV EAX, 0x1
0x34bd4c: MOV RCX, qword ptr [R13]
0x34bd50: CMP RCX, qword ptr [RBP + -0x30]
0x34bd54: JNZ 0x0034bdab
0x34bd56: ADD RSP, 0x18
0x34bd5a: POP RBX
0x34bd5b: POP R12
0x34bd5d: POP R13
0x34bd5f: POP R14
0x34bd61: POP R15
0x34bd63: POP RBP
0x34bd64: RET
0x34bd65: MOV RAX, qword ptr [RBP + -0x38]
0x34bd69: LEA RSI, [0x134f297]
0x34bd70: XOR EDX, EDX
0x34bd72: MOV qword ptr [R15], RAX
0x34bd75: MOV RDI, qword ptr GS:[0x0]
0x34bd7e: CALL 0x00c1a3e0
0x34bd83: MOV EDX, 0x160
0x34bd88: MOV RDI, R15
0x34bd8b: MOV RSI, RBX
0x34bd8e: CALL 0x002591d0
0x34bd93: MOV EBX, EAX
0x34bd95: MOV ESI, 0x160
0x34bd9a: MOV RDI, R15
0x34bd9d: MOV EDX, 0xa
0x34bda2: CALL 0x00b24250
0x34bda7: MOV EAX, EBX
0x34bda9: JMP 0x0034bd4c
0x34bdab: CALL 0x006fd6b0
0x34bdb0: UD2
; END FUNCTION sys_660

; FUNCTION sys_608 CONTEXT / separate function | ev_738694d1b7fb232d245b2fc2a4db775fa6ab33eb9f5acbaf31c883b6839b3a7b
; Ghidra body: 0x34bdc0..0x34c283
sys_608:
0x34bdc0: PUSH RBP
0x34bdc1: MOV RBP, RSP
0x34bdc4: PUSH R15
0x34bdc6: PUSH R14
0x34bdc8: PUSH R13
0x34bdca: PUSH R12
0x34bdcc: PUSH RBX
0x34bdcd: SUB RSP, 0x28
0x34bdd1: LEA R13, [0x391c310]
0x34bdd8: MOV RAX, qword ptr [R13]
0x34bddc: MOV qword ptr [RBP + -0x30], RAX
0x34bde0: MOV RBX, qword ptr [RDI + 0x8]
0x34bde4: MOV R15, qword ptr [RBX + 0x3e8]
0x34bdeb: TEST R15, R15
0x34bdee: JZ 0x0034c08c
0x34bdf4: MOV RAX, qword ptr [R15 + 0x10]
0x34bdf8: CMP qword ptr [RAX + 0x148], 0x0
0x34be00: JZ 0x0034c08c
0x34be06: MOV EAX, dword ptr [RSI + 0x8]
0x34be09: MOV R12D, dword ptr [RSI]
0x34be0c: MOV R14, qword ptr [RSI + 0x10]
0x34be10: LEA RSI, [0x1397f3d]
0x34be17: XOR EDX, EDX
0x34be19: MOV dword ptr [RBP + -0x3c], EAX
0x34be1c: MOV RDI, qword ptr GS:[0x0]
0x34be25: CALL 0x00c1a3e0
0x34be2a: LEA RSI, [RBP + -0x38]
0x34be2e: MOV EDX, 0x8
0x34be33: MOV RDI, R14
0x34be36: CALL 0x00259280
0x34be3b: MOV ECX, EAX
0x34be3d: MOV EAX, 0xe
0x34be42: TEST ECX, ECX
0x34be44: JNZ 0x0034c0b2
0x34be4a: CMP qword ptr [RBP + -0x38], 0x1a8
0x34be52: MOV EAX, 0x16
0x34be57: JNZ 0x0034c0b2
0x34be5d: MOV EDI, 0x1a8
0x34be62: MOV ESI, 0xa
0x34be67: MOV qword ptr [RBP + -0x50], R14
0x34be6b: CALL 0x00b2ac60
0x34be70: LEA RDI, [R15 + 0x70]
0x34be74: MOV R14, RAX
0x34be77: XOR ESI, ESI
0x34be79: XOR EDX, EDX
0x34be7b: XOR ECX, ECX
0x34be7d: MOV qword ptr [RBP + -0x48], RDI
0x34be81: CALL 0x00c4bb20
0x34be86: NOP word ptr CS:[RAX + RAX*0x1]
0x34be90: MOV R15, qword ptr [R15]
0x34be93: TEST R15, R15
0x34be96: JZ 0x0034c0cf
0x34be9c: CMP R12D, dword ptr [R15 + 0x28]
0x34bea0: JNZ 0x0034be90
0x34bea2: MOV ESI, 0x1a8
0x34bea7: MOV RDI, R14
0x34beaa: CALL 0x00258ff0
0x34beaf: MOV R12, qword ptr [R15 + 0x8]
0x34beb3: TEST R12, R12
0x34beb6: JZ 0x0034beff
0x34beb8: MOV ESI, 0x400
0x34bebd: MOV RDI, R12
0x34bec0: CALL 0x00444eb0
0x34bec5: CMP RAX, 0x6
0x34bec9: JC 0x0034beff
0x34becb: CMP byte ptr [R12], 0x2f
0x34bed0: JNZ 0x0034beff
0x34bed2: CMP byte ptr [R12 + 0x1], 0x68
0x34bed8: JNZ 0x0034beff
0x34beda: CMP byte ptr [R12 + 0x2], 0x6f
0x34bee0: JNZ 0x0034beff
0x34bee2: CMP byte ptr [R12 + 0x3], 0x73
0x34bee8: JNZ 0x0034beff
0x34beea: CMP byte ptr [R12 + 0x4], 0x74
0x34bef0: JNZ 0x0034beff
0x34bef2: CMP byte ptr [R12 + 0x5], 0x2f
0x34bef8: MOV ESI, 0x5c
0x34befd: JZ 0x0034bf04
0x34beff: MOV ESI, 0x2f
0x34bf04: MOV R12, qword ptr [R15 + 0x8]
0x34bf08: MOV RDI, R12
0x34bf0b: CALL 0x00272200
0x34bf10: LEA RSI, [RAX + 0x1]
0x34bf14: TEST RAX, RAX
0x34bf17: MOV EDX, 0x100
0x34bf1c: CMOVZ RSI, R12
0x34bf20: LEA R12, [R14 + 0x8]
0x34bf24: MOV RDI, R12
0x34bf27: CALL 0x00984440
0x34bf2c: MOV byte ptr [R14 + 0x107], 0x0
0x34bf34: MOV ESI, dword ptr [RBP + -0x3c]
0x34bf37: MOV EAX, dword ptr [R15 + 0x28]
0x34bf3b: MOV dword ptr [R14 + 0x108], EAX
0x34bf42: MOVZX EAX, word ptr [R15 + 0x70]
0x34bf47: MOV dword ptr [R14 + 0x10c], EAX
0x34bf4e: TEST SIL, 0x1
0x34bf52: JZ 0x0034bf78
0x34bf54: MOVZX ECX, word ptr [R15 + 0x11c]
0x34bf5c: MOV EDX, 0x108
0x34bf61: BEXTR EDX, ECX, EDX
0x34bf66: AND ECX, 0x1
0x34bf69: LEA ECX, [RDX + RCX*0x2]
0x34bf6c: SHL ECX, 0x10
0x34bf6f: OR ECX, EAX
0x34bf71: MOV dword ptr [R14 + 0x10c], ECX
0x34bf78: TEST SIL, 0x2
0x34bf7c: JZ 0x0034bfa4
0x34bf7e: TEST byte ptr [R15 + 0x11d], 0x1
0x34bf86: JNZ 0x0034bf97
0x34bf88: MOV EDI, 0x2
0x34bf8d: CALL 0x00b2bb00
0x34bf92: CMP EAX, 0x1
0x34bf95: JNZ 0x0034bfa4
0x34bf97: MOV ESI, 0x100
0x34bf9c: MOV RDI, R12
0x34bf9f: CALL 0x00258ff0
0x34bfa4: MOV RAX, qword ptr [R15 + 0x78]
0x34bfa8: MOV EDI, 0x2
0x34bfad: MOV qword ptr [R14 + 0x110], RAX
0x34bfb4: MOV EAX, dword ptr [R15 + 0x80]
0x34bfbb: MOV dword ptr [R14 + 0x118], EAX
0x34bfc2: MOV EAX, dword ptr [R15 + 0x88]
0x34bfc9: MOV dword ptr [R14 + 0x11c], EAX
0x34bfd0: MOV EAX, dword ptr [R15 + 0x90]
0x34bfd7: MOV dword ptr [R14 + 0x120], EAX
0x34bfde: MOV EAX, dword ptr [R15 + 0x98]
0x34bfe5: MOV dword ptr [R14 + 0x124], EAX
0x34bfec: MOV qword ptr [R14 + 0x138], 0x0
0x34bff7: MOV qword ptr [R14 + 0x140], 0x0
0x34c002: MOV RAX, qword ptr [R15 + 0xf8]
0x34c009: MOV qword ptr [R14 + 0x148], RAX
0x34c010: MOV RAX, qword ptr [R15 + 0x108]
0x34c017: MOV qword ptr [R14 + 0x150], RAX
0x34c01e: MOV EAX, dword ptr [R15 + 0x100]
0x34c025: MOV dword ptr [R14 + 0x158], EAX
0x34c02c: MOV EAX, dword ptr [R15 + 0x110]
0x34c033: MOV dword ptr [R14 + 0x15c], EAX
0x34c03a: MOV EAX, dword ptr [R15 + 0x20]
0x34c03e: MOV dword ptr [R14 + 0x1a4], EAX
0x34c045: CALL 0x00b2bb00
0x34c04a: TEST EAX, EAX
0x34c04c: JZ 0x0034c0f5
0x34c052: MOV RDI, R14
0x34c055: MOV ESI, 0x40
0x34c05a: MOV qword ptr [R14 + 0x128], 0x0
0x34c065: MOV qword ptr [R14 + 0x130], 0x0
0x34c070: MOV dword ptr [R14 + 0x1a0], 0x0
0x34c07b: ADD RDI, 0x160
0x34c082: CALL 0x00258ff0
0x34c087: JMP 0x0034c22d
0x34c08c: LEA RDI, [0x128a674]
0x34c093: LEA RDX, [0x12fbd8a]
0x34c09a: LEA RCX, [0x135ae30]
0x34c0a1: MOV ESI, 0x504
0x34c0a6: XOR EAX, EAX
0x34c0a8: CALL 0x00b22a30
0x34c0ad: MOV EAX, 0x1
0x34c0b2: MOV RCX, qword ptr [R13]
0x34c0b6: CMP RCX, qword ptr [RBP + -0x30]
0x34c0ba: JNZ 0x0034c27d
0x34c0c0: ADD RSP, 0x28
0x34c0c4: POP RBX
0x34c0c5: POP R12
0x34c0c7: POP R13
0x34c0c9: POP R14
0x34c0cb: POP R15
0x34c0cd: POP RBP
0x34c0ce: RET
0x34c0cf: MOV RDI, qword ptr [RBP + -0x48]
0x34c0d3: XOR ESI, ESI
0x34c0d5: XOR EDX, EDX
0x34c0d7: CALL 0x00c4c4b0
0x34c0dc: MOV ESI, 0x1a8
0x34c0e1: MOV RDI, R14
0x34c0e4: MOV EDX, 0xa
0x34c0e9: CALL 0x00b24250
0x34c0ee: MOV EAX, 0x3
0x34c0f3: JMP 0x0034c0b2
0x34c0f5: TEST byte ptr [R15 + 0x11d], 0x10
0x34c0fd: JNZ 0x0034c116
0x34c0ff: MOV RAX, qword ptr [R15 + 0xe8]
0x34c106: MOV qword ptr [R14 + 0x128], RAX
0x34c10d: MOV RAX, qword ptr [R15 + 0xf0]
0x34c114: JMP 0x0034c123
0x34c116: MOV qword ptr [R14 + 0x128], 0x0
0x34c121: XOR EAX, EAX
0x34c123: MOV qword ptr [R14 + 0x130], RAX
0x34c12a: CMP byte ptr [RBX + 0xc81], 0x0
0x34c131: JZ 0x0034c1d2
0x34c137: MOV ECX, dword ptr [R15 + 0x48]
0x34c13b: MOV EAX, 0x4
0x34c140: MOV dword ptr [R14 + 0x1a0], 0x0
0x34c14b: CMP ECX, 0x4
0x34c14e: CMOVC EAX, ECX
0x34c151: TEST ECX, ECX
0x34c153: JZ 0x0034c1c9
0x34c155: MOV ECX, EAX
0x34c157: MOV RDX, R14
0x34c15a: XOR ESI, ESI
0x34c15c: SHL RCX, 0x3
0x34c160: ADD RDX, 0x16c
0x34c167: LEA RCX, [RCX + RCX*0x2]
0x34c16b: JMP 0x0034c17a
0x34c16d: ADD RSI, 0x18
0x34c171: ADD RDX, 0x10
0x34c175: CMP RCX, RSI
0x34c178: JZ 0x0034c1c9
0x34c17a: MOV R8, qword ptr [R15 + 0x40]
0x34c17e: MOV RDI, qword ptr [R8 + RSI*0x1 + 0x8]
0x34c183: MOV qword ptr [RDX + -0xc], RDI
0x34c187: MOV EDI, dword ptr [R8 + RSI*0x1 + 0x10]
0x34c18c: MOV dword ptr [RDX + -0x4], EDI
0x34c18f: MOV dword ptr [RDX], 0x0
0x34c195: MOV RDI, qword ptr [R8 + RSI*0x1]
0x34c199: MOV EDI, dword ptr [RDI + 0xc]
0x34c19c: AND EDI, 0x1
0x34c19f: MOV dword ptr [RDX], EDI
0x34c1a1: MOV R9, qword ptr [R8 + RSI*0x1]
0x34c1a5: MOV R9D, dword ptr [R9 + 0xc]
0x34c1a9: TEST R9B, 0x2
0x34c1ad: JZ 0x0034c1bc
0x34c1af: OR EDI, 0x2
0x34c1b2: MOV dword ptr [RDX], EDI
0x34c1b4: MOV R8, qword ptr [R8 + RSI*0x1]
0x34c1b8: MOV R9D, dword ptr [R8 + 0xc]
0x34c1bc: TEST R9B, 0x4
0x34c1c0: JZ 0x0034c16d
0x34c1c2: OR EDI, 0x4
0x34c1c5: MOV dword ptr [RDX], EDI
0x34c1c7: JMP 0x0034c16d
0x34c1c9: MOV dword ptr [R14 + 0x1a0], EAX
0x34c1d0: JMP 0x0034c22d
0x34c1d2: MOV RAX, qword ptr [R15 + 0x50]
0x34c1d6: MOV RAX, qword ptr [RAX + 0x8]
0x34c1da: MOV qword ptr [R14 + 0x160], RAX
0x34c1e1: MOV RAX, qword ptr [R15 + 0x50]
0x34c1e5: MOV EAX, dword ptr [RAX + 0x10]
0x34c1e8: MOV dword ptr [R14 + 0x168], EAX
0x34c1ef: MOV dword ptr [R14 + 0x16c], 0x5
0x34c1fa: MOV RAX, qword ptr [R15 + 0x60]
0x34c1fe: MOV RAX, qword ptr [RAX + 0x8]
0x34c202: MOV qword ptr [R14 + 0x170], RAX
0x34c209: MOV RAX, qword ptr [R15 + 0x60]
0x34c20d: MOV EAX, dword ptr [RAX + 0x10]
0x34c210: MOV dword ptr [R14 + 0x178], EAX
0x34c217: MOV dword ptr [R14 + 0x17c], 0x3
0x34c222: MOV dword ptr [R14 + 0x1a0], 0x2
0x34c22d: MOV RDI, qword ptr [RBP + -0x48]
0x34c231: XOR ESI, ESI
0x34c233: XOR EDX, EDX
0x34c235: CALL 0x00c4c4b0
0x34c23a: MOV RDI, qword ptr GS:[0x0]
0x34c243: LEA RSI, [0x134f297]
0x34c24a: XOR EDX, EDX
0x34c24c: CALL 0x00c1a3e0
0x34c251: MOV RSI, qword ptr [RBP + -0x50]
0x34c255: MOV EDX, 0x1a8
0x34c25a: MOV RDI, R14
0x34c25d: CALL 0x002591d0
0x34c262: MOV ESI, 0x1a8
0x34c267: MOV RDI, R14
0x34c26a: MOV EDX, 0xa
0x34c26f: MOV EBX, EAX
0x34c271: CALL 0x00b24250
0x34c276: MOV EAX, EBX
0x34c278: JMP 0x0034c0b2
0x34c27d: CALL 0x006fd6b0
0x34c282: UD2
; END FUNCTION sys_608

; FUNCTION sub_34c290 CONTEXT / separate function | ev_6cf6a3576d9cc0b395f57d7d090a43d5d60e62eb688868851fc04dd699fec14a
; Ghidra body: 0x34c290..0x34c2e5
sub_34c290:
0x34c290: PUSH RBP
0x34c291: MOV RBP, RSP
0x34c294: PUSH R14
0x34c296: PUSH RBX
0x34c297: XOR R14D, R14D
0x34c29a: TEST RDI, RDI
0x34c29d: JZ 0x0034c2de
0x34c29f: MOV ESI, 0x400
0x34c2a4: MOV RBX, RDI
0x34c2a7: CALL 0x00444eb0
0x34c2ac: CMP RAX, 0x6
0x34c2b0: JC 0x0034c2de
0x34c2b2: CMP byte ptr [RBX], 0x2f
0x34c2b5: JNZ 0x0034c2db
0x34c2b7: CMP byte ptr [RBX + 0x1], 0x68
0x34c2bb: JNZ 0x0034c2db
0x34c2bd: CMP byte ptr [RBX + 0x2], 0x6f
0x34c2c1: JNZ 0x0034c2db
0x34c2c3: CMP byte ptr [RBX + 0x3], 0x73
0x34c2c7: JNZ 0x0034c2db
0x34c2c9: CMP byte ptr [RBX + 0x4], 0x74
0x34c2cd: JNZ 0x0034c2db
0x34c2cf: CMP byte ptr [RBX + 0x5], 0x2f
0x34c2d3: MOV R14D, 0x1
0x34c2d9: JZ 0x0034c2de
0x34c2db: XOR R14D, R14D
0x34c2de: MOV EAX, R14D
0x34c2e1: POP RBX
0x34c2e2: POP R14
0x34c2e4: POP RBP
0x34c2e5: RET
; END FUNCTION sub_34c290

; FUNCTION sub_34c2f0 CONTEXT / separate function | ev_face82640cb3d9e3fa1f2abcda2ff5bc4a8573c256023184d913474158711de6
; Ghidra body: 0x34c2f0..0x34c317
sub_34c2f0:
0x34c2f0: PUSH RBP
0x34c2f1: MOV RBP, RSP
0x34c2f4: PUSH RBX
0x34c2f5: PUSH RAX
0x34c2f6: MOV ESI, 0x5c
0x34c2fb: MOV RBX, RDI
0x34c2fe: CALL 0x00272200
0x34c303: LEA RCX, [RAX + 0x1]
0x34c307: TEST RAX, RAX
0x34c30a: CMOVZ RCX, RBX
0x34c30e: MOV RAX, RCX
0x34c311: ADD RSP, 0x8
0x34c315: POP RBX
0x34c316: POP RBP
0x34c317: RET
; END FUNCTION sub_34c2f0

; FUNCTION sub_34c320 CONTEXT / separate function | ev_e6b0d7d043031dc452fb27b7db4614db0bb2a47a8308e40cd8c3cda21ef8b422
; Ghidra body: 0x34c320..0x34c347
sub_34c320:
0x34c320: PUSH RBP
0x34c321: MOV RBP, RSP
0x34c324: PUSH RBX
0x34c325: PUSH RAX
0x34c326: MOV ESI, 0x2f
0x34c32b: MOV RBX, RDI
0x34c32e: CALL 0x00272200
0x34c333: LEA RCX, [RAX + 0x1]
0x34c337: TEST RAX, RAX
0x34c33a: CMOVZ RCX, RBX
0x34c33e: MOV RAX, RCX
0x34c341: ADD RSP, 0x8
0x34c345: POP RBX
0x34c346: POP RBP
0x34c347: RET
; END FUNCTION sub_34c320

; FUNCTION sys_656 CONTEXT / separate function | ev_88a1bf476d98a26e64eb2a97d62a07f4fcbf40d3da73f0385c0750eb4de8964d
; Ghidra body: 0x34c350..0x34c4fc, 0x34c500..0x34c66d
sys_656:
0x34c350: PUSH RBP
0x34c351: MOV RBP, RSP
0x34c354: PUSH R15
0x34c356: PUSH R14
0x34c358: PUSH R13
0x34c35a: PUSH R12
0x34c35c: PUSH RBX
0x34c35d: SUB RSP, 0x18
0x34c361: LEA R12, [0x391c310]
0x34c368: MOV RAX, qword ptr [R12]
0x34c36c: MOV qword ptr [RBP + -0x30], RAX
0x34c370: MOV RAX, qword ptr [RDI + 0x8]
0x34c374: MOV R13D, dword ptr [RSI]
0x34c377: MOV RBX, qword ptr [RSI + 0x8]
0x34c37b: MOV R14, qword ptr [RAX + 0x3e8]
0x34c382: CALL 0x00acce10
0x34c387: TEST EAX, EAX
0x34c389: JNZ 0x0034c398
0x34c38b: CALL 0x00acce50
0x34c390: TEST EAX, EAX
0x34c392: JZ 0x0034c5be
0x34c398: TEST R14, R14
0x34c39b: JZ 0x0034c59d
0x34c3a1: MOV RAX, qword ptr [R14 + 0x10]
0x34c3a5: CMP qword ptr [RAX + 0x148], 0x0
0x34c3ad: JZ 0x0034c59d
0x34c3b3: MOV RDI, qword ptr GS:[0x0]
0x34c3bc: LEA RSI, [0x1397f3d]
0x34c3c3: XOR EDX, EDX
0x34c3c5: CALL 0x00c1a3e0
0x34c3ca: LEA RSI, [RBP + -0x38]
0x34c3ce: MOV EDX, 0x8
0x34c3d3: MOV RDI, RBX
0x34c3d6: CALL 0x00259280
0x34c3db: MOV ECX, EAX
0x34c3dd: MOV EAX, 0xe
0x34c3e2: TEST ECX, ECX
0x34c3e4: JNZ 0x0034c5c3
0x34c3ea: CMP qword ptr [RBP + -0x38], 0x160
0x34c3f2: MOV EAX, 0x16
0x34c3f7: JNZ 0x0034c5c3
0x34c3fd: MOV EDI, 0x160
0x34c402: MOV ESI, 0xa
0x34c407: CALL 0x00b2ac60
0x34c40c: LEA RDI, [R14 + 0x70]
0x34c410: MOV R15, RAX
0x34c413: XOR ESI, ESI
0x34c415: XOR EDX, EDX
0x34c417: XOR ECX, ECX
0x34c419: MOV qword ptr [RBP + -0x40], RDI
0x34c41d: CALL 0x00c4bb20
0x34c422: NOP word ptr CS:[RAX + RAX*0x1]
0x34c430: MOV R14, qword ptr [R14]
0x34c433: TEST R14, R14
0x34c436: JZ 0x0034c5e0
0x34c43c: CMP R13D, dword ptr [R14 + 0x28]
0x34c440: JNZ 0x0034c430
0x34c442: MOV ESI, 0x160
0x34c447: MOV RDI, R15
0x34c44a: CALL 0x00258ff0
0x34c44f: MOV RAX, qword ptr [RBP + -0x38]
0x34c453: MOV qword ptr [R15], RAX
0x34c456: MOV R13, qword ptr [R14 + 0x8]
0x34c45a: TEST R13, R13
0x34c45d: JZ 0x0034c4a1
0x34c45f: MOV ESI, 0x400
0x34c464: MOV RDI, R13
0x34c467: CALL 0x00444eb0
0x34c46c: CMP RAX, 0x6
0x34c470: JC 0x0034c4a1
0x34c472: CMP byte ptr [R13], 0x2f
0x34c477: JNZ 0x0034c4a1
0x34c479: CMP byte ptr [R13 + 0x1], 0x68
0x34c47e: JNZ 0x0034c4a1
0x34c480: CMP byte ptr [R13 + 0x2], 0x6f
0x34c485: JNZ 0x0034c4a1
0x34c487: CMP byte ptr [R13 + 0x3], 0x73
0x34c48c: JNZ 0x0034c4a1
0x34c48e: CMP byte ptr [R13 + 0x4], 0x74
0x34c493: JNZ 0x0034c4a1
0x34c495: CMP byte ptr [R13 + 0x5], 0x2f
0x34c49a: MOV ESI, 0x5c
0x34c49f: JZ 0x0034c4a6
0x34c4a1: MOV ESI, 0x2f
0x34c4a6: MOV R13, qword ptr [R14 + 0x8]
0x34c4aa: MOV RDI, R13
0x34c4ad: CALL 0x00272200
0x34c4b2: LEA RSI, [RAX + 0x1]
0x34c4b6: TEST RAX, RAX
0x34c4b9: LEA RDI, [R15 + 0x8]
0x34c4bd: MOV EDX, 0x100
0x34c4c2: CMOVZ RSI, R13
0x34c4c6: CALL 0x00984440
0x34c4cb: MOV byte ptr [R15 + 0x107], 0x0
0x34c4d3: MOV dword ptr [R15 + 0x148], 0x0
0x34c4de: CMP dword ptr [R14 + 0x48], 0x0
0x34c4e3: JZ 0x0034c606
0x34c4e9: LEA RAX, [R15 + 0x108]
0x34c4f0: MOV EDX, 0x4
0x34c4f5: XOR ECX, ECX
0x34c4f7: XOR ESI, ESI
0x34c4f9: XOR EDI, EDI
0x34c4fb: JMP 0x0034c52c
0x34c500: MOV EDI, dword ptr [R15 + 0x148]
0x34c507: INC RSI
0x34c50a: INC EDI
0x34c50c: MOV dword ptr [R15 + 0x148], EDI
0x34c513: MOV R8D, dword ptr [R14 + 0x48]
0x34c517: CMP R8D, 0x4
0x34c51b: CMOVNC R8D, EDX
0x34c51f: ADD RCX, 0x18
0x34c523: CMP RSI, R8
0x34c526: JNC 0x0034c606
0x34c52c: MOV R9, qword ptr [R14 + 0x40]
0x34c530: MOV R10D, EDI
0x34c533: SHL R10, 0x4
0x34c537: LEA RDI, [RAX + R10*0x1]
0x34c53b: MOV R8, qword ptr [R9 + RCX*0x1 + 0x8]
0x34c540: MOV qword ptr [RAX + R10*0x1], R8
0x34c544: MOV R8D, dword ptr [R9 + RCX*0x1 + 0x10]
0x34c549: MOV dword ptr [RAX + R10*0x1 + 0x8], R8D
0x34c54e: MOV dword ptr [RAX + R10*0x1 + 0xc], 0x0
0x34c557: MOV R8, qword ptr [R9 + RCX*0x1]
0x34c55b: MOV R8D, dword ptr [R8 + 0xc]
0x34c55f: AND R8D, 0x1
0x34c563: MOV dword ptr [RAX + R10*0x1 + 0xc], R8D
0x34c568: MOV R10, qword ptr [R9 + RCX*0x1]
0x34c56c: MOV R10D, dword ptr [R10 + 0xc]
0x34c570: TEST R10B, 0x2
0x34c574: JZ 0x0034c586
0x34c576: OR R8D, 0x2
0x34c57a: MOV dword ptr [RDI + 0xc], R8D
0x34c57e: MOV R9, qword ptr [R9 + RCX*0x1]
0x34c582: MOV R10D, dword ptr [R9 + 0xc]
0x34c586: TEST R10B, 0x4
0x34c58a: JZ 0x0034c500
0x34c590: OR R8D, 0x4
0x34c594: MOV dword ptr [RDI + 0xc], R8D
0x34c598: JMP 0x0034c500
0x34c59d: LEA RDI, [0x13a3d13]
0x34c5a4: LEA RDX, [0x12fbd8a]
0x34c5ab: LEA RCX, [0x135ae30]
0x34c5b2: MOV ESI, 0x5b4
0x34c5b7: XOR EAX, EAX
0x34c5b9: CALL 0x00b22a30
0x34c5be: MOV EAX, 0x1
0x34c5c3: MOV RCX, qword ptr [R12]
0x34c5c7: CMP RCX, qword ptr [RBP + -0x30]
0x34c5cb: JNZ 0x0034c667
0x34c5d1: ADD RSP, 0x18
0x34c5d5: POP RBX
0x34c5d6: POP R12
0x34c5d8: POP R13
0x34c5da: POP R14
0x34c5dc: POP R15
0x34c5de: POP RBP
0x34c5df: RET
0x34c5e0: MOV RDI, qword ptr [RBP + -0x40]
0x34c5e4: XOR ESI, ESI
0x34c5e6: XOR EDX, EDX
0x34c5e8: CALL 0x00c4c4b0
0x34c5ed: MOV ESI, 0x160
0x34c5f2: MOV RDI, R15
0x34c5f5: MOV EDX, 0xa
0x34c5fa: CALL 0x00b24250
0x34c5ff: MOV EAX, 0x3
0x34c604: JMP 0x0034c5c3
0x34c606: MOV RDI, R15
0x34c609: MOV RSI, R14
0x34c60c: ADD RDI, 0x14c
0x34c613: CALL 0x00b2b740
0x34c618: MOV RDI, qword ptr [RBP + -0x40]
0x34c61c: XOR ESI, ESI
0x34c61e: XOR EDX, EDX
0x34c620: CALL 0x00c4c4b0
0x34c625: MOV RDI, qword ptr GS:[0x0]
0x34c62e: LEA RSI, [0x134f297]
0x34c635: XOR EDX, EDX
0x34c637: CALL 0x00c1a3e0
0x34c63c: MOV EDX, 0x160
0x34c641: MOV RDI, R15
0x34c644: MOV RSI, RBX
0x34c647: CALL 0x002591d0
0x34c64c: MOV ESI, 0x160
0x34c651: MOV RDI, R15
0x34c654: MOV EDX, 0xa
0x34c659: MOV EBX, EAX
0x34c65b: CALL 0x00b24250
0x34c660: MOV EAX, EBX
0x34c662: JMP 0x0034c5c3
0x34c667: CALL 0x006fd6b0
0x34c66c: UD2
; END FUNCTION sys_656

; FUNCTION sys_672 CONTEXT / separate function | ev_7a9ddfca4cf41dc939f659fe932a537fcb74d606f26cfa93ae145c3b6a99b506
; Ghidra body: 0x34c670..0x34c703
sys_672:
0x34c670: PUSH RBP
0x34c671: MOV RBP, RSP
0x34c674: PUSH R15
0x34c676: PUSH R14
0x34c678: PUSH RBX
0x34c679: PUSH RAX
0x34c67a: MOV RAX, qword ptr [RDI + 0x8]
0x34c67e: MOV RBX, RSI
0x34c681: MOV R14, RDI
0x34c684: MOV R15, qword ptr [RAX + 0x3e8]
0x34c68b: CALL 0x00acce10
0x34c690: TEST EAX, EAX
0x34c692: JNZ 0x0034c69d
0x34c694: CALL 0x00acce50
0x34c699: TEST EAX, EAX
0x34c69b: JZ 0x0034c6f4
0x34c69d: TEST R15, R15
0x34c6a0: JZ 0x0034c6d3
0x34c6a2: MOV RAX, qword ptr [R15 + 0x10]
0x34c6a6: CMP qword ptr [RAX + 0x148], 0x0
0x34c6ae: JZ 0x0034c6d3
0x34c6b0: MOV RDI, qword ptr [R14 + 0x8]
0x34c6b4: MOV RSI, qword ptr [RBX]
0x34c6b7: MOV RDX, qword ptr [RBX + 0x8]
0x34c6bb: MOV R8, qword ptr [RBX + 0x10]
0x34c6bf: MOV ECX, 0x1
0x34c6c4: ADD RSP, 0x8
0x34c6c8: POP RBX
0x34c6c9: POP R14
0x34c6cb: POP R15
0x34c6cd: POP RBP
0x34c6ce: JMP 0x0034b540
0x34c6d3: LEA RDI, [0x1306572]
0x34c6da: LEA RDX, [0x12fbd8a]
0x34c6e1: LEA RCX, [0x135ae30]
0x34c6e8: MOV ESI, 0x617
0x34c6ed: XOR EAX, EAX
0x34c6ef: CALL 0x00b22a30
0x34c6f4: MOV EAX, 0x1
0x34c6f9: ADD RSP, 0x8
0x34c6fd: POP RBX
0x34c6fe: POP R14
0x34c700: POP R15
0x34c702: POP RBP
0x34c703: RET
; END FUNCTION sys_672

; FUNCTION sub_34c710 CONTEXT / separate function | ev_4dd2c190b62dc1f25af97124193022f9e785c5a8c47bd0b4c5f1c8b554e73c2e
; Ghidra body: 0x34c710..0x34c74e
sub_34c710:
0x34c710: PUSH RBP
0x34c711: MOV RBP, RSP
0x34c714: PUSH R14
0x34c716: PUSH RBX
0x34c717: MOV ESI, 0x2f
0x34c71c: MOV RBX, RDI
0x34c71f: CALL 0x00272200
0x34c724: LEA R14, [RAX + 0x1]
0x34c728: TEST RAX, RAX
0x34c72b: MOV ESI, 0x5c
0x34c730: CMOVZ R14, RBX
0x34c734: MOV RDI, R14
0x34c737: CALL 0x00272200
0x34c73c: LEA RCX, [RAX + 0x1]
0x34c740: TEST RAX, RAX
0x34c743: CMOVZ RCX, R14
0x34c747: MOV RAX, RCX
0x34c74a: POP RBX
0x34c74b: POP R14
0x34c74d: POP RBP
0x34c74e: RET
; END FUNCTION sub_34c710

; FUNCTION sys_596 CONTEXT / separate function | ev_a73c4371fc8e8c8a38299cf6d1a1ad382d19dcbd574996f155a51bb152f723c2
; Ghidra body: 0x34c750..0x34c80c
sys_596:
0x34c750: PUSH RBP
0x34c751: MOV RBP, RSP
0x34c754: PUSH R15
0x34c756: PUSH R14
0x34c758: PUSH RBX
0x34c759: PUSH RAX
0x34c75a: MOV RAX, qword ptr [RDI + 0x8]
0x34c75e: MOV R14, qword ptr [RAX + 0x3e8]
0x34c765: TEST R14, R14
0x34c768: JZ 0x0034c7da
0x34c76a: MOV RAX, qword ptr [R14 + 0x10]
0x34c76e: CMP qword ptr [RAX + 0x148], 0x0
0x34c776: JZ 0x0034c7da
0x34c778: LEA R15, [R14 + 0x70]
0x34c77c: XOR EBX, EBX
0x34c77e: XOR ESI, ESI
0x34c780: XOR EDX, EDX
0x34c782: XOR ECX, ECX
0x34c784: MOV RDI, R15
0x34c787: CALL 0x00c4bb20
0x34c78c: MOV RSI, qword ptr [R14 + 0x10]
0x34c790: MOV RDI, R14
0x34c793: CALL 0x00b2b1a0
0x34c798: MOV RDI, R15
0x34c79b: MOV R14D, EAX
0x34c79e: XOR ESI, ESI
0x34c7a0: XOR EDX, EDX
0x34c7a2: CALL 0x00c4c4b0
0x34c7a7: TEST R14D, R14D
0x34c7aa: JZ 0x0034c800
0x34c7ac: LEA RDI, [0x1295072]
0x34c7b3: LEA RDX, [0x12fbd8a]
0x34c7ba: LEA RCX, [0x1383f80]
0x34c7c1: MOV ESI, 0x664
0x34c7c6: MOV R8D, 0x16
0x34c7cc: XOR EAX, EAX
0x34c7ce: MOV EBX, 0x16
0x34c7d3: CALL 0x00b22a30
0x34c7d8: JMP 0x0034c800
0x34c7da: LEA RDI, [0x1295072]
0x34c7e1: LEA RDX, [0x12fbd8a]
0x34c7e8: LEA RCX, [0x135ae30]
0x34c7ef: MOV ESI, 0x65a
0x34c7f4: XOR EAX, EAX
0x34c7f6: CALL 0x00b22a30
0x34c7fb: MOV EBX, 0x1
0x34c800: MOV EAX, EBX
0x34c802: ADD RSP, 0x8
0x34c806: POP RBX
0x34c807: POP R14
0x34c809: POP R15
0x34c80b: POP RBP
0x34c80c: RET
; END FUNCTION sys_596

; FUNCTION sub_34c810 CONTEXT / separate function | ev_71fa44ccafcf89e93fd6b715cfee5d8a9ba48924c223499afd835b2ef6d2a36b
; Ghidra body: 0x34c810..0x34c81a
sub_34c810:
0x34c810: PUSH RBP
0x34c811: MOV RBP, RSP
0x34c814: MOV EAX, 0x4e
0x34c819: POP RBP
0x34c81a: RET
; END FUNCTION sub_34c810

; FUNCTION sub_34c820 CONTEXT / separate function | ev_fdca02471c1708a4b5da8a29c20fc60e94f789962f67397eac22828730572b2e
; Ghidra body: 0x34c820..0x34c8ac
sub_34c820:
0x34c820: PUSH RBP
0x34c821: MOV RBP, RSP
0x34c824: PUSH R14
0x34c826: PUSH RBX
0x34c827: SUB RSP, 0x10
0x34c82b: LEA RBX, [0x391c310]
0x34c832: MOV RAX, qword ptr [RBX]
0x34c835: MOV qword ptr [RBP + -0x18], RAX
0x34c839: MOV R14, qword ptr [RDI + 0x8]
0x34c83d: CALL 0x00acce10
0x34c842: MOV ECX, EAX
0x34c844: MOV EAX, 0x2d
0x34c849: CMP ECX, 0x1
0x34c84c: JNZ 0x0034c894
0x34c84e: MOV RAX, qword ptr GS:[0x0]
0x34c857: MOV RDI, qword ptr [RAX + 0x8]
0x34c85b: LEA RSI, [RBP + -0x1c]
0x34c85f: CALL 0x009f81c0
0x34c864: MOV ECX, EAX
0x34c866: XOR EAX, EAX
0x34c868: TEST ECX, ECX
0x34c86a: JNZ 0x0034c894
0x34c86c: CMP dword ptr [RBP + -0x1c], 0xffffff
0x34c873: JA 0x0034c894
0x34c875: MOV RCX, qword ptr [R14 + 0x3e8]
0x34c87c: MOV dword ptr [RCX + 0x150], 0x1
0x34c886: MOV RCX, qword ptr [R14 + 0x3e8]
0x34c88d: OR dword ptr [RCX + 0x140], 0x40
0x34c894: MOV RCX, qword ptr [RBX]
0x34c897: CMP RCX, qword ptr [RBP + -0x18]
0x34c89b: JNZ 0x0034c8a6
0x34c89d: ADD RSP, 0x10
0x34c8a1: POP RBX
0x34c8a2: POP R14
0x34c8a4: POP RBP
0x34c8a5: RET
0x34c8a6: CALL 0x006fd6b0
0x34c8ab: UD2
; END FUNCTION sub_34c820

; FUNCTION sub_34c8b0 CONTEXT / separate function | ev_c990b88c62de8b10ec53707805454f866f1f07d004cac1704b390e0b6690cb81
; Ghidra body: 0x34c8b0..0x34c8ba
sub_34c8b0:
0x34c8b0: PUSH RBP
0x34c8b1: MOV RBP, RSP
0x34c8b4: MOV EAX, 0x4e
0x34c8b9: POP RBP
0x34c8ba: RET
; END FUNCTION sub_34c8b0

; FUNCTION sub_34c8c0 CONTEXT / separate function | ev_6b6ac4d85d73f846dfd5ec8204a11a2556c5a2ec5c1dbed09ea07536f0fab693
; Ghidra body: 0x34c8c0..0x34c98a
sub_34c8c0:
0x34c8c0: PUSH RBP
0x34c8c1: MOV RBP, RSP
0x34c8c4: PUSH R15
0x34c8c6: PUSH R14
0x34c8c8: PUSH R12
0x34c8ca: PUSH RBX
0x34c8cb: MOV R12, qword ptr [RDI + 0x3e8]
0x34c8d2: MOV EAX, 0x2
0x34c8d7: TEST R12, R12
0x34c8da: JZ 0x0034c982
0x34c8e0: MOV RCX, qword ptr [R12 + 0x10]
0x34c8e5: CMP qword ptr [RCX + 0x148], 0x0
0x34c8ed: JZ 0x0034c982
0x34c8f3: CMP qword ptr [R12 + 0xc8], 0x0
0x34c8fc: JZ 0x0034c982
0x34c902: MOV RBX, RSI
0x34c905: MOV ESI, 0x60
0x34c90a: MOV R14D, 0x60
0x34c910: MOV RDI, RBX
0x34c913: CALL 0x00258ff0
0x34c918: MOV RAX, qword ptr [R12 + 0xd0]
0x34c920: MOV R15, qword ptr [R12 + 0xc8]
0x34c928: LEA RSI, [0x1397f3d]
0x34c92f: CMP RAX, 0x60
0x34c933: CMOVC R14, RAX
0x34c937: MOV RDI, qword ptr GS:[0x0]
0x34c940: XOR EDX, EDX
0x34c942: CALL 0x00c1a3e0
0x34c947: MOV RDI, R15
0x34c94a: MOV RSI, RBX
0x34c94d: MOV RDX, R14
0x34c950: CALL 0x00259280
0x34c955: TEST EAX, EAX
0x34c957: JNZ 0x0034c982
0x34c959: MOV RAX, qword ptr [RBX]
0x34c95c: CMP RAX, 0x5f
0x34c960: JA 0x0034c973
0x34c962: MOV ESI, 0x60
0x34c967: LEA RDI, [RBX + RAX*0x1]
0x34c96b: SUB RSI, RAX
0x34c96e: CALL 0x00258ff0
0x34c973: XOR EAX, EAX
0x34c975: CMP dword ptr [RBX + 0x8], 0x4942524f
0x34c97c: SETNZ AL
0x34c97f: SHL EAX, 0x3
0x34c982: POP RBX
0x34c983: POP R12
0x34c985: POP R14
0x34c987: POP R15
0x34c989: POP RBP
0x34c98a: RET
; END FUNCTION sub_34c8c0

; FUNCTION sys_598 CONTEXT / separate function | ev_3deac02c917aedc938868db2181d36528335c328bf6a6707699e9072bebd5fa5
; Ghidra body: 0x34c990..0x34ca97
sys_598:
0x34c990: PUSH RBP
0x34c991: MOV RBP, RSP
0x34c994: PUSH R15
0x34c996: PUSH R14
0x34c998: PUSH RBX
0x34c999: SUB RSP, 0x18
0x34c99d: LEA R15, [0x391c310]
0x34c9a4: MOV RAX, qword ptr [R15]
0x34c9a7: MOV qword ptr [RBP + -0x20], RAX
0x34c9ab: MOV RAX, qword ptr [RDI + 0x8]
0x34c9af: MOV RAX, qword ptr [RAX + 0x3e8]
0x34c9b6: TEST RAX, RAX
0x34c9b9: JZ 0x0034ca57
0x34c9bf: MOV RCX, qword ptr [RAX + 0x10]
0x34c9c3: CMP qword ptr [RCX + 0x148], 0x0
0x34c9cb: JZ 0x0034ca57
0x34c9d1: MOV RCX, qword ptr [RAX + 0xc8]
0x34c9d8: MOV R14, qword ptr [RSI]
0x34c9db: MOV RBX, qword ptr [RSI + 0x8]
0x34c9df: LEA RSI, [0x134f297]
0x34c9e6: XOR EDX, EDX
0x34c9e8: MOV qword ptr [RBP + -0x28], RCX
0x34c9ec: MOV RAX, qword ptr [RAX + 0xd0]
0x34c9f3: MOV qword ptr [RBP + -0x30], RAX
0x34c9f7: MOV RDI, qword ptr GS:[0x0]
0x34ca00: CALL 0x00c1a3e0
0x34ca05: LEA RDI, [RBP + -0x28]
0x34ca09: MOV EDX, 0x8
0x34ca0e: MOV RSI, R14
0x34ca11: CALL 0x002591d0
0x34ca16: MOV ECX, EAX
0x34ca18: MOV EAX, 0xe
0x34ca1d: TEST ECX, ECX
0x34ca1f: JNZ 0x0034ca7d
0x34ca21: MOV RDI, qword ptr GS:[0x0]
0x34ca2a: LEA RSI, [0x134f297]
0x34ca31: XOR EDX, EDX
0x34ca33: CALL 0x00c1a3e0
0x34ca38: LEA RDI, [RBP + -0x30]
0x34ca3c: MOV EDX, 0x8
0x34ca41: MOV RSI, RBX
0x34ca44: CALL 0x002591d0
0x34ca49: MOV ECX, EAX
0x34ca4b: TEST EAX, EAX
0x34ca4d: MOV EAX, 0xe
0x34ca52: CMOVZ EAX, ECX
0x34ca55: JMP 0x0034ca7d
0x34ca57: LEA RDI, [0x138e7d0]
0x34ca5e: LEA RDX, [0x12fbd8a]
0x34ca65: LEA RCX, [0x135ae30]
0x34ca6c: MOV ESI, 0x717
0x34ca71: XOR EAX, EAX
0x34ca73: CALL 0x00b22a30
0x34ca78: MOV EAX, 0x1
0x34ca7d: MOV RCX, qword ptr [R15]
0x34ca80: CMP RCX, qword ptr [RBP + -0x20]
0x34ca84: JNZ 0x0034ca91
0x34ca86: ADD RSP, 0x18
0x34ca8a: POP RBX
0x34ca8b: POP R14
0x34ca8d: POP R15
0x34ca8f: POP RBP
0x34ca90: RET
0x34ca91: CALL 0x006fd6b0
0x34ca96: UD2
; END FUNCTION sys_598

; FUNCTION sys_599 CONTEXT / separate function | ev_4955ba1c84b30e8578a861cd84e723393f0c2de28003609406f3e5c6f48149c6
; Ghidra body: 0x34caa0..0x34cbd0, 0x34cbe0..0x34cc84
sys_599:
0x34caa0: PUSH RBP
0x34caa1: MOV RBP, RSP
0x34caa4: PUSH R15
0x34caa6: PUSH R14
0x34caa8: PUSH R13
0x34caaa: PUSH R12
0x34caac: PUSH RBX
0x34caad: SUB RSP, 0x18
0x34cab1: LEA R13, [0x391c310]
0x34cab8: MOV RAX, qword ptr [R13]
0x34cabc: MOV qword ptr [RBP + -0x30], RAX
0x34cac0: MOV R14, qword ptr GS:[0x0]
0x34cac9: MOV RAX, qword ptr [R14 + 0x8]
0x34cacd: MOV RAX, qword ptr [RAX + 0x3e8]
0x34cad4: TEST RAX, RAX
0x34cad7: JZ 0x0034cb8e
0x34cadd: MOV RAX, qword ptr [RAX + 0x10]
0x34cae1: CMP qword ptr [RAX + 0x148], 0x0
0x34cae9: JZ 0x0034cb8e
0x34caef: MOV RAX, qword ptr [RDI + 0x8]
0x34caf3: MOV RBX, RDI
0x34caf6: XOR ESI, ESI
0x34caf8: XOR EDX, EDX
0x34cafa: XOR ECX, ECX
0x34cafc: MOV RDI, qword ptr [RAX + 0x3e8]
0x34cb03: ADD RDI, 0x70
0x34cb07: CALL 0x00c4bb20
0x34cb0c: MOV RDI, qword ptr [RBX + 0x8]
0x34cb10: CALL 0x00b27250
0x34cb15: TEST EAX, EAX
0x34cb17: JNZ 0x0034cb22
0x34cb19: MOV RDI, qword ptr [RBX + 0x8]
0x34cb1d: CALL 0x00b277c0
0x34cb22: MOV RCX, qword ptr [RBX + 0x8]
0x34cb26: XOR ESI, ESI
0x34cb28: XOR EDX, EDX
0x34cb2a: MOV R15D, EAX
0x34cb2d: MOV RDI, qword ptr [RCX + 0x3e8]
0x34cb34: ADD RDI, 0x70
0x34cb38: CALL 0x00c4c4b0
0x34cb3d: MOV EAX, R15D
0x34cb40: TEST R15D, R15D
0x34cb43: JNZ 0x0034cbb4
0x34cb45: MOV RDI, qword ptr [R14 + 0x8]
0x34cb49: CALL 0x0034cc90
0x34cb4e: MOV dword ptr [RBP + -0x34], EAX
0x34cb51: TEST EAX, EAX
0x34cb53: JNZ 0x0034cbb4
0x34cb55: LEA RDI, [0x1306591]
0x34cb5c: CALL 0x0073e2e0
0x34cb61: TEST RAX, RAX
0x34cb64: JZ 0x0034cc77
0x34cb6a: MOV R15, RAX
0x34cb6d: MOV EAX, dword ptr [RAX + 0xc]
0x34cb70: LEA ECX, [RAX + 0x1]
0x34cb73: MOV dword ptr [R15 + 0xc], ECX
0x34cb77: MOV R14, qword ptr [R15 + 0x40]
0x34cb7b: TEST R14, R14
0x34cb7e: JZ 0x0034cc4d
0x34cb84: MOV qword ptr [RBP + -0x40], R15
0x34cb88: ADD R15, 0x28
0x34cb8c: JMP 0x0034cc05
0x34cb8e: LEA RDI, [0x12a8ef3]
0x34cb95: LEA RDX, [0x12fbd8a]
0x34cb9c: LEA RCX, [0x135ae30]
0x34cba3: MOV ESI, 0x760
0x34cba8: XOR EAX, EAX
0x34cbaa: CALL 0x00b22a30
0x34cbaf: MOV EAX, 0x16
0x34cbb4: MOV RCX, qword ptr [R13]
0x34cbb8: CMP RCX, qword ptr [RBP + -0x30]
0x34cbbc: JNZ 0x0034cc7e
0x34cbc2: ADD RSP, 0x18
0x34cbc6: POP RBX
0x34cbc7: POP R12
0x34cbc9: POP R13
0x34cbcb: POP R14
0x34cbcd: POP R15
0x34cbcf: POP RBP
0x34cbd0: RET
0x34cbe0: MOV RDI, qword ptr [R14 + 0x18]
0x34cbe4: MOV RSI, qword ptr [RBX + 0x8]
0x34cbe8: LEA RDX, [RBP + -0x34]
0x34cbec: CALL R12
0x34cbef: MOV RDI, R15
0x34cbf2: XOR ESI, ESI
0x34cbf4: XOR EDX, EDX
0x34cbf6: XOR ECX, ECX
0x34cbf8: CALL 0x004c6a00
0x34cbfd: MOV R14, qword ptr [R14]
0x34cc00: TEST R14, R14
0x34cc03: JZ 0x0034cc43
0x34cc05: CMP dword ptr [R14 + 0x10], -0x1
0x34cc0a: JZ 0x0034cbfd
0x34cc0c: MOV RDI, R15
0x34cc0f: XOR ESI, ESI
0x34cc11: XOR EDX, EDX
0x34cc13: XOR ECX, ECX
0x34cc15: CALL 0x004c6fa0
0x34cc1a: MOV R12, qword ptr [R14 + 0x28]
0x34cc1e: LEA RAX, [0x268440]
0x34cc25: SUB RAX, R12
0x34cc28: ROR RAX, 0x3
0x34cc2c: CMP RAX, 0x42
0x34cc30: JBE 0x0034cbe0
0x34cc32: LEA RDI, [0x1a9ca30]
0x34cc39: MOV RSI, R12
0x34cc3c: CALL 0x0044f8c0
0x34cc41: JMP 0x0034cbe0
0x34cc43: MOV R15, qword ptr [RBP + -0x40]
0x34cc47: MOV EAX, dword ptr [R15 + 0xc]
0x34cc4b: DEC EAX
0x34cc4d: MOV dword ptr [R15 + 0xc], EAX
0x34cc51: TEST EAX, EAX
0x34cc53: JNZ 0x0034cc5d
0x34cc55: MOV RDI, R15
0x34cc58: CALL 0x0073e370
0x34cc5d: ADD R15, 0x28
0x34cc61: XOR ESI, ESI
0x34cc63: XOR EDX, EDX
0x34cc65: XOR ECX, ECX
0x34cc67: MOV RDI, R15
0x34cc6a: CALL 0x004c6fa0
0x34cc6f: MOV EAX, dword ptr [RBP + -0x34]
0x34cc72: JMP 0x0034cbb4
0x34cc77: XOR EAX, EAX
0x34cc79: JMP 0x0034cbb4
0x34cc7e: CALL 0x006fd6b0
0x34cc83: UD2
; END FUNCTION sys_599

; FUNCTION sub_34cc90 CONTEXT / separate function | ev_54977efa1f715836fafa851abc56c5e9645f8c341768818baf363dfa24a6f5b9
; Ghidra body: 0x34cc90..0x34ce4e
sub_34cc90:
0x34cc90: PUSH RBP
0x34cc91: MOV RBP, RSP
0x34cc94: PUSH R15
0x34cc96: PUSH R14
0x34cc98: PUSH R12
0x34cc9a: PUSH RBX
0x34cc9b: SUB RSP, 0x90
0x34cca2: LEA R12, [0x391c310]
0x34cca9: MOV RBX, RDI
0x34ccac: MOV ESI, 0x20
0x34ccb1: MOV RAX, qword ptr [R12]
0x34ccb5: MOV qword ptr [RBP + -0x28], RAX
0x34ccb9: MOV dword ptr [RDI + 0xcd0], 0x0
0x34ccc3: LEA RDI, [RBP + -0xb0]
0x34ccca: CALL 0x00258ff0
0x34cccf: LEA RSI, [RBP + -0x90]
0x34ccd6: MOV RDI, RBX
0x34ccd9: CALL 0x0034c8c0
0x34ccde: TEST EAX, EAX
0x34cce0: JZ 0x0034cd1c
0x34cce2: MOV ESI, dword ptr [RBX + 0xbc]
0x34cce8: LEA RDI, [0x12d2da6]
0x34ccef: MOV EDX, EAX
0x34ccf1: MOV R14D, EAX
0x34ccf4: XOR EAX, EAX
0x34ccf6: CALL 0x0025d410
0x34ccfb: MOV RAX, qword ptr [R12]
0x34ccff: CMP RAX, qword ptr [RBP + -0x28]
0x34cd03: JNZ 0x0034ce48
0x34cd09: MOV EAX, R14D
0x34cd0c: ADD RSP, 0x90
0x34cd13: POP RBX
0x34cd14: POP R12
0x34cd16: POP R14
0x34cd18: POP R15
0x34cd1a: POP RBP
0x34cd1b: RET
0x34cd1c: CMP dword ptr [RBP + -0x84], 0x3
0x34cd23: MOV R14, qword ptr [RBP + -0x48]
0x34cd27: SETC AL
0x34cd2a: CMP qword ptr [RBP + -0x90], 0x50
0x34cd32: SETC CL
0x34cd35: OR CL, AL
0x34cd37: TEST R14, R14
0x34cd3a: SETZ AL
0x34cd3d: OR AL, CL
0x34cd3f: CMP AL, 0x1
0x34cd41: JNZ 0x0034cd89
0x34cd43: MOV R14, qword ptr [RBP + -0xa8]
0x34cd4a: TEST R14, R14
0x34cd4d: JZ 0x0034cdd7
0x34cd53: MOV RDI, qword ptr GS:[0x0]
0x34cd5c: LEA RSI, [0x1397f3d]
0x34cd63: XOR EDX, EDX
0x34cd65: ADD RBX, 0xcd0
0x34cd6c: CALL 0x00c1a3e0
0x34cd71: MOV EDX, 0x4
0x34cd76: MOV RDI, R14
0x34cd79: MOV RSI, RBX
0x34cd7c: CALL 0x00259280
0x34cd81: MOV R14D, EAX
0x34cd84: JMP 0x0034ccfb
0x34cd89: MOV RDI, qword ptr GS:[0x0]
0x34cd92: LEA RSI, [0x1397f3d]
0x34cd99: XOR EDX, EDX
0x34cd9b: CALL 0x00c1a3e0
0x34cda0: LEA RSI, [RBP + -0x30]
0x34cda4: MOV EDX, 0x8
0x34cda9: MOV RDI, R14
0x34cdac: CALL 0x00259280
0x34cdb1: TEST EAX, EAX
0x34cdb3: JZ 0x0034cddf
0x34cdb5: MOV ESI, dword ptr [RBX + 0xbc]
0x34cdbb: MOV RCX, qword ptr [RBP + -0x48]
0x34cdbf: LEA RDI, [0x138e7af]
0x34cdc6: MOV EDX, EAX
0x34cdc8: MOV R14D, EAX
0x34cdcb: XOR EAX, EAX
0x34cdcd: CALL 0x0025d410
0x34cdd2: JMP 0x0034ccfb
0x34cdd7: XOR R14D, R14D
0x34cdda: JMP 0x0034ccfb
0x34cddf: MOV R14, qword ptr [RBP + -0x30]
0x34cde3: CMP R14, 0x21
0x34cde7: JC 0x0034ce0b
0x34cde9: MOV ESI, dword ptr [RBX + 0xbc]
0x34cdef: LEA RDI, [0x13ae857]
0x34cdf6: MOV RDX, R14
0x34cdf9: XOR EAX, EAX
0x34cdfb: CALL 0x0025d410
0x34ce00: MOV R14D, 0x16
0x34ce06: JMP 0x0034ccfb
0x34ce0b: MOV R15, qword ptr [RBP + -0x48]
0x34ce0f: MOV RDI, qword ptr GS:[0x0]
0x34ce18: LEA RSI, [0x1397f3d]
0x34ce1f: XOR EDX, EDX
0x34ce21: CALL 0x00c1a3e0
0x34ce26: LEA RSI, [RBP + -0xb0]
0x34ce2d: MOV RDI, R15
0x34ce30: MOV RDX, R14
0x34ce33: CALL 0x00259280
0x34ce38: MOV R14D, EAX
0x34ce3b: TEST EAX, EAX
0x34ce3d: JNZ 0x0034ccfb
0x34ce43: JMP 0x0034cd43
0x34ce48: CALL 0x006fd6b0
0x34ce4d: UD2
; END FUNCTION sub_34cc90

; FUNCTION sys_612 CONTEXT / separate function | ev_68bb280e17055ca117ae61aa591435d2bd6d400bf9e9a1125856d4e3fc4cfeed
; Ghidra body: 0x34ce50..0x34cf9d
sys_612:
0x34ce50: PUSH RBP
0x34ce51: MOV RBP, RSP
0x34ce54: PUSH R15
0x34ce56: PUSH R14
0x34ce58: PUSH RBX
0x34ce59: SUB RSP, 0x28
0x34ce5d: LEA R15, [0x391c310]
0x34ce64: XOR EDX, EDX
0x34ce66: MOV RAX, qword ptr [R15]
0x34ce69: MOV qword ptr [RBP + -0x20], RAX
0x34ce6d: MOV RAX, qword ptr [RDI + 0x8]
0x34ce71: MOV RBX, qword ptr [RSI]
0x34ce74: LEA RSI, [0x1397f3d]
0x34ce7b: MOV R14, qword ptr [RAX + 0x40]
0x34ce7f: MOV RDI, qword ptr GS:[0x0]
0x34ce88: CALL 0x00c1a3e0
0x34ce8d: LEA RSI, [RBP + -0x38]
0x34ce91: MOV EDX, 0x8
0x34ce96: MOV RDI, RBX
0x34ce99: CALL 0x00259280
0x34ce9e: MOV ECX, EAX
0x34cea0: MOV EAX, 0xe
0x34cea5: TEST ECX, ECX
0x34cea7: JNZ 0x0034cf83
0x34cead: CMP qword ptr [RBP + -0x38], 0x10
0x34ceb2: MOV EAX, 0x16
0x34ceb7: JNZ 0x0034cf83
0x34cebd: LEA RDI, [RBP + -0x30]
0x34cec1: MOV ESI, 0x10
0x34cec6: CALL 0x00258ff0
0x34cecb: MOV RAX, qword ptr [RBP + -0x38]
0x34cecf: MOV qword ptr [RBP + -0x30], RAX
0x34ced3: CALL 0x005a6c70
0x34ced8: MOV RDI, R14
0x34cedb: MOV dword ptr [RBP + -0x28], EAX
0x34cede: CALL 0x006095c0
0x34cee3: TEST EAX, EAX
0x34cee5: JZ 0x0034ceeb
0x34cee7: OR byte ptr [RBP + -0x24], 0x1
0x34ceeb: MOV RDI, R14
0x34ceee: CALL 0x00609620
0x34cef3: TEST EAX, EAX
0x34cef5: JZ 0x0034cefb
0x34cef7: OR byte ptr [RBP + -0x24], 0x2
0x34cefb: MOV RDI, R14
0x34cefe: CALL 0x006091f0
0x34cf03: TEST EAX, EAX
0x34cf05: JZ 0x0034cf0b
0x34cf07: OR byte ptr [RBP + -0x24], 0x4
0x34cf0b: MOV RDI, R14
0x34cf0e: CALL 0x00609230
0x34cf13: TEST EAX, EAX
0x34cf15: JZ 0x0034cf1b
0x34cf17: OR byte ptr [RBP + -0x24], 0x8
0x34cf1b: MOV RDI, R14
0x34cf1e: CALL 0x00609750
0x34cf23: TEST EAX, EAX
0x34cf25: JZ 0x0034cf2b
0x34cf27: OR byte ptr [RBP + -0x24], 0x10
0x34cf2b: MOV RDI, R14
0x34cf2e: CALL 0x00609270
0x34cf33: TEST EAX, EAX
0x34cf35: JZ 0x0034cf3b
0x34cf37: OR byte ptr [RBP + -0x24], 0x20
0x34cf3b: MOV RDI, R14
0x34cf3e: CALL 0x006096b0
0x34cf43: TEST EAX, EAX
0x34cf45: JZ 0x0034cf4b
0x34cf47: OR byte ptr [RBP + -0x24], 0x40
0x34cf4b: MOV RDI, R14
0x34cf4e: CALL 0x00609890
0x34cf53: TEST EAX, EAX
0x34cf55: JZ 0x0034cf5b
0x34cf57: OR byte ptr [RBP + -0x24], 0x80
0x34cf5b: MOV RDI, qword ptr GS:[0x0]
0x34cf64: LEA RSI, [0x134f297]
0x34cf6b: XOR EDX, EDX
0x34cf6d: CALL 0x00c1a3e0
0x34cf72: LEA RDI, [RBP + -0x30]
0x34cf76: MOV EDX, 0x10
0x34cf7b: MOV RSI, RBX
0x34cf7e: CALL 0x002591d0
0x34cf83: MOV RCX, qword ptr [R15]
0x34cf86: CMP RCX, qword ptr [RBP + -0x20]
0x34cf8a: JNZ 0x0034cf97
0x34cf8c: ADD RSP, 0x28
0x34cf90: POP RBX
0x34cf91: POP R14
0x34cf93: POP R15
0x34cf95: POP RBP
0x34cf96: RET
0x34cf97: CALL 0x006fd6b0
0x34cf9c: UD2
; END FUNCTION sys_612

; FUNCTION sys_649 TARGET | ev_00ae4cf44e1d918a77e6620496eef75ed9da470241dd042706d68d2cd58a7017
; Ghidra body: 0x34cfa0..0x34d02d, 0x34d044..0x34d084, 0x34d093..0x34d0a5, 0x34d106..0x34d122
sys_649:
0x34cfa0: PUSH RBP
0x34cfa1: MOV RBP, RSP
0x34cfa4: PUSH R15
0x34cfa6: PUSH R14
0x34cfa8: PUSH R12
0x34cfaa: PUSH RBX
0x34cfab: SUB RSP, 0x10
0x34cfaf: LEA R15, [0x391c310]
0x34cfb6: MOV RAX, qword ptr [R15]
0x34cfb9: MOV qword ptr [RBP + -0x28], RAX
0x34cfbd: MOV RAX, qword ptr GS:[0x0]
0x34cfc6: MOV RAX, qword ptr [RAX + 0x8]
0x34cfca: MOV R12, qword ptr [RAX + 0x3e8]
0x34cfd1: TEST R12, R12
0x34cfd4: JZ 0x0034d044
0x34cfd6: MOV RAX, qword ptr [R12 + 0x10]
0x34cfdb: CMP qword ptr [RAX + 0x148], 0x0
0x34cfe3: JZ 0x0034d044
0x34cfe5: LEA R14, [R12 + 0x70]
0x34cfea: MOV RBX, RSI
0x34cfed: XOR ESI, ESI
0x34cfef: XOR EDX, EDX
0x34cff1: XOR ECX, ECX
0x34cff3: MOV RDI, R14
0x34cff6: CALL 0x00c4bb20
0x34cffb: NOP dword ptr [RAX + RAX*0x1]
0x34d000: MOV R12, qword ptr [R12]
0x34d004: TEST R12, R12
0x34d007: JZ 0x0034d06f
0x34d009: MOVSXD RAX, dword ptr [RBX]
0x34d00c: CMP qword ptr [R12 + 0x28], RAX
0x34d011: JNZ 0x0034d000
0x34d013: MOVZX EAX, byte ptr [RBX + 0x8]
0x34d017: DEC EAX
0x34d019: CMP EAX, 0x7
0x34d01c: JA 0x0034d093
0x34d01e: LEA RCX, [0x14c02b0]
0x34d025: MOVSXD RAX, dword ptr [RCX + RAX*0x4]
0x34d029: ADD RAX, RCX
0x34d02c: JMP RAX
0x34d044: LEA RDI, [0x131ba2d]
0x34d04b: LEA RDX, [0x12fbd8a]
0x34d052: LEA RCX, [0x135ae30]
0x34d059: MOV ESI, 0x7c4
0x34d05e: XOR EAX, EAX
0x34d060: CALL 0x00b22a30
0x34d065: MOV EAX, 0x16
0x34d06a: JMP 0x0034d106
0x34d06f: MOV RDI, R14
0x34d072: XOR ESI, ESI
0x34d074: XOR EDX, EDX
0x34d076: CALL 0x00c4c4b0
0x34d07b: MOV EAX, 0x3
0x34d080: JMP 0x0034d106
0x34d093: MOV RDI, R14
0x34d096: XOR ESI, ESI
0x34d098: XOR EDX, EDX
0x34d09a: CALL 0x00c4c4b0
0x34d09f: MOV EAX, 0x16
0x34d0a4: JMP 0x0034d106
0x34d106: MOV RCX, qword ptr [R15]
0x34d109: CMP RCX, qword ptr [RBP + -0x28]
0x34d10d: JNZ 0x0034d11c
0x34d10f: ADD RSP, 0x10
0x34d113: POP RBX
0x34d114: POP R12
0x34d116: POP R14
0x34d118: POP R15
0x34d11a: POP RBP
0x34d11b: RET
0x34d11c: CALL 0x006fd6b0
0x34d121: UD2
; END FUNCTION sys_649

; FUNCTION sub_34d130 CONTEXT / separate function | ev_9ef23d158cd7a3bbeaa69c096f8db4faeca644ee035217f86f1ff360c7d50d64
; Ghidra body: 0x34d130..0x34d5dc
sub_34d130:
0x34d130: PUSH RBP
0x34d131: MOV RBP, RSP
0x34d134: PUSH R15
0x34d136: PUSH R14
0x34d138: PUSH R12
0x34d13a: PUSH RBX
0x34d13b: SUB RSP, 0x140
0x34d142: LEA R12, [0x391c310]
0x34d149: MOV RBX, RCX
0x34d14c: MOV RAX, qword ptr [R12]
0x34d150: MOV qword ptr [RBP + -0x28], RAX
0x34d154: MOV qword ptr [RBP + -0x40], 0x0
0x34d15c: MOV qword ptr [RBP + -0x38], 0x0
0x34d164: MOV dword ptr [RBP + -0x15c], 0x0
0x34d16e: MOV R14, qword ptr GS:[0x0]
0x34d177: MOV RDI, qword ptr [R14 + 0x140]
0x34d17e: CALL 0x0026d0a0
0x34d183: CMP EAX, 0x1
0x34d186: JNZ 0x0034d1f2
0x34d188: MOV RAX, qword ptr GS:[0x0]
0x34d191: MOV RAX, qword ptr [RAX + 0x8]
0x34d195: CMP qword ptr [RAX + 0x3e8], 0x0
0x34d19d: JZ 0x0034d3fd
0x34d1a3: MOV RCX, qword ptr [RAX + 0x5a0]
0x34d1aa: MOV qword ptr [RBP + -0xf0], RCX
0x34d1b1: MOV RAX, qword ptr [RAX + 0x5a8]
0x34d1b8: MOV qword ptr [RBP + -0xe8], RAX
0x34d1bf: LEA RAX, [0x269338]
0x34d1c6: MOV R14, qword ptr [RBX + 0x28]
0x34d1ca: SUB RAX, R14
0x34d1cd: ROR RAX, 0x3
0x34d1d1: CMP RAX, 0x3
0x34d1d5: JA 0x0034d5c9
0x34d1db: LEA RSI, [RBP + -0xf0]
0x34d1e2: MOV EDX, 0x10
0x34d1e7: MOV RDI, RBX
0x34d1ea: CALL R14
0x34d1ed: JMP 0x0034d509
0x34d1f2: MOV RDI, qword ptr [R14 + 0x140]
0x34d1f9: CALL 0x00608f90
0x34d1fe: CMP EAX, 0x1
0x34d201: JNZ 0x0034d2ac
0x34d207: CALL 0x0060ae80
0x34d20c: CMP EAX, 0x1
0x34d20f: JNZ 0x0034d4d8
0x34d215: LEA RSI, [RBP + -0x15c]
0x34d21c: MOV EDI, 0x7802be00
0x34d221: MOV dword ptr [RBP + -0x15c], 0x0
0x34d22b: CALL 0x00ae70c0
0x34d230: TEST EAX, EAX
0x34d232: JNZ 0x0034d4d8
0x34d238: CMP dword ptr [RBP + -0x15c], 0x0
0x34d23f: JZ 0x0034d4d8
0x34d245: MOV RAX, qword ptr GS:[0x0]
0x34d24e: MOV RAX, qword ptr [RAX + 0x8]
0x34d252: CMP qword ptr [RAX + 0x3e8], 0x0
0x34d25a: JZ 0x0034d3fd
0x34d260: MOV RCX, qword ptr [RAX + 0x5a0]
0x34d267: MOV qword ptr [RBP + -0xf0], RCX
0x34d26e: MOV RAX, qword ptr [RAX + 0x5a8]
0x34d275: MOV qword ptr [RBP + -0xe8], RAX
0x34d27c: LEA RAX, [0x269338]
0x34d283: MOV R14, qword ptr [RBX + 0x28]
0x34d287: SUB RAX, R14
0x34d28a: ROR RAX, 0x3
0x34d28e: CMP RAX, 0x3
0x34d292: JBE 0x0034d1db
0x34d298: LEA RDI, [0x1a9ca90]
0x34d29f: MOV RSI, R14
0x34d2a2: CALL 0x0044f8c0
0x34d2a7: JMP 0x0034d1db
0x34d2ac: MOV RDI, qword ptr [R14 + 0x140]
0x34d2b3: CALL 0x00609270
0x34d2b8: CMP EAX, 0x1
0x34d2bb: JNZ 0x0034d311
0x34d2bd: CALL 0x00acce10
0x34d2c2: MOV ECX, EAX
0x34d2c4: MOV EAX, 0x3
0x34d2c9: CMP ECX, 0x1
0x34d2cc: JNZ 0x0034d4d8
0x34d2d2: CALL 0x0060ae80
0x34d2d7: CMP EAX, 0x1
0x34d2da: JNZ 0x0034d4d8
0x34d2e0: LEA RSI, [RBP + -0x15c]
0x34d2e7: MOV EDI, 0x7802be00
0x34d2ec: MOV dword ptr [RBP + -0x15c], 0x0
0x34d2f6: CALL 0x00ae70c0
0x34d2fb: TEST EAX, EAX
0x34d2fd: JNZ 0x0034d4d8
0x34d303: CMP dword ptr [RBP + -0x15c], 0x0
0x34d30a: JNZ 0x0034d34d
0x34d30c: JMP 0x0034d4d8
0x34d311: CALL 0x0060ae80
0x34d316: CMP EAX, 0x1
0x34d319: JNZ 0x0034d35a
0x34d31b: CALL 0x00acce10
0x34d320: CMP EAX, 0x1
0x34d323: JNZ 0x0034d35a
0x34d325: LEA RSI, [RBP + -0x15c]
0x34d32c: MOV EDI, 0x7802b700
0x34d331: MOV dword ptr [RBP + -0x15c], 0x0
0x34d33b: CALL 0x00ae70c0
0x34d340: TEST EAX, EAX
0x34d342: JNZ 0x0034d35a
0x34d344: CMP dword ptr [RBP + -0x15c], 0x0
0x34d34b: JZ 0x0034d35a
0x34d34d: MOV RDI, RBX
0x34d350: CALL 0x0034d5e0
0x34d355: JMP 0x0034d509
0x34d35a: CALL 0x00acce10
0x34d35f: CMP EAX, 0x1
0x34d362: JZ 0x0034d372
0x34d364: CALL 0x00acce50
0x34d369: CMP EAX, 0x1
0x34d36c: JNZ 0x0034d407
0x34d372: LEA RSI, [RBP + -0x15c]
0x34d379: MOV EDI, 0x7802bf00
0x34d37e: MOV dword ptr [RBP + -0x15c], 0x0
0x34d388: CALL 0x00ae70c0
0x34d38d: TEST EAX, EAX
0x34d38f: JNZ 0x0034d407
0x34d391: CMP dword ptr [RBP + -0x15c], 0x0
0x34d398: JZ 0x0034d407
0x34d39a: MOV RAX, qword ptr GS:[0x0]
0x34d3a3: MOV RAX, qword ptr [RAX + 0x8]
0x34d3a7: CMP qword ptr [RAX + 0x3e8], 0x0
0x34d3af: JZ 0x0034d3fd
0x34d3b1: MOV RCX, qword ptr [RAX + 0x5a0]
0x34d3b8: MOV qword ptr [RBP + -0xf0], RCX
0x34d3bf: MOV RAX, qword ptr [RAX + 0x5a8]
0x34d3c6: MOV qword ptr [RBP + -0xe8], RAX
0x34d3cd: LEA RAX, [0x269338]
0x34d3d4: MOV R14, qword ptr [RBX + 0x28]
0x34d3d8: SUB RAX, R14
0x34d3db: ROR RAX, 0x3
0x34d3df: CMP RAX, 0x3
0x34d3e3: JBE 0x0034d1db
0x34d3e9: LEA RDI, [0x1a9ca90]
0x34d3f0: MOV RSI, R14
0x34d3f3: CALL 0x0044f8c0
0x34d3f8: JMP 0x0034d1db
0x34d3fd: MOV EAX, 0x16
0x34d402: JMP 0x0034d509
0x34d407: MOV R14, qword ptr [R14 + 0x8]
0x34d40b: LEA RDI, [RBP + -0xf0]
0x34d412: MOV ESI, 0xa8
0x34d417: CALL 0x00258ff0
0x34d41c: LEA RSI, [RBP + -0x158]
0x34d423: MOV RDI, R14
0x34d426: CALL 0x0034c8c0
0x34d42b: TEST EAX, EAX
0x34d42d: JNZ 0x0034d4d8
0x34d433: CMP dword ptr [RBP + -0x14c], 0x0
0x34d43a: MOV R14, qword ptr [RBP + -0x120]
0x34d441: SETZ AL
0x34d444: CMP qword ptr [RBP + -0x158], 0x40
0x34d44c: SETC CL
0x34d44f: TEST R14, R14
0x34d452: SETZ DL
0x34d455: OR DL, AL
0x34d457: MOV EAX, 0x8
0x34d45c: OR DL, CL
0x34d45e: JNZ 0x0034d4d8
0x34d460: MOV RDI, qword ptr GS:[0x0]
0x34d469: LEA RSI, [0x1397f3d]
0x34d470: XOR EDX, EDX
0x34d472: CALL 0x00c1a3e0
0x34d477: LEA RSI, [RBP + -0xf8]
0x34d47e: MOV EDX, 0x8
0x34d483: MOV RDI, R14
0x34d486: CALL 0x00259280
0x34d48b: TEST EAX, EAX
0x34d48d: JNZ 0x0034d4d8
0x34d48f: MOV R14, qword ptr [RBP + -0xf8]
0x34d496: MOV EAX, 0x16
0x34d49b: CMP R14, 0xa9
0x34d4a2: JNC 0x0034d4d8
0x34d4a4: MOV R15, qword ptr [RBP + -0x120]
0x34d4ab: MOV RDI, qword ptr GS:[0x0]
0x34d4b4: LEA RSI, [0x1397f3d]
0x34d4bb: XOR EDX, EDX
0x34d4bd: CALL 0x00c1a3e0
0x34d4c2: LEA RSI, [RBP + -0xf0]
0x34d4c9: MOV RDI, R15
0x34d4cc: MOV RDX, R14
0x34d4cf: CALL 0x00259280
0x34d4d4: TEST EAX, EAX
0x34d4d6: JZ 0x0034d527
0x34d4d8: MOV R14, qword ptr [RBX + 0x28]
0x34d4dc: MOV R15D, EAX
0x34d4df: LEA RAX, [0x269338]
0x34d4e6: SUB RAX, R14
0x34d4e9: ROR RAX, 0x3
0x34d4ed: CMP RAX, 0x3
0x34d4f1: JA 0x0034d5b5
0x34d4f7: LEA RSI, [RBP + -0x40]
0x34d4fb: MOV EDX, 0x10
0x34d500: MOV RDI, RBX
0x34d503: CALL R14
0x34d506: MOV EAX, R15D
0x34d509: MOV RCX, qword ptr [R12]
0x34d50d: CMP RCX, qword ptr [RBP + -0x28]
0x34d511: JNZ 0x0034d5ae
0x34d517: ADD RSP, 0x140
0x34d51e: POP RBX
0x34d51f: POP R12
0x34d521: POP R14
0x34d523: POP R15
0x34d525: POP RBP
0x34d526: RET
0x34d527: CMP dword ptr [RBP + -0xe8], 0x9
0x34d52e: JC 0x0034d566
0x34d530: CMP dword ptr [RBP + -0xe4], 0x1
0x34d537: MOV EAX, 0x0
0x34d53c: JNZ 0x0034d568
0x34d53e: MOV RDI, qword ptr [RBP + -0x80]
0x34d542: LEA RSI, [RBP + -0x158]
0x34d549: CALL 0x0034b910
0x34d54e: TEST EAX, EAX
0x34d550: JNZ 0x0034d568
0x34d552: TEST byte ptr [RBP + -0x158], 0x8
0x34d559: MOV EAX, 0x0
0x34d55e: JNZ 0x0034d34d
0x34d564: JMP 0x0034d568
0x34d566: XOR EAX, EAX
0x34d568: CMP dword ptr [RBP + -0xe8], 0xc
0x34d56f: JC 0x0034d4d8
0x34d575: CMP dword ptr [RBP + -0xe4], 0x1
0x34d57c: JNZ 0x0034d4d8
0x34d582: MOV RDI, qword ptr [RBP + -0x68]
0x34d586: LEA RSI, [RBP + -0x158]
0x34d58d: CALL 0x0034b910
0x34d592: TEST EAX, EAX
0x34d594: JNZ 0x0034d4d8
0x34d59a: XOR EAX, EAX
0x34d59c: TEST byte ptr [RBP + -0x158], 0x8
0x34d5a3: JNZ 0x0034d34d
0x34d5a9: JMP 0x0034d4d8
0x34d5ae: CALL 0x006fd6b0
0x34d5b3: UD2
0x34d5b5: LEA RDI, [0x1a9ca50]
0x34d5bc: MOV RSI, R14
0x34d5bf: CALL 0x0044f8c0
0x34d5c4: JMP 0x0034d4f7
0x34d5c9: LEA RDI, [0x1a9ca90]
0x34d5d0: MOV RSI, R14
0x34d5d3: CALL 0x0044f8c0
0x34d5d8: JMP 0x0034d1db
; END FUNCTION sub_34d130

; FUNCTION sub_34d5e0 CONTEXT / separate function | ev_4fce982f77573a11b568bea3220efc0dff604933dca558b44c5962cd46d7069d
; Ghidra body: 0x34d5e0..0x34d686
sub_34d5e0:
0x34d5e0: PUSH RBP
0x34d5e1: MOV RBP, RSP
0x34d5e4: PUSH R15
0x34d5e6: PUSH R14
0x34d5e8: PUSH RBX
0x34d5e9: SUB RSP, 0x18
0x34d5ed: LEA R14, [0x391c310]
0x34d5f4: MOV RAX, qword ptr [R14]
0x34d5f7: MOV qword ptr [RBP + -0x20], RAX
0x34d5fb: MOV RAX, qword ptr GS:[0x0]
0x34d604: MOV RAX, qword ptr [RAX + 0x8]
0x34d608: CMP qword ptr [RAX + 0x3e8], 0x0
0x34d610: JZ 0x0034d64d
0x34d612: MOV RCX, qword ptr [RAX + 0x5a0]
0x34d619: MOV qword ptr [RBP + -0x30], RCX
0x34d61d: MOV RAX, qword ptr [RAX + 0x5a8]
0x34d624: MOV qword ptr [RBP + -0x28], RAX
0x34d628: LEA RAX, [0x269338]
0x34d62f: MOV RBX, qword ptr [RDI + 0x28]
0x34d633: SUB RAX, RBX
0x34d636: ROR RAX, 0x3
0x34d63a: CMP RAX, 0x3
0x34d63e: JA 0x0034d66d
0x34d640: LEA RSI, [RBP + -0x30]
0x34d644: MOV EDX, 0x10
0x34d649: CALL RBX
0x34d64b: JMP 0x0034d652
0x34d64d: MOV EAX, 0x16
0x34d652: MOV RCX, qword ptr [R14]
0x34d655: CMP RCX, qword ptr [RBP + -0x20]
0x34d659: JNZ 0x0034d666
0x34d65b: ADD RSP, 0x18
0x34d65f: POP RBX
0x34d660: POP R14
0x34d662: POP R15
0x34d664: POP RBP
0x34d665: RET
0x34d666: CALL 0x006fd6b0
0x34d66b: UD2
0x34d66d: LEA RAX, [0x1a9ca90]
0x34d674: MOV R15, RDI
0x34d677: MOV RSI, RBX
0x34d67a: MOV RDI, RAX
0x34d67d: CALL 0x0044f8c0
0x34d682: MOV RDI, R15
0x34d685: JMP 0x0034d640
; END FUNCTION sub_34d5e0

; FUNCTION FUN_0034d6d3 CONTEXT / separate function | ev_f4d8e82cb1ade49587b08c8fb1bd6fb37be29492a154c7364019887779862e23
; Ghidra body: 0x34d6d3..0x34d6dd
FUN_0034d6d3:
0x34d6d3: MOV EDX, 0x18
0x34d6d8: MOV RDI, RCX
0x34d6db: JMP R8
; END FUNCTION FUN_0034d6d3

; FUNCTION sub_34d6de CONTEXT / separate function | ev_b7087f188f57e03e077f8bb13f2eb918dd5d5a146f65d32bfa58f8b4a14a868d
; Ghidra body: 0x34d6de..0x34d714
sub_34d6de:
0x34d6de: PUSH RBP
0x34d6df: MOV RBP, RSP
0x34d6e2: PUSH R15
0x34d6e4: PUSH R14
0x34d6e6: PUSH RBX
0x34d6e7: PUSH RAX
0x34d6e8: MOV RBX, RSI
0x34d6eb: LEA RDI, [0x1a9ca70]
0x34d6f2: MOV RSI, R8
0x34d6f5: MOV R14, RCX
0x34d6f8: MOV R15, R8
0x34d6fb: CALL 0x0044f8c0
0x34d700: MOV R8, R15
0x34d703: MOV RSI, RBX
0x34d706: MOV RCX, R14
0x34d709: ADD RSP, 0x8
0x34d70d: POP RBX
0x34d70e: POP R14
0x34d710: POP R15
0x34d712: POP RBP
0x34d713: JMP 0x0034d6d3
; END FUNCTION sub_34d6de

; FUNCTION sub_34d720 CONTEXT / separate function | ev_7ba135f04c117b4ab1e792de13f7a895a8ef097b7b756adbc5faff64eef69b25
; Ghidra body: 0x34d720..0x34d77d, 0x34d780..0x34d7ab
sub_34d720:
0x34d720: PUSH RBP
0x34d721: MOV RBP, RSP
0x34d724: PUSH R15
0x34d726: PUSH R14
0x34d728: PUSH RBX
0x34d729: PUSH RAX
0x34d72a: MOV RBX, RSI
0x34d72d: MOV R14, RDI
0x34d730: MOV ESI, 0x400
0x34d735: MOV RDI, RBX
0x34d738: CALL 0x00444eb0
0x34d73d: MOV ESI, 0x400
0x34d742: MOV RDI, R14
0x34d745: MOV R15, RAX
0x34d748: CALL 0x00444eb0
0x34d74d: LEA RCX, [R15 + RAX*0x1 + -0x406]
0x34d755: MOV EAX, 0xffffffff
0x34d75a: CMP RCX, -0x401
0x34d761: JC 0x0034d7a1
0x34d763: ADD R14, 0x6
0x34d767: MOV EDX, 0x400
0x34d76c: MOV RDI, RBX
0x34d76f: MOV RSI, R14
0x34d772: CALL 0x00886560
0x34d777: MOV ECX, 0x6
0x34d77c: JMP 0x0034d790
0x34d780: MOV byte ptr [RBX + RCX*0x1], 0x5c
0x34d784: INC RCX
0x34d787: CMP RCX, 0x400
0x34d78e: JZ 0x0034d79f
0x34d790: MOVZX EAX, byte ptr [RBX + RCX*0x1]
0x34d794: CMP EAX, 0x2f
0x34d797: JZ 0x0034d780
0x34d799: TEST EAX, EAX
0x34d79b: JNZ 0x0034d784
0x34d79d: JMP 0x0034d7a1
0x34d79f: XOR EAX, EAX
0x34d7a1: ADD RSP, 0x8
0x34d7a5: POP RBX
0x34d7a6: POP R14
0x34d7a8: POP R15
0x34d7aa: POP RBP
0x34d7ab: RET
; END FUNCTION sub_34d720

; FUNCTION sub_34d7b0 CONTEXT / separate function | ev_c495cf3826ba22bed83d609d1ba95fee3435a3e7349ad712ea46fff541f5f66b
; Ghidra body: 0x34d7b0..0x34d86a
sub_34d7b0:
0x34d7b0: PUSH RBP
0x34d7b1: MOV RBP, RSP
0x34d7b4: PUSH R15
0x34d7b6: PUSH R14
0x34d7b8: PUSH R13
0x34d7ba: PUSH R12
0x34d7bc: PUSH RBX
0x34d7bd: SUB RSP, 0x28
0x34d7c1: LEA R12, [0x391c310]
0x34d7c8: XOR EBX, EBX
0x34d7ca: MOV RAX, qword ptr [R12]
0x34d7ce: MOV qword ptr [RBP + -0x30], RAX
0x34d7d2: TEST byte ptr [RSI + 0x11c], 0x1
0x34d7d9: JNZ 0x0034d849
0x34d7db: MOV R13D, dword ptr [RDI + 0x5d8]
0x34d7e2: LEA R15, [RBP + -0x50]
0x34d7e6: MOV R14, RSI
0x34d7e9: MOV ESI, 0x20
0x34d7ee: MOV RDI, R15
0x34d7f1: CALL 0x00258ff0
0x34d7f6: MOV R14, qword ptr [R14 + 0x168]
0x34d7fd: MOV RDI, qword ptr GS:[0x0]
0x34d806: LEA RSI, [0x1397f3d]
0x34d80d: XOR EDX, EDX
0x34d80f: XOR EBX, EBX
0x34d811: CALL 0x00c1a3e0
0x34d816: MOV EDX, 0x18
0x34d81b: MOV RDI, R14
0x34d81e: MOV RSI, R15
0x34d821: CALL 0x00259280
0x34d826: TEST EAX, EAX
0x34d828: JNZ 0x0034d849
0x34d82a: CMP dword ptr [RBP + -0x48], 0x3c13f4bf
0x34d831: JNZ 0x0034d849
0x34d833: CMP dword ptr [RBP + -0x44], 0x2
0x34d837: JC 0x0034d849
0x34d839: XOR R13D, dword ptr [RBP + -0x3c]
0x34d83d: XOR EBX, EBX
0x34d83f: CMP R13D, 0x10000
0x34d846: SETC BL
0x34d849: MOV RAX, qword ptr [R12]
0x34d84d: CMP RAX, qword ptr [RBP + -0x30]
0x34d851: JNZ 0x0034d864
0x34d853: MOV EAX, EBX
0x34d855: ADD RSP, 0x28
0x34d859: POP RBX
0x34d85a: POP R12
0x34d85c: POP R13
0x34d85e: POP R14
0x34d860: POP R15
0x34d862: POP RBP
0x34d863: RET
0x34d864: CALL 0x006fd6b0
0x34d869: UD2
; END FUNCTION sub_34d7b0

; FUNCTION sub_34d870 CONTEXT / separate function | ev_db390d4555b1527c3f4ffe2e95fea96dea984ba47a80584311265a23a7621363
; Ghidra body: 0x34d870..0x34dc36
sub_34d870:
0x34d870: PUSH RBP
0x34d871: MOV RBP, RSP
0x34d874: PUSH R15
0x34d876: PUSH R14
0x34d878: PUSH R13
0x34d87a: PUSH R12
0x34d87c: PUSH RBX
0x34d87d: SUB RSP, 0x48
0x34d881: LEA R12, [0x391c310]
0x34d888: MOV R14, RDI
0x34d88b: MOV EDI, 0x800
0x34d890: XOR ESI, ESI
0x34d892: MOV RAX, qword ptr [R12]
0x34d896: MOV qword ptr [RBP + -0x30], RAX
0x34d89a: CALL 0x00b2ac60
0x34d89f: TEST RAX, RAX
0x34d8a2: JZ 0x0034dc0a
0x34d8a8: MOV ESI, 0x800
0x34d8ad: MOV RDI, RAX
0x34d8b0: MOV R13, RAX
0x34d8b3: CALL 0x00258ff0
0x34d8b8: LEA RSI, [0x128040b]
0x34d8bf: MOV EDX, 0x1b
0x34d8c4: MOV RDI, R13
0x34d8c7: MOV dword ptr [R13 + 0x44], 0x0
0x34d8cf: CALL 0x00984440
0x34d8d4: LEA R15, [R14 + 0x18]
0x34d8d8: MOV ESI, 0x25
0x34d8dd: MOV RDI, R15
0x34d8e0: CALL 0x00444eb0
0x34d8e5: CMP RAX, 0x24
0x34d8e9: JNZ 0x0034d920
0x34d8eb: LEA RDI, [R13 + 0x48]
0x34d8ef: LEA RSI, [0x1326472]
0x34d8f6: MOV ECX, 0x25
0x34d8fb: MOV RDX, R15
0x34d8fe: CALL 0x0034dc40
0x34d903: INC dword ptr [R13 + 0x44]
0x34d907: MOV RBX, qword ptr [R14 + 0x8]
0x34d90b: MOV RCX, RBX
0x34d90e: SHR RCX, 0x20
0x34d912: JNZ 0x0034d936
0x34d914: LEA RDI, [0x12c828f]
0x34d91b: MOV RSI, RBX
0x34d91e: JMP 0x0034d92a
0x34d920: LEA RDI, [0x1398f9d]
0x34d927: MOV RSI, R15
0x34d92a: XOR EAX, EAX
0x34d92c: CALL 0x0025d410
0x34d931: JMP 0x0034da44
0x34d936: LEA RDI, [RBP + -0x50]
0x34d93a: MOV ESI, 0x19
0x34d93f: MOV qword ptr [RBP + -0x68], RAX
0x34d943: CALL 0x00258ff0
0x34d948: MOV EAX, 0x830
0x34d94d: MOV R11D, EBX
0x34d950: MOV RCX, RBX
0x34d953: LEA RDX, [0x13ae895]
0x34d95a: MOV ESI, 0x19
0x34d95f: LEA RDI, [RBP + -0x50]
0x34d963: BEXTR R8, RBX, RAX
0x34d968: MOV EAX, 0x828
0x34d96d: SHR RCX, 0x38
0x34d971: SHR R11D, 0x18
0x34d975: BEXTR R9, RBX, RAX
0x34d97a: MOV EAX, 0x820
0x34d97f: BEXTR RAX, RBX, RAX
0x34d984: MOV qword ptr [RBP + -0x60], RAX
0x34d988: MOV EAX, 0x810
0x34d98d: BEXTR EAX, EBX, EAX
0x34d992: MOV qword ptr [RBP + -0x58], RAX
0x34d996: MOVZX EAX, BH
0x34d999: MOV R12, RAX
0x34d99c: MOV EAX, 0x404
0x34d9a1: BEXTR R10D, EBX, EAX
0x34d9a6: AND EBX, 0xf
0x34d9a9: XOR EAX, EAX
0x34d9ab: PUSH RBX
0x34d9ac: PUSH R10
0x34d9ae: PUSH R12
0x34d9b0: PUSH qword ptr [RBP + -0x58]
0x34d9b3: PUSH R11
0x34d9b5: PUSH qword ptr [RBP + -0x60]
0x34d9b8: CALL 0x004aee40
0x34d9bd: ADD RSP, 0x30
0x34d9c1: MOV RDI, qword ptr [RBP + -0x68]
0x34d9c5: LEA RSI, [0x12bd732]
0x34d9cc: MOV ECX, 0x19
0x34d9d1: LEA RDX, [RBP + -0x50]
0x34d9d5: CALL 0x0034dc40
0x34d9da: INC dword ptr [R13 + 0x44]
0x34d9de: LEA R12, [R14 + 0x3d]
0x34d9e2: MOV ESI, 0x25
0x34d9e7: MOV RBX, RAX
0x34d9ea: MOV RDI, R12
0x34d9ed: CALL 0x00444eb0
0x34d9f2: CMP RAX, 0x24
0x34d9f6: JNZ 0x0034da2c
0x34d9f8: LEA RSI, [0x1398fc7]
0x34d9ff: MOV ECX, 0x25
0x34da04: MOV RDI, RBX
0x34da07: MOV RDX, R12
0x34da0a: CALL 0x0034dc40
0x34da0f: INC dword ptr [R13 + 0x44]
0x34da13: MOV RBX, qword ptr [R14 + 0x10]
0x34da17: MOV RCX, RBX
0x34da1a: SHR RCX, 0x20
0x34da1e: JNZ 0x0034da93
0x34da20: LEA RDI, [0x13799ce]
0x34da27: MOV RSI, RBX
0x34da2a: JMP 0x0034da36
0x34da2c: LEA RDI, [0x12dd468]
0x34da33: MOV RSI, R12
0x34da36: XOR EAX, EAX
0x34da38: CALL 0x0025d410
0x34da3d: LEA R12, [0x391c310]
0x34da44: MOV R9, qword ptr [R14]
0x34da47: MOV RDX, qword ptr [R14 + 0x8]
0x34da4b: MOV R8, qword ptr [R14 + 0x10]
0x34da4f: ADD R14, 0x3d
0x34da53: LEA RDI, [0x138e80a]
0x34da5a: MOV RSI, R15
0x34da5d: XOR EAX, EAX
0x34da5f: MOV RCX, R14
0x34da62: CALL 0x0025d410
0x34da67: MOV ESI, 0x800
0x34da6c: MOV RDI, R13
0x34da6f: XOR EDX, EDX
0x34da71: CALL 0x00b24250
0x34da76: MOV RAX, qword ptr [R12]
0x34da7a: CMP RAX, qword ptr [RBP + -0x30]
0x34da7e: JNZ 0x0034dc30
0x34da84: ADD RSP, 0x48
0x34da88: POP RBX
0x34da89: POP R12
0x34da8b: POP R13
0x34da8d: POP R14
0x34da8f: POP R15
0x34da91: POP RBP
0x34da92: RET
0x34da93: LEA RDI, [RBP + -0x50]
0x34da97: MOV ESI, 0x19
0x34da9c: MOV qword ptr [RBP + -0x68], RAX
0x34daa0: CALL 0x00258ff0
0x34daa5: MOV EAX, 0x830
0x34daaa: MOV R11D, EBX
0x34daad: MOV RCX, RBX
0x34dab0: LEA RDX, [0x13ae895]
0x34dab7: MOV ESI, 0x19
0x34dabc: LEA RDI, [RBP + -0x50]
0x34dac0: BEXTR R8, RBX, RAX
0x34dac5: MOV EAX, 0x828
0x34daca: SHR RCX, 0x38
0x34dace: SHR R11D, 0x18
0x34dad2: BEXTR R9, RBX, RAX
0x34dad7: MOV EAX, 0x820
0x34dadc: BEXTR RAX, RBX, RAX
0x34dae1: MOV qword ptr [RBP + -0x60], RAX
0x34dae5: MOV EAX, 0x810
0x34daea: BEXTR EAX, EBX, EAX
0x34daef: MOV qword ptr [RBP + -0x58], RAX
0x34daf3: MOVZX EAX, BH
0x34daf6: MOV R12, RAX
0x34daf9: MOV EAX, 0x404
0x34dafe: BEXTR R10D, EBX, EAX
0x34db03: AND EBX, 0xf
0x34db06: XOR EAX, EAX
0x34db08: PUSH RBX
0x34db09: PUSH R10
0x34db0b: PUSH R12
0x34db0d: PUSH qword ptr [RBP + -0x58]
0x34db10: PUSH R11
0x34db12: PUSH qword ptr [RBP + -0x60]
0x34db15: CALL 0x004aee40
0x34db1a: ADD RSP, 0x30
0x34db1e: MOV RDI, qword ptr [RBP + -0x68]
0x34db22: LEA RSI, [0x12c82bd]
0x34db29: MOV ECX, 0x19
0x34db2e: LEA RDX, [RBP + -0x50]
0x34db32: CALL 0x0034dc40
0x34db37: INC dword ptr [R13 + 0x44]
0x34db3b: MOV R12, RAX
0x34db3e: MOV RBX, qword ptr [R14]
0x34db41: TEST RBX, RBX
0x34db44: JZ 0x0034db81
0x34db46: MOV ESI, 0x400
0x34db4b: MOV RDI, RBX
0x34db4e: CALL 0x00444eb0
0x34db53: CMP RAX, 0x6
0x34db57: JC 0x0034db81
0x34db59: CMP byte ptr [RBX], 0x2f
0x34db5c: JNZ 0x0034db81
0x34db5e: CMP byte ptr [RBX + 0x1], 0x68
0x34db62: JNZ 0x0034db81
0x34db64: CMP byte ptr [RBX + 0x2], 0x6f
0x34db68: JNZ 0x0034db81
0x34db6a: CMP byte ptr [RBX + 0x3], 0x73
0x34db6e: JNZ 0x0034db81
0x34db70: CMP byte ptr [RBX + 0x4], 0x74
0x34db74: JNZ 0x0034db81
0x34db76: CMP byte ptr [RBX + 0x5], 0x2f
0x34db7a: MOV ESI, 0x5c
0x34db7f: JZ 0x0034db86
0x34db81: MOV ESI, 0x2f
0x34db86: MOV RBX, qword ptr [R14]
0x34db89: MOV RDI, RBX
0x34db8c: CALL 0x00272200
0x34db91: LEA RDX, [RAX + 0x1]
0x34db95: TEST RAX, RAX
0x34db98: LEA RSI, [0x1310e97]
0x34db9f: MOV ECX, 0x401
0x34dba4: MOV RDI, R12
0x34dba7: CMOVZ RDX, RBX
0x34dbab: CALL 0x0034dc40
0x34dbb0: INC dword ptr [R13 + 0x44]
0x34dbb4: SUB RAX, R13
0x34dbb7: CMP RAX, 0x81
0x34dbbd: JA 0x0034dbce
0x34dbbf: LEA RDI, [0x13799fc]
0x34dbc6: MOV RSI, RAX
0x34dbc9: JMP 0x0034da36
0x34dbce: MOV EDI, 0x4
0x34dbd3: MOV RSI, R13
0x34dbd6: MOV RDX, RAX
0x34dbd9: MOV ECX, 0x4
0x34dbde: CALL 0x0057e790
0x34dbe3: LEA R12, [0x391c310]
0x34dbea: TEST EAX, EAX
0x34dbec: JZ 0x0034da67
0x34dbf2: MOV RSI, qword ptr [R14]
0x34dbf5: MOV EDX, EAX
0x34dbf7: LEA RDI, [0x12a8f8c]
0x34dbfe: XOR EAX, EAX
0x34dc00: CALL 0x0025d410
0x34dc05: JMP 0x0034da44
0x34dc0a: CALL 0x007f1950
0x34dc0f: LEA RDI, [0x34dc0a]
0x34dc16: CALL 0x007f1810
0x34dc1b: LEA RSI, [0x1384006]
0x34dc22: MOV EDI, 0xc
0x34dc27: XOR EAX, EAX
0x34dc29: CALL 0x00c9aa10
0x34dc2e: UD2
0x34dc30: CALL 0x006fd6b0
0x34dc35: UD2
; END FUNCTION sub_34d870

; FUNCTION sub_34dc40 CONTEXT / separate function | ev_7d18af5067696aa417857feb0f6a691a377c139871e15d9349ef2840aff1e57c
; Ghidra body: 0x34dc40..0x34dcc0
sub_34dc40:
0x34dc40: PUSH RBP
0x34dc41: MOV RBP, RSP
0x34dc44: PUSH R15
0x34dc46: PUSH R14
0x34dc48: PUSH RBX
0x34dc49: PUSH RAX
0x34dc4a: TEST RDI, RDI
0x34dc4d: JZ 0x0034dc92
0x34dc4f: MOV R14, RCX
0x34dc52: MOV R15, RDX
0x34dc55: MOV RBX, RDI
0x34dc58: MOV EDX, 0x41
0x34dc5d: MOV dword ptr [RDI], R14D
0x34dc60: MOV byte ptr [RDI + 0x4], 0x2
0x34dc64: ADD RDI, 0x5
0x34dc68: CALL 0x00957b70
0x34dc6d: LEA RDI, [RBX + 0x46]
0x34dc71: MOV RSI, R15
0x34dc74: MOV RDX, R14
0x34dc77: CALL 0x00957b70
0x34dc7c: MOV EAX, dword ptr [RBX]
0x34dc7e: ADD EAX, 0x49
0x34dc81: AND EAX, 0xfffffffc
0x34dc84: ADD RAX, RBX
0x34dc87: ADD RSP, 0x8
0x34dc8b: POP RBX
0x34dc8c: POP R14
0x34dc8e: POP R15
0x34dc90: POP RBP
0x34dc91: RET
0x34dc92: MOV RBX, RSI
0x34dc95: CALL 0x007f1950
0x34dc9a: LEA RDI, [0x34dc92]
0x34dca1: MOV RSI, RBX
0x34dca4: CALL 0x007f18a0
0x34dca9: LEA RSI, [0x1280426]
0x34dcb0: MOV EDI, 0x4
0x34dcb5: MOV RDX, RBX
0x34dcb8: XOR EAX, EAX
0x34dcba: CALL 0x00c9aa10
0x34dcbf: UD2
; END FUNCTION sub_34dc40

; FUNCTION sub_34dcd0 CONTEXT / separate function | ev_bcb62c2396caf6572682682b02b615e829975afbe44416cf4de2ba22c8a7c5d5
; Ghidra body: 0x34dcd0..0x34dd78
sub_34dcd0:
0x34dcd0: PUSH RBP
0x34dcd1: MOV RBP, RSP
0x34dcd4: PUSH R15
0x34dcd6: PUSH R14
0x34dcd8: PUSH R13
0x34dcda: PUSH R12
0x34dcdc: PUSH RBX
0x34dcdd: SUB RSP, 0x48
0x34dce1: LEA RAX, [0x391c310]
0x34dce8: MOV qword ptr [RBP + -0x60], R9
0x34dcec: MOV qword ptr [RBP + -0x68], R8
0x34dcf0: MOV R13D, ESI
0x34dcf3: MOV RBX, RDI
0x34dcf6: LEA RDI, [RBP + -0x50]
0x34dcfa: MOV ESI, 0x20
0x34dcff: MOV R15, RCX
0x34dd02: MOV R12D, EDX
0x34dd05: MOV RAX, qword ptr [RAX]
0x34dd08: MOV qword ptr [RBP + -0x30], RAX
0x34dd0c: CALL 0x00258ff0
0x34dd11: LEA R14, [RBP + -0x58]
0x34dd15: MOV ESI, 0x8
0x34dd1a: MOV RDI, R14
0x34dd1d: CALL 0x00258ff0
0x34dd22: SUB RSP, 0x8
0x34dd26: MOV RDI, RBX
0x34dd29: MOV ESI, R13D
0x34dd2c: MOV EDX, R12D
0x34dd2f: LEA RCX, [RBP + -0x50]
0x34dd33: MOV R8, R14
0x34dd36: MOV R9, R15
0x34dd39: PUSH qword ptr [RBP + 0x18]
0x34dd3c: PUSH qword ptr [RBP + 0x10]
0x34dd3f: PUSH qword ptr [RBP + -0x60]
0x34dd42: PUSH qword ptr [RBP + -0x68]
0x34dd45: PUSH 0x4000
0x34dd4a: CALL 0x00338550
0x34dd4f: ADD RSP, 0x30
0x34dd53: LEA RCX, [0x391c310]
0x34dd5a: MOV RCX, qword ptr [RCX]
0x34dd5d: CMP RCX, qword ptr [RBP + -0x30]
0x34dd61: JNZ 0x0034dd72
0x34dd63: ADD RSP, 0x48
0x34dd67: POP RBX
0x34dd68: POP R12
0x34dd6a: POP R13
0x34dd6c: POP R14
0x34dd6e: POP R15
0x34dd70: POP RBP
0x34dd71: RET
0x34dd72: CALL 0x006fd6b0
0x34dd77: UD2
; END FUNCTION sub_34dcd0

; FUNCTION sub_34dd80 CONTEXT / separate function | ev_41f1fe01f7e8b5c7792ff3a1f0a831f0a281d342d8089c0a9459c96a4a547f4c
; Ghidra body: 0x34dd80..0x34dda9
sub_34dd80:
0x34dd80: PUSH RBP
0x34dd81: MOV RBP, RSP
0x34dd84: MOV EAX, 0xffffffdd
0x34dd89: CMP RSI, 0x40
0x34dd8d: JC 0x0034dda8
0x34dd8f: MOVZX EAX, word ptr [RDI + 0x38]
0x34dd93: XOR ECX, ECX
0x34dd95: IMUL RAX, RAX, 0x38
0x34dd99: ADD RAX, 0x40
0x34dd9d: CMP RSI, RAX
0x34dda0: MOV EAX, 0xffffffdd
0x34dda5: CMOVNC EAX, ECX
0x34dda8: POP RBP
0x34dda9: RET
; END FUNCTION sub_34dd80

; FUNCTION sub_34ddb0 CONTEXT / separate function | ev_dbdc0f598c225dc17de19073381a8078f4280987e3a20f82731b519c3d39ce46
; Ghidra body: 0x34ddb0..0x34de56
sub_34ddb0:
0x34ddb0: PUSH RBP
0x34ddb1: MOV RBP, RSP
0x34ddb4: PUSH RBX
0x34ddb5: PUSH RAX
0x34ddb6: CMP dword ptr [RDI], 0x1
0x34ddb9: MOV EBX, 0xffffffea
0x34ddbe: JNZ 0x0034de4e
0x34ddc4: MOV R9, qword ptr [RDI + 0x38]
0x34ddc8: TEST R9, R9
0x34ddcb: JZ 0x0034de18
0x34ddcd: MOVZX EAX, word ptr [R9 + 0x38]
0x34ddd2: MOV EBX, 0xffffffde
0x34ddd7: CMP ESI, EAX
0x34ddd9: JNC 0x0034de1d
0x34dddb: MOV EAX, ESI
0x34dddd: MOV EBX, 0xffffffda
0x34dde2: IMUL RAX, RAX, 0x38
0x34dde6: MOV R9, qword ptr [R9 + RAX*0x1 + 0x48]
0x34ddeb: MOV qword ptr [RDX], R9
0x34ddee: CMP dword ptr [RDI], 0x0
0x34ddf1: JZ 0x0034de32
0x34ddf3: MOV RDX, qword ptr [RDI + 0x38]
0x34ddf7: TEST RDX, RDX
0x34ddfa: JZ 0x0034de32
0x34ddfc: MOVZX EDI, word ptr [RDX + 0x38]
0x34de00: MOV EBX, 0xffffffea
0x34de05: CMP ESI, EDI
0x34de07: JNC 0x0034de32
0x34de09: MOV RAX, qword ptr [RDX + RAX*0x1 + 0x60]
0x34de0e: XOR EBX, EBX
0x34de10: MOV qword ptr [RCX], RAX
0x34de13: MOV qword ptr [R8], RAX
0x34de16: JMP 0x0034de4e
0x34de18: MOV EBX, 0xffffffda
0x34de1d: LEA RDI, [0x1280444]
0x34de24: LEA RSI, [0x135ae9a]
0x34de2b: MOV EDX, 0xd4
0x34de30: JMP 0x0034de45
0x34de32: LEA RDI, [0x1344efb]
0x34de39: LEA RSI, [0x135ae9a]
0x34de40: MOV EDX, 0xe0
0x34de45: MOV ECX, EBX
0x34de47: XOR EAX, EAX
0x34de49: CALL 0x0025d410
0x34de4e: MOV EAX, EBX
0x34de50: ADD RSP, 0x8
0x34de54: POP RBX
0x34de55: POP RBP
0x34de56: RET
; END FUNCTION sub_34ddb0

; FUNCTION sub_34de60 CONTEXT / separate function | ev_8647756e89a7fc2afc45d3bff43e34c55ad1e2df41e03555109cabcc5ec072f9
; Ghidra body: 0x34de60..0x34de75
sub_34de60:
0x34de60: PUSH RBP
0x34de61: MOV RBP, RSP
0x34de64: LEA RSI, [0xe6ba00]
0x34de6b: MOV EDX, 0xffffffec
0x34de70: POP RBP
0x34de71: JMP 0x0081a6a0
; END FUNCTION sub_34de60

; FUNCTION sub_34de80 CONTEXT / separate function | ev_bab40f823b1ce615d781c371e45475462865460d3b631c6b405821c1ada509bc
; Ghidra body: 0x34de80..0x34de9d
sub_34de80:
0x34de80: PUSH RBP
0x34de81: MOV RBP, RSP
0x34de84: LEA RDX, [0xe6ba20]
0x34de8b: MOV ESI, 0x100000
0x34de90: MOV ECX, 0x1
0x34de95: CALL 0x0081a730
0x34de9a: XOR EAX, EAX
0x34de9c: POP RBP
0x34de9d: RET
; END FUNCTION sub_34de80

; FUNCTION sub_34dea0 CONTEXT / separate function | ev_349fc8e39ff5c100cefc25f70a2a1a97ffe08db6bf9e36df59df1701c417f66e
; Ghidra body: 0x34dea0..0x34df9e
sub_34dea0:
0x34dea0: PUSH RBP
0x34dea1: MOV RBP, RSP
0x34dea4: PUSH R15
0x34dea6: PUSH R14
0x34dea8: PUSH R12
0x34deaa: PUSH RBX
0x34deab: MOV R15, qword ptr [RSI + 0x8]
0x34deaf: MOV R14D, EDX
0x34deb2: MOV RBX, RDI
0x34deb5: CMP EDX, 0x1
0x34deb8: JZ 0x0034df19
0x34deba: CMP R14D, 0x2
0x34debe: JNZ 0x0034df54
0x34dec4: MOV RDI, RBX
0x34dec7: MOV R12, RSI
0x34deca: CALL 0x00819390
0x34decf: MOV EDX, dword ptr [R15 + 0x10]
0x34ded3: MOV ESI, 0x781f
0x34ded8: MOV RAX, R12
0x34dedb: MOV ECX, EDX
0x34dedd: AND ECX, 0xe0
0x34dee3: CMP ECX, 0x20
0x34dee6: MOV ECX, 0x1f
0x34deeb: CMOVZ ECX, ESI
0x34deee: AND ECX, EDX
0x34def0: CMP ECX, 0x6
0x34def3: JZ 0x0034defa
0x34def5: CMP ECX, 0x3
0x34def8: JNZ 0x0034df54
0x34defa: MOV RCX, 0x2200000000
0x34df04: MOV RDI, RBX
0x34df07: MOV ESI, 0x2
0x34df0c: MOV qword ptr [RAX + 0x3c], RCX
0x34df10: MOV dword ptr [RBX + 0x68], 0x3
0x34df17: JMP 0x0034df7e
0x34df19: MOV RDI, RBX
0x34df1c: CALL 0x00819a50
0x34df21: CMP EAX, -0x2
0x34df24: JZ 0x0034df83
0x34df26: MOV EAX, dword ptr [R15 + 0x10]
0x34df2a: MOV ESI, 0x781f
0x34df2f: MOV EDX, 0x1f
0x34df34: MOV ECX, EAX
0x34df36: AND ECX, 0xe0
0x34df3c: CMP ECX, 0x20
0x34df3f: CMOVZ EDX, ESI
0x34df42: TEST EDX, EAX
0x34df44: JZ 0x0034df54
0x34df46: MOV EAX, dword ptr [RBX + 0x68]
0x34df49: TEST EAX, EAX
0x34df4b: JLE 0x0034df54
0x34df4d: DEC EAX
0x34df4f: MOV dword ptr [RBX + 0x68], EAX
0x34df52: JMP 0x0034df83
0x34df54: MOV RAX, qword ptr [RBX + 0x38]
0x34df58: MOV R15, qword ptr [RAX + 0x8]
0x34df5c: LEA RAX, [0x2652d0]
0x34df63: SUB RAX, R15
0x34df66: ROR RAX, 0x3
0x34df6a: CMP RAX, 0x8bc
0x34df70: JA 0x0034df8e
0x34df72: MOV RDI, RBX
0x34df75: CALL R15
0x34df78: MOV RDI, RBX
0x34df7b: MOV ESI, R14D
0x34df7e: CALL 0x00819e90
0x34df83: XOR EAX, EAX
0x34df85: POP RBX
0x34df86: POP R12
0x34df88: POP R14
0x34df8a: POP R15
0x34df8c: POP RBP
0x34df8d: RET
0x34df8e: LEA RDI, [0x1a9cb90]
0x34df95: MOV RSI, R15
0x34df98: CALL 0x0044f8c0
0x34df9d: JMP 0x0034df72
; END FUNCTION sub_34dea0

; FUNCTION sub_34dfa0 CONTEXT / separate function | ev_c60215fe7193e2abd3a4a656e7114dd1bfb8574615266107912007ba3c18ec14
; Ghidra body: 0x34dfa0..0x34e245
sub_34dfa0:
0x34dfa0: PUSH RBP
0x34dfa1: MOV RBP, RSP
0x34dfa4: PUSH R15
0x34dfa6: PUSH R14
0x34dfa8: PUSH R13
0x34dfaa: PUSH R12
0x34dfac: PUSH RBX
0x34dfad: SUB RSP, 0x18
0x34dfb1: MOV RCX, qword ptr [RDI + 0x40]
0x34dfb5: MOV RAX, 0x2000000001
0x34dfbf: LEA RSI, [0x2c095b0]
0x34dfc6: MOV qword ptr [RBP + -0x30], RDI
0x34dfca: MOV qword ptr [RCX + 0x3c], RAX
0x34dfce: MOV qword ptr [RBP + -0x40], RCX
0x34dfd2: MOV R14, qword ptr [RDI]
0x34dfd5: MOVZX EDX, byte ptr [RSI]
0x34dfd8: MOV R15D, dword ptr [RDI + 0x28]
0x34dfdc: MOV RCX, qword ptr [R14]
0x34dfdf: MOV RAX, qword ptr [RCX + RDX*0x8]
0x34dfe3: CMP qword ptr [RAX], RSI
0x34dfe6: JZ 0x0034dfff
0x34dfe8: LEA RSI, [RCX + RDX*0x8]
0x34dfec: MOV RDI, qword ptr [RCX + 0x800]
0x34dff3: LEA RDX, [0x2c095b0]
0x34dffa: CALL 0x00325ff0
0x34dfff: MOV R12, qword ptr [RAX + 0x8]
0x34e003: LEA RBX, [0x267140]
0x34e00a: MOV RAX, RBX
0x34e00d: SUB RAX, R12
0x34e010: ROR RAX, 0x3
0x34e014: CMP RAX, 0x26
0x34e018: JA 0x0034e1f6
0x34e01e: MOV RDI, R14
0x34e021: MOV ESI, R15D
0x34e024: MOV EDX, 0x1
0x34e029: CALL R12
0x34e02c: MOV RCX, qword ptr [RBP + -0x30]
0x34e030: LEA RSI, [0x2c095b0]
0x34e037: MOV dword ptr [RBP + -0x38], EAX
0x34e03a: MOV R15, qword ptr [RCX]
0x34e03d: MOV R12D, dword ptr [RCX + 0x28]
0x34e041: MOVZX EDX, byte ptr [RSI]
0x34e044: MOV RCX, qword ptr [R15]
0x34e047: MOV RAX, qword ptr [RCX + RDX*0x8]
0x34e04b: CMP qword ptr [RAX], RSI
0x34e04e: JZ 0x0034e067
0x34e050: LEA RSI, [RCX + RDX*0x8]
0x34e054: MOV RDI, qword ptr [RCX + 0x800]
0x34e05b: LEA RDX, [0x2c095b0]
0x34e062: CALL 0x00325ff0
0x34e067: MOV R14, qword ptr [RAX + 0x8]
0x34e06b: MOV RAX, RBX
0x34e06e: SUB RAX, R14
0x34e071: ROR RAX, 0x3
0x34e075: CMP RAX, 0x26
0x34e079: JA 0x0034e20a
0x34e07f: MOV RDI, R15
0x34e082: MOV ESI, R12D
0x34e085: MOV EDX, 0x1
0x34e08a: CALL R14
0x34e08d: MOV RCX, qword ptr [RBP + -0x30]
0x34e091: LEA RSI, [0x2c095b0]
0x34e098: MOV dword ptr [RBP + -0x34], EAX
0x34e09b: MOV R12, qword ptr [RCX]
0x34e09e: MOV R13D, dword ptr [RCX + 0x28]
0x34e0a2: MOVZX EDX, byte ptr [RSI]
0x34e0a5: MOV RCX, qword ptr [R12]
0x34e0a9: MOV RAX, qword ptr [RCX + RDX*0x8]
0x34e0ad: CMP qword ptr [RAX], RSI
0x34e0b0: JZ 0x0034e0c9
0x34e0b2: LEA RSI, [RCX + RDX*0x8]
0x34e0b6: MOV RDI, qword ptr [RCX + 0x800]
0x34e0bd: LEA RDX, [0x2c095b0]
0x34e0c4: CALL 0x00325ff0
0x34e0c9: MOV R14, qword ptr [RAX + 0x8]
0x34e0cd: MOV RAX, RBX
0x34e0d0: SUB RAX, R14
0x34e0d3: ROR RAX, 0x3
0x34e0d7: CMP RAX, 0x26
0x34e0db: JA 0x0034e21e
0x34e0e1: MOV RDI, R12
0x34e0e4: MOV ESI, R13D
0x34e0e7: MOV EDX, 0x16
0x34e0ec: CALL R14
0x34e0ef: MOV R12D, EAX
0x34e0f2: TEST R12W, R12W
0x34e0f6: JNS 0x0034e100
0x34e0f8: MOV RAX, qword ptr [RBP + -0x40]
0x34e0fc: OR byte ptr [RAX + 0x3c], 0x2
0x34e100: MOV RAX, qword ptr [RBP + -0x30]
0x34e104: LEA RSI, [0x2c095b0]
0x34e10b: MOV R13, qword ptr [RAX]
0x34e10e: MOVZX EDX, byte ptr [RSI]
0x34e111: MOV R14D, dword ptr [RAX + 0x28]
0x34e115: MOV RCX, qword ptr [R13]
0x34e119: MOV RAX, qword ptr [RCX + RDX*0x8]
0x34e11d: CMP qword ptr [RAX], RSI
0x34e120: JZ 0x0034e139
0x34e122: LEA RSI, [RCX + RDX*0x8]
0x34e126: MOV RDI, qword ptr [RCX + 0x800]
0x34e12d: LEA RDX, [0x2c095b0]
0x34e134: CALL 0x00325ff0
0x34e139: MOV R15, qword ptr [RAX + 0x8]
0x34e13d: SUB RBX, R15
0x34e140: ROR RBX, 0x3
0x34e144: CMP RBX, 0x26
0x34e148: JA 0x0034e232
0x34e14e: MOV RDI, R13
0x34e151: MOV ESI, R14D
0x34e154: XOR EDX, EDX
0x34e156: CALL R15
0x34e159: MOV RBX, qword ptr [RBP + -0x40]
0x34e15d: TEST EAX, 0x400
0x34e162: JNZ 0x0034e187
0x34e164: TEST EAX, 0x4000
0x34e169: JZ 0x0034e16f
0x34e16b: OR byte ptr [RBX + 0x43], 0x8
0x34e16f: TEST EAX, 0x1000
0x34e174: JZ 0x0034e194
0x34e176: MOV EAX, dword ptr [RBP + -0x34]
0x34e179: OR EAX, dword ptr [RBP + -0x38]
0x34e17c: AND EAX, 0x20
0x34e17f: JNZ 0x0034e194
0x34e181: OR byte ptr [RBX + 0x40], 0x2
0x34e185: JMP 0x0034e1e7
0x34e187: OR byte ptr [RBX + 0x40], 0x2
0x34e18b: MOV dword ptr [RBX + 0x3c], 0x0
0x34e192: JMP 0x0034e1e7
0x34e194: MOV ECX, dword ptr [RBX + 0x40]
0x34e197: MOV EAX, R12D
0x34e19a: AND EAX, 0x6000
0x34e19f: CMP EAX, 0x2000
0x34e1a4: JZ 0x0034e1b1
0x34e1a6: TEST EAX, EAX
0x34e1a8: JNZ 0x0034e1e1
0x34e1aa: MOV EAX, 0x3
0x34e1af: JMP 0x0034e1b6
0x34e1b1: MOV EAX, 0x6
0x34e1b6: OR EAX, ECX
0x34e1b8: MOV dword ptr [RBX + 0x40], EAX
0x34e1bb: TEST R12D, 0x1000
0x34e1c2: JNZ 0x0034e1cb
0x34e1c4: OR EAX, 0x200000
0x34e1c9: JMP 0x0034e1dc
0x34e1cb: MOV RDI, qword ptr [RBP + -0x30]
0x34e1cf: CALL 0x0081aab0
0x34e1d4: OR EAX, dword ptr [RBX + 0x40]
0x34e1d7: OR EAX, 0x100000
0x34e1dc: MOV dword ptr [RBX + 0x40], EAX
0x34e1df: JMP 0x0034e1e7
0x34e1e1: OR ECX, 0x2
0x34e1e4: MOV dword ptr [RBX + 0x40], ECX
0x34e1e7: ADD RSP, 0x18
0x34e1eb: POP RBX
0x34e1ec: POP R12
0x34e1ee: POP R13
0x34e1f0: POP R14
0x34e1f2: POP R15
0x34e1f4: POP RBP
0x34e1f5: RET
0x34e1f6: LEA RDI, [0x1a9cbb0]
0x34e1fd: MOV RSI, R12
0x34e200: CALL 0x0044f8c0
0x34e205: JMP 0x0034e01e
0x34e20a: LEA RDI, [0x1a9cbb0]
0x34e211: MOV RSI, R14
0x34e214: CALL 0x0044f8c0
0x34e219: JMP 0x0034e07f
0x34e21e: LEA RDI, [0x1a9cbb0]
0x34e225: MOV RSI, R14
0x34e228: CALL 0x0044f8c0
0x34e22d: JMP 0x0034e0e1
0x34e232: LEA RDI, [0x1a9cbb0]
0x34e239: MOV RSI, R15
0x34e23c: CALL 0x0044f8c0
0x34e241: JMP 0x0034e14e
; END FUNCTION sub_34dfa0

; FUNCTION sub_34e255 CONTEXT / separate function | ev_9f4c4090602b6a2a0e6d8b6ad76a50b8457e9053cf45fcae33f01d59f519fb4f
; Ghidra body: 0x34e255..0x34e273
sub_34e255:
0x34e255: PUSH RBP
0x34e256: MOV RBP, RSP
0x34e259: MOV R8, RSI
0x34e25c: MOV EDX, 0x68000
0x34e261: MOV ECX, 0x5
0x34e266: XOR ESI, ESI
0x34e268: CALL 0x0069d360
0x34e26d: XOR AL, 0x1
0x34e26f: MOVZX EAX, AL
0x34e272: POP RBP
0x34e273: RET
; END FUNCTION sub_34e255

; FUNCTION sub_34e285 CONTEXT / separate function | ev_79b90233da1bdb43184daf03b664f1df9fcf869f04701aaa9e5b7926f5999134
; Ghidra body: 0x34e285..0x34e2a3
sub_34e285:
0x34e285: PUSH RBP
0x34e286: MOV RBP, RSP
0x34e289: MOV R8, RSI
0x34e28c: MOV EDX, 0x68028
0x34e291: MOV ECX, 0x1
0x34e296: XOR ESI, ESI
0x34e298: CALL 0x0069d360
0x34e29d: XOR AL, 0x1
0x34e29f: MOVZX EAX, AL
0x34e2a2: POP RBP
0x34e2a3: RET
; END FUNCTION sub_34e285

; FUNCTION sub_34e2b5 CONTEXT / separate function | ev_4bcab105195ada711958718955c5fbabe2f183f070c2cbd7af78630f2c4582e4
; Ghidra body: 0x34e2b5..0x34e2d3
sub_34e2b5:
0x34e2b5: PUSH RBP
0x34e2b6: MOV RBP, RSP
0x34e2b9: MOV R8, RSI
0x34e2bc: MOV EDX, 0x68029
0x34e2c1: MOV ECX, 0x1
0x34e2c6: XOR ESI, ESI
0x34e2c8: CALL 0x0069d360
0x34e2cd: XOR AL, 0x1
0x34e2cf: MOVZX EAX, AL
0x34e2d2: POP RBP
0x34e2d3: RET
; END FUNCTION sub_34e2b5

; FUNCTION sub_34e2e5 CONTEXT / separate function | ev_47cc8dbd9bae002b1f2ab6c152cafc382fa932d756b3bfc858a138e0f20f459a
; Ghidra body: 0x34e2e5..0x34e303
sub_34e2e5:
0x34e2e5: PUSH RBP
0x34e2e6: MOV RBP, RSP
0x34e2e9: MOV R8, RSI
0x34e2ec: MOV EDX, 0x68005
0x34e2f1: MOV ECX, 0x2
0x34e2f6: XOR ESI, ESI
0x34e2f8: CALL 0x0069d360
0x34e2fd: XOR AL, 0x1
0x34e2ff: MOVZX EAX, AL
0x34e302: POP RBP
0x34e303: RET
; END FUNCTION sub_34e2e5

; FUNCTION sub_34e315 CONTEXT / separate function | ev_76e8b9fa83b75fcd744313f89ed2b12093dccd9639284349bc77ce035f09138f
; Ghidra body: 0x34e315..0x34e333
sub_34e315:
0x34e315: PUSH RBP
0x34e316: MOV RBP, RSP
0x34e319: MOV R8, RSI
0x34e31c: MOV EDX, 0x6802c
0x34e321: MOV ECX, 0xf
0x34e326: XOR ESI, ESI
0x34e328: CALL 0x0069d360
0x34e32d: XOR AL, 0x1
0x34e32f: MOVZX EAX, AL
0x34e332: POP RBP
0x34e333: RET
; END FUNCTION sub_34e315

; FUNCTION sub_34e340 CONTEXT / separate function | ev_a5d97c866296888df7d2599920b59f69ad8e50efe5467f977514ff9b689b404b
; Ghidra body: 0x34e340..0x34e40b
sub_34e340:
0x34e340: PUSH RBP
0x34e341: MOV RBP, RSP
0x34e344: PUSH R15
0x34e346: PUSH R14
0x34e348: PUSH RBX
0x34e349: PUSH RAX
0x34e34a: MOV EBX, 0x1
0x34e34f: TEST RSI, RSI
0x34e352: JZ 0x0034e3ff
0x34e358: MOV R14, RSI
0x34e35b: MOV EDX, 0x68014
0x34e360: MOV ECX, 0x4
0x34e365: MOV R15D, EDI
0x34e368: XOR ESI, ESI
0x34e36a: MOV R8, R14
0x34e36d: CALL 0x0069d360
0x34e372: TEST AL, AL
0x34e374: JZ 0x0034e3ff
0x34e37a: MOV R8, R14
0x34e37d: ADD R8, 0x4
0x34e381: JZ 0x0034e3ff
0x34e383: MOV EDI, R15D
0x34e386: MOV EDX, 0x68018
0x34e38b: MOV ECX, 0x4
0x34e390: XOR ESI, ESI
0x34e392: CALL 0x0069d360
0x34e397: TEST AL, AL
0x34e399: JZ 0x0034e3ff
0x34e39b: MOV R8, R14
0x34e39e: ADD R8, 0x8
0x34e3a2: JZ 0x0034e3ff
0x34e3a4: MOV EDI, R15D
0x34e3a7: MOV EDX, 0x6801c
0x34e3ac: MOV ECX, 0x4
0x34e3b1: XOR ESI, ESI
0x34e3b3: CALL 0x0069d360
0x34e3b8: TEST AL, AL
0x34e3ba: JZ 0x0034e3ff
0x34e3bc: MOV R8, R14
0x34e3bf: ADD R8, 0xc
0x34e3c3: JZ 0x0034e3ff
0x34e3c5: MOV EDI, R15D
0x34e3c8: MOV EDX, 0x68020
0x34e3cd: MOV ECX, 0x4
0x34e3d2: XOR ESI, ESI
0x34e3d4: CALL 0x0069d360
0x34e3d9: TEST AL, AL
0x34e3db: JZ 0x0034e3ff
0x34e3dd: ADD R14, 0x10
0x34e3e1: JZ 0x0034e3ff
0x34e3e3: MOV EDI, R15D
0x34e3e6: MOV EDX, 0x68024
0x34e3eb: MOV ECX, 0x4
0x34e3f0: MOV R8, R14
0x34e3f3: XOR ESI, ESI
0x34e3f5: CALL 0x0069d360
0x34e3fa: XOR AL, 0x1
0x34e3fc: MOVZX EBX, AL
0x34e3ff: MOV EAX, EBX
0x34e401: ADD RSP, 0x8
0x34e405: POP RBX
0x34e406: POP R14
0x34e408: POP R15
0x34e40a: POP RBP
0x34e40b: RET
; END FUNCTION sub_34e340

; FUNCTION sub_34e415 CONTEXT / separate function | ev_3ddf117c00f9b77d5f4935915ab0db5024f701feec67a1ece68faf998cc9810f
; Ghidra body: 0x34e415..0x34e433
sub_34e415:
0x34e415: PUSH RBP
0x34e416: MOV RBP, RSP
0x34e419: MOV R8, RSI
0x34e41c: MOV EDX, 0x6802a
0x34e421: MOV ECX, 0x2
0x34e426: XOR ESI, ESI
0x34e428: CALL 0x0069d360
0x34e42d: XOR AL, 0x1
0x34e42f: MOVZX EAX, AL
0x34e432: POP RBP
0x34e433: RET
; END FUNCTION sub_34e415

; FUNCTION sub_34e445 CONTEXT / separate function | ev_0449a83b50b6db71a7eb5e75996ed30943a90338d12e26f2e464d0e4ef07c527
; Ghidra body: 0x34e445..0x34e463
sub_34e445:
0x34e445: PUSH RBP
0x34e446: MOV RBP, RSP
0x34e449: MOV R8, RSI
0x34e44c: MOV EDX, 0x68007
0x34e451: MOV ECX, 0x5
0x34e456: XOR ESI, ESI
0x34e458: CALL 0x0069efd0
0x34e45d: XOR AL, 0x1
0x34e45f: MOVZX EAX, AL
0x34e462: POP RBP
0x34e463: RET
; END FUNCTION sub_34e445

; FUNCTION sub_34e475 CONTEXT / separate function | ev_6f1a077c343114478dd9eeb6d998e1bb3447ffb32c56799fb2c27a7ebadcd3ac
; Ghidra body: 0x34e475..0x34e493
sub_34e475:
0x34e475: PUSH RBP
0x34e476: MOV RBP, RSP
0x34e479: MOV R8, RSI
0x34e47c: MOV EDX, 0x6803b
0x34e481: MOV ECX, 0x1
0x34e486: XOR ESI, ESI
0x34e488: CALL 0x0069efd0
0x34e48d: XOR AL, 0x1
0x34e48f: MOVZX EAX, AL
0x34e492: POP RBP
0x34e493: RET
; END FUNCTION sub_34e475

; FUNCTION sub_34e4a5 CONTEXT / separate function | ev_054502ec5649b4379378d64bd2b274b7a5fc851ca870ec353e222a536e7beb3b
; Ghidra body: 0x34e4a5..0x34e4c3
sub_34e4a5:
0x34e4a5: PUSH RBP
0x34e4a6: MOV RBP, RSP
0x34e4a9: MOV R8, RSI
0x34e4ac: MOV EDX, 0x6800c
0x34e4b1: MOV ECX, 0x8
0x34e4b6: XOR ESI, ESI
0x34e4b8: CALL 0x0069efd0
0x34e4bd: XOR AL, 0x1
0x34e4bf: MOVZX EAX, AL
0x34e4c2: POP RBP
0x34e4c3: RET
; END FUNCTION sub_34e4a5

; FUNCTION sub_34e4d5 CONTEXT / separate function | ev_94fe115c7841d5e0f3db4b3a480548e1db737b537466311ef2d3e5e0776ee9b7
; Ghidra body: 0x34e4d5..0x34e4f3
sub_34e4d5:
0x34e4d5: PUSH RBP
0x34e4d6: MOV RBP, RSP
0x34e4d9: MOV R8, RSI
0x34e4dc: MOV EDX, 0x6921d
0x34e4e1: MOV ECX, 0x3
0x34e4e6: XOR ESI, ESI
0x34e4e8: CALL 0x0069d360
0x34e4ed: XOR AL, 0x1
0x34e4ef: MOVZX EAX, AL
0x34e4f2: POP RBP
0x34e4f3: RET
; END FUNCTION sub_34e4d5

; FUNCTION sub_34e505 CONTEXT / separate function | ev_432ed6279a61cb6ae9b9e4b2ea063beac78c0e2fc55eac6295305ea07eb8ac2b
; Ghidra body: 0x34e505..0x34e523
sub_34e505:
0x34e505: PUSH RBP
0x34e506: MOV RBP, RSP
0x34e509: MOV R8, RSI
0x34e50c: MOV EDX, 0x69493
0x34e511: MOV ECX, 0x1
0x34e516: XOR ESI, ESI
0x34e518: CALL 0x0069d360
0x34e51d: XOR AL, 0x1
0x34e51f: MOVZX EAX, AL
0x34e522: POP RBP
0x34e523: RET
; END FUNCTION sub_34e505

; FUNCTION sub_34e530 CONTEXT / separate function | ev_25f107af73fcec5f9eae08e43bce7a7e646aa1cabab2e776a259d58d29cfae2f
; Ghidra body: 0x34e530..0x34e5aa
sub_34e530:
0x34e530: PUSH RBP
0x34e531: MOV RBP, RSP
0x34e534: PUSH R15
0x34e536: PUSH R14
0x34e538: PUSH R13
0x34e53a: PUSH R12
0x34e53c: PUSH RBX
0x34e53d: PUSH RAX
0x34e53e: MOV R14, RSI
0x34e541: MOV EAX, 0x1
0x34e546: INC R14
0x34e549: JZ 0x0034e59c
0x34e54b: MOV R15D, EDI
0x34e54e: MOV R13D, 0x215
0x34e554: XOR EBX, EBX
0x34e556: NOP word ptr CS:[RAX + RAX*0x1]
0x34e560: CMP R13D, 0x10
0x34e564: MOV R12D, 0x10
0x34e56a: MOV R8D, EBX
0x34e56d: LEA EDX, [RBX + 0x6900b]
0x34e573: MOV EDI, R15D
0x34e576: CMOVC R12D, R13D
0x34e57a: ADD R8, R14
0x34e57d: XOR ESI, ESI
0x34e57f: MOV ECX, R12D
0x34e582: CALL 0x0069d360
0x34e587: TEST AL, AL
0x34e589: JZ 0x0034e597
0x34e58b: ADD EBX, R12D
0x34e58e: SUB R13D, R12D
0x34e591: JNZ 0x0034e560
0x34e593: XOR EAX, EAX
0x34e595: JMP 0x0034e59c
0x34e597: MOV EAX, 0x1
0x34e59c: ADD RSP, 0x8
0x34e5a0: POP RBX
0x34e5a1: POP R12
0x34e5a3: POP R13
0x34e5a5: POP R14
0x34e5a7: POP R15
0x34e5a9: POP RBP
0x34e5aa: RET
; END FUNCTION sub_34e530

; FUNCTION sub_34e5b0 CONTEXT / separate function | ev_0282662f109399c53126150bf1bf301f6698ec63253d1322b0bca5d06d411d5f
; Ghidra body: 0x34e5b0..0x34e611
sub_34e5b0:
0x34e5b0: PUSH RBP
0x34e5b1: MOV RBP, RSP
0x34e5b4: PUSH R15
0x34e5b6: PUSH R14
0x34e5b8: PUSH RBX
0x34e5b9: PUSH RAX
0x34e5ba: MOV R8, RSI
0x34e5bd: MOV R14D, 0x1
0x34e5c3: INC R8
0x34e5c6: JZ 0x0034e604
0x34e5c8: MOV EDX, 0x692c0
0x34e5cd: MOV ECX, 0x10
0x34e5d2: MOV RBX, RSI
0x34e5d5: XOR ESI, ESI
0x34e5d7: MOV R15D, EDI
0x34e5da: CALL 0x0069d360
0x34e5df: TEST AL, AL
0x34e5e1: JZ 0x0034e604
0x34e5e3: ADD RBX, 0x11
0x34e5e7: MOV EDI, R15D
0x34e5ea: MOV EDX, 0x692d0
0x34e5ef: MOV ECX, 0x10
0x34e5f4: XOR ESI, ESI
0x34e5f6: MOV R8, RBX
0x34e5f9: CALL 0x0069d360
0x34e5fe: XOR AL, 0x1
0x34e600: MOVZX R14D, AL
0x34e604: MOV EAX, R14D
0x34e607: ADD RSP, 0x8
0x34e60b: POP RBX
0x34e60c: POP R14
0x34e60e: POP R15
0x34e610: POP RBP
0x34e611: RET
; END FUNCTION sub_34e5b0

; FUNCTION sub_34e628 CONTEXT / separate function | ev_dc45d969908f444ec4abc1c841151e2d1d1d21a4467019727e6ea5c7d2052e2c
; Ghidra body: 0x34e628..0x34e643
sub_34e628:
0x34e628: PUSH RBP
0x34e629: MOV RBP, RSP
0x34e62c: MOV EDX, 0x692e0
0x34e631: MOV ECX, 0x10
0x34e636: XOR ESI, ESI
0x34e638: CALL 0x0069d360
0x34e63d: XOR AL, 0x1
0x34e63f: MOVZX EAX, AL
0x34e642: POP RBP
0x34e643: RET
; END FUNCTION sub_34e628

; FUNCTION sub_34e650 CONTEXT / separate function | ev_5eee4ac9e442d870f3a897ed5a6c0b20a1115cab2c1c6dedc3a20520eccf3716
; Ghidra body: 0x34e650..0x34e6b1
sub_34e650:
0x34e650: PUSH RBP
0x34e651: MOV RBP, RSP
0x34e654: PUSH R15
0x34e656: PUSH R14
0x34e658: PUSH RBX
0x34e659: PUSH RAX
0x34e65a: MOV R8, RSI
0x34e65d: MOV R14D, 0x1
0x34e663: INC R8
0x34e666: JZ 0x0034e6a4
0x34e668: MOV EDX, 0x692f8
0x34e66d: MOV ECX, 0x10
0x34e672: MOV RBX, RSI
0x34e675: XOR ESI, ESI
0x34e677: MOV R15D, EDI
0x34e67a: CALL 0x0069d360
0x34e67f: TEST AL, AL
0x34e681: JZ 0x0034e6a4
0x34e683: ADD RBX, 0x11
0x34e687: MOV EDI, R15D
0x34e68a: MOV EDX, 0x69308
0x34e68f: MOV ECX, 0x10
0x34e694: XOR ESI, ESI
0x34e696: MOV R8, RBX
0x34e699: CALL 0x0069d360
0x34e69e: XOR AL, 0x1
0x34e6a0: MOVZX R14D, AL
0x34e6a4: MOV EAX, R14D
0x34e6a7: ADD RSP, 0x8
0x34e6ab: POP RBX
0x34e6ac: POP R14
0x34e6ae: POP R15
0x34e6b0: POP RBP
0x34e6b1: RET
; END FUNCTION sub_34e650

; FUNCTION sub_34e6c0 CONTEXT / separate function | ev_cad1beb1acef999eb6a6a542bdbf86ba47494ef736e925f8daf97f3806929384
; Ghidra body: 0x34e6c0..0x34e866
sub_34e6c0:
0x34e6c0: PUSH RBP
0x34e6c1: MOV RBP, RSP
0x34e6c4: PUSH R15
0x34e6c6: PUSH R14
0x34e6c8: PUSH RBX
0x34e6c9: PUSH RAX
0x34e6ca: MOV R8, RSI
0x34e6cd: MOV EBX, 0x1
0x34e6d2: INC R8
0x34e6d5: JZ 0x0034e85a
0x34e6db: MOV EDX, 0x69330
0x34e6e0: MOV ECX, 0x10
0x34e6e5: MOV R14, RSI
0x34e6e8: XOR ESI, ESI
0x34e6ea: MOV R15D, EDI
0x34e6ed: CALL 0x0069d360
0x34e6f2: TEST AL, AL
0x34e6f4: JZ 0x0034e85a
0x34e6fa: LEA R8, [R14 + 0x11]
0x34e6fe: MOV EDI, R15D
0x34e701: MOV EDX, 0x69340
0x34e706: MOV ECX, 0x10
0x34e70b: XOR ESI, ESI
0x34e70d: CALL 0x0069d360
0x34e712: TEST AL, AL
0x34e714: JZ 0x0034e85a
0x34e71a: LEA R8, [R14 + 0x21]
0x34e71e: MOV EDI, R15D
0x34e721: MOV EDX, 0x69350
0x34e726: MOV ECX, 0x10
0x34e72b: XOR ESI, ESI
0x34e72d: CALL 0x0069d360
0x34e732: TEST AL, AL
0x34e734: JZ 0x0034e85a
0x34e73a: LEA R8, [R14 + 0x31]
0x34e73e: MOV EDI, R15D
0x34e741: MOV EDX, 0x69360
0x34e746: MOV ECX, 0x10
0x34e74b: XOR ESI, ESI
0x34e74d: CALL 0x0069d360
0x34e752: TEST AL, AL
0x34e754: JZ 0x0034e85a
0x34e75a: LEA R8, [R14 + 0x41]
0x34e75e: MOV EDI, R15D
0x34e761: MOV EDX, 0x69370
0x34e766: MOV ECX, 0x10
0x34e76b: XOR ESI, ESI
0x34e76d: CALL 0x0069d360
0x34e772: TEST AL, AL
0x34e774: JZ 0x0034e85a
0x34e77a: LEA R8, [R14 + 0x51]
0x34e77e: MOV EDI, R15D
0x34e781: MOV EDX, 0x69380
0x34e786: MOV ECX, 0x10
0x34e78b: XOR ESI, ESI
0x34e78d: CALL 0x0069d360
0x34e792: TEST AL, AL
0x34e794: JZ 0x0034e85a
0x34e79a: LEA R8, [R14 + 0x61]
0x34e79e: MOV EDI, R15D
0x34e7a1: MOV EDX, 0x69390
0x34e7a6: MOV ECX, 0x10
0x34e7ab: XOR ESI, ESI
0x34e7ad: CALL 0x0069d360
0x34e7b2: TEST AL, AL
0x34e7b4: JZ 0x0034e85a
0x34e7ba: LEA R8, [R14 + 0x71]
0x34e7be: MOV EDI, R15D
0x34e7c1: MOV EDX, 0x693a0
0x34e7c6: MOV ECX, 0x10
0x34e7cb: XOR ESI, ESI
0x34e7cd: CALL 0x0069d360
0x34e7d2: TEST AL, AL
0x34e7d4: JZ 0x0034e85a
0x34e7da: LEA R8, [R14 + 0x81]
0x34e7e1: MOV EDI, R15D
0x34e7e4: MOV EDX, 0x693b0
0x34e7e9: MOV ECX, 0x10
0x34e7ee: XOR ESI, ESI
0x34e7f0: CALL 0x0069d360
0x34e7f5: TEST AL, AL
0x34e7f7: JZ 0x0034e85a
0x34e7f9: LEA R8, [R14 + 0x91]
0x34e800: MOV EDI, R15D
0x34e803: MOV EDX, 0x693c0
0x34e808: MOV ECX, 0x10
0x34e80d: XOR ESI, ESI
0x34e80f: CALL 0x0069d360
0x34e814: TEST AL, AL
0x34e816: JZ 0x0034e85a
0x34e818: LEA R8, [R14 + 0xa1]
0x34e81f: MOV EDI, R15D
0x34e822: MOV EDX, 0x693d0
0x34e827: MOV ECX, 0x10
0x34e82c: XOR ESI, ESI
0x34e82e: CALL 0x0069d360
0x34e833: TEST AL, AL
0x34e835: JZ 0x0034e85a
0x34e837: ADD R14, 0xb1
0x34e83e: MOV EDI, R15D
0x34e841: MOV EDX, 0x693e0
0x34e846: MOV ECX, 0x1
0x34e84b: XOR ESI, ESI
0x34e84d: MOV R8, R14
0x34e850: CALL 0x0069d360
0x34e855: XOR AL, 0x1
0x34e857: MOVZX EBX, AL
0x34e85a: MOV EAX, EBX
0x34e85c: ADD RSP, 0x8
0x34e860: POP RBX
0x34e861: POP R14
0x34e863: POP R15
0x34e865: POP RBP
0x34e866: RET
; END FUNCTION sub_34e6c0

; FUNCTION sub_34e870 CONTEXT / separate function | ev_a6101af9df822aeacb37fd321a5ef4c83f99f00fbebf4e4ccb65c0adeac62162
; Ghidra body: 0x34e870..0x34e8d1
sub_34e870:
0x34e870: PUSH RBP
0x34e871: MOV RBP, RSP
0x34e874: PUSH R15
0x34e876: PUSH R14
0x34e878: PUSH RBX
0x34e879: PUSH RAX
0x34e87a: MOV R8, RSI
0x34e87d: MOV R14D, 0x1
0x34e883: INC R8
0x34e886: JZ 0x0034e8c4
0x34e888: MOV EDX, 0x69473
0x34e88d: MOV ECX, 0x10
0x34e892: MOV RBX, RSI
0x34e895: XOR ESI, ESI
0x34e897: MOV R15D, EDI
0x34e89a: CALL 0x0069d360
0x34e89f: TEST AL, AL
0x34e8a1: JZ 0x0034e8c4
0x34e8a3: ADD RBX, 0x11
0x34e8a7: MOV EDI, R15D
0x34e8aa: MOV EDX, 0x69483
0x34e8af: MOV ECX, 0x10
0x34e8b4: XOR ESI, ESI
0x34e8b6: MOV R8, RBX
0x34e8b9: CALL 0x0069d360
0x34e8be: XOR AL, 0x1
0x34e8c0: MOVZX R14D, AL
0x34e8c4: MOV EAX, R14D
0x34e8c7: ADD RSP, 0x8
0x34e8cb: POP RBX
0x34e8cc: POP R14
0x34e8ce: POP R15
0x34e8d0: POP RBP
0x34e8d1: RET
; END FUNCTION sub_34e870

; FUNCTION sub_34e8e8 CONTEXT / separate function | ev_d77479e61670ecb05afe27f84153272420ef8c1f125f50ee5134c27a6da63279
; Ghidra body: 0x34e8e8..0x34e903
sub_34e8e8:
0x34e8e8: PUSH RBP
0x34e8e9: MOV RBP, RSP
0x34e8ec: MOV EDX, 0x69000
0x34e8f1: MOV ECX, 0xb
0x34e8f6: XOR ESI, ESI
0x34e8f8: CALL 0x0069efd0
0x34e8fd: XOR AL, 0x1
0x34e8ff: MOVZX EAX, AL
0x34e902: POP RBP
0x34e903: RET
; END FUNCTION sub_34e8e8

; FUNCTION sub_34e910 CONTEXT / separate function | ev_c404355ae1780c236779017f5057a5b37efa5762c3bb83c83cdf50bc0a445962
; Ghidra body: 0x34e910..0x34ea26
sub_34e910:
0x34e910: PUSH RBP
0x34e911: MOV RBP, RSP
0x34e914: PUSH R15
0x34e916: PUSH R14
0x34e918: PUSH RBX
0x34e919: PUSH RAX
0x34e91a: MOV R8, RSI
0x34e91d: MOV EBX, 0x1
0x34e922: INC R8
0x34e925: JZ 0x0034ea1a
0x34e92b: MOV EDX, 0x69220
0x34e930: MOV ECX, 0x10
0x34e935: MOV R14, RSI
0x34e938: XOR ESI, ESI
0x34e93a: MOV R15D, EDI
0x34e93d: CALL 0x0069efd0
0x34e942: TEST AL, AL
0x34e944: JZ 0x0034ea1a
0x34e94a: LEA R8, [R14 + 0x11]
0x34e94e: MOV EDI, R15D
0x34e951: MOV EDX, 0x69230
0x34e956: MOV ECX, 0x10
0x34e95b: XOR ESI, ESI
0x34e95d: CALL 0x0069efd0
0x34e962: TEST AL, AL
0x34e964: JZ 0x0034ea1a
0x34e96a: LEA R8, [R14 + 0x21]
0x34e96e: MOV EDI, R15D
0x34e971: MOV EDX, 0x69240
0x34e976: MOV ECX, 0x10
0x34e97b: XOR ESI, ESI
0x34e97d: CALL 0x0069efd0
0x34e982: TEST AL, AL
0x34e984: JZ 0x0034ea1a
0x34e98a: LEA R8, [R14 + 0x31]
0x34e98e: MOV EDI, R15D
0x34e991: MOV EDX, 0x69250
0x34e996: MOV ECX, 0x10
0x34e99b: XOR ESI, ESI
0x34e99d: CALL 0x0069efd0
0x34e9a2: TEST AL, AL
0x34e9a4: JZ 0x0034ea1a
0x34e9a6: LEA R8, [R14 + 0x41]
0x34e9aa: MOV EDI, R15D
0x34e9ad: MOV EDX, 0x69260
0x34e9b2: MOV ECX, 0x10
0x34e9b7: XOR ESI, ESI
0x34e9b9: CALL 0x0069efd0
0x34e9be: TEST AL, AL
0x34e9c0: JZ 0x0034ea1a
0x34e9c2: LEA R8, [R14 + 0x51]
0x34e9c6: MOV EDI, R15D
0x34e9c9: MOV EDX, 0x69270
0x34e9ce: MOV ECX, 0x10
0x34e9d3: XOR ESI, ESI
0x34e9d5: CALL 0x0069efd0
0x34e9da: TEST AL, AL
0x34e9dc: JZ 0x0034ea1a
0x34e9de: LEA R8, [R14 + 0x61]
0x34e9e2: MOV EDI, R15D
0x34e9e5: MOV EDX, 0x69280
0x34e9ea: MOV ECX, 0x10
0x34e9ef: XOR ESI, ESI
0x34e9f1: CALL 0x0069efd0
0x34e9f6: TEST AL, AL
0x34e9f8: JZ 0x0034ea1a
0x34e9fa: ADD R14, 0x71
0x34e9fe: MOV EDI, R15D
0x34ea01: MOV EDX, 0x69290
0x34ea06: MOV ECX, 0x10
0x34ea0b: XOR ESI, ESI
0x34ea0d: MOV R8, R14
0x34ea10: CALL 0x0069efd0
0x34ea15: XOR AL, 0x1
0x34ea17: MOVZX EBX, AL
0x34ea1a: MOV EAX, EBX
0x34ea1c: ADD RSP, 0x8
0x34ea20: POP RBX
0x34ea21: POP R14
0x34ea23: POP R15
0x34ea25: POP RBP
0x34ea26: RET
; END FUNCTION sub_34e910

; FUNCTION sub_34ea30 CONTEXT / separate function | ev_0cc63209a5b0b3584224e41ec8ddea64b7849db20494a2033bf0906ebe955cba
; Ghidra body: 0x34ea30..0x34ea91
sub_34ea30:
0x34ea30: PUSH RBP
0x34ea31: MOV RBP, RSP
0x34ea34: PUSH R15
0x34ea36: PUSH R14
0x34ea38: PUSH RBX
0x34ea39: PUSH RAX
0x34ea3a: MOV R8, RSI
0x34ea3d: MOV R14D, 0x1
0x34ea43: INC R8
0x34ea46: JZ 0x0034ea84
0x34ea48: MOV EDX, 0x692a0
0x34ea4d: MOV ECX, 0x10
0x34ea52: MOV RBX, RSI
0x34ea55: XOR ESI, ESI
0x34ea57: MOV R15D, EDI
0x34ea5a: CALL 0x0069efd0
0x34ea5f: TEST AL, AL
0x34ea61: JZ 0x0034ea84
0x34ea63: ADD RBX, 0x11
0x34ea67: MOV EDI, R15D
0x34ea6a: MOV EDX, 0x692b0
0x34ea6f: MOV ECX, 0x10
0x34ea74: XOR ESI, ESI
0x34ea76: MOV R8, RBX
0x34ea79: CALL 0x0069efd0
0x34ea7e: XOR AL, 0x1
0x34ea80: MOVZX R14D, AL
0x34ea84: MOV EAX, R14D
0x34ea87: ADD RSP, 0x8
0x34ea8b: POP RBX
0x34ea8c: POP R14
0x34ea8e: POP R15
0x34ea90: POP RBP
0x34ea91: RET
; END FUNCTION sub_34ea30

; FUNCTION sub_34eaa8 CONTEXT / separate function | ev_bda2530ad3c3c365fa2076f69043115643394089a85601cf39d118fbdaa5905c
; Ghidra body: 0x34eaa8..0x34eac3
sub_34eaa8:
0x34eaa8: PUSH RBP
0x34eaa9: MOV RBP, RSP
0x34eaac: MOV EDX, 0x692f0
0x34eab1: MOV ECX, 0x8
0x34eab6: XOR ESI, ESI
0x34eab8: CALL 0x0069efd0
0x34eabd: XOR AL, 0x1
0x34eabf: MOVZX EAX, AL
0x34eac2: POP RBP
0x34eac3: RET
; END FUNCTION sub_34eaa8

; FUNCTION sub_34ead0 CONTEXT / separate function | ev_a297cada5ccdca923ff132ae971645dd8c957bf0c32585f2f7a7a1bf142fdb23
; Ghidra body: 0x34ead0..0x34eb31
sub_34ead0:
0x34ead0: PUSH RBP
0x34ead1: MOV RBP, RSP
0x34ead4: PUSH R15
0x34ead6: PUSH R14
0x34ead8: PUSH RBX
0x34ead9: PUSH RAX
0x34eada: MOV R8, RSI
0x34eadd: MOV R14D, 0x1
0x34eae3: INC R8
0x34eae6: JZ 0x0034eb24
0x34eae8: MOV EDX, 0x69318
0x34eaed: MOV ECX, 0x10
0x34eaf2: MOV RBX, RSI
0x34eaf5: XOR ESI, ESI
0x34eaf7: MOV R15D, EDI
0x34eafa: CALL 0x0069efd0
0x34eaff: TEST AL, AL
0x34eb01: JZ 0x0034eb24
0x34eb03: ADD RBX, 0x11
0x34eb07: MOV EDI, R15D
0x34eb0a: MOV EDX, 0x69328
0x34eb0f: MOV ECX, 0x8
0x34eb14: XOR ESI, ESI
0x34eb16: MOV R8, RBX
0x34eb19: CALL 0x0069efd0
0x34eb1e: XOR AL, 0x1
0x34eb20: MOVZX R14D, AL
0x34eb24: MOV EAX, R14D
0x34eb27: ADD RSP, 0x8
0x34eb2b: POP RBX
0x34eb2c: POP R14
0x34eb2e: POP R15
0x34eb30: POP RBP
0x34eb31: RET
; END FUNCTION sub_34ead0

; FUNCTION sub_34eb48 CONTEXT / separate function | ev_62f79da0e15bc8bb4ccd5f25c499dc19775fdcdb7f02b872cbc0b136470fc2b5
; Ghidra body: 0x34eb48..0x34eb63
sub_34eb48:
0x34eb48: PUSH RBP
0x34eb49: MOV RBP, RSP
0x34eb4c: MOV EDX, 0x693e0
0x34eb51: MOV ECX, 0x10
0x34eb56: XOR ESI, ESI
0x34eb58: CALL 0x0069efd0
0x34eb5d: XOR AL, 0x1
0x34eb5f: MOVZX EAX, AL
0x34eb62: POP RBP
0x34eb63: RET
; END FUNCTION sub_34eb48

; FUNCTION sub_34eb78 CONTEXT / separate function | ev_b659e52b05a2c2905bab52017090008502eb5c3a7e1977176f6b692fa3901ede
; Ghidra body: 0x34eb78..0x34eb93
sub_34eb78:
0x34eb78: PUSH RBP
0x34eb79: MOV RBP, RSP
0x34eb7c: MOV EDX, 0x693f0
0x34eb81: MOV ECX, 0x7
0x34eb86: XOR ESI, ESI
0x34eb88: CALL 0x0069efd0
0x34eb8d: XOR AL, 0x1
0x34eb8f: MOVZX EAX, AL
0x34eb92: POP RBP
0x34eb93: RET
; END FUNCTION sub_34eb78

; FUNCTION sub_34eba5 CONTEXT / separate function | ev_20fa3f4ca07efbb663973420e1f8b8fb97055cfd8a769dbda4a90f9eb2bca743
; Ghidra body: 0x34eba5..0x34ebc3
sub_34eba5:
0x34eba5: PUSH RBP
0x34eba6: MOV RBP, RSP
0x34eba9: MOV R8, RSI
0x34ebac: MOV EDX, 0x69494
0x34ebb1: MOV ECX, 0x1
0x34ebb6: XOR ESI, ESI
0x34ebb8: CALL 0x0069efd0
0x34ebbd: XOR AL, 0x1
0x34ebbf: MOVZX EAX, AL
0x34ebc2: POP RBP
0x34ebc3: RET
; END FUNCTION sub_34eba5

; FUNCTION sub_34ebd0 CONTEXT / separate function | ev_b1af541f9e9139a55f4bc51ba87920c536e1f4a17aa68a2bb6cdb1bc72a21560
; Ghidra body: 0x34ebd0..0x34ec15, 0x34ec20..0x34ed95
sub_34ebd0:
0x34ebd0: PUSH RBP
0x34ebd1: MOV RBP, RSP
0x34ebd4: PUSH R15
0x34ebd6: PUSH R14
0x34ebd8: PUSH R13
0x34ebda: PUSH R12
0x34ebdc: PUSH RBX
0x34ebdd: SUB RSP, 0xd8
0x34ebe4: LEA RAX, [0x391c310]
0x34ebeb: MOV R14, RDI
0x34ebee: MOV RAX, qword ptr [RAX]
0x34ebf1: MOV qword ptr [RBP + -0x30], RAX
0x34ebf5: MOV EDI, dword ptr [RDI]
0x34ebf7: CALL 0x0039b1e0
0x34ebfc: LEA R15, [RBP + -0xf0]
0x34ec03: LEA RBX, [0x12f1b6f]
0x34ec0a: LEA R13, [0x136f6ce]
0x34ec11: XOR R12D, R12D
0x34ec14: JMP 0x0034ec3a
0x34ec20: MOV RDI, RBX
0x34ec23: MOV RSI, R13
0x34ec26: XOR EAX, EAX
0x34ec28: CALL 0x0025d410
0x34ec2d: INC R12D
0x34ec30: CMP R12D, 0x10
0x34ec34: JZ 0x0034ed0b
0x34ec3a: MOV EDI, dword ptr [R14]
0x34ec3d: MOV ESI, R12D
0x34ec40: CALL 0x002a3970
0x34ec45: TEST RAX, RAX
0x34ec48: JZ 0x0034eced
0x34ec4e: MOV EDI, dword ptr [R14]
0x34ec51: MOV ECX, 0xc0
0x34ec56: MOV RSI, RAX
0x34ec59: MOV RDX, R15
0x34ec5c: CALL 0x00b95060
0x34ec61: TEST AL, AL
0x34ec63: JZ 0x0034ec20
0x34ec65: CMP dword ptr [RBP + -0xf0], 0x3
0x34ec6c: JNZ 0x0034ec2d
0x34ec6e: LEA RDI, [R14 + 0x8]
0x34ec72: LEA RSI, [RBP + -0xe8]
0x34ec79: MOV EDX, 0xb8
0x34ec7e: MOV dword ptr [R14 + 0x4], R12D
0x34ec82: CALL 0x002590b0
0x34ec87: MOV R14D, dword ptr [R14]
0x34ec8a: MOV EDI, R14D
0x34ec8d: CALL 0x002a3930
0x34ec92: TEST RAX, RAX
0x34ec95: JZ 0x0034ed1e
0x34ec9b: MOV R15, RAX
0x34ec9e: LEA RDX, [RBP + -0xf8]
0x34eca5: MOV ECX, 0x8
0x34ecaa: MOV EDI, R14D
0x34ecad: ADD R15, 0x30
0x34ecb1: MOV RSI, R15
0x34ecb4: CALL 0x00b95060
0x34ecb9: LEA R12, [0x391c310]
0x34ecc0: TEST AL, AL
0x34ecc2: JZ 0x0034ed43
0x34ecc4: INC qword ptr [RBP + -0xf8]
0x34eccb: LEA RDX, [RBP + -0xf8]
0x34ecd2: MOV ECX, 0x8
0x34ecd7: MOV EDI, R14D
0x34ecda: MOV RSI, R15
0x34ecdd: CALL 0x00b951c0
0x34ece2: TEST AL, AL
0x34ece4: JZ 0x0034ed3c
0x34ece6: XOR EAX, EAX
0x34ece8: JMP 0x0034ed73
0x34eced: LEA RDI, [0x126d389]
0x34ecf4: LEA RSI, [0x136f6ce]
0x34ecfb: XOR EAX, EAX
0x34ecfd: CALL 0x0025d410
0x34ed02: LEA R12, [0x391c310]
0x34ed09: JMP 0x0034ed6e
0x34ed0b: LEA R12, [0x391c310]
0x34ed12: MOV dword ptr [R14 + 0x4], 0xffffffff
0x34ed1a: XOR EAX, EAX
0x34ed1c: JMP 0x0034ed73
0x34ed1e: LEA RDI, [0x12fb0b2]
0x34ed25: LEA RSI, [0x129f32d]
0x34ed2c: XOR EAX, EAX
0x34ed2e: CALL 0x0025d410
0x34ed33: LEA R12, [0x391c310]
0x34ed3a: JMP 0x0034ed54
0x34ed3c: LEA RBX, [0x126d3fa]
0x34ed43: LEA RSI, [0x129f32d]
0x34ed4a: MOV RDI, RBX
0x34ed4d: XOR EAX, EAX
0x34ed4f: CALL 0x0025d410
0x34ed54: LEA RDI, [0x126d3be]
0x34ed5b: LEA RSI, [0x136f6ce]
0x34ed62: MOV EDX, 0x1
0x34ed67: XOR EAX, EAX
0x34ed69: CALL 0x0025d410
0x34ed6e: MOV EAX, 0x1
0x34ed73: MOV RCX, qword ptr [R12]
0x34ed77: CMP RCX, qword ptr [RBP + -0x30]
0x34ed7b: JNZ 0x0034ed8f
0x34ed7d: ADD RSP, 0xd8
0x34ed84: POP RBX
0x34ed85: POP R12
0x34ed87: POP R13
0x34ed89: POP R14
0x34ed8b: POP R15
0x34ed8d: POP RBP
0x34ed8e: RET
0x34ed8f: CALL 0x006fd6b0
0x34ed94: UD2
; END FUNCTION sub_34ebd0

; FUNCTION sub_34eda0 CONTEXT / separate function | ev_c64466e3584dd7530ea53886b1378a3a4fc50e658041ddc8502c31e68cdc5b89
; Ghidra body: 0x34eda0..0x34eec4
sub_34eda0:
0x34eda0: PUSH RBP
0x34eda1: MOV RBP, RSP
0x34eda4: PUSH R15
0x34eda6: PUSH R14
0x34eda8: PUSH RBX
0x34eda9: SUB RSP, 0x18
0x34edad: LEA R15, [0x391c310]
0x34edb4: MOV RAX, qword ptr [R15]
0x34edb7: MOV qword ptr [RBP + -0x20], RAX
0x34edbb: MOV EAX, 0x16
0x34edc0: MOV ESI, dword ptr [RDI + 0x4]
0x34edc3: CMP ESI, 0xf
0x34edc6: JA 0x0034eeaa
0x34edcc: MOV RBX, RDI
0x34edcf: MOV EDI, dword ptr [RDI]
0x34edd1: CALL 0x002a3970
0x34edd6: TEST RAX, RAX
0x34edd9: JZ 0x0034ee44
0x34eddb: MOV dword ptr [RBP + -0x2c], 0x2
0x34ede2: LEA RDX, [RBP + -0x2c]
0x34ede6: MOV ECX, 0x4
0x34edeb: MOV RSI, RAX
0x34edee: MOV EDI, dword ptr [RBX]
0x34edf0: CALL 0x00b951c0
0x34edf5: TEST AL, AL
0x34edf7: JZ 0x0034ee4d
0x34edf9: MOV EBX, dword ptr [RBX]
0x34edfb: MOV EDI, EBX
0x34edfd: CALL 0x002a3930
0x34ee02: TEST RAX, RAX
0x34ee05: JZ 0x0034ee64
0x34ee07: MOV R14, RAX
0x34ee0a: LEA RDX, [RBP + -0x28]
0x34ee0e: MOV ECX, 0x8
0x34ee13: MOV EDI, EBX
0x34ee15: ADD R14, 0x38
0x34ee19: MOV RSI, R14
0x34ee1c: CALL 0x00b95060
0x34ee21: TEST AL, AL
0x34ee23: JZ 0x0034ee6d
0x34ee25: INC qword ptr [RBP + -0x28]
0x34ee29: LEA RDX, [RBP + -0x28]
0x34ee2d: MOV ECX, 0x8
0x34ee32: MOV EDI, EBX
0x34ee34: MOV RSI, R14
0x34ee37: CALL 0x00b951c0
0x34ee3c: TEST AL, AL
0x34ee3e: JZ 0x0034ee76
0x34ee40: XOR EAX, EAX
0x34ee42: JMP 0x0034eeaa
0x34ee44: LEA RDI, [0x126d389]
0x34ee4b: JMP 0x0034ee54
0x34ee4d: LEA RDI, [0x126d3fa]
0x34ee54: LEA RSI, [0x12f1b8b]
0x34ee5b: XOR EAX, EAX
0x34ee5d: CALL 0x0025d410
0x34ee62: JMP 0x0034eea5
0x34ee64: LEA RDI, [0x12fb0b2]
0x34ee6b: JMP 0x0034ee7d
0x34ee6d: LEA RDI, [0x12f1b6f]
0x34ee74: JMP 0x0034ee7d
0x34ee76: LEA RDI, [0x126d3fa]
0x34ee7d: LEA RSI, [0x129f32d]
0x34ee84: XOR EAX, EAX
0x34ee86: CALL 0x0025d410
0x34ee8b: LEA RDI, [0x126d3be]
0x34ee92: LEA RSI, [0x12f1b8b]
0x34ee99: MOV EDX, 0x1
0x34ee9e: XOR EAX, EAX
0x34eea0: CALL 0x0025d410
0x34eea5: MOV EAX, 0x1
0x34eeaa: MOV RCX, qword ptr [R15]
0x34eead: CMP RCX, qword ptr [RBP + -0x20]
0x34eeb1: JNZ 0x0034eebe
0x34eeb3: ADD RSP, 0x18
0x34eeb7: POP RBX
0x34eeb8: POP R14
0x34eeba: POP R15
0x34eebc: POP RBP
0x34eebd: RET
0x34eebe: CALL 0x006fd6b0
0x34eec3: UD2
; END FUNCTION sub_34eda0

; FUNCTION sub_34eed0 CONTEXT / separate function | ev_5878abb3e5ebd60f7bacdc9a02ad6fd9b51f4f78bf8d77abe68e84773cce4e0f
; Ghidra body: 0x34eed0..0x34ef11
sub_34eed0:
0x34eed0: PUSH RBP
0x34eed1: MOV RBP, RSP
0x34eed4: MOV RAX, qword ptr GS:[0x0]
0x34eedd: MOV RDI, qword ptr [RAX + 0x140]
0x34eee4: CALL 0x00c366a0
0x34eee9: TEST EAX, EAX
0x34eeeb: JZ 0x0034ef10
0x34eeed: LEA RDI, [0x345f3f8]
0x34eef4: MOV ESI, 0x18
0x34eef9: CALL 0x00258ff0
0x34eefe: LEA RDI, [0x345f410]
0x34ef05: MOV ESI, 0x18
0x34ef0a: POP RBP
0x34ef0b: JMP 0x00258ff0
0x34ef10: POP RBP
0x34ef11: RET
; END FUNCTION sub_34eed0

; FUNCTION sub_34ef20 CONTEXT / separate function | ev_93ceb025120b6f69fa9b23b5ff4e42e4a58286500cc279a3d8943b65d63a6c2a
; Ghidra body: 0x34ef20..0x34ef35
sub_34ef20:
0x34ef20: PUSH RBP
0x34ef21: MOV RBP, RSP
0x34ef24: LEA RSI, [0x345f3f8]
0x34ef2b: MOV EDX, 0x18
0x34ef30: POP RBP
0x34ef31: JMP 0x002590b0
; END FUNCTION sub_34ef20

; FUNCTION sub_34ef40 CONTEXT / separate function | ev_a0f54d0654e6695b051af98f911009a30c5b563c07d4b26cedf1ffc6c1de7faf
; Ghidra body: 0x34ef40..0x34ef55
sub_34ef40:
0x34ef40: PUSH RBP
0x34ef41: MOV RBP, RSP
0x34ef44: LEA RSI, [0x345f410]
0x34ef4b: MOV EDX, 0x18
0x34ef50: POP RBP
0x34ef51: JMP 0x002590b0
; END FUNCTION sub_34ef40

; FUNCTION sub_34ef60 CONTEXT / separate function | ev_10967e7c63261b21d88154701bcb7f007e8d2581dc8aed9d16b7aedb5c7a6d5e
; Ghidra body: 0x34ef60..0x34f01d
sub_34ef60:
0x34ef60: PUSH RBP
0x34ef61: MOV RBP, RSP
0x34ef64: TEST byte ptr [RDI + 0x510], 0x1
0x34ef6b: JZ 0x0034f01c
0x34ef71: CMP dword ptr [0x0345f428], 0x0
0x34ef78: JZ 0x0034ef8a
0x34ef7a: MOV qword ptr [RDI + 0x430], 0x0
0x34ef85: JMP 0x0034f011
0x34ef8a: MOV RDX, qword ptr [RDI + 0x430]
0x34ef91: MOV RSI, 0x3e7fffffc17
0x34ef9b: MOV EAX, 0xffffffff
0x34efa0: MOV RCX, 0x20c49ba5e353f7cf
0x34efaa: MOV R8D, 0xffffffff
0x34efb0: SHL RDX, 0x3
0x34efb4: CMP RDX, RSI
0x34efb7: JA 0x0034efc6
0x34efb9: SHR RDX, 0x3
0x34efbd: MULX R8, R8, RCX
0x34efc2: SHR R8, 0x4
0x34efc6: MOV EDX, dword ptr [RDI + 0x428]
0x34efcc: CMP R8, RDX
0x34efcf: JBE 0x0034efd8
0x34efd1: MOV dword ptr [RDI + 0x428], R8D
0x34efd8: MOV qword ptr [RDI + 0x430], 0x0
0x34efe3: MOV RDX, qword ptr [RDI + 0x438]
0x34efea: SHL RDX, 0x3
0x34efee: CMP RDX, RSI
0x34eff1: JA 0x0034f000
0x34eff3: SHR RDX, 0x3
0x34eff7: MULX RAX, RAX, RCX
0x34effc: SHR RAX, 0x4
0x34f000: MOV ECX, dword ptr [RDI + 0x42c]
0x34f006: CMP RAX, RCX
0x34f009: JBE 0x0034f011
0x34f00b: MOV dword ptr [RDI + 0x42c], EAX
0x34f011: MOV qword ptr [RDI + 0x438], 0x0
0x34f01c: POP RBP
0x34f01d: RET
; END FUNCTION sub_34ef60

; FUNCTION sub_34f020 CONTEXT / separate function | ev_c820b03c89247f22daefe266186dfa51fd685b4245564eeb70aea0bb082da93e
; Ghidra body: 0x34f020..0x34f068
sub_34f020:
0x34f020: PUSH RBP
0x34f021: MOV RBP, RSP
0x34f024: TEST byte ptr [RDI + 0x1f], 0x20
0x34f028: JZ 0x0034f067
0x34f02a: CMP EDX, ECX
0x34f02c: MOV EAX, 0x1
0x34f031: SETLE DIL
0x34f035: TEST ECX, ECX
0x34f037: SETLE R8B
0x34f03b: OR R8B, DIL
0x34f03e: JNZ 0x0034f051
0x34f040: MOV EAX, EDX
0x34f042: MOV EDI, EDX
0x34f044: CDQ
0x34f045: IDIV ECX
0x34f047: MOV ECX, EDX
0x34f049: MOV EDX, EDI
0x34f04b: CMP ECX, 0x1
0x34f04e: SBB EAX, -0x1
0x34f051: MOVSXD RCX, EDX
0x34f054: ADD dword ptr [RSI + 0x420], EAX
0x34f05a: ADD dword ptr [RSI + 0x418], EAX
0x34f060: ADD qword ptr [RSI + 0x438], RCX
0x34f067: POP RBP
0x34f068: RET
; END FUNCTION sub_34f020

; FUNCTION sub_34f070 CONTEXT / separate function | ev_f5318a9eb2d3cd4721129a3d01ebd465d3267d0a55081382321d016aabc62e08
; Ghidra body: 0x34f070..0x34f0c7
sub_34f070:
0x34f070: PUSH RBP
0x34f071: MOV RBP, RSP
0x34f074: CMP dword ptr [0x0345f428], 0x0
0x34f07b: JZ 0x0034f08a
0x34f07d: MOV qword ptr [RDI + 0x41c], 0x0
0x34f088: POP RBP
0x34f089: RET
0x34f08a: MOV EAX, dword ptr [RDI + 0x41c]
0x34f090: CMP dword ptr [RDI + 0x40c], EAX
0x34f096: JNC 0x0034f09e
0x34f098: MOV dword ptr [RDI + 0x40c], EAX
0x34f09e: MOV dword ptr [RDI + 0x41c], 0x0
0x34f0a8: MOV EAX, dword ptr [RDI + 0x420]
0x34f0ae: CMP dword ptr [RDI + 0x410], EAX
0x34f0b4: JNC 0x0034f0bc
0x34f0b6: MOV dword ptr [RDI + 0x410], EAX
0x34f0bc: MOV dword ptr [RDI + 0x420], 0x0
0x34f0c6: POP RBP
0x34f0c7: RET
; END FUNCTION sub_34f070

; FUNCTION sub_34f0d0 CONTEXT / separate function | ev_5c5ec397af1c13c688db3fe77b8bbe283f2897fee2e367a38e435a2cf781faa5
; Ghidra body: 0x34f0d0..0x34f26a
sub_34f0d0:
0x34f0d0: PUSH RBP
0x34f0d1: MOV RBP, RSP
0x34f0d4: PUSH R15
0x34f0d6: PUSH R14
0x34f0d8: PUSH R12
0x34f0da: PUSH RBX
0x34f0db: SUB RSP, 0xd0
0x34f0e2: LEA R12, [0x391c310]
0x34f0e9: LEA RSI, [0x2bfc080]
0x34f0f0: MOV R14, RDI
0x34f0f3: MOV EDI, 0xa38
0x34f0f8: MOV EDX, 0x101
0x34f0fd: MOV RAX, qword ptr [R12]
0x34f101: MOV qword ptr [RBP + -0x28], RAX
0x34f105: CALL 0x00c08b50
0x34f10a: TEST RAX, RAX
0x34f10d: JZ 0x0034f243
0x34f113: MOV EDI, dword ptr [R14 + 0xbc]
0x34f11a: MOV RBX, RAX
0x34f11d: XOR ESI, ESI
0x34f11f: XOR EDX, EDX
0x34f121: XOR ECX, ECX
0x34f123: MOV dword ptr [RBX + 0x10], EDI
0x34f126: LEA RDI, [0x345f448]
0x34f12d: CALL 0x004c6a00
0x34f132: MOV RAX, qword ptr [0x0345f450]
0x34f139: MOV qword ptr [RBX], RAX
0x34f13c: TEST RAX, RAX
0x34f13f: JZ 0x0034f145
0x34f141: MOV qword ptr [RAX + 0x8], RBX
0x34f145: LEA RAX, [0x345f450]
0x34f14c: LEA RDI, [0x345f448]
0x34f153: MOV qword ptr [0x0345f450], RBX
0x34f15a: XOR ESI, ESI
0x34f15c: XOR EDX, EDX
0x34f15e: XOR ECX, ECX
0x34f160: MOV qword ptr [RBX + 0x8], RAX
0x34f164: XOR EBX, EBX
0x34f166: CALL 0x004c6fa0
0x34f16b: LEA R15, [RBP + -0xc8]
0x34f172: LEA RSI, [0x345f460]
0x34f179: MOV EDX, 0xa0
0x34f17e: MOV RDI, R15
0x34f181: CALL 0x002590b0
0x34f186: OR byte ptr [RBP + -0xc2], 0x2
0x34f18d: MOV RSI, R15
0x34f190: MOV EDX, 0x1
0x34f195: MOV R14, qword ptr GS:[0x0]
0x34f19e: MOV RDI, R14
0x34f1a1: CALL 0x0034f270
0x34f1a6: LEA RDI, [RBP + -0xe8]
0x34f1ad: MOV ESI, 0x20
0x34f1b2: CALL 0x00258ff0
0x34f1b7: MOV dword ptr [RBP + -0xe8], 0x0
0x34f1c1: MOV RDI, qword ptr [R14 + 0x140]
0x34f1c8: CALL 0x00c366d0
0x34f1cd: MOV ECX, 0x1d
0x34f1d2: TEST EAX, EAX
0x34f1d4: JNZ 0x0034f1f1
0x34f1d6: MOV RDI, qword ptr [R14 + 0x140]
0x34f1dd: CALL 0x00c36710
0x34f1e2: TEST EAX, EAX
0x34f1e4: MOV EAX, 0x10
0x34f1e9: MOV ECX, 0x1d
0x34f1ee: CMOVZ ECX, EAX
0x34f1f1: LEA RSI, [RBP + -0xe8]
0x34f1f8: MOV RDI, R14
0x34f1fb: MOV dword ptr [RBP + -0xe4], ECX
0x34f201: CALL 0x0034f8f0
0x34f206: MOV RAX, qword ptr GS:[0x0]
0x34f20f: MOV RDI, qword ptr [RAX + 0x140]
0x34f216: CALL 0x00c366a0
0x34f21b: TEST EAX, EAX
0x34f21d: JZ 0x0034f248
0x34f21f: LEA RDI, [0x345f3f8]
0x34f226: MOV ESI, 0x18
0x34f22b: CALL 0x00258ff0
0x34f230: LEA RDI, [0x345f410]
0x34f237: MOV ESI, 0x18
0x34f23c: CALL 0x00258ff0
0x34f241: JMP 0x0034f248
0x34f243: MOV EBX, 0xc
0x34f248: MOV RAX, qword ptr [R12]
0x34f24c: CMP RAX, qword ptr [RBP + -0x28]
0x34f250: JNZ 0x0034f264
0x34f252: MOV EAX, EBX
0x34f254: ADD RSP, 0xd0
0x34f25b: POP RBX
0x34f25c: POP R12
0x34f25e: POP R14
0x34f260: POP R15
0x34f262: POP RBP
0x34f263: RET
0x34f264: CALL 0x006fd6b0
0x34f269: UD2
; END FUNCTION sub_34f0d0

; FUNCTION sub_34f270 CONTEXT / separate function | ev_7b99712d925a4867e3802961063240960faa39a199bad3007923e0ed809d913b
; Ghidra body: 0x34f270..0x34f769, 0x34f776..0x34f781
sub_34f270:
0x34f270: PUSH RBP
0x34f271: MOV RBP, RSP
0x34f274: PUSH R15
0x34f276: PUSH R14
0x34f278: PUSH R13
0x34f27a: PUSH R12
0x34f27c: PUSH RBX
0x34f27d: SUB RSP, 0x28
0x34f281: MOV RAX, qword ptr [RDI + 0x8]
0x34f285: MOV R14, RDI
0x34f288: MOV R12D, EDX
0x34f28b: MOV R15, RSI
0x34f28e: XOR EDI, EDI
0x34f290: MOV EBX, dword ptr [RAX + 0xbc]
0x34f296: CALL 0x00acc9a0
0x34f29b: TEST EAX, EAX
0x34f29d: JNZ 0x0034f2b3
0x34f29f: MOV RDI, qword ptr [R14 + 0x140]
0x34f2a6: CALL 0x00c36710
0x34f2ab: TEST EAX, EAX
0x34f2ad: JZ 0x0034f41d
0x34f2b3: TEST R12D, R12D
0x34f2b6: JNZ 0x0034f2d5
0x34f2b8: TEST byte ptr [0x0345f46c], 0x1
0x34f2bf: JZ 0x0034f2d5
0x34f2c1: MOV RDI, qword ptr [R14 + 0x140]
0x34f2c8: CALL 0x00c36710
0x34f2cd: TEST EAX, EAX
0x34f2cf: JZ 0x0034f41d
0x34f2d5: CMP dword ptr [R15 + 0x90], 0x0
0x34f2dd: MOV ECX, dword ptr [R15 + 0x4]
0x34f2e1: MOV dword ptr [RBP + -0x48], R12D
0x34f2e5: MOV dword ptr [RBP + -0x38], ECX
0x34f2e8: JZ 0x0034f2f9
0x34f2ea: MOV R13, R15
0x34f2ed: MOV R15D, ECX
0x34f2f0: AND R15D, 0x1000000
0x34f2f7: JMP 0x0034f322
0x34f2f9: CMP dword ptr [R15 + 0x8], 0x0
0x34f2fe: MOV R13, R15
0x34f301: MOV R15D, ECX
0x34f304: MOV R12D, 0x16
0x34f30a: SETZ AL
0x34f30d: AND R15D, 0x1000000
0x34f314: SETZ CL
0x34f317: OR CL, AL
0x34f319: CMP CL, 0x1
0x34f31c: JNZ 0x0034f579
0x34f322: MOV RDI, qword ptr [R14 + 0x140]
0x34f329: CALL 0x00c366d0
0x34f32e: TEST EAX, EAX
0x34f330: MOV R12D, 0x16
0x34f336: SETNZ AL
0x34f339: TEST R15D, R15D
0x34f33c: SETZ CL
0x34f33f: AND CL, AL
0x34f341: MOVZX EAX, CL
0x34f344: LEA EAX, [0xf + RAX*0x4]
0x34f34b: CMP dword ptr [R13 + 0x8], EAX
0x34f34f: JA 0x0034f579
0x34f355: MOV RDI, qword ptr [R14 + 0x140]
0x34f35c: CALL 0x00c366d0
0x34f361: TEST EAX, EAX
0x34f363: JZ 0x0034f433
0x34f369: LEA RDI, [0x345f448]
0x34f370: MOV dword ptr [RBP + -0x34], R15D
0x34f374: XOR ESI, ESI
0x34f376: XOR EDX, EDX
0x34f378: XOR ECX, ECX
0x34f37a: CALL 0x004c6a00
0x34f37f: LEA R15, [0x345f450]
0x34f386: NOP word ptr CS:[RAX + RAX*0x1]
0x34f390: MOV R15, qword ptr [R15]
0x34f393: TEST R15, R15
0x34f396: JZ 0x0034f428
0x34f39c: CMP dword ptr [R15 + 0x10], EBX
0x34f3a0: JNZ 0x0034f390
0x34f3a2: MOV EBX, dword ptr [R13 + 0x8]
0x34f3a6: MOVZX R12D, word ptr [R13]
0x34f3ab: LEA RDX, [0x345f500]
0x34f3b2: MOV RDI, R13
0x34f3b5: LEA EAX, [RBX + -0x10]
0x34f3b8: LEA RCX, [RBX + RBX*0x4]
0x34f3bc: LEA RAX, [RAX + RAX*0x4]
0x34f3c0: SHL RCX, 0x5
0x34f3c4: SHL RAX, 0x5
0x34f3c8: LEA RCX, [R15 + RCX*0x1 + 0x14]
0x34f3cd: ADD RAX, RDX
0x34f3d0: CMP EBX, 0x10
0x34f3d3: CMOVNC RCX, RAX
0x34f3d7: MOV qword ptr [RBP + -0x30], RCX
0x34f3db: TEST R12D, R12D
0x34f3de: JZ 0x0034f46d
0x34f3e4: MOV EAX, dword ptr [RDI + 0x90]
0x34f3ea: MOV ESI, 0xa0
0x34f3ef: MOV R13, RDI
0x34f3f2: MOV dword ptr [RBP + -0x40], EAX
0x34f3f5: CALL 0x00258ff0
0x34f3fa: CMP R12D, 0x3
0x34f3fe: JZ 0x0034f453
0x34f400: CMP R12D, 0x2
0x34f404: JZ 0x0034f446
0x34f406: CMP R12D, 0x1
0x34f40a: JNZ 0x0034f58b
0x34f410: MOV RDI, R13
0x34f413: MOV dword ptr [R13 + 0x16], 0x64
0x34f41b: JMP 0x0034f45d
0x34f41d: MOV R12D, 0x2d
0x34f423: JMP 0x0034f579
0x34f428: MOV R12D, 0xc
0x34f42e: JMP 0x0034f567
0x34f433: CMP dword ptr [R13 + 0x90], 0x0
0x34f43b: JNZ 0x0034f579
0x34f441: JMP 0x0034f369
0x34f446: MOV RDI, R13
0x34f449: MOV dword ptr [R13 + 0x20], 0x20000
0x34f451: JMP 0x0034f45d
0x34f453: MOV RDI, R13
0x34f456: MOV word ptr [R13 + 0x10], 0x5
0x34f45d: MOV EAX, dword ptr [RBP + -0x40]
0x34f460: MOV word ptr [RDI], R12W
0x34f464: MOV dword ptr [RDI + 0x8], EBX
0x34f467: MOV dword ptr [RDI + 0x90], EAX
0x34f46d: CMP word ptr [RDI + 0x2], 0x0
0x34f472: MOV RBX, RDI
0x34f475: JZ 0x0034f47d
0x34f477: MOV word ptr [RBX + 0x2], 0x0
0x34f47d: MOV RDI, qword ptr [R14 + 0x140]
0x34f484: CALL 0x00c366d0
0x34f489: OR EAX, dword ptr [RBP + -0x48]
0x34f48c: JZ 0x0034f49f
0x34f48e: MOV EDX, dword ptr [RBP + -0x38]
0x34f491: TEST EDX, 0xfefcfeff
0x34f497: JNZ 0x0034f552
0x34f49d: JMP 0x0034f4ae
0x34f49f: MOV EDX, dword ptr [RBP + -0x38]
0x34f4a2: TEST EDX, 0xfffffeff
0x34f4a8: JNZ 0x0034f552
0x34f4ae: CMP dword ptr [RBP + -0x34], 0x0
0x34f4b2: JZ 0x0034f4cf
0x34f4b4: CMP dword ptr [RBX + 0x90], 0x0
0x34f4bb: SETZ AL
0x34f4be: TEST EDX, 0x30000
0x34f4c4: SETZ CL
0x34f4c7: OR CL, AL
0x34f4c9: JZ 0x0034f552
0x34f4cf: CMP byte ptr [RBX + 0x94], 0x0
0x34f4d6: JNZ 0x0034f53b
0x34f4d8: CMP byte ptr [RBX + 0x95], 0x0
0x34f4df: JNZ 0x0034f53b
0x34f4e1: CMP byte ptr [RBX + 0x96], 0x0
0x34f4e8: JNZ 0x0034f53b
0x34f4ea: CMP byte ptr [RBX + 0x97], 0x0
0x34f4f1: JNZ 0x0034f53b
0x34f4f3: CMP byte ptr [RBX + 0x98], 0x0
0x34f4fa: JNZ 0x0034f53b
0x34f4fc: CMP byte ptr [RBX + 0x99], 0x0
0x34f503: JNZ 0x0034f53b
0x34f505: CMP byte ptr [RBX + 0x9a], 0x0
0x34f50c: JNZ 0x0034f53b
0x34f50e: CMP byte ptr [RBX + 0x9b], 0x0
0x34f515: JNZ 0x0034f53b
0x34f517: CMP byte ptr [RBX + 0x9c], 0x0
0x34f51e: JNZ 0x0034f53b
0x34f520: CMP byte ptr [RBX + 0x9d], 0x0
0x34f527: JNZ 0x0034f53b
0x34f529: CMP byte ptr [RBX + 0x9e], 0x0
0x34f530: JNZ 0x0034f53b
0x34f532: CMP byte ptr [RBX + 0x9f], 0x0
0x34f539: JZ 0x0034f5a2
0x34f53b: MOV RAX, qword ptr [RBP + -0x30]
0x34f53f: MOV R12D, 0x1c
0x34f545: TEST RAX, RAX
0x34f548: JZ 0x0034f567
0x34f54a: MOV word ptr [RAX + 0x2], 0x94
0x34f550: JMP 0x0034f567
0x34f552: MOV RAX, qword ptr [RBP + -0x30]
0x34f556: MOV R12D, 0x1c
0x34f55c: TEST RAX, RAX
0x34f55f: JZ 0x0034f567
0x34f561: MOV word ptr [RAX + 0x2], 0x4
0x34f567: LEA RDI, [0x345f448]
0x34f56e: XOR ESI, ESI
0x34f570: XOR EDX, EDX
0x34f572: XOR ECX, ECX
0x34f574: CALL 0x004c6fa0
0x34f579: MOV EAX, R12D
0x34f57c: ADD RSP, 0x28
0x34f580: POP RBX
0x34f581: POP R12
0x34f583: POP R13
0x34f585: POP R14
0x34f587: POP R15
0x34f589: POP RBP
0x34f58a: RET
0x34f58b: MOV RAX, qword ptr [RBP + -0x30]
0x34f58f: MOV R12D, 0x1c
0x34f595: TEST RAX, RAX
0x34f598: JZ 0x0034f567
0x34f59a: MOV word ptr [RAX + 0x2], 0x0
0x34f5a0: JMP 0x0034f567
0x34f5a2: MOV RSI, qword ptr [RBP + -0x30]
0x34f5a6: MOV RDI, RBX
0x34f5a9: MOV qword ptr [RBP + -0x40], RBX
0x34f5ad: CALL 0x00350000
0x34f5b2: MOV R12D, EAX
0x34f5b5: TEST EAX, EAX
0x34f5b7: JNZ 0x0034f567
0x34f5b9: MOV RDI, qword ptr [R14 + 0x140]
0x34f5c0: CALL 0x00c36710
0x34f5c5: MOV RBX, qword ptr [RBP + -0x40]
0x34f5c9: MOV RDI, RBX
0x34f5cc: CALL 0x003503f0
0x34f5d1: MOV EAX, dword ptr [RBP + -0x38]
0x34f5d4: MOV dword ptr [RBX + 0x4], EAX
0x34f5d7: TEST EAX, 0x30000
0x34f5dc: JZ 0x0034f7bc
0x34f5e2: MOV RAX, qword ptr [0x0345f450]
0x34f5e9: JMP 0x0034f5f2
0x34f5eb: MOV RAX, qword ptr [RBP + -0x30]
0x34f5ef: MOV RAX, qword ptr [RAX]
0x34f5f2: MOV qword ptr [RBP + -0x30], RAX
0x34f5f6: TEST RAX, RAX
0x34f5f9: JZ 0x0034f6fc
0x34f5ff: MOV RAX, qword ptr [RBP + -0x30]
0x34f603: XOR R12D, R12D
0x34f606: LEA RCX, [RAX + 0x14]
0x34f60a: LEA R14, [RAX + 0x24]
0x34f60e: LEA R13, [RAX + 0x64]
0x34f612: MOV qword ptr [RBP + -0x48], RCX
0x34f616: JMP 0x0034f652
0x34f618: LEA RDI, [RBX + 0x10]
0x34f61c: MOV ESI, 0x40
0x34f621: CALL 0x00258ff0
0x34f626: LEA RDI, [RBX + 0x50]
0x34f62a: MOV ESI, 0x40
0x34f62f: CALL 0x00258ff0
0x34f634: AND dword ptr [RBX + 0xc], 0xfffefffe
0x34f63b: INC R12
0x34f63e: ADD R14, 0xa0
0x34f645: ADD R13, 0xa0
0x34f64c: CMP R12, 0x10
0x34f650: JZ 0x0034f5eb
0x34f652: LEA RBX, [R12 + R12*0x4]
0x34f656: SHL RBX, 0x5
0x34f65a: ADD RBX, qword ptr [RBP + -0x48]
0x34f65e: CMP dword ptr [RBP + -0x34], 0x0
0x34f662: JNZ 0x0034f618
0x34f664: MOV ECX, dword ptr [RBX + 0xc]
0x34f667: TEST ECX, 0x10000
0x34f66d: JZ 0x0034f63b
0x34f66f: LEA RDX, [0x345f460]
0x34f676: XOR EAX, EAX
0x34f678: JMP 0x0034f683
0x34f67a: INC RAX
0x34f67d: CMP RAX, 0x40
0x34f681: JZ 0x0034f691
0x34f683: CMP byte ptr [RAX + RDX*0x1 + 0x10], 0x0
0x34f688: JZ 0x0034f67a
0x34f68a: MOV byte ptr [R14 + RAX*0x1], 0x0
0x34f68f: JMP 0x0034f67a
0x34f691: XOR EAX, EAX
0x34f693: JMP 0x0034f69e
0x34f695: INC RAX
0x34f698: CMP RAX, 0x40
0x34f69c: JZ 0x0034f6ad
0x34f69e: CMP byte ptr [RAX + RDX*0x1 + 0x50], 0x0
0x34f6a3: JZ 0x0034f695
0x34f6a5: MOV byte ptr [R13 + RAX*0x1], 0x0
0x34f6ab: JMP 0x0034f695
0x34f6ad: MOV EAX, ECX
0x34f6af: AND ECX, 0xfffefffe
0x34f6b5: MOV dword ptr [RBX + 0xc], ECX
0x34f6b8: AND EAX, 0xfffeffff
0x34f6bd: XOR ECX, ECX
0x34f6bf: CMP byte ptr [R14 + RCX*0x1], 0x0
0x34f6c4: JNZ 0x0034f6d6
0x34f6c6: INC RCX
0x34f6c9: CMP RCX, 0x40
0x34f6cd: JNZ 0x0034f6bf
0x34f6cf: OR EAX, 0x1
0x34f6d2: XOR ECX, ECX
0x34f6d4: JMP 0x0034f6de
0x34f6d6: OR EAX, 0x1
0x34f6d9: XOR ECX, ECX
0x34f6db: MOV dword ptr [RBX + 0xc], EAX
0x34f6de: CMP byte ptr [R13 + RCX*0x1], 0x0
0x34f6e4: JNZ 0x0034f6f4
0x34f6e6: INC RCX
0x34f6e9: CMP RCX, 0x40
0x34f6ed: JNZ 0x0034f6de
0x34f6ef: JMP 0x0034f63b
0x34f6f4: MOV dword ptr [RBX + 0xc], EAX
0x34f6f7: JMP 0x0034f63b
0x34f6fc: MOV RSI, qword ptr [RBP + -0x40]
0x34f700: LEA RDI, [0x345f460]
0x34f707: MOV EDX, 0xa0
0x34f70c: CALL 0x002590b0
0x34f711: MOV dword ptr [0x0345f468], 0x0
0x34f71b: MOV dword ptr [0x0345f4f0], 0x0
0x34f725: XOR R12D, R12D
0x34f728: TEST byte ptr [0x0345f46c], 0x1
0x34f72f: JZ 0x0034f567
0x34f735: TEST dword ptr [RBP + -0x38], 0x10000
0x34f73c: JNZ 0x0034f86f
0x34f742: TEST dword ptr [RBP + -0x38], 0x20000
0x34f749: MOV R15, qword ptr [0x0345f450]
0x34f750: SETZ AL
0x34f753: TEST R15, R15
0x34f756: SETZ CL
0x34f759: OR CL, AL
0x34f75b: JNZ 0x0034f567
0x34f761: LEA RBX, [0x345f460]
0x34f768: JMP 0x0034f776
0x34f776: LEA R14, [R15 + 0x14]
0x34f77a: MOV R13D, 0x10
0x34f780: JMP 0x0034f796
; END FUNCTION sub_34f270

; FUNCTION copyout_candidate CONTEXT / separate function | ev_71486184be245b984abbb9be576981c38f613a7db64a834e00ab1b4e60ea2113
; Ghidra body: 0x2591d0..0x259258, 0x259260..0x25927f
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
; END FUNCTION copyout_candidate

; SUPPLEMENTAL GNU OBJDUMP FULL ORIGINAL4096BYTES
; Independent linear decode, not REA pseudocode/function recovery. INT3 bytes are padding.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_649.bin:     file format binary


Disassembly of section .data:

00000000002655e8 <.data>:
  2655e8:	e9 b3 79 0e 00       	jmp    0x34cfa0
  2655ed:	cc                   	int3
  2655ee:	cc                   	int3
  2655ef:	cc                   	int3
  2655f0:	e9 ab 74 11 00       	jmp    0x37caa0
  2655f5:	cc                   	int3
  2655f6:	cc                   	int3
  2655f7:	cc                   	int3
  2655f8:	e9 23 75 11 00       	jmp    0x37cb20
  2655fd:	cc                   	int3
  2655fe:	cc                   	int3
  2655ff:	cc                   	int3
  265600:	e9 3b 96 11 00       	jmp    0x37ec40
  265605:	cc                   	int3
  265606:	cc                   	int3
  265607:	cc                   	int3
  265608:	e9 83 a4 11 00       	jmp    0x37fa90
  26560d:	cc                   	int3
  26560e:	cc                   	int3
  26560f:	cc                   	int3
  265610:	e9 8b a4 11 00       	jmp    0x37faa0
  265615:	cc                   	int3
  265616:	cc                   	int3
  265617:	cc                   	int3
  265618:	e9 a3 a5 11 00       	jmp    0x37fbc0
  26561d:	cc                   	int3
  26561e:	cc                   	int3
  26561f:	cc                   	int3
  265620:	e9 4b a6 11 00       	jmp    0x37fc70
  265625:	cc                   	int3
  265626:	cc                   	int3
  265627:	cc                   	int3
  265628:	e9 63 a6 11 00       	jmp    0x37fc90
  26562d:	cc                   	int3
  26562e:	cc                   	int3
  26562f:	cc                   	int3
  265630:	e9 3b a7 11 00       	jmp    0x37fd70
  265635:	cc                   	int3
  265636:	cc                   	int3
  265637:	cc                   	int3
  265638:	e9 43 a7 11 00       	jmp    0x37fd80
  26563d:	cc                   	int3
  26563e:	cc                   	int3
  26563f:	cc                   	int3
  265640:	e9 1b ac 11 00       	jmp    0x380260
  265645:	cc                   	int3
  265646:	cc                   	int3
  265647:	cc                   	int3
  265648:	e9 13 b1 11 00       	jmp    0x380760
  26564d:	cc                   	int3
  26564e:	cc                   	int3
  26564f:	cc                   	int3
  265650:	e9 3b b6 11 00       	jmp    0x380c90
  265655:	cc                   	int3
  265656:	cc                   	int3
  265657:	cc                   	int3
  265658:	e9 e3 ba 11 00       	jmp    0x381140
  26565d:	cc                   	int3
  26565e:	cc                   	int3
  26565f:	cc                   	int3
  265660:	e9 cb bb 11 00       	jmp    0x381230
  265665:	cc                   	int3
  265666:	cc                   	int3
  265667:	cc                   	int3
  265668:	e9 c3 bc 11 00       	jmp    0x381330
  26566d:	cc                   	int3
  26566e:	cc                   	int3
  26566f:	cc                   	int3
  265670:	e9 bb bd 11 00       	jmp    0x381430
  265675:	cc                   	int3
  265676:	cc                   	int3
  265677:	cc                   	int3
  265678:	e9 83 c2 11 00       	jmp    0x381900
  26567d:	cc                   	int3
  26567e:	cc                   	int3
  26567f:	cc                   	int3
  265680:	e9 6b c3 11 00       	jmp    0x3819f0
  265685:	cc                   	int3
  265686:	cc                   	int3
  265687:	cc                   	int3
  265688:	e9 83 c3 11 00       	jmp    0x381a10
  26568d:	cc                   	int3
  26568e:	cc                   	int3
  26568f:	cc                   	int3
  265690:	e9 5b c4 11 00       	jmp    0x381af0
  265695:	cc                   	int3
  265696:	cc                   	int3
  265697:	cc                   	int3
  265698:	e9 d3 c7 11 00       	jmp    0x381e70
  26569d:	cc                   	int3
  26569e:	cc                   	int3
  26569f:	cc                   	int3
  2656a0:	e9 db cb 11 00       	jmp    0x382280
  2656a5:	cc                   	int3
  2656a6:	cc                   	int3
  2656a7:	cc                   	int3
  2656a8:	e9 d3 cd 11 00       	jmp    0x382480
  2656ad:	cc                   	int3
  2656ae:	cc                   	int3
  2656af:	cc                   	int3
  2656b0:	e9 db ce 11 00       	jmp    0x382590
  2656b5:	cc                   	int3
  2656b6:	cc                   	int3
  2656b7:	cc                   	int3
  2656b8:	e9 a3 d3 11 00       	jmp    0x382a60
  2656bd:	cc                   	int3
  2656be:	cc                   	int3
  2656bf:	cc                   	int3
  2656c0:	e9 5b da 11 00       	jmp    0x383120
  2656c5:	cc                   	int3
  2656c6:	cc                   	int3
  2656c7:	cc                   	int3
  2656c8:	e9 e3 de 11 00       	jmp    0x3835b0
  2656cd:	cc                   	int3
  2656ce:	cc                   	int3
  2656cf:	cc                   	int3
  2656d0:	e9 1b e1 11 00       	jmp    0x3837f0
  2656d5:	cc                   	int3
  2656d6:	cc                   	int3
  2656d7:	cc                   	int3
  2656d8:	e9 23 e1 11 00       	jmp    0x383800
  2656dd:	cc                   	int3
  2656de:	cc                   	int3
  2656df:	cc                   	int3
  2656e0:	e9 bb 4b 12 00       	jmp    0x38a2a0
  2656e5:	cc                   	int3
  2656e6:	cc                   	int3
  2656e7:	cc                   	int3
  2656e8:	e9 93 9c 18 00       	jmp    0x3ef380
  2656ed:	cc                   	int3
  2656ee:	cc                   	int3
  2656ef:	cc                   	int3
  2656f0:	e9 eb 09 14 00       	jmp    0x3a60e0
  2656f5:	cc                   	int3
  2656f6:	cc                   	int3
  2656f7:	cc                   	int3
  2656f8:	e9 03 94 14 00       	jmp    0x3aeb00
  2656fd:	cc                   	int3
  2656fe:	cc                   	int3
  2656ff:	cc                   	int3
  265700:	e9 eb 94 14 00       	jmp    0x3aebf0
  265705:	cc                   	int3
  265706:	cc                   	int3
  265707:	cc                   	int3
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

; SUPPLEMENTAL FULL BODY/CARRIER LINEAR DECODE: GNU objdump.
; Code versus data uncertain outside REA body ranges; these are not added function claims.

; Source kernel_text.bin RVA0x34b790 length0x4000,SHA256dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/a_linear_34b790_4000.bin:     file format binary


Disassembly of section .data:

000000000034b790 <.data>:
  34b790:	55                   	push   rbp
  34b791:	48 89 e5             	mov    rbp,rsp
  34b794:	48 8b 06             	mov    rax,QWORD PTR [rsi]
  34b797:	48 8b 7f 08          	mov    rdi,QWORD PTR [rdi+0x8]
  34b79b:	48 8b 56 08          	mov    rdx,QWORD PTR [rsi+0x8]
  34b79f:	4c 8b 46 10          	mov    r8,QWORD PTR [rsi+0x10]
  34b7a3:	31 c9                	xor    ecx,ecx
  34b7a5:	48 89 c6             	mov    rsi,rax
  34b7a8:	5d                   	pop    rbp
  34b7a9:	e9 92 fd ff ff       	jmp    0x34b540
  34b7ae:	90                   	nop
  34b7af:	90                   	nop
  34b7b0:	55                   	push   rbp
  34b7b1:	48 89 e5             	mov    rbp,rsp
  34b7b4:	41 57                	push   r15
  34b7b6:	41 56                	push   r14
  34b7b8:	41 55                	push   r13
  34b7ba:	41 54                	push   r12
  34b7bc:	53                   	push   rbx
  34b7bd:	48 83 ec 18          	sub    rsp,0x18
  34b7c1:	4c 8d 2d 48 0b 5d 03 	lea    r13,[rip+0x35d0b48]        # 0x391c310
  34b7c8:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  34b7cc:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34b7d0:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  34b7d4:	4c 8b b0 e8 03 00 00 	mov    r14,QWORD PTR [rax+0x3e8]
  34b7db:	4d 85 f6             	test   r14,r14
  34b7de:	0f 84 9d 00 00 00    	je     0x34b881
  34b7e4:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
  34b7e8:	48 83 b8 48 01 00 00 	cmp    QWORD PTR [rax+0x148],0x0
  34b7ef:	00 
  34b7f0:	0f 84 8b 00 00 00    	je     0x34b881
  34b7f6:	44 8b 3e             	mov    r15d,DWORD PTR [rsi]
  34b7f9:	48 8b 5e 08          	mov    rbx,QWORD PTR [rsi+0x8]
  34b7fd:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34b804:	00 00 
  34b806:	48 8d 35 30 c7 04 01 	lea    rsi,[rip+0x104c730]        # 0x1397f3d
  34b80d:	31 d2                	xor    edx,edx
  34b80f:	e8 cc eb 8c 00       	call   0xc1a3e0
  34b814:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  34b818:	ba 08 00 00 00       	mov    edx,0x8
  34b81d:	48 89 df             	mov    rdi,rbx
  34b820:	e8 5b da f0 ff       	call   0x259280
  34b825:	89 c1                	mov    ecx,eax
  34b827:	b8 0e 00 00 00       	mov    eax,0xe
  34b82c:	85 c9                	test   ecx,ecx
  34b82e:	75 77                	jne    0x34b8a7
  34b830:	48 81 7d c8 60 01 00 	cmp    QWORD PTR [rbp-0x38],0x160
  34b837:	00 
  34b838:	b8 16 00 00 00       	mov    eax,0x16
  34b83d:	75 68                	jne    0x34b8a7
  34b83f:	bf 60 01 00 00       	mov    edi,0x160
  34b844:	be 0a 00 00 00       	mov    esi,0xa
  34b849:	e8 12 f4 7d 00       	call   0xb2ac60
  34b84e:	4c 89 f7             	mov    rdi,r14
  34b851:	44 89 fe             	mov    esi,r15d
  34b854:	ba 01 00 00 00       	mov    edx,0x1
  34b859:	48 89 c1             	mov    rcx,rax
  34b85c:	49 89 c4             	mov    r12,rax
  34b85f:	e8 ec 00 00 00       	call   0x34b950
  34b864:	85 c0                	test   eax,eax
  34b866:	74 58                	je     0x34b8c0
  34b868:	be 60 01 00 00       	mov    esi,0x160
  34b86d:	4c 89 e7             	mov    rdi,r12
  34b870:	ba 0a 00 00 00       	mov    edx,0xa
  34b875:	e8 d6 89 7d 00       	call   0xb24250
  34b87a:	b8 03 00 00 00       	mov    eax,0x3
  34b87f:	eb 26                	jmp    0x34b8a7
  34b881:	48 8d 3d d8 ed f3 00 	lea    rdi,[rip+0xf3edd8]        # 0x128a660
  34b888:	48 8d 15 fb 04 fb 00 	lea    rdx,[rip+0xfb04fb]        # 0x12fbd8a
  34b88f:	48 8d 0d 9a f5 00 01 	lea    rcx,[rip+0x100f59a]        # 0x135ae30
  34b896:	be 97 04 00 00       	mov    esi,0x497
  34b89b:	31 c0                	xor    eax,eax
  34b89d:	e8 8e 71 7d 00       	call   0xb22a30
  34b8a2:	b8 01 00 00 00       	mov    eax,0x1
  34b8a7:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  34b8ab:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  34b8af:	75 4e                	jne    0x34b8ff
  34b8b1:	48 83 c4 18          	add    rsp,0x18
  34b8b5:	5b                   	pop    rbx
  34b8b6:	41 5c                	pop    r12
  34b8b8:	41 5d                	pop    r13
  34b8ba:	41 5e                	pop    r14
  34b8bc:	41 5f                	pop    r15
  34b8be:	5d                   	pop    rbp
  34b8bf:	c3                   	ret
  34b8c0:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34b8c7:	00 00 
  34b8c9:	48 8d 35 c7 39 00 01 	lea    rsi,[rip+0x10039c7]        # 0x134f297
  34b8d0:	31 d2                	xor    edx,edx
  34b8d2:	e8 09 eb 8c 00       	call   0xc1a3e0
  34b8d7:	ba 60 01 00 00       	mov    edx,0x160
  34b8dc:	4c 89 e7             	mov    rdi,r12
  34b8df:	48 89 de             	mov    rsi,rbx
  34b8e2:	e8 e9 d8 f0 ff       	call   0x2591d0
  34b8e7:	be 60 01 00 00       	mov    esi,0x160
  34b8ec:	4c 89 e7             	mov    rdi,r12
  34b8ef:	ba 0a 00 00 00       	mov    edx,0xa
  34b8f4:	89 c3                	mov    ebx,eax
  34b8f6:	e8 55 89 7d 00       	call   0xb24250
  34b8fb:	89 d8                	mov    eax,ebx
  34b8fd:	eb a8                	jmp    0x34b8a7
  34b8ff:	e8 ac 1d 3b 00       	call   0x6fd6b0
  34b904:	0f 0b                	ud2
  34b906:	90                   	nop
  34b907:	90                   	nop
  34b908:	90                   	nop
  34b909:	90                   	nop
  34b90a:	90                   	nop
  34b90b:	90                   	nop
  34b90c:	90                   	nop
  34b90d:	90                   	nop
  34b90e:	90                   	nop
  34b90f:	90                   	nop
  34b910:	55                   	push   rbp
  34b911:	48 89 e5             	mov    rbp,rsp
  34b914:	41 56                	push   r14
  34b916:	53                   	push   rbx
  34b917:	49 89 fe             	mov    r14,rdi
  34b91a:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34b921:	00 00 
  34b923:	48 89 f3             	mov    rbx,rsi
  34b926:	48 8d 35 10 c6 04 01 	lea    rsi,[rip+0x104c610]        # 0x1397f3d
  34b92d:	31 d2                	xor    edx,edx
  34b92f:	e8 ac ea 8c 00       	call   0xc1a3e0
  34b934:	ba 04 00 00 00       	mov    edx,0x4
  34b939:	4c 89 f7             	mov    rdi,r14
  34b93c:	48 89 de             	mov    rsi,rbx
  34b93f:	5b                   	pop    rbx
  34b940:	41 5e                	pop    r14
  34b942:	5d                   	pop    rbp
  34b943:	e9 38 d9 f0 ff       	jmp    0x259280
  34b948:	90                   	nop
  34b949:	90                   	nop
  34b94a:	90                   	nop
  34b94b:	90                   	nop
  34b94c:	90                   	nop
  34b94d:	90                   	nop
  34b94e:	90                   	nop
  34b94f:	90                   	nop
  34b950:	55                   	push   rbp
  34b951:	48 89 e5             	mov    rbp,rsp
  34b954:	41 57                	push   r15
  34b956:	41 56                	push   r14
  34b958:	41 55                	push   r13
  34b95a:	41 54                	push   r12
  34b95c:	53                   	push   rbx
  34b95d:	50                   	push   rax
  34b95e:	48 8d 5f 70          	lea    rbx,[rdi+0x70]
  34b962:	49 89 ff             	mov    r15,rdi
  34b965:	49 89 ce             	mov    r14,rcx
  34b968:	41 89 d4             	mov    r12d,edx
  34b96b:	41 89 f5             	mov    r13d,esi
  34b96e:	31 f6                	xor    esi,esi
  34b970:	31 d2                	xor    edx,edx
  34b972:	31 c9                	xor    ecx,ecx
  34b974:	48 89 df             	mov    rdi,rbx
  34b977:	e8 a4 01 90 00       	call   0xc4bb20
  34b97c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  34b980:	4d 8b 3f             	mov    r15,QWORD PTR [r15]
  34b983:	4d 85 ff             	test   r15,r15
  34b986:	0f 84 dd 00 00 00    	je     0x34ba69
  34b98c:	45 3b 6f 28          	cmp    r13d,DWORD PTR [r15+0x28]
  34b990:	75 ee                	jne    0x34b980
  34b992:	be 60 01 00 00       	mov    esi,0x160
  34b997:	4c 89 f7             	mov    rdi,r14
  34b99a:	e8 51 d6 f0 ff       	call   0x258ff0
  34b99f:	45 85 e4             	test   r12d,r12d
  34b9a2:	75 14                	jne    0x34b9b8
  34b9a4:	41 f6 87 1d 01 00 00 	test   BYTE PTR [r15+0x11d],0x1
  34b9ab:	01 
  34b9ac:	41 bc 01 00 00 00    	mov    r12d,0x1
  34b9b2:	0f 85 b8 01 00 00    	jne    0x34bb70
  34b9b8:	4d 8b 67 08          	mov    r12,QWORD PTR [r15+0x8]
  34b9bc:	4d 85 e4             	test   r12,r12
  34b9bf:	74 47                	je     0x34ba08
  34b9c1:	be 00 04 00 00       	mov    esi,0x400
  34b9c6:	4c 89 e7             	mov    rdi,r12
  34b9c9:	e8 e2 94 0f 00       	call   0x444eb0
  34b9ce:	48 83 f8 06          	cmp    rax,0x6
  34b9d2:	72 34                	jb     0x34ba08
  34b9d4:	41 80 3c 24 2f       	cmp    BYTE PTR [r12],0x2f
  34b9d9:	75 2d                	jne    0x34ba08
  34b9db:	41 80 7c 24 01 68    	cmp    BYTE PTR [r12+0x1],0x68
  34b9e1:	75 25                	jne    0x34ba08
  34b9e3:	41 80 7c 24 02 6f    	cmp    BYTE PTR [r12+0x2],0x6f
  34b9e9:	75 1d                	jne    0x34ba08
  34b9eb:	41 80 7c 24 03 73    	cmp    BYTE PTR [r12+0x3],0x73
  34b9f1:	75 15                	jne    0x34ba08
  34b9f3:	41 80 7c 24 04 74    	cmp    BYTE PTR [r12+0x4],0x74
  34b9f9:	75 0d                	jne    0x34ba08
  34b9fb:	41 80 7c 24 05 2f    	cmp    BYTE PTR [r12+0x5],0x2f
  34ba01:	be 5c 00 00 00       	mov    esi,0x5c
  34ba06:	74 05                	je     0x34ba0d
  34ba08:	be 2f 00 00 00       	mov    esi,0x2f
  34ba0d:	4d 8b 67 08          	mov    r12,QWORD PTR [r15+0x8]
  34ba11:	4c 89 e7             	mov    rdi,r12
  34ba14:	e8 e7 67 f2 ff       	call   0x272200
  34ba19:	48 8d 70 01          	lea    rsi,[rax+0x1]
  34ba1d:	48 85 c0             	test   rax,rax
  34ba20:	49 8d 7e 08          	lea    rdi,[r14+0x8]
  34ba24:	ba 00 01 00 00       	mov    edx,0x100
  34ba29:	49 0f 44 f4          	cmove  rsi,r12
  34ba2d:	e8 0e 8a 63 00       	call   0x984440
  34ba32:	bf 01 00 00 00       	mov    edi,0x1
  34ba37:	41 c6 86 07 01 00 00 	mov    BYTE PTR [r14+0x107],0x0
  34ba3e:	00 
  34ba3f:	e8 bc 00 7e 00       	call   0xb2bb00
  34ba44:	85 c0                	test   eax,eax
  34ba46:	74 2c                	je     0x34ba74
  34ba48:	49 8d be 08 01 00 00 	lea    rdi,[r14+0x108]
  34ba4f:	be 40 00 00 00       	mov    esi,0x40
  34ba54:	41 c7 86 48 01 00 00 	mov    DWORD PTR [r14+0x148],0x0
  34ba5b:	00 00 00 00 
  34ba5f:	e8 8c d5 f0 ff       	call   0x258ff0
  34ba64:	e9 f2 00 00 00       	jmp    0x34bb5b
  34ba69:	41 bc 03 00 00 00    	mov    r12d,0x3
  34ba6f:	e9 fc 00 00 00       	jmp    0x34bb70
  34ba74:	41 8b 47 48          	mov    eax,DWORD PTR [r15+0x48]
  34ba78:	83 f8 03             	cmp    eax,0x3
  34ba7b:	74 5b                	je     0x34bad8
  34ba7d:	83 f8 02             	cmp    eax,0x2
  34ba80:	0f 85 08 01 00 00    	jne    0x34bb8e
  34ba86:	49 8b 47 50          	mov    rax,QWORD PTR [r15+0x50]
  34ba8a:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34ba8e:	49 89 86 08 01 00 00 	mov    QWORD PTR [r14+0x108],rax
  34ba95:	49 8b 47 50          	mov    rax,QWORD PTR [r15+0x50]
  34ba99:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
  34ba9c:	41 89 86 10 01 00 00 	mov    DWORD PTR [r14+0x110],eax
  34baa3:	41 c7 86 14 01 00 00 	mov    DWORD PTR [r14+0x114],0x5
  34baaa:	05 00 00 00 
  34baae:	49 8b 47 60          	mov    rax,QWORD PTR [r15+0x60]
  34bab2:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34bab6:	49 89 86 18 01 00 00 	mov    QWORD PTR [r14+0x118],rax
  34babd:	49 8b 47 60          	mov    rax,QWORD PTR [r15+0x60]
  34bac1:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
  34bac4:	41 89 86 20 01 00 00 	mov    DWORD PTR [r14+0x120],eax
  34bacb:	41 c7 86 24 01 00 00 	mov    DWORD PTR [r14+0x124],0x3
  34bad2:	03 00 00 00 
  34bad6:	eb 78                	jmp    0x34bb50
  34bad8:	49 8b 47 50          	mov    rax,QWORD PTR [r15+0x50]
  34badc:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34bae0:	49 89 86 08 01 00 00 	mov    QWORD PTR [r14+0x108],rax
  34bae7:	49 8b 47 50          	mov    rax,QWORD PTR [r15+0x50]
  34baeb:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
  34baee:	41 89 86 10 01 00 00 	mov    DWORD PTR [r14+0x110],eax
  34baf5:	41 c7 86 14 01 00 00 	mov    DWORD PTR [r14+0x114],0x5
  34bafc:	05 00 00 00 
  34bb00:	49 8b 47 60          	mov    rax,QWORD PTR [r15+0x60]
  34bb04:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34bb08:	49 89 86 18 01 00 00 	mov    QWORD PTR [r14+0x118],rax
  34bb0f:	49 8b 47 60          	mov    rax,QWORD PTR [r15+0x60]
  34bb13:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
  34bb16:	41 89 86 20 01 00 00 	mov    DWORD PTR [r14+0x120],eax
  34bb1d:	41 c7 86 24 01 00 00 	mov    DWORD PTR [r14+0x124],0x3
  34bb24:	03 00 00 00 
  34bb28:	49 8b 47 58          	mov    rax,QWORD PTR [r15+0x58]
  34bb2c:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34bb30:	49 89 86 28 01 00 00 	mov    QWORD PTR [r14+0x128],rax
  34bb37:	49 8b 47 58          	mov    rax,QWORD PTR [r15+0x58]
  34bb3b:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
  34bb3e:	41 89 86 30 01 00 00 	mov    DWORD PTR [r14+0x130],eax
  34bb45:	41 c7 86 34 01 00 00 	mov    DWORD PTR [r14+0x134],0x1
  34bb4c:	01 00 00 00 
  34bb50:	41 8b 47 48          	mov    eax,DWORD PTR [r15+0x48]
  34bb54:	41 89 86 48 01 00 00 	mov    DWORD PTR [r14+0x148],eax
  34bb5b:	49 81 c6 4c 01 00 00 	add    r14,0x14c
  34bb62:	4c 89 fe             	mov    rsi,r15
  34bb65:	4c 89 f7             	mov    rdi,r14
  34bb68:	e8 d3 fb 7d 00       	call   0xb2b740
  34bb6d:	45 31 e4             	xor    r12d,r12d
  34bb70:	48 89 df             	mov    rdi,rbx
  34bb73:	31 f6                	xor    esi,esi
  34bb75:	31 d2                	xor    edx,edx
  34bb77:	e8 34 09 90 00       	call   0xc4c4b0
  34bb7c:	44 89 e0             	mov    eax,r12d
  34bb7f:	48 83 c4 08          	add    rsp,0x8
  34bb83:	5b                   	pop    rbx
  34bb84:	41 5c                	pop    r12
  34bb86:	41 5d                	pop    r13
  34bb88:	41 5e                	pop    r14
  34bb8a:	41 5f                	pop    r15
  34bb8c:	5d                   	pop    rbp
  34bb8d:	c3                   	ret
  34bb8e:	41 c7 86 48 01 00 00 	mov    DWORD PTR [r14+0x148],0x0
  34bb95:	00 00 00 00 
  34bb99:	41 8b 47 48          	mov    eax,DWORD PTR [r15+0x48]
  34bb9d:	85 c0                	test   eax,eax
  34bb9f:	74 ba                	je     0x34bb5b
  34bba1:	83 f8 04             	cmp    eax,0x4
  34bba4:	b9 04 00 00 00       	mov    ecx,0x4
  34bba9:	0f 42 c8             	cmovb  ecx,eax
  34bbac:	49 8d 86 08 01 00 00 	lea    rax,[r14+0x108]
  34bbb3:	31 d2                	xor    edx,edx
  34bbb5:	31 f6                	xor    esi,esi
  34bbb7:	48 c1 e1 03          	shl    rcx,0x3
  34bbbb:	48 8d 0c 49          	lea    rcx,[rcx+rcx*2]
  34bbbf:	eb 2c                	jmp    0x34bbed
  34bbc1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  34bbc8:	0f 1f 84 00 00 00 00 
  34bbcf:	00 
  34bbd0:	41 8b b6 48 01 00 00 	mov    esi,DWORD PTR [r14+0x148]
  34bbd7:	48 83 c2 18          	add    rdx,0x18
  34bbdb:	ff c6                	inc    esi
  34bbdd:	41 89 b6 48 01 00 00 	mov    DWORD PTR [r14+0x148],esi
  34bbe4:	48 39 d1             	cmp    rcx,rdx
  34bbe7:	0f 84 6e ff ff ff    	je     0x34bb5b
  34bbed:	4d 8b 47 40          	mov    r8,QWORD PTR [r15+0x40]
  34bbf1:	41 89 f1             	mov    r9d,esi
  34bbf4:	49 c1 e1 04          	shl    r9,0x4
  34bbf8:	4a 8d 34 08          	lea    rsi,[rax+r9*1]
  34bbfc:	49 8b 7c 10 08       	mov    rdi,QWORD PTR [r8+rdx*1+0x8]
  34bc01:	4a 89 3c 08          	mov    QWORD PTR [rax+r9*1],rdi
  34bc05:	41 8b 7c 10 10       	mov    edi,DWORD PTR [r8+rdx*1+0x10]
  34bc0a:	42 89 7c 08 08       	mov    DWORD PTR [rax+r9*1+0x8],edi
  34bc0f:	42 c7 44 08 0c 00 00 	mov    DWORD PTR [rax+r9*1+0xc],0x0
  34bc16:	00 00 
  34bc18:	49 8b 3c 10          	mov    rdi,QWORD PTR [r8+rdx*1]
  34bc1c:	8b 7f 0c             	mov    edi,DWORD PTR [rdi+0xc]
  34bc1f:	83 e7 01             	and    edi,0x1
  34bc22:	42 89 7c 08 0c       	mov    DWORD PTR [rax+r9*1+0xc],edi
  34bc27:	4d 8b 0c 10          	mov    r9,QWORD PTR [r8+rdx*1]
  34bc2b:	45 8b 49 0c          	mov    r9d,DWORD PTR [r9+0xc]
  34bc2f:	41 f6 c1 02          	test   r9b,0x2
  34bc33:	74 0e                	je     0x34bc43
  34bc35:	83 cf 02             	or     edi,0x2
  34bc38:	89 7e 0c             	mov    DWORD PTR [rsi+0xc],edi
  34bc3b:	4d 8b 04 10          	mov    r8,QWORD PTR [r8+rdx*1]
  34bc3f:	45 8b 48 0c          	mov    r9d,DWORD PTR [r8+0xc]
  34bc43:	41 f6 c1 04          	test   r9b,0x4
  34bc47:	74 87                	je     0x34bbd0
  34bc49:	83 cf 04             	or     edi,0x4
  34bc4c:	89 7e 0c             	mov    DWORD PTR [rsi+0xc],edi
  34bc4f:	e9 7c ff ff ff       	jmp    0x34bbd0
  34bc54:	90                   	nop
  34bc55:	90                   	nop
  34bc56:	90                   	nop
  34bc57:	90                   	nop
  34bc58:	90                   	nop
  34bc59:	90                   	nop
  34bc5a:	90                   	nop
  34bc5b:	90                   	nop
  34bc5c:	90                   	nop
  34bc5d:	90                   	nop
  34bc5e:	90                   	nop
  34bc5f:	90                   	nop
  34bc60:	55                   	push   rbp
  34bc61:	48 89 e5             	mov    rbp,rsp
  34bc64:	41 57                	push   r15
  34bc66:	41 56                	push   r14
  34bc68:	41 55                	push   r13
  34bc6a:	41 54                	push   r12
  34bc6c:	53                   	push   rbx
  34bc6d:	48 83 ec 18          	sub    rsp,0x18
  34bc71:	4c 8d 2d 98 06 5d 03 	lea    r13,[rip+0x35d0698]        # 0x391c310
  34bc78:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  34bc7c:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34bc80:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  34bc84:	4c 8b b0 e8 03 00 00 	mov    r14,QWORD PTR [rax+0x3e8]
  34bc8b:	4d 85 f6             	test   r14,r14
  34bc8e:	0f 84 92 00 00 00    	je     0x34bd26
  34bc94:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
  34bc98:	48 83 b8 48 01 00 00 	cmp    QWORD PTR [rax+0x148],0x0
  34bc9f:	00 
  34bca0:	0f 84 80 00 00 00    	je     0x34bd26
  34bca6:	44 8b 26             	mov    r12d,DWORD PTR [rsi]
  34bca9:	48 8b 5e 08          	mov    rbx,QWORD PTR [rsi+0x8]
  34bcad:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34bcb4:	00 00 
  34bcb6:	48 8d 35 80 c2 04 01 	lea    rsi,[rip+0x104c280]        # 0x1397f3d
  34bcbd:	31 d2                	xor    edx,edx
  34bcbf:	e8 1c e7 8c 00       	call   0xc1a3e0
  34bcc4:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  34bcc8:	ba 08 00 00 00       	mov    edx,0x8
  34bccd:	48 89 df             	mov    rdi,rbx
  34bcd0:	e8 ab d5 f0 ff       	call   0x259280
  34bcd5:	89 c1                	mov    ecx,eax
  34bcd7:	b8 0e 00 00 00       	mov    eax,0xe
  34bcdc:	85 c9                	test   ecx,ecx
  34bcde:	75 6c                	jne    0x34bd4c
  34bce0:	48 81 7d c8 60 01 00 	cmp    QWORD PTR [rbp-0x38],0x160
  34bce7:	00 
  34bce8:	b8 16 00 00 00       	mov    eax,0x16
  34bced:	75 5d                	jne    0x34bd4c
  34bcef:	bf 60 01 00 00       	mov    edi,0x160
  34bcf4:	be 0a 00 00 00       	mov    esi,0xa
  34bcf9:	e8 62 ef 7d 00       	call   0xb2ac60
  34bcfe:	4c 89 f7             	mov    rdi,r14
  34bd01:	44 89 e6             	mov    esi,r12d
  34bd04:	48 89 c1             	mov    rcx,rax
  34bd07:	31 d2                	xor    edx,edx
  34bd09:	49 89 c7             	mov    r15,rax
  34bd0c:	e8 3f fc ff ff       	call   0x34b950
  34bd11:	85 c0                	test   eax,eax
  34bd13:	74 50                	je     0x34bd65
  34bd15:	be 60 01 00 00       	mov    esi,0x160
  34bd1a:	4c 89 ff             	mov    rdi,r15
  34bd1d:	ba 0a 00 00 00       	mov    edx,0xa
  34bd22:	89 c3                	mov    ebx,eax
  34bd24:	eb 7c                	jmp    0x34bda2
  34bd26:	48 8d 3d 1d 48 fe 00 	lea    rdi,[rip+0xfe481d]        # 0x133054a
  34bd2d:	48 8d 15 56 00 fb 00 	lea    rdx,[rip+0xfb0056]        # 0x12fbd8a
  34bd34:	48 8d 0d f5 f0 00 01 	lea    rcx,[rip+0x100f0f5]        # 0x135ae30
  34bd3b:	be cb 04 00 00       	mov    esi,0x4cb
  34bd40:	31 c0                	xor    eax,eax
  34bd42:	e8 e9 6c 7d 00       	call   0xb22a30
  34bd47:	b8 01 00 00 00       	mov    eax,0x1
  34bd4c:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  34bd50:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  34bd54:	75 55                	jne    0x34bdab
  34bd56:	48 83 c4 18          	add    rsp,0x18
  34bd5a:	5b                   	pop    rbx
  34bd5b:	41 5c                	pop    r12
  34bd5d:	41 5d                	pop    r13
  34bd5f:	41 5e                	pop    r14
  34bd61:	41 5f                	pop    r15
  34bd63:	5d                   	pop    rbp
  34bd64:	c3                   	ret
  34bd65:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  34bd69:	48 8d 35 27 35 00 01 	lea    rsi,[rip+0x1003527]        # 0x134f297
  34bd70:	31 d2                	xor    edx,edx
  34bd72:	49 89 07             	mov    QWORD PTR [r15],rax
  34bd75:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34bd7c:	00 00 
  34bd7e:	e8 5d e6 8c 00       	call   0xc1a3e0
  34bd83:	ba 60 01 00 00       	mov    edx,0x160
  34bd88:	4c 89 ff             	mov    rdi,r15
  34bd8b:	48 89 de             	mov    rsi,rbx
  34bd8e:	e8 3d d4 f0 ff       	call   0x2591d0
  34bd93:	89 c3                	mov    ebx,eax
  34bd95:	be 60 01 00 00       	mov    esi,0x160
  34bd9a:	4c 89 ff             	mov    rdi,r15
  34bd9d:	ba 0a 00 00 00       	mov    edx,0xa
  34bda2:	e8 a9 84 7d 00       	call   0xb24250
  34bda7:	89 d8                	mov    eax,ebx
  34bda9:	eb a1                	jmp    0x34bd4c
  34bdab:	e8 00 19 3b 00       	call   0x6fd6b0
  34bdb0:	0f 0b                	ud2
  34bdb2:	90                   	nop
  34bdb3:	90                   	nop
  34bdb4:	90                   	nop
  34bdb5:	90                   	nop
  34bdb6:	90                   	nop
  34bdb7:	90                   	nop
  34bdb8:	90                   	nop
  34bdb9:	90                   	nop
  34bdba:	90                   	nop
  34bdbb:	90                   	nop
  34bdbc:	90                   	nop
  34bdbd:	90                   	nop
  34bdbe:	90                   	nop
  34bdbf:	90                   	nop
  34bdc0:	55                   	push   rbp
  34bdc1:	48 89 e5             	mov    rbp,rsp
  34bdc4:	41 57                	push   r15
  34bdc6:	41 56                	push   r14
  34bdc8:	41 55                	push   r13
  34bdca:	41 54                	push   r12
  34bdcc:	53                   	push   rbx
  34bdcd:	48 83 ec 28          	sub    rsp,0x28
  34bdd1:	4c 8d 2d 38 05 5d 03 	lea    r13,[rip+0x35d0538]        # 0x391c310
  34bdd8:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  34bddc:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34bde0:	48 8b 5f 08          	mov    rbx,QWORD PTR [rdi+0x8]
  34bde4:	4c 8b bb e8 03 00 00 	mov    r15,QWORD PTR [rbx+0x3e8]
  34bdeb:	4d 85 ff             	test   r15,r15
  34bdee:	0f 84 98 02 00 00    	je     0x34c08c
  34bdf4:	49 8b 47 10          	mov    rax,QWORD PTR [r15+0x10]
  34bdf8:	48 83 b8 48 01 00 00 	cmp    QWORD PTR [rax+0x148],0x0
  34bdff:	00 
  34be00:	0f 84 86 02 00 00    	je     0x34c08c
  34be06:	8b 46 08             	mov    eax,DWORD PTR [rsi+0x8]
  34be09:	44 8b 26             	mov    r12d,DWORD PTR [rsi]
  34be0c:	4c 8b 76 10          	mov    r14,QWORD PTR [rsi+0x10]
  34be10:	48 8d 35 26 c1 04 01 	lea    rsi,[rip+0x104c126]        # 0x1397f3d
  34be17:	31 d2                	xor    edx,edx
  34be19:	89 45 c4             	mov    DWORD PTR [rbp-0x3c],eax
  34be1c:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34be23:	00 00 
  34be25:	e8 b6 e5 8c 00       	call   0xc1a3e0
  34be2a:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  34be2e:	ba 08 00 00 00       	mov    edx,0x8
  34be33:	4c 89 f7             	mov    rdi,r14
  34be36:	e8 45 d4 f0 ff       	call   0x259280
  34be3b:	89 c1                	mov    ecx,eax
  34be3d:	b8 0e 00 00 00       	mov    eax,0xe
  34be42:	85 c9                	test   ecx,ecx
  34be44:	0f 85 68 02 00 00    	jne    0x34c0b2
  34be4a:	48 81 7d c8 a8 01 00 	cmp    QWORD PTR [rbp-0x38],0x1a8
  34be51:	00 
  34be52:	b8 16 00 00 00       	mov    eax,0x16
  34be57:	0f 85 55 02 00 00    	jne    0x34c0b2
  34be5d:	bf a8 01 00 00       	mov    edi,0x1a8
  34be62:	be 0a 00 00 00       	mov    esi,0xa
  34be67:	4c 89 75 b0          	mov    QWORD PTR [rbp-0x50],r14
  34be6b:	e8 f0 ed 7d 00       	call   0xb2ac60
  34be70:	49 8d 7f 70          	lea    rdi,[r15+0x70]
  34be74:	49 89 c6             	mov    r14,rax
  34be77:	31 f6                	xor    esi,esi
  34be79:	31 d2                	xor    edx,edx
  34be7b:	31 c9                	xor    ecx,ecx
  34be7d:	48 89 7d b8          	mov    QWORD PTR [rbp-0x48],rdi
  34be81:	e8 9a fc 8f 00       	call   0xc4bb20
  34be86:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  34be8d:	00 00 00 
  34be90:	4d 8b 3f             	mov    r15,QWORD PTR [r15]
  34be93:	4d 85 ff             	test   r15,r15
  34be96:	0f 84 33 02 00 00    	je     0x34c0cf
  34be9c:	45 3b 67 28          	cmp    r12d,DWORD PTR [r15+0x28]
  34bea0:	75 ee                	jne    0x34be90
  34bea2:	be a8 01 00 00       	mov    esi,0x1a8
  34bea7:	4c 89 f7             	mov    rdi,r14
  34beaa:	e8 41 d1 f0 ff       	call   0x258ff0
  34beaf:	4d 8b 67 08          	mov    r12,QWORD PTR [r15+0x8]
  34beb3:	4d 85 e4             	test   r12,r12
  34beb6:	74 47                	je     0x34beff
  34beb8:	be 00 04 00 00       	mov    esi,0x400
  34bebd:	4c 89 e7             	mov    rdi,r12
  34bec0:	e8 eb 8f 0f 00       	call   0x444eb0
  34bec5:	48 83 f8 06          	cmp    rax,0x6
  34bec9:	72 34                	jb     0x34beff
  34becb:	41 80 3c 24 2f       	cmp    BYTE PTR [r12],0x2f
  34bed0:	75 2d                	jne    0x34beff
  34bed2:	41 80 7c 24 01 68    	cmp    BYTE PTR [r12+0x1],0x68
  34bed8:	75 25                	jne    0x34beff
  34beda:	41 80 7c 24 02 6f    	cmp    BYTE PTR [r12+0x2],0x6f
  34bee0:	75 1d                	jne    0x34beff
  34bee2:	41 80 7c 24 03 73    	cmp    BYTE PTR [r12+0x3],0x73
  34bee8:	75 15                	jne    0x34beff
  34beea:	41 80 7c 24 04 74    	cmp    BYTE PTR [r12+0x4],0x74
  34bef0:	75 0d                	jne    0x34beff
  34bef2:	41 80 7c 24 05 2f    	cmp    BYTE PTR [r12+0x5],0x2f
  34bef8:	be 5c 00 00 00       	mov    esi,0x5c
  34befd:	74 05                	je     0x34bf04
  34beff:	be 2f 00 00 00       	mov    esi,0x2f
  34bf04:	4d 8b 67 08          	mov    r12,QWORD PTR [r15+0x8]
  34bf08:	4c 89 e7             	mov    rdi,r12
  34bf0b:	e8 f0 62 f2 ff       	call   0x272200
  34bf10:	48 8d 70 01          	lea    rsi,[rax+0x1]
  34bf14:	48 85 c0             	test   rax,rax
  34bf17:	ba 00 01 00 00       	mov    edx,0x100
  34bf1c:	49 0f 44 f4          	cmove  rsi,r12
  34bf20:	4d 8d 66 08          	lea    r12,[r14+0x8]
  34bf24:	4c 89 e7             	mov    rdi,r12
  34bf27:	e8 14 85 63 00       	call   0x984440
  34bf2c:	41 c6 86 07 01 00 00 	mov    BYTE PTR [r14+0x107],0x0
  34bf33:	00 
  34bf34:	8b 75 c4             	mov    esi,DWORD PTR [rbp-0x3c]
  34bf37:	41 8b 47 28          	mov    eax,DWORD PTR [r15+0x28]
  34bf3b:	41 89 86 08 01 00 00 	mov    DWORD PTR [r14+0x108],eax
  34bf42:	41 0f b7 47 70       	movzx  eax,WORD PTR [r15+0x70]
  34bf47:	41 89 86 0c 01 00 00 	mov    DWORD PTR [r14+0x10c],eax
  34bf4e:	40 f6 c6 01          	test   sil,0x1
  34bf52:	74 24                	je     0x34bf78
  34bf54:	41 0f b7 8f 1c 01 00 	movzx  ecx,WORD PTR [r15+0x11c]
  34bf5b:	00 
  34bf5c:	ba 08 01 00 00       	mov    edx,0x108
  34bf61:	c4 e2 68 f7 d1       	bextr  edx,ecx,edx
  34bf66:	83 e1 01             	and    ecx,0x1
  34bf69:	8d 0c 4a             	lea    ecx,[rdx+rcx*2]
  34bf6c:	c1 e1 10             	shl    ecx,0x10
  34bf6f:	09 c1                	or     ecx,eax
  34bf71:	41 89 8e 0c 01 00 00 	mov    DWORD PTR [r14+0x10c],ecx
  34bf78:	40 f6 c6 02          	test   sil,0x2
  34bf7c:	74 26                	je     0x34bfa4
  34bf7e:	41 f6 87 1d 01 00 00 	test   BYTE PTR [r15+0x11d],0x1
  34bf85:	01 
  34bf86:	75 0f                	jne    0x34bf97
  34bf88:	bf 02 00 00 00       	mov    edi,0x2
  34bf8d:	e8 6e fb 7d 00       	call   0xb2bb00
  34bf92:	83 f8 01             	cmp    eax,0x1
  34bf95:	75 0d                	jne    0x34bfa4
  34bf97:	be 00 01 00 00       	mov    esi,0x100
  34bf9c:	4c 89 e7             	mov    rdi,r12
  34bf9f:	e8 4c d0 f0 ff       	call   0x258ff0
  34bfa4:	49 8b 47 78          	mov    rax,QWORD PTR [r15+0x78]
  34bfa8:	bf 02 00 00 00       	mov    edi,0x2
  34bfad:	49 89 86 10 01 00 00 	mov    QWORD PTR [r14+0x110],rax
  34bfb4:	41 8b 87 80 00 00 00 	mov    eax,DWORD PTR [r15+0x80]
  34bfbb:	41 89 86 18 01 00 00 	mov    DWORD PTR [r14+0x118],eax
  34bfc2:	41 8b 87 88 00 00 00 	mov    eax,DWORD PTR [r15+0x88]
  34bfc9:	41 89 86 1c 01 00 00 	mov    DWORD PTR [r14+0x11c],eax
  34bfd0:	41 8b 87 90 00 00 00 	mov    eax,DWORD PTR [r15+0x90]
  34bfd7:	41 89 86 20 01 00 00 	mov    DWORD PTR [r14+0x120],eax
  34bfde:	41 8b 87 98 00 00 00 	mov    eax,DWORD PTR [r15+0x98]
  34bfe5:	41 89 86 24 01 00 00 	mov    DWORD PTR [r14+0x124],eax
  34bfec:	49 c7 86 38 01 00 00 	mov    QWORD PTR [r14+0x138],0x0
  34bff3:	00 00 00 00 
  34bff7:	49 c7 86 40 01 00 00 	mov    QWORD PTR [r14+0x140],0x0
  34bffe:	00 00 00 00 
  34c002:	49 8b 87 f8 00 00 00 	mov    rax,QWORD PTR [r15+0xf8]
  34c009:	49 89 86 48 01 00 00 	mov    QWORD PTR [r14+0x148],rax
  34c010:	49 8b 87 08 01 00 00 	mov    rax,QWORD PTR [r15+0x108]
  34c017:	49 89 86 50 01 00 00 	mov    QWORD PTR [r14+0x150],rax
  34c01e:	41 8b 87 00 01 00 00 	mov    eax,DWORD PTR [r15+0x100]
  34c025:	41 89 86 58 01 00 00 	mov    DWORD PTR [r14+0x158],eax
  34c02c:	41 8b 87 10 01 00 00 	mov    eax,DWORD PTR [r15+0x110]
  34c033:	41 89 86 5c 01 00 00 	mov    DWORD PTR [r14+0x15c],eax
  34c03a:	41 8b 47 20          	mov    eax,DWORD PTR [r15+0x20]
  34c03e:	41 89 86 a4 01 00 00 	mov    DWORD PTR [r14+0x1a4],eax
  34c045:	e8 b6 fa 7d 00       	call   0xb2bb00
  34c04a:	85 c0                	test   eax,eax
  34c04c:	0f 84 a3 00 00 00    	je     0x34c0f5
  34c052:	4c 89 f7             	mov    rdi,r14
  34c055:	be 40 00 00 00       	mov    esi,0x40
  34c05a:	49 c7 86 28 01 00 00 	mov    QWORD PTR [r14+0x128],0x0
  34c061:	00 00 00 00 
  34c065:	49 c7 86 30 01 00 00 	mov    QWORD PTR [r14+0x130],0x0
  34c06c:	00 00 00 00 
  34c070:	41 c7 86 a0 01 00 00 	mov    DWORD PTR [r14+0x1a0],0x0
  34c077:	00 00 00 00 
  34c07b:	48 81 c7 60 01 00 00 	add    rdi,0x160
  34c082:	e8 69 cf f0 ff       	call   0x258ff0
  34c087:	e9 a1 01 00 00       	jmp    0x34c22d
  34c08c:	48 8d 3d e1 e5 f3 00 	lea    rdi,[rip+0xf3e5e1]        # 0x128a674
  34c093:	48 8d 15 f0 fc fa 00 	lea    rdx,[rip+0xfafcf0]        # 0x12fbd8a
  34c09a:	48 8d 0d 8f ed 00 01 	lea    rcx,[rip+0x100ed8f]        # 0x135ae30
  34c0a1:	be 04 05 00 00       	mov    esi,0x504
  34c0a6:	31 c0                	xor    eax,eax
  34c0a8:	e8 83 69 7d 00       	call   0xb22a30
  34c0ad:	b8 01 00 00 00       	mov    eax,0x1
  34c0b2:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  34c0b6:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  34c0ba:	0f 85 bd 01 00 00    	jne    0x34c27d
  34c0c0:	48 83 c4 28          	add    rsp,0x28
  34c0c4:	5b                   	pop    rbx
  34c0c5:	41 5c                	pop    r12
  34c0c7:	41 5d                	pop    r13
  34c0c9:	41 5e                	pop    r14
  34c0cb:	41 5f                	pop    r15
  34c0cd:	5d                   	pop    rbp
  34c0ce:	c3                   	ret
  34c0cf:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  34c0d3:	31 f6                	xor    esi,esi
  34c0d5:	31 d2                	xor    edx,edx
  34c0d7:	e8 d4 03 90 00       	call   0xc4c4b0
  34c0dc:	be a8 01 00 00       	mov    esi,0x1a8
  34c0e1:	4c 89 f7             	mov    rdi,r14
  34c0e4:	ba 0a 00 00 00       	mov    edx,0xa
  34c0e9:	e8 62 81 7d 00       	call   0xb24250
  34c0ee:	b8 03 00 00 00       	mov    eax,0x3
  34c0f3:	eb bd                	jmp    0x34c0b2
  34c0f5:	41 f6 87 1d 01 00 00 	test   BYTE PTR [r15+0x11d],0x10
  34c0fc:	10 
  34c0fd:	75 17                	jne    0x34c116
  34c0ff:	49 8b 87 e8 00 00 00 	mov    rax,QWORD PTR [r15+0xe8]
  34c106:	49 89 86 28 01 00 00 	mov    QWORD PTR [r14+0x128],rax
  34c10d:	49 8b 87 f0 00 00 00 	mov    rax,QWORD PTR [r15+0xf0]
  34c114:	eb 0d                	jmp    0x34c123
  34c116:	49 c7 86 28 01 00 00 	mov    QWORD PTR [r14+0x128],0x0
  34c11d:	00 00 00 00 
  34c121:	31 c0                	xor    eax,eax
  34c123:	49 89 86 30 01 00 00 	mov    QWORD PTR [r14+0x130],rax
  34c12a:	80 bb 81 0c 00 00 00 	cmp    BYTE PTR [rbx+0xc81],0x0
  34c131:	0f 84 9b 00 00 00    	je     0x34c1d2
  34c137:	41 8b 4f 48          	mov    ecx,DWORD PTR [r15+0x48]
  34c13b:	b8 04 00 00 00       	mov    eax,0x4
  34c140:	41 c7 86 a0 01 00 00 	mov    DWORD PTR [r14+0x1a0],0x0
  34c147:	00 00 00 00 
  34c14b:	83 f9 04             	cmp    ecx,0x4
  34c14e:	0f 42 c1             	cmovb  eax,ecx
  34c151:	85 c9                	test   ecx,ecx
  34c153:	74 74                	je     0x34c1c9
  34c155:	89 c1                	mov    ecx,eax
  34c157:	4c 89 f2             	mov    rdx,r14
  34c15a:	31 f6                	xor    esi,esi
  34c15c:	48 c1 e1 03          	shl    rcx,0x3
  34c160:	48 81 c2 6c 01 00 00 	add    rdx,0x16c
  34c167:	48 8d 0c 49          	lea    rcx,[rcx+rcx*2]
  34c16b:	eb 0d                	jmp    0x34c17a
  34c16d:	48 83 c6 18          	add    rsi,0x18
  34c171:	48 83 c2 10          	add    rdx,0x10
  34c175:	48 39 f1             	cmp    rcx,rsi
  34c178:	74 4f                	je     0x34c1c9
  34c17a:	4d 8b 47 40          	mov    r8,QWORD PTR [r15+0x40]
  34c17e:	49 8b 7c 30 08       	mov    rdi,QWORD PTR [r8+rsi*1+0x8]
  34c183:	48 89 7a f4          	mov    QWORD PTR [rdx-0xc],rdi
  34c187:	41 8b 7c 30 10       	mov    edi,DWORD PTR [r8+rsi*1+0x10]
  34c18c:	89 7a fc             	mov    DWORD PTR [rdx-0x4],edi
  34c18f:	c7 02 00 00 00 00    	mov    DWORD PTR [rdx],0x0
  34c195:	49 8b 3c 30          	mov    rdi,QWORD PTR [r8+rsi*1]
  34c199:	8b 7f 0c             	mov    edi,DWORD PTR [rdi+0xc]
  34c19c:	83 e7 01             	and    edi,0x1
  34c19f:	89 3a                	mov    DWORD PTR [rdx],edi
  34c1a1:	4d 8b 0c 30          	mov    r9,QWORD PTR [r8+rsi*1]
  34c1a5:	45 8b 49 0c          	mov    r9d,DWORD PTR [r9+0xc]
  34c1a9:	41 f6 c1 02          	test   r9b,0x2
  34c1ad:	74 0d                	je     0x34c1bc
  34c1af:	83 cf 02             	or     edi,0x2
  34c1b2:	89 3a                	mov    DWORD PTR [rdx],edi
  34c1b4:	4d 8b 04 30          	mov    r8,QWORD PTR [r8+rsi*1]
  34c1b8:	45 8b 48 0c          	mov    r9d,DWORD PTR [r8+0xc]
  34c1bc:	41 f6 c1 04          	test   r9b,0x4
  34c1c0:	74 ab                	je     0x34c16d
  34c1c2:	83 cf 04             	or     edi,0x4
  34c1c5:	89 3a                	mov    DWORD PTR [rdx],edi
  34c1c7:	eb a4                	jmp    0x34c16d
  34c1c9:	41 89 86 a0 01 00 00 	mov    DWORD PTR [r14+0x1a0],eax
  34c1d0:	eb 5b                	jmp    0x34c22d
  34c1d2:	49 8b 47 50          	mov    rax,QWORD PTR [r15+0x50]
  34c1d6:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34c1da:	49 89 86 60 01 00 00 	mov    QWORD PTR [r14+0x160],rax
  34c1e1:	49 8b 47 50          	mov    rax,QWORD PTR [r15+0x50]
  34c1e5:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
  34c1e8:	41 89 86 68 01 00 00 	mov    DWORD PTR [r14+0x168],eax
  34c1ef:	41 c7 86 6c 01 00 00 	mov    DWORD PTR [r14+0x16c],0x5
  34c1f6:	05 00 00 00 
  34c1fa:	49 8b 47 60          	mov    rax,QWORD PTR [r15+0x60]
  34c1fe:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34c202:	49 89 86 70 01 00 00 	mov    QWORD PTR [r14+0x170],rax
  34c209:	49 8b 47 60          	mov    rax,QWORD PTR [r15+0x60]
  34c20d:	8b 40 10             	mov    eax,DWORD PTR [rax+0x10]
  34c210:	41 89 86 78 01 00 00 	mov    DWORD PTR [r14+0x178],eax
  34c217:	41 c7 86 7c 01 00 00 	mov    DWORD PTR [r14+0x17c],0x3
  34c21e:	03 00 00 00 
  34c222:	41 c7 86 a0 01 00 00 	mov    DWORD PTR [r14+0x1a0],0x2
  34c229:	02 00 00 00 
  34c22d:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  34c231:	31 f6                	xor    esi,esi
  34c233:	31 d2                	xor    edx,edx
  34c235:	e8 76 02 90 00       	call   0xc4c4b0
  34c23a:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34c241:	00 00 
  34c243:	48 8d 35 4d 30 00 01 	lea    rsi,[rip+0x100304d]        # 0x134f297
  34c24a:	31 d2                	xor    edx,edx
  34c24c:	e8 8f e1 8c 00       	call   0xc1a3e0
  34c251:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
  34c255:	ba a8 01 00 00       	mov    edx,0x1a8
  34c25a:	4c 89 f7             	mov    rdi,r14
  34c25d:	e8 6e cf f0 ff       	call   0x2591d0
  34c262:	be a8 01 00 00       	mov    esi,0x1a8
  34c267:	4c 89 f7             	mov    rdi,r14
  34c26a:	ba 0a 00 00 00       	mov    edx,0xa
  34c26f:	89 c3                	mov    ebx,eax
  34c271:	e8 da 7f 7d 00       	call   0xb24250
  34c276:	89 d8                	mov    eax,ebx
  34c278:	e9 35 fe ff ff       	jmp    0x34c0b2
  34c27d:	e8 2e 14 3b 00       	call   0x6fd6b0
  34c282:	0f 0b                	ud2
  34c284:	90                   	nop
  34c285:	90                   	nop
  34c286:	90                   	nop
  34c287:	90                   	nop
  34c288:	90                   	nop
  34c289:	90                   	nop
  34c28a:	90                   	nop
  34c28b:	90                   	nop
  34c28c:	90                   	nop
  34c28d:	90                   	nop
  34c28e:	90                   	nop
  34c28f:	90                   	nop
  34c290:	55                   	push   rbp
  34c291:	48 89 e5             	mov    rbp,rsp
  34c294:	41 56                	push   r14
  34c296:	53                   	push   rbx
  34c297:	45 31 f6             	xor    r14d,r14d
  34c29a:	48 85 ff             	test   rdi,rdi
  34c29d:	74 3f                	je     0x34c2de
  34c29f:	be 00 04 00 00       	mov    esi,0x400
  34c2a4:	48 89 fb             	mov    rbx,rdi
  34c2a7:	e8 04 8c 0f 00       	call   0x444eb0
  34c2ac:	48 83 f8 06          	cmp    rax,0x6
  34c2b0:	72 2c                	jb     0x34c2de
  34c2b2:	80 3b 2f             	cmp    BYTE PTR [rbx],0x2f
  34c2b5:	75 24                	jne    0x34c2db
  34c2b7:	80 7b 01 68          	cmp    BYTE PTR [rbx+0x1],0x68
  34c2bb:	75 1e                	jne    0x34c2db
  34c2bd:	80 7b 02 6f          	cmp    BYTE PTR [rbx+0x2],0x6f
  34c2c1:	75 18                	jne    0x34c2db
  34c2c3:	80 7b 03 73          	cmp    BYTE PTR [rbx+0x3],0x73
  34c2c7:	75 12                	jne    0x34c2db
  34c2c9:	80 7b 04 74          	cmp    BYTE PTR [rbx+0x4],0x74
  34c2cd:	75 0c                	jne    0x34c2db
  34c2cf:	80 7b 05 2f          	cmp    BYTE PTR [rbx+0x5],0x2f
  34c2d3:	41 be 01 00 00 00    	mov    r14d,0x1
  34c2d9:	74 03                	je     0x34c2de
  34c2db:	45 31 f6             	xor    r14d,r14d
  34c2de:	44 89 f0             	mov    eax,r14d
  34c2e1:	5b                   	pop    rbx
  34c2e2:	41 5e                	pop    r14
  34c2e4:	5d                   	pop    rbp
  34c2e5:	c3                   	ret
  34c2e6:	90                   	nop
  34c2e7:	90                   	nop
  34c2e8:	90                   	nop
  34c2e9:	90                   	nop
  34c2ea:	90                   	nop
  34c2eb:	90                   	nop
  34c2ec:	90                   	nop
  34c2ed:	90                   	nop
  34c2ee:	90                   	nop
  34c2ef:	90                   	nop
  34c2f0:	55                   	push   rbp
  34c2f1:	48 89 e5             	mov    rbp,rsp
  34c2f4:	53                   	push   rbx
  34c2f5:	50                   	push   rax
  34c2f6:	be 5c 00 00 00       	mov    esi,0x5c
  34c2fb:	48 89 fb             	mov    rbx,rdi
  34c2fe:	e8 fd 5e f2 ff       	call   0x272200
  34c303:	48 8d 48 01          	lea    rcx,[rax+0x1]
  34c307:	48 85 c0             	test   rax,rax
  34c30a:	48 0f 44 cb          	cmove  rcx,rbx
  34c30e:	48 89 c8             	mov    rax,rcx
  34c311:	48 83 c4 08          	add    rsp,0x8
  34c315:	5b                   	pop    rbx
  34c316:	5d                   	pop    rbp
  34c317:	c3                   	ret
  34c318:	90                   	nop
  34c319:	90                   	nop
  34c31a:	90                   	nop
  34c31b:	90                   	nop
  34c31c:	90                   	nop
  34c31d:	90                   	nop
  34c31e:	90                   	nop
  34c31f:	90                   	nop
  34c320:	55                   	push   rbp
  34c321:	48 89 e5             	mov    rbp,rsp
  34c324:	53                   	push   rbx
  34c325:	50                   	push   rax
  34c326:	be 2f 00 00 00       	mov    esi,0x2f
  34c32b:	48 89 fb             	mov    rbx,rdi
  34c32e:	e8 cd 5e f2 ff       	call   0x272200
  34c333:	48 8d 48 01          	lea    rcx,[rax+0x1]
  34c337:	48 85 c0             	test   rax,rax
  34c33a:	48 0f 44 cb          	cmove  rcx,rbx
  34c33e:	48 89 c8             	mov    rax,rcx
  34c341:	48 83 c4 08          	add    rsp,0x8
  34c345:	5b                   	pop    rbx
  34c346:	5d                   	pop    rbp
  34c347:	c3                   	ret
  34c348:	90                   	nop
  34c349:	90                   	nop
  34c34a:	90                   	nop
  34c34b:	90                   	nop
  34c34c:	90                   	nop
  34c34d:	90                   	nop
  34c34e:	90                   	nop
  34c34f:	90                   	nop
  34c350:	55                   	push   rbp
  34c351:	48 89 e5             	mov    rbp,rsp
  34c354:	41 57                	push   r15
  34c356:	41 56                	push   r14
  34c358:	41 55                	push   r13
  34c35a:	41 54                	push   r12
  34c35c:	53                   	push   rbx
  34c35d:	48 83 ec 18          	sub    rsp,0x18
  34c361:	4c 8d 25 a8 ff 5c 03 	lea    r12,[rip+0x35cffa8]        # 0x391c310
  34c368:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  34c36c:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34c370:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  34c374:	44 8b 2e             	mov    r13d,DWORD PTR [rsi]
  34c377:	48 8b 5e 08          	mov    rbx,QWORD PTR [rsi+0x8]
  34c37b:	4c 8b b0 e8 03 00 00 	mov    r14,QWORD PTR [rax+0x3e8]
  34c382:	e8 89 0a 78 00       	call   0xacce10
  34c387:	85 c0                	test   eax,eax
  34c389:	75 0d                	jne    0x34c398
  34c38b:	e8 c0 0a 78 00       	call   0xacce50
  34c390:	85 c0                	test   eax,eax
  34c392:	0f 84 26 02 00 00    	je     0x34c5be
  34c398:	4d 85 f6             	test   r14,r14
  34c39b:	0f 84 fc 01 00 00    	je     0x34c59d
  34c3a1:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
  34c3a5:	48 83 b8 48 01 00 00 	cmp    QWORD PTR [rax+0x148],0x0
  34c3ac:	00 
  34c3ad:	0f 84 ea 01 00 00    	je     0x34c59d
  34c3b3:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34c3ba:	00 00 
  34c3bc:	48 8d 35 7a bb 04 01 	lea    rsi,[rip+0x104bb7a]        # 0x1397f3d
  34c3c3:	31 d2                	xor    edx,edx
  34c3c5:	e8 16 e0 8c 00       	call   0xc1a3e0
  34c3ca:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  34c3ce:	ba 08 00 00 00       	mov    edx,0x8
  34c3d3:	48 89 df             	mov    rdi,rbx
  34c3d6:	e8 a5 ce f0 ff       	call   0x259280
  34c3db:	89 c1                	mov    ecx,eax
  34c3dd:	b8 0e 00 00 00       	mov    eax,0xe
  34c3e2:	85 c9                	test   ecx,ecx
  34c3e4:	0f 85 d9 01 00 00    	jne    0x34c5c3
  34c3ea:	48 81 7d c8 60 01 00 	cmp    QWORD PTR [rbp-0x38],0x160
  34c3f1:	00 
  34c3f2:	b8 16 00 00 00       	mov    eax,0x16
  34c3f7:	0f 85 c6 01 00 00    	jne    0x34c5c3
  34c3fd:	bf 60 01 00 00       	mov    edi,0x160
  34c402:	be 0a 00 00 00       	mov    esi,0xa
  34c407:	e8 54 e8 7d 00       	call   0xb2ac60
  34c40c:	49 8d 7e 70          	lea    rdi,[r14+0x70]
  34c410:	49 89 c7             	mov    r15,rax
  34c413:	31 f6                	xor    esi,esi
  34c415:	31 d2                	xor    edx,edx
  34c417:	31 c9                	xor    ecx,ecx
  34c419:	48 89 7d c0          	mov    QWORD PTR [rbp-0x40],rdi
  34c41d:	e8 fe f6 8f 00       	call   0xc4bb20
  34c422:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  34c429:	1f 84 00 00 00 00 00 
  34c430:	4d 8b 36             	mov    r14,QWORD PTR [r14]
  34c433:	4d 85 f6             	test   r14,r14
  34c436:	0f 84 a4 01 00 00    	je     0x34c5e0
  34c43c:	45 3b 6e 28          	cmp    r13d,DWORD PTR [r14+0x28]
  34c440:	75 ee                	jne    0x34c430
  34c442:	be 60 01 00 00       	mov    esi,0x160
  34c447:	4c 89 ff             	mov    rdi,r15
  34c44a:	e8 a1 cb f0 ff       	call   0x258ff0
  34c44f:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  34c453:	49 89 07             	mov    QWORD PTR [r15],rax
  34c456:	4d 8b 6e 08          	mov    r13,QWORD PTR [r14+0x8]
  34c45a:	4d 85 ed             	test   r13,r13
  34c45d:	74 42                	je     0x34c4a1
  34c45f:	be 00 04 00 00       	mov    esi,0x400
  34c464:	4c 89 ef             	mov    rdi,r13
  34c467:	e8 44 8a 0f 00       	call   0x444eb0
  34c46c:	48 83 f8 06          	cmp    rax,0x6
  34c470:	72 2f                	jb     0x34c4a1
  34c472:	41 80 7d 00 2f       	cmp    BYTE PTR [r13+0x0],0x2f
  34c477:	75 28                	jne    0x34c4a1
  34c479:	41 80 7d 01 68       	cmp    BYTE PTR [r13+0x1],0x68
  34c47e:	75 21                	jne    0x34c4a1
  34c480:	41 80 7d 02 6f       	cmp    BYTE PTR [r13+0x2],0x6f
  34c485:	75 1a                	jne    0x34c4a1
  34c487:	41 80 7d 03 73       	cmp    BYTE PTR [r13+0x3],0x73
  34c48c:	75 13                	jne    0x34c4a1
  34c48e:	41 80 7d 04 74       	cmp    BYTE PTR [r13+0x4],0x74
  34c493:	75 0c                	jne    0x34c4a1
  34c495:	41 80 7d 05 2f       	cmp    BYTE PTR [r13+0x5],0x2f
  34c49a:	be 5c 00 00 00       	mov    esi,0x5c
  34c49f:	74 05                	je     0x34c4a6
  34c4a1:	be 2f 00 00 00       	mov    esi,0x2f
  34c4a6:	4d 8b 6e 08          	mov    r13,QWORD PTR [r14+0x8]
  34c4aa:	4c 89 ef             	mov    rdi,r13
  34c4ad:	e8 4e 5d f2 ff       	call   0x272200
  34c4b2:	48 8d 70 01          	lea    rsi,[rax+0x1]
  34c4b6:	48 85 c0             	test   rax,rax
  34c4b9:	49 8d 7f 08          	lea    rdi,[r15+0x8]
  34c4bd:	ba 00 01 00 00       	mov    edx,0x100
  34c4c2:	49 0f 44 f5          	cmove  rsi,r13
  34c4c6:	e8 75 7f 63 00       	call   0x984440
  34c4cb:	41 c6 87 07 01 00 00 	mov    BYTE PTR [r15+0x107],0x0
  34c4d2:	00 
  34c4d3:	41 c7 87 48 01 00 00 	mov    DWORD PTR [r15+0x148],0x0
  34c4da:	00 00 00 00 
  34c4de:	41 83 7e 48 00       	cmp    DWORD PTR [r14+0x48],0x0
  34c4e3:	0f 84 1d 01 00 00    	je     0x34c606
  34c4e9:	49 8d 87 08 01 00 00 	lea    rax,[r15+0x108]
  34c4f0:	ba 04 00 00 00       	mov    edx,0x4
  34c4f5:	31 c9                	xor    ecx,ecx
  34c4f7:	31 f6                	xor    esi,esi
  34c4f9:	31 ff                	xor    edi,edi
  34c4fb:	eb 2f                	jmp    0x34c52c
  34c4fd:	0f 1f 00             	nop    DWORD PTR [rax]
  34c500:	41 8b bf 48 01 00 00 	mov    edi,DWORD PTR [r15+0x148]
  34c507:	48 ff c6             	inc    rsi
  34c50a:	ff c7                	inc    edi
  34c50c:	41 89 bf 48 01 00 00 	mov    DWORD PTR [r15+0x148],edi
  34c513:	45 8b 46 48          	mov    r8d,DWORD PTR [r14+0x48]
  34c517:	41 83 f8 04          	cmp    r8d,0x4
  34c51b:	44 0f 43 c2          	cmovae r8d,edx
  34c51f:	48 83 c1 18          	add    rcx,0x18
  34c523:	4c 39 c6             	cmp    rsi,r8
  34c526:	0f 83 da 00 00 00    	jae    0x34c606
  34c52c:	4d 8b 4e 40          	mov    r9,QWORD PTR [r14+0x40]
  34c530:	41 89 fa             	mov    r10d,edi
  34c533:	49 c1 e2 04          	shl    r10,0x4
  34c537:	4a 8d 3c 10          	lea    rdi,[rax+r10*1]
  34c53b:	4d 8b 44 09 08       	mov    r8,QWORD PTR [r9+rcx*1+0x8]
  34c540:	4e 89 04 10          	mov    QWORD PTR [rax+r10*1],r8
  34c544:	45 8b 44 09 10       	mov    r8d,DWORD PTR [r9+rcx*1+0x10]
  34c549:	46 89 44 10 08       	mov    DWORD PTR [rax+r10*1+0x8],r8d
  34c54e:	42 c7 44 10 0c 00 00 	mov    DWORD PTR [rax+r10*1+0xc],0x0
  34c555:	00 00 
  34c557:	4d 8b 04 09          	mov    r8,QWORD PTR [r9+rcx*1]
  34c55b:	45 8b 40 0c          	mov    r8d,DWORD PTR [r8+0xc]
  34c55f:	41 83 e0 01          	and    r8d,0x1
  34c563:	46 89 44 10 0c       	mov    DWORD PTR [rax+r10*1+0xc],r8d
  34c568:	4d 8b 14 09          	mov    r10,QWORD PTR [r9+rcx*1]
  34c56c:	45 8b 52 0c          	mov    r10d,DWORD PTR [r10+0xc]
  34c570:	41 f6 c2 02          	test   r10b,0x2
  34c574:	74 10                	je     0x34c586
  34c576:	41 83 c8 02          	or     r8d,0x2
  34c57a:	44 89 47 0c          	mov    DWORD PTR [rdi+0xc],r8d
  34c57e:	4d 8b 0c 09          	mov    r9,QWORD PTR [r9+rcx*1]
  34c582:	45 8b 51 0c          	mov    r10d,DWORD PTR [r9+0xc]
  34c586:	41 f6 c2 04          	test   r10b,0x4
  34c58a:	0f 84 70 ff ff ff    	je     0x34c500
  34c590:	41 83 c8 04          	or     r8d,0x4
  34c594:	44 89 47 0c          	mov    DWORD PTR [rdi+0xc],r8d
  34c598:	e9 63 ff ff ff       	jmp    0x34c500
  34c59d:	48 8d 3d 6f 77 05 01 	lea    rdi,[rip+0x105776f]        # 0x13a3d13
  34c5a4:	48 8d 15 df f7 fa 00 	lea    rdx,[rip+0xfaf7df]        # 0x12fbd8a
  34c5ab:	48 8d 0d 7e e8 00 01 	lea    rcx,[rip+0x100e87e]        # 0x135ae30
  34c5b2:	be b4 05 00 00       	mov    esi,0x5b4
  34c5b7:	31 c0                	xor    eax,eax
  34c5b9:	e8 72 64 7d 00       	call   0xb22a30
  34c5be:	b8 01 00 00 00       	mov    eax,0x1
  34c5c3:	49 8b 0c 24          	mov    rcx,QWORD PTR [r12]
  34c5c7:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  34c5cb:	0f 85 96 00 00 00    	jne    0x34c667
  34c5d1:	48 83 c4 18          	add    rsp,0x18
  34c5d5:	5b                   	pop    rbx
  34c5d6:	41 5c                	pop    r12
  34c5d8:	41 5d                	pop    r13
  34c5da:	41 5e                	pop    r14
  34c5dc:	41 5f                	pop    r15
  34c5de:	5d                   	pop    rbp
  34c5df:	c3                   	ret
  34c5e0:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  34c5e4:	31 f6                	xor    esi,esi
  34c5e6:	31 d2                	xor    edx,edx
  34c5e8:	e8 c3 fe 8f 00       	call   0xc4c4b0
  34c5ed:	be 60 01 00 00       	mov    esi,0x160
  34c5f2:	4c 89 ff             	mov    rdi,r15
  34c5f5:	ba 0a 00 00 00       	mov    edx,0xa
  34c5fa:	e8 51 7c 7d 00       	call   0xb24250
  34c5ff:	b8 03 00 00 00       	mov    eax,0x3
  34c604:	eb bd                	jmp    0x34c5c3
  34c606:	4c 89 ff             	mov    rdi,r15
  34c609:	4c 89 f6             	mov    rsi,r14
  34c60c:	48 81 c7 4c 01 00 00 	add    rdi,0x14c
  34c613:	e8 28 f1 7d 00       	call   0xb2b740
  34c618:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  34c61c:	31 f6                	xor    esi,esi
  34c61e:	31 d2                	xor    edx,edx
  34c620:	e8 8b fe 8f 00       	call   0xc4c4b0
  34c625:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34c62c:	00 00 
  34c62e:	48 8d 35 62 2c 00 01 	lea    rsi,[rip+0x1002c62]        # 0x134f297
  34c635:	31 d2                	xor    edx,edx
  34c637:	e8 a4 dd 8c 00       	call   0xc1a3e0
  34c63c:	ba 60 01 00 00       	mov    edx,0x160
  34c641:	4c 89 ff             	mov    rdi,r15
  34c644:	48 89 de             	mov    rsi,rbx
  34c647:	e8 84 cb f0 ff       	call   0x2591d0
  34c64c:	be 60 01 00 00       	mov    esi,0x160
  34c651:	4c 89 ff             	mov    rdi,r15
  34c654:	ba 0a 00 00 00       	mov    edx,0xa
  34c659:	89 c3                	mov    ebx,eax
  34c65b:	e8 f0 7b 7d 00       	call   0xb24250
  34c660:	89 d8                	mov    eax,ebx
  34c662:	e9 5c ff ff ff       	jmp    0x34c5c3
  34c667:	e8 44 10 3b 00       	call   0x6fd6b0
  34c66c:	0f 0b                	ud2
  34c66e:	90                   	nop
  34c66f:	90                   	nop
  34c670:	55                   	push   rbp
  34c671:	48 89 e5             	mov    rbp,rsp
  34c674:	41 57                	push   r15
  34c676:	41 56                	push   r14
  34c678:	53                   	push   rbx
  34c679:	50                   	push   rax
  34c67a:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  34c67e:	48 89 f3             	mov    rbx,rsi
  34c681:	49 89 fe             	mov    r14,rdi
  34c684:	4c 8b b8 e8 03 00 00 	mov    r15,QWORD PTR [rax+0x3e8]
  34c68b:	e8 80 07 78 00       	call   0xacce10
  34c690:	85 c0                	test   eax,eax
  34c692:	75 09                	jne    0x34c69d
  34c694:	e8 b7 07 78 00       	call   0xacce50
  34c699:	85 c0                	test   eax,eax
  34c69b:	74 57                	je     0x34c6f4
  34c69d:	4d 85 ff             	test   r15,r15
  34c6a0:	74 31                	je     0x34c6d3
  34c6a2:	49 8b 47 10          	mov    rax,QWORD PTR [r15+0x10]
  34c6a6:	48 83 b8 48 01 00 00 	cmp    QWORD PTR [rax+0x148],0x0
  34c6ad:	00 
  34c6ae:	74 23                	je     0x34c6d3
  34c6b0:	49 8b 7e 08          	mov    rdi,QWORD PTR [r14+0x8]
  34c6b4:	48 8b 33             	mov    rsi,QWORD PTR [rbx]
  34c6b7:	48 8b 53 08          	mov    rdx,QWORD PTR [rbx+0x8]
  34c6bb:	4c 8b 43 10          	mov    r8,QWORD PTR [rbx+0x10]
  34c6bf:	b9 01 00 00 00       	mov    ecx,0x1
  34c6c4:	48 83 c4 08          	add    rsp,0x8
  34c6c8:	5b                   	pop    rbx
  34c6c9:	41 5e                	pop    r14
  34c6cb:	41 5f                	pop    r15
  34c6cd:	5d                   	pop    rbp
  34c6ce:	e9 6d ee ff ff       	jmp    0x34b540
  34c6d3:	48 8d 3d 98 9e fb 00 	lea    rdi,[rip+0xfb9e98]        # 0x1306572
  34c6da:	48 8d 15 a9 f6 fa 00 	lea    rdx,[rip+0xfaf6a9]        # 0x12fbd8a
  34c6e1:	48 8d 0d 48 e7 00 01 	lea    rcx,[rip+0x100e748]        # 0x135ae30
  34c6e8:	be 17 06 00 00       	mov    esi,0x617
  34c6ed:	31 c0                	xor    eax,eax
  34c6ef:	e8 3c 63 7d 00       	call   0xb22a30
  34c6f4:	b8 01 00 00 00       	mov    eax,0x1
  34c6f9:	48 83 c4 08          	add    rsp,0x8
  34c6fd:	5b                   	pop    rbx
  34c6fe:	41 5e                	pop    r14
  34c700:	41 5f                	pop    r15
  34c702:	5d                   	pop    rbp
  34c703:	c3                   	ret
  34c704:	90                   	nop
  34c705:	90                   	nop
  34c706:	90                   	nop
  34c707:	90                   	nop
  34c708:	90                   	nop
  34c709:	90                   	nop
  34c70a:	90                   	nop
  34c70b:	90                   	nop
  34c70c:	90                   	nop
  34c70d:	90                   	nop
  34c70e:	90                   	nop
  34c70f:	90                   	nop
  34c710:	55                   	push   rbp
  34c711:	48 89 e5             	mov    rbp,rsp
  34c714:	41 56                	push   r14
  34c716:	53                   	push   rbx
  34c717:	be 2f 00 00 00       	mov    esi,0x2f
  34c71c:	48 89 fb             	mov    rbx,rdi
  34c71f:	e8 dc 5a f2 ff       	call   0x272200
  34c724:	4c 8d 70 01          	lea    r14,[rax+0x1]
  34c728:	48 85 c0             	test   rax,rax
  34c72b:	be 5c 00 00 00       	mov    esi,0x5c
  34c730:	4c 0f 44 f3          	cmove  r14,rbx
  34c734:	4c 89 f7             	mov    rdi,r14
  34c737:	e8 c4 5a f2 ff       	call   0x272200
  34c73c:	48 8d 48 01          	lea    rcx,[rax+0x1]
  34c740:	48 85 c0             	test   rax,rax
  34c743:	49 0f 44 ce          	cmove  rcx,r14
  34c747:	48 89 c8             	mov    rax,rcx
  34c74a:	5b                   	pop    rbx
  34c74b:	41 5e                	pop    r14
  34c74d:	5d                   	pop    rbp
  34c74e:	c3                   	ret
  34c74f:	90                   	nop
  34c750:	55                   	push   rbp
  34c751:	48 89 e5             	mov    rbp,rsp
  34c754:	41 57                	push   r15
  34c756:	41 56                	push   r14
  34c758:	53                   	push   rbx
  34c759:	50                   	push   rax
  34c75a:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  34c75e:	4c 8b b0 e8 03 00 00 	mov    r14,QWORD PTR [rax+0x3e8]
  34c765:	4d 85 f6             	test   r14,r14
  34c768:	74 70                	je     0x34c7da
  34c76a:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
  34c76e:	48 83 b8 48 01 00 00 	cmp    QWORD PTR [rax+0x148],0x0
  34c775:	00 
  34c776:	74 62                	je     0x34c7da
  34c778:	4d 8d 7e 70          	lea    r15,[r14+0x70]
  34c77c:	31 db                	xor    ebx,ebx
  34c77e:	31 f6                	xor    esi,esi
  34c780:	31 d2                	xor    edx,edx
  34c782:	31 c9                	xor    ecx,ecx
  34c784:	4c 89 ff             	mov    rdi,r15
  34c787:	e8 94 f3 8f 00       	call   0xc4bb20
  34c78c:	49 8b 76 10          	mov    rsi,QWORD PTR [r14+0x10]
  34c790:	4c 89 f7             	mov    rdi,r14
  34c793:	e8 08 ea 7d 00       	call   0xb2b1a0
  34c798:	4c 89 ff             	mov    rdi,r15
  34c79b:	41 89 c6             	mov    r14d,eax
  34c79e:	31 f6                	xor    esi,esi
  34c7a0:	31 d2                	xor    edx,edx
  34c7a2:	e8 09 fd 8f 00       	call   0xc4c4b0
  34c7a7:	45 85 f6             	test   r14d,r14d
  34c7aa:	74 54                	je     0x34c800
  34c7ac:	48 8d 3d bf 88 f4 00 	lea    rdi,[rip+0xf488bf]        # 0x1295072
  34c7b3:	48 8d 15 d0 f5 fa 00 	lea    rdx,[rip+0xfaf5d0]        # 0x12fbd8a
  34c7ba:	48 8d 0d bf 77 03 01 	lea    rcx,[rip+0x10377bf]        # 0x1383f80
  34c7c1:	be 64 06 00 00       	mov    esi,0x664
  34c7c6:	41 b8 16 00 00 00    	mov    r8d,0x16
  34c7cc:	31 c0                	xor    eax,eax
  34c7ce:	bb 16 00 00 00       	mov    ebx,0x16
  34c7d3:	e8 58 62 7d 00       	call   0xb22a30
  34c7d8:	eb 26                	jmp    0x34c800
  34c7da:	48 8d 3d 91 88 f4 00 	lea    rdi,[rip+0xf48891]        # 0x1295072
  34c7e1:	48 8d 15 a2 f5 fa 00 	lea    rdx,[rip+0xfaf5a2]        # 0x12fbd8a
  34c7e8:	48 8d 0d 41 e6 00 01 	lea    rcx,[rip+0x100e641]        # 0x135ae30
  34c7ef:	be 5a 06 00 00       	mov    esi,0x65a
  34c7f4:	31 c0                	xor    eax,eax
  34c7f6:	e8 35 62 7d 00       	call   0xb22a30
  34c7fb:	bb 01 00 00 00       	mov    ebx,0x1
  34c800:	89 d8                	mov    eax,ebx
  34c802:	48 83 c4 08          	add    rsp,0x8
  34c806:	5b                   	pop    rbx
  34c807:	41 5e                	pop    r14
  34c809:	41 5f                	pop    r15
  34c80b:	5d                   	pop    rbp
  34c80c:	c3                   	ret
  34c80d:	90                   	nop
  34c80e:	90                   	nop
  34c80f:	90                   	nop
  34c810:	55                   	push   rbp
  34c811:	48 89 e5             	mov    rbp,rsp
  34c814:	b8 4e 00 00 00       	mov    eax,0x4e
  34c819:	5d                   	pop    rbp
  34c81a:	c3                   	ret
  34c81b:	90                   	nop
  34c81c:	90                   	nop
  34c81d:	90                   	nop
  34c81e:	90                   	nop
  34c81f:	90                   	nop
  34c820:	55                   	push   rbp
  34c821:	48 89 e5             	mov    rbp,rsp
  34c824:	41 56                	push   r14
  34c826:	53                   	push   rbx
  34c827:	48 83 ec 10          	sub    rsp,0x10
  34c82b:	48 8d 1d de fa 5c 03 	lea    rbx,[rip+0x35cfade]        # 0x391c310
  34c832:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  34c835:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
  34c839:	4c 8b 77 08          	mov    r14,QWORD PTR [rdi+0x8]
  34c83d:	e8 ce 05 78 00       	call   0xacce10
  34c842:	89 c1                	mov    ecx,eax
  34c844:	b8 2d 00 00 00       	mov    eax,0x2d
  34c849:	83 f9 01             	cmp    ecx,0x1
  34c84c:	75 46                	jne    0x34c894
  34c84e:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  34c855:	00 00 
  34c857:	48 8b 78 08          	mov    rdi,QWORD PTR [rax+0x8]
  34c85b:	48 8d 75 e4          	lea    rsi,[rbp-0x1c]
  34c85f:	e8 5c b9 6a 00       	call   0x9f81c0
  34c864:	89 c1                	mov    ecx,eax
  34c866:	31 c0                	xor    eax,eax
  34c868:	85 c9                	test   ecx,ecx
  34c86a:	75 28                	jne    0x34c894
  34c86c:	81 7d e4 ff ff ff 00 	cmp    DWORD PTR [rbp-0x1c],0xffffff
  34c873:	77 1f                	ja     0x34c894
  34c875:	49 8b 8e e8 03 00 00 	mov    rcx,QWORD PTR [r14+0x3e8]
  34c87c:	c7 81 50 01 00 00 01 	mov    DWORD PTR [rcx+0x150],0x1
  34c883:	00 00 00 
  34c886:	49 8b 8e e8 03 00 00 	mov    rcx,QWORD PTR [r14+0x3e8]
  34c88d:	83 89 40 01 00 00 40 	or     DWORD PTR [rcx+0x140],0x40
  34c894:	48 8b 0b             	mov    rcx,QWORD PTR [rbx]
  34c897:	48 3b 4d e8          	cmp    rcx,QWORD PTR [rbp-0x18]
  34c89b:	75 09                	jne    0x34c8a6
  34c89d:	48 83 c4 10          	add    rsp,0x10
  34c8a1:	5b                   	pop    rbx
  34c8a2:	41 5e                	pop    r14
  34c8a4:	5d                   	pop    rbp
  34c8a5:	c3                   	ret
  34c8a6:	e8 05 0e 3b 00       	call   0x6fd6b0
  34c8ab:	0f 0b                	ud2
  34c8ad:	90                   	nop
  34c8ae:	90                   	nop
  34c8af:	90                   	nop
  34c8b0:	55                   	push   rbp
  34c8b1:	48 89 e5             	mov    rbp,rsp
  34c8b4:	b8 4e 00 00 00       	mov    eax,0x4e
  34c8b9:	5d                   	pop    rbp
  34c8ba:	c3                   	ret
  34c8bb:	90                   	nop
  34c8bc:	90                   	nop
  34c8bd:	90                   	nop
  34c8be:	90                   	nop
  34c8bf:	90                   	nop
  34c8c0:	55                   	push   rbp
  34c8c1:	48 89 e5             	mov    rbp,rsp
  34c8c4:	41 57                	push   r15
  34c8c6:	41 56                	push   r14
  34c8c8:	41 54                	push   r12
  34c8ca:	53                   	push   rbx
  34c8cb:	4c 8b a7 e8 03 00 00 	mov    r12,QWORD PTR [rdi+0x3e8]
  34c8d2:	b8 02 00 00 00       	mov    eax,0x2
  34c8d7:	4d 85 e4             	test   r12,r12
  34c8da:	0f 84 a2 00 00 00    	je     0x34c982
  34c8e0:	49 8b 4c 24 10       	mov    rcx,QWORD PTR [r12+0x10]
  34c8e5:	48 83 b9 48 01 00 00 	cmp    QWORD PTR [rcx+0x148],0x0
  34c8ec:	00 
  34c8ed:	0f 84 8f 00 00 00    	je     0x34c982
  34c8f3:	49 83 bc 24 c8 00 00 	cmp    QWORD PTR [r12+0xc8],0x0
  34c8fa:	00 00 
  34c8fc:	0f 84 80 00 00 00    	je     0x34c982
  34c902:	48 89 f3             	mov    rbx,rsi
  34c905:	be 60 00 00 00       	mov    esi,0x60
  34c90a:	41 be 60 00 00 00    	mov    r14d,0x60
  34c910:	48 89 df             	mov    rdi,rbx
  34c913:	e8 d8 c6 f0 ff       	call   0x258ff0
  34c918:	49 8b 84 24 d0 00 00 	mov    rax,QWORD PTR [r12+0xd0]
  34c91f:	00 
  34c920:	4d 8b bc 24 c8 00 00 	mov    r15,QWORD PTR [r12+0xc8]
  34c927:	00 
  34c928:	48 8d 35 0e b6 04 01 	lea    rsi,[rip+0x104b60e]        # 0x1397f3d
  34c92f:	48 83 f8 60          	cmp    rax,0x60
  34c933:	4c 0f 42 f0          	cmovb  r14,rax
  34c937:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34c93e:	00 00 
  34c940:	31 d2                	xor    edx,edx
  34c942:	e8 99 da 8c 00       	call   0xc1a3e0
  34c947:	4c 89 ff             	mov    rdi,r15
  34c94a:	48 89 de             	mov    rsi,rbx
  34c94d:	4c 89 f2             	mov    rdx,r14
  34c950:	e8 2b c9 f0 ff       	call   0x259280
  34c955:	85 c0                	test   eax,eax
  34c957:	75 29                	jne    0x34c982
  34c959:	48 8b 03             	mov    rax,QWORD PTR [rbx]
  34c95c:	48 83 f8 5f          	cmp    rax,0x5f
  34c960:	77 11                	ja     0x34c973
  34c962:	be 60 00 00 00       	mov    esi,0x60
  34c967:	48 8d 3c 03          	lea    rdi,[rbx+rax*1]
  34c96b:	48 29 c6             	sub    rsi,rax
  34c96e:	e8 7d c6 f0 ff       	call   0x258ff0
  34c973:	31 c0                	xor    eax,eax
  34c975:	81 7b 08 4f 52 42 49 	cmp    DWORD PTR [rbx+0x8],0x4942524f
  34c97c:	0f 95 c0             	setne  al
  34c97f:	c1 e0 03             	shl    eax,0x3
  34c982:	5b                   	pop    rbx
  34c983:	41 5c                	pop    r12
  34c985:	41 5e                	pop    r14
  34c987:	41 5f                	pop    r15
  34c989:	5d                   	pop    rbp
  34c98a:	c3                   	ret
  34c98b:	90                   	nop
  34c98c:	90                   	nop
  34c98d:	90                   	nop
  34c98e:	90                   	nop
  34c98f:	90                   	nop
  34c990:	55                   	push   rbp
  34c991:	48 89 e5             	mov    rbp,rsp
  34c994:	41 57                	push   r15
  34c996:	41 56                	push   r14
  34c998:	53                   	push   rbx
  34c999:	48 83 ec 18          	sub    rsp,0x18
  34c99d:	4c 8d 3d 6c f9 5c 03 	lea    r15,[rip+0x35cf96c]        # 0x391c310
  34c9a4:	49 8b 07             	mov    rax,QWORD PTR [r15]
  34c9a7:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  34c9ab:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  34c9af:	48 8b 80 e8 03 00 00 	mov    rax,QWORD PTR [rax+0x3e8]
  34c9b6:	48 85 c0             	test   rax,rax
  34c9b9:	0f 84 98 00 00 00    	je     0x34ca57
  34c9bf:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
  34c9c3:	48 83 b9 48 01 00 00 	cmp    QWORD PTR [rcx+0x148],0x0
  34c9ca:	00 
  34c9cb:	0f 84 86 00 00 00    	je     0x34ca57
  34c9d1:	48 8b 88 c8 00 00 00 	mov    rcx,QWORD PTR [rax+0xc8]
  34c9d8:	4c 8b 36             	mov    r14,QWORD PTR [rsi]
  34c9db:	48 8b 5e 08          	mov    rbx,QWORD PTR [rsi+0x8]
  34c9df:	48 8d 35 b1 28 00 01 	lea    rsi,[rip+0x10028b1]        # 0x134f297
  34c9e6:	31 d2                	xor    edx,edx
  34c9e8:	48 89 4d d8          	mov    QWORD PTR [rbp-0x28],rcx
  34c9ec:	48 8b 80 d0 00 00 00 	mov    rax,QWORD PTR [rax+0xd0]
  34c9f3:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34c9f7:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34c9fe:	00 00 
  34ca00:	e8 db d9 8c 00       	call   0xc1a3e0
  34ca05:	48 8d 7d d8          	lea    rdi,[rbp-0x28]
  34ca09:	ba 08 00 00 00       	mov    edx,0x8
  34ca0e:	4c 89 f6             	mov    rsi,r14
  34ca11:	e8 ba c7 f0 ff       	call   0x2591d0
  34ca16:	89 c1                	mov    ecx,eax
  34ca18:	b8 0e 00 00 00       	mov    eax,0xe
  34ca1d:	85 c9                	test   ecx,ecx
  34ca1f:	75 5c                	jne    0x34ca7d
  34ca21:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34ca28:	00 00 
  34ca2a:	48 8d 35 66 28 00 01 	lea    rsi,[rip+0x1002866]        # 0x134f297
  34ca31:	31 d2                	xor    edx,edx
  34ca33:	e8 a8 d9 8c 00       	call   0xc1a3e0
  34ca38:	48 8d 7d d0          	lea    rdi,[rbp-0x30]
  34ca3c:	ba 08 00 00 00       	mov    edx,0x8
  34ca41:	48 89 de             	mov    rsi,rbx
  34ca44:	e8 87 c7 f0 ff       	call   0x2591d0
  34ca49:	89 c1                	mov    ecx,eax
  34ca4b:	85 c0                	test   eax,eax
  34ca4d:	b8 0e 00 00 00       	mov    eax,0xe
  34ca52:	0f 44 c1             	cmove  eax,ecx
  34ca55:	eb 26                	jmp    0x34ca7d
  34ca57:	48 8d 3d 72 1d 04 01 	lea    rdi,[rip+0x1041d72]        # 0x138e7d0
  34ca5e:	48 8d 15 25 f3 fa 00 	lea    rdx,[rip+0xfaf325]        # 0x12fbd8a
  34ca65:	48 8d 0d c4 e3 00 01 	lea    rcx,[rip+0x100e3c4]        # 0x135ae30
  34ca6c:	be 17 07 00 00       	mov    esi,0x717
  34ca71:	31 c0                	xor    eax,eax
  34ca73:	e8 b8 5f 7d 00       	call   0xb22a30
  34ca78:	b8 01 00 00 00       	mov    eax,0x1
  34ca7d:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  34ca80:	48 3b 4d e0          	cmp    rcx,QWORD PTR [rbp-0x20]
  34ca84:	75 0b                	jne    0x34ca91
  34ca86:	48 83 c4 18          	add    rsp,0x18
  34ca8a:	5b                   	pop    rbx
  34ca8b:	41 5e                	pop    r14
  34ca8d:	41 5f                	pop    r15
  34ca8f:	5d                   	pop    rbp
  34ca90:	c3                   	ret
  34ca91:	e8 1a 0c 3b 00       	call   0x6fd6b0
  34ca96:	0f 0b                	ud2
  34ca98:	90                   	nop
  34ca99:	90                   	nop
  34ca9a:	90                   	nop
  34ca9b:	90                   	nop
  34ca9c:	90                   	nop
  34ca9d:	90                   	nop
  34ca9e:	90                   	nop
  34ca9f:	90                   	nop
  34caa0:	55                   	push   rbp
  34caa1:	48 89 e5             	mov    rbp,rsp
  34caa4:	41 57                	push   r15
  34caa6:	41 56                	push   r14
  34caa8:	41 55                	push   r13
  34caaa:	41 54                	push   r12
  34caac:	53                   	push   rbx
  34caad:	48 83 ec 18          	sub    rsp,0x18
  34cab1:	4c 8d 2d 58 f8 5c 03 	lea    r13,[rip+0x35cf858]        # 0x391c310
  34cab8:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  34cabc:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34cac0:	65 4c 8b 34 25 00 00 	mov    r14,QWORD PTR gs:0x0
  34cac7:	00 00 
  34cac9:	49 8b 46 08          	mov    rax,QWORD PTR [r14+0x8]
  34cacd:	48 8b 80 e8 03 00 00 	mov    rax,QWORD PTR [rax+0x3e8]
  34cad4:	48 85 c0             	test   rax,rax
  34cad7:	0f 84 b1 00 00 00    	je     0x34cb8e
  34cadd:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
  34cae1:	48 83 b8 48 01 00 00 	cmp    QWORD PTR [rax+0x148],0x0
  34cae8:	00 
  34cae9:	0f 84 9f 00 00 00    	je     0x34cb8e
  34caef:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  34caf3:	48 89 fb             	mov    rbx,rdi
  34caf6:	31 f6                	xor    esi,esi
  34caf8:	31 d2                	xor    edx,edx
  34cafa:	31 c9                	xor    ecx,ecx
  34cafc:	48 8b b8 e8 03 00 00 	mov    rdi,QWORD PTR [rax+0x3e8]
  34cb03:	48 83 c7 70          	add    rdi,0x70
  34cb07:	e8 14 f0 8f 00       	call   0xc4bb20
  34cb0c:	48 8b 7b 08          	mov    rdi,QWORD PTR [rbx+0x8]
  34cb10:	e8 3b a7 7d 00       	call   0xb27250
  34cb15:	85 c0                	test   eax,eax
  34cb17:	75 09                	jne    0x34cb22
  34cb19:	48 8b 7b 08          	mov    rdi,QWORD PTR [rbx+0x8]
  34cb1d:	e8 9e ac 7d 00       	call   0xb277c0
  34cb22:	48 8b 4b 08          	mov    rcx,QWORD PTR [rbx+0x8]
  34cb26:	31 f6                	xor    esi,esi
  34cb28:	31 d2                	xor    edx,edx
  34cb2a:	41 89 c7             	mov    r15d,eax
  34cb2d:	48 8b b9 e8 03 00 00 	mov    rdi,QWORD PTR [rcx+0x3e8]
  34cb34:	48 83 c7 70          	add    rdi,0x70
  34cb38:	e8 73 f9 8f 00       	call   0xc4c4b0
  34cb3d:	44 89 f8             	mov    eax,r15d
  34cb40:	45 85 ff             	test   r15d,r15d
  34cb43:	75 6f                	jne    0x34cbb4
  34cb45:	49 8b 7e 08          	mov    rdi,QWORD PTR [r14+0x8]
  34cb49:	e8 42 01 00 00       	call   0x34cc90
  34cb4e:	89 45 cc             	mov    DWORD PTR [rbp-0x34],eax
  34cb51:	85 c0                	test   eax,eax
  34cb53:	75 5f                	jne    0x34cbb4
  34cb55:	48 8d 3d 35 9a fb 00 	lea    rdi,[rip+0xfb9a35]        # 0x1306591
  34cb5c:	e8 7f 17 3f 00       	call   0x73e2e0
  34cb61:	48 85 c0             	test   rax,rax
  34cb64:	0f 84 0d 01 00 00    	je     0x34cc77
  34cb6a:	49 89 c7             	mov    r15,rax
  34cb6d:	8b 40 0c             	mov    eax,DWORD PTR [rax+0xc]
  34cb70:	8d 48 01             	lea    ecx,[rax+0x1]
  34cb73:	41 89 4f 0c          	mov    DWORD PTR [r15+0xc],ecx
  34cb77:	4d 8b 77 40          	mov    r14,QWORD PTR [r15+0x40]
  34cb7b:	4d 85 f6             	test   r14,r14
  34cb7e:	0f 84 c9 00 00 00    	je     0x34cc4d
  34cb84:	4c 89 7d c0          	mov    QWORD PTR [rbp-0x40],r15
  34cb88:	49 83 c7 28          	add    r15,0x28
  34cb8c:	eb 77                	jmp    0x34cc05
  34cb8e:	48 8d 3d 5e c3 f5 00 	lea    rdi,[rip+0xf5c35e]        # 0x12a8ef3
  34cb95:	48 8d 15 ee f1 fa 00 	lea    rdx,[rip+0xfaf1ee]        # 0x12fbd8a
  34cb9c:	48 8d 0d 8d e2 00 01 	lea    rcx,[rip+0x100e28d]        # 0x135ae30
  34cba3:	be 60 07 00 00       	mov    esi,0x760
  34cba8:	31 c0                	xor    eax,eax
  34cbaa:	e8 81 5e 7d 00       	call   0xb22a30
  34cbaf:	b8 16 00 00 00       	mov    eax,0x16
  34cbb4:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  34cbb8:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  34cbbc:	0f 85 bc 00 00 00    	jne    0x34cc7e
  34cbc2:	48 83 c4 18          	add    rsp,0x18
  34cbc6:	5b                   	pop    rbx
  34cbc7:	41 5c                	pop    r12
  34cbc9:	41 5d                	pop    r13
  34cbcb:	41 5e                	pop    r14
  34cbcd:	41 5f                	pop    r15
  34cbcf:	5d                   	pop    rbp
  34cbd0:	c3                   	ret
  34cbd1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  34cbd8:	0f 1f 84 00 00 00 00 
  34cbdf:	00 
  34cbe0:	49 8b 7e 18          	mov    rdi,QWORD PTR [r14+0x18]
  34cbe4:	48 8b 73 08          	mov    rsi,QWORD PTR [rbx+0x8]
  34cbe8:	48 8d 55 cc          	lea    rdx,[rbp-0x34]
  34cbec:	41 ff d4             	call   r12
  34cbef:	4c 89 ff             	mov    rdi,r15
  34cbf2:	31 f6                	xor    esi,esi
  34cbf4:	31 d2                	xor    edx,edx
  34cbf6:	31 c9                	xor    ecx,ecx
  34cbf8:	e8 03 9e 17 00       	call   0x4c6a00
  34cbfd:	4d 8b 36             	mov    r14,QWORD PTR [r14]
  34cc00:	4d 85 f6             	test   r14,r14
  34cc03:	74 3e                	je     0x34cc43
  34cc05:	41 83 7e 10 ff       	cmp    DWORD PTR [r14+0x10],0xffffffff
  34cc0a:	74 f1                	je     0x34cbfd
  34cc0c:	4c 89 ff             	mov    rdi,r15
  34cc0f:	31 f6                	xor    esi,esi
  34cc11:	31 d2                	xor    edx,edx
  34cc13:	31 c9                	xor    ecx,ecx
  34cc15:	e8 86 a3 17 00       	call   0x4c6fa0
  34cc1a:	4d 8b 66 28          	mov    r12,QWORD PTR [r14+0x28]
  34cc1e:	48 8d 05 1b b8 f1 ff 	lea    rax,[rip+0xfffffffffff1b81b]        # 0x268440
  34cc25:	4c 29 e0             	sub    rax,r12
  34cc28:	48 c1 c8 03          	ror    rax,0x3
  34cc2c:	48 83 f8 42          	cmp    rax,0x42
  34cc30:	76 ae                	jbe    0x34cbe0
  34cc32:	48 8d 3d f7 fd 74 01 	lea    rdi,[rip+0x174fdf7]        # 0x1a9ca30
  34cc39:	4c 89 e6             	mov    rsi,r12
  34cc3c:	e8 7f 2c 10 00       	call   0x44f8c0
  34cc41:	eb 9d                	jmp    0x34cbe0
  34cc43:	4c 8b 7d c0          	mov    r15,QWORD PTR [rbp-0x40]
  34cc47:	41 8b 47 0c          	mov    eax,DWORD PTR [r15+0xc]
  34cc4b:	ff c8                	dec    eax
  34cc4d:	41 89 47 0c          	mov    DWORD PTR [r15+0xc],eax
  34cc51:	85 c0                	test   eax,eax
  34cc53:	75 08                	jne    0x34cc5d
  34cc55:	4c 89 ff             	mov    rdi,r15
  34cc58:	e8 13 17 3f 00       	call   0x73e370
  34cc5d:	49 83 c7 28          	add    r15,0x28
  34cc61:	31 f6                	xor    esi,esi
  34cc63:	31 d2                	xor    edx,edx
  34cc65:	31 c9                	xor    ecx,ecx
  34cc67:	4c 89 ff             	mov    rdi,r15
  34cc6a:	e8 31 a3 17 00       	call   0x4c6fa0
  34cc6f:	8b 45 cc             	mov    eax,DWORD PTR [rbp-0x34]
  34cc72:	e9 3d ff ff ff       	jmp    0x34cbb4
  34cc77:	31 c0                	xor    eax,eax
  34cc79:	e9 36 ff ff ff       	jmp    0x34cbb4
  34cc7e:	e8 2d 0a 3b 00       	call   0x6fd6b0
  34cc83:	0f 0b                	ud2
  34cc85:	90                   	nop
  34cc86:	90                   	nop
  34cc87:	90                   	nop
  34cc88:	90                   	nop
  34cc89:	90                   	nop
  34cc8a:	90                   	nop
  34cc8b:	90                   	nop
  34cc8c:	90                   	nop
  34cc8d:	90                   	nop
  34cc8e:	90                   	nop
  34cc8f:	90                   	nop
  34cc90:	55                   	push   rbp
  34cc91:	48 89 e5             	mov    rbp,rsp
  34cc94:	41 57                	push   r15
  34cc96:	41 56                	push   r14
  34cc98:	41 54                	push   r12
  34cc9a:	53                   	push   rbx
  34cc9b:	48 81 ec 90 00 00 00 	sub    rsp,0x90
  34cca2:	4c 8d 25 67 f6 5c 03 	lea    r12,[rip+0x35cf667]        # 0x391c310
  34cca9:	48 89 fb             	mov    rbx,rdi
  34ccac:	be 20 00 00 00       	mov    esi,0x20
  34ccb1:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  34ccb5:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  34ccb9:	c7 87 d0 0c 00 00 00 	mov    DWORD PTR [rdi+0xcd0],0x0
  34ccc0:	00 00 00 
  34ccc3:	48 8d bd 50 ff ff ff 	lea    rdi,[rbp-0xb0]
  34ccca:	e8 21 c3 f0 ff       	call   0x258ff0
  34cccf:	48 8d b5 70 ff ff ff 	lea    rsi,[rbp-0x90]
  34ccd6:	48 89 df             	mov    rdi,rbx
  34ccd9:	e8 e2 fb ff ff       	call   0x34c8c0
  34ccde:	85 c0                	test   eax,eax
  34cce0:	74 3a                	je     0x34cd1c
  34cce2:	8b b3 bc 00 00 00    	mov    esi,DWORD PTR [rbx+0xbc]
  34cce8:	48 8d 3d b7 60 f8 00 	lea    rdi,[rip+0xf860b7]        # 0x12d2da6
  34ccef:	89 c2                	mov    edx,eax
  34ccf1:	41 89 c6             	mov    r14d,eax
  34ccf4:	31 c0                	xor    eax,eax
  34ccf6:	e8 15 07 f1 ff       	call   0x25d410
  34ccfb:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  34ccff:	48 3b 45 d8          	cmp    rax,QWORD PTR [rbp-0x28]
  34cd03:	0f 85 3f 01 00 00    	jne    0x34ce48
  34cd09:	44 89 f0             	mov    eax,r14d
  34cd0c:	48 81 c4 90 00 00 00 	add    rsp,0x90
  34cd13:	5b                   	pop    rbx
  34cd14:	41 5c                	pop    r12
  34cd16:	41 5e                	pop    r14
  34cd18:	41 5f                	pop    r15
  34cd1a:	5d                   	pop    rbp
  34cd1b:	c3                   	ret
  34cd1c:	83 bd 7c ff ff ff 03 	cmp    DWORD PTR [rbp-0x84],0x3
  34cd23:	4c 8b 75 b8          	mov    r14,QWORD PTR [rbp-0x48]
  34cd27:	0f 92 c0             	setb   al
  34cd2a:	48 83 bd 70 ff ff ff 	cmp    QWORD PTR [rbp-0x90],0x50
  34cd31:	50 
  34cd32:	0f 92 c1             	setb   cl
  34cd35:	08 c1                	or     cl,al
  34cd37:	4d 85 f6             	test   r14,r14
  34cd3a:	0f 94 c0             	sete   al
  34cd3d:	08 c8                	or     al,cl
  34cd3f:	3c 01                	cmp    al,0x1
  34cd41:	75 46                	jne    0x34cd89
  34cd43:	4c 8b b5 58 ff ff ff 	mov    r14,QWORD PTR [rbp-0xa8]
  34cd4a:	4d 85 f6             	test   r14,r14
  34cd4d:	0f 84 84 00 00 00    	je     0x34cdd7
  34cd53:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34cd5a:	00 00 
  34cd5c:	48 8d 35 da b1 04 01 	lea    rsi,[rip+0x104b1da]        # 0x1397f3d
  34cd63:	31 d2                	xor    edx,edx
  34cd65:	48 81 c3 d0 0c 00 00 	add    rbx,0xcd0
  34cd6c:	e8 6f d6 8c 00       	call   0xc1a3e0
  34cd71:	ba 04 00 00 00       	mov    edx,0x4
  34cd76:	4c 89 f7             	mov    rdi,r14
  34cd79:	48 89 de             	mov    rsi,rbx
  34cd7c:	e8 ff c4 f0 ff       	call   0x259280
  34cd81:	41 89 c6             	mov    r14d,eax
  34cd84:	e9 72 ff ff ff       	jmp    0x34ccfb
  34cd89:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34cd90:	00 00 
  34cd92:	48 8d 35 a4 b1 04 01 	lea    rsi,[rip+0x104b1a4]        # 0x1397f3d
  34cd99:	31 d2                	xor    edx,edx
  34cd9b:	e8 40 d6 8c 00       	call   0xc1a3e0
  34cda0:	48 8d 75 d0          	lea    rsi,[rbp-0x30]
  34cda4:	ba 08 00 00 00       	mov    edx,0x8
  34cda9:	4c 89 f7             	mov    rdi,r14
  34cdac:	e8 cf c4 f0 ff       	call   0x259280
  34cdb1:	85 c0                	test   eax,eax
  34cdb3:	74 2a                	je     0x34cddf
  34cdb5:	8b b3 bc 00 00 00    	mov    esi,DWORD PTR [rbx+0xbc]
  34cdbb:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
  34cdbf:	48 8d 3d e9 19 04 01 	lea    rdi,[rip+0x10419e9]        # 0x138e7af
  34cdc6:	89 c2                	mov    edx,eax
  34cdc8:	41 89 c6             	mov    r14d,eax
  34cdcb:	31 c0                	xor    eax,eax
  34cdcd:	e8 3e 06 f1 ff       	call   0x25d410
  34cdd2:	e9 24 ff ff ff       	jmp    0x34ccfb
  34cdd7:	45 31 f6             	xor    r14d,r14d
  34cdda:	e9 1c ff ff ff       	jmp    0x34ccfb
  34cddf:	4c 8b 75 d0          	mov    r14,QWORD PTR [rbp-0x30]
  34cde3:	49 83 fe 21          	cmp    r14,0x21
  34cde7:	72 22                	jb     0x34ce0b
  34cde9:	8b b3 bc 00 00 00    	mov    esi,DWORD PTR [rbx+0xbc]
  34cdef:	48 8d 3d 61 1a 06 01 	lea    rdi,[rip+0x1061a61]        # 0x13ae857
  34cdf6:	4c 89 f2             	mov    rdx,r14
  34cdf9:	31 c0                	xor    eax,eax
  34cdfb:	e8 10 06 f1 ff       	call   0x25d410
  34ce00:	41 be 16 00 00 00    	mov    r14d,0x16
  34ce06:	e9 f0 fe ff ff       	jmp    0x34ccfb
  34ce0b:	4c 8b 7d b8          	mov    r15,QWORD PTR [rbp-0x48]
  34ce0f:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34ce16:	00 00 
  34ce18:	48 8d 35 1e b1 04 01 	lea    rsi,[rip+0x104b11e]        # 0x1397f3d
  34ce1f:	31 d2                	xor    edx,edx
  34ce21:	e8 ba d5 8c 00       	call   0xc1a3e0
  34ce26:	48 8d b5 50 ff ff ff 	lea    rsi,[rbp-0xb0]
  34ce2d:	4c 89 ff             	mov    rdi,r15
  34ce30:	4c 89 f2             	mov    rdx,r14
  34ce33:	e8 48 c4 f0 ff       	call   0x259280
  34ce38:	41 89 c6             	mov    r14d,eax
  34ce3b:	85 c0                	test   eax,eax
  34ce3d:	0f 85 b8 fe ff ff    	jne    0x34ccfb
  34ce43:	e9 fb fe ff ff       	jmp    0x34cd43
  34ce48:	e8 63 08 3b 00       	call   0x6fd6b0
  34ce4d:	0f 0b                	ud2
  34ce4f:	90                   	nop
  34ce50:	55                   	push   rbp
  34ce51:	48 89 e5             	mov    rbp,rsp
  34ce54:	41 57                	push   r15
  34ce56:	41 56                	push   r14
  34ce58:	53                   	push   rbx
  34ce59:	48 83 ec 28          	sub    rsp,0x28
  34ce5d:	4c 8d 3d ac f4 5c 03 	lea    r15,[rip+0x35cf4ac]        # 0x391c310
  34ce64:	31 d2                	xor    edx,edx
  34ce66:	49 8b 07             	mov    rax,QWORD PTR [r15]
  34ce69:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  34ce6d:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  34ce71:	48 8b 1e             	mov    rbx,QWORD PTR [rsi]
  34ce74:	48 8d 35 c2 b0 04 01 	lea    rsi,[rip+0x104b0c2]        # 0x1397f3d
  34ce7b:	4c 8b 70 40          	mov    r14,QWORD PTR [rax+0x40]
  34ce7f:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34ce86:	00 00 
  34ce88:	e8 53 d5 8c 00       	call   0xc1a3e0
  34ce8d:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  34ce91:	ba 08 00 00 00       	mov    edx,0x8
  34ce96:	48 89 df             	mov    rdi,rbx
  34ce99:	e8 e2 c3 f0 ff       	call   0x259280
  34ce9e:	89 c1                	mov    ecx,eax
  34cea0:	b8 0e 00 00 00       	mov    eax,0xe
  34cea5:	85 c9                	test   ecx,ecx
  34cea7:	0f 85 d6 00 00 00    	jne    0x34cf83
  34cead:	48 83 7d c8 10       	cmp    QWORD PTR [rbp-0x38],0x10
  34ceb2:	b8 16 00 00 00       	mov    eax,0x16
  34ceb7:	0f 85 c6 00 00 00    	jne    0x34cf83
  34cebd:	48 8d 7d d0          	lea    rdi,[rbp-0x30]
  34cec1:	be 10 00 00 00       	mov    esi,0x10
  34cec6:	e8 25 c1 f0 ff       	call   0x258ff0
  34cecb:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  34cecf:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34ced3:	e8 98 9d 25 00       	call   0x5a6c70
  34ced8:	4c 89 f7             	mov    rdi,r14
  34cedb:	89 45 d8             	mov    DWORD PTR [rbp-0x28],eax
  34cede:	e8 dd c6 2b 00       	call   0x6095c0
  34cee3:	85 c0                	test   eax,eax
  34cee5:	74 04                	je     0x34ceeb
  34cee7:	80 4d dc 01          	or     BYTE PTR [rbp-0x24],0x1
  34ceeb:	4c 89 f7             	mov    rdi,r14
  34ceee:	e8 2d c7 2b 00       	call   0x609620
  34cef3:	85 c0                	test   eax,eax
  34cef5:	74 04                	je     0x34cefb
  34cef7:	80 4d dc 02          	or     BYTE PTR [rbp-0x24],0x2
  34cefb:	4c 89 f7             	mov    rdi,r14
  34cefe:	e8 ed c2 2b 00       	call   0x6091f0
  34cf03:	85 c0                	test   eax,eax
  34cf05:	74 04                	je     0x34cf0b
  34cf07:	80 4d dc 04          	or     BYTE PTR [rbp-0x24],0x4
  34cf0b:	4c 89 f7             	mov    rdi,r14
  34cf0e:	e8 1d c3 2b 00       	call   0x609230
  34cf13:	85 c0                	test   eax,eax
  34cf15:	74 04                	je     0x34cf1b
  34cf17:	80 4d dc 08          	or     BYTE PTR [rbp-0x24],0x8
  34cf1b:	4c 89 f7             	mov    rdi,r14
  34cf1e:	e8 2d c8 2b 00       	call   0x609750
  34cf23:	85 c0                	test   eax,eax
  34cf25:	74 04                	je     0x34cf2b
  34cf27:	80 4d dc 10          	or     BYTE PTR [rbp-0x24],0x10
  34cf2b:	4c 89 f7             	mov    rdi,r14
  34cf2e:	e8 3d c3 2b 00       	call   0x609270
  34cf33:	85 c0                	test   eax,eax
  34cf35:	74 04                	je     0x34cf3b
  34cf37:	80 4d dc 20          	or     BYTE PTR [rbp-0x24],0x20
  34cf3b:	4c 89 f7             	mov    rdi,r14
  34cf3e:	e8 6d c7 2b 00       	call   0x6096b0
  34cf43:	85 c0                	test   eax,eax
  34cf45:	74 04                	je     0x34cf4b
  34cf47:	80 4d dc 40          	or     BYTE PTR [rbp-0x24],0x40
  34cf4b:	4c 89 f7             	mov    rdi,r14
  34cf4e:	e8 3d c9 2b 00       	call   0x609890
  34cf53:	85 c0                	test   eax,eax
  34cf55:	74 04                	je     0x34cf5b
  34cf57:	80 4d dc 80          	or     BYTE PTR [rbp-0x24],0x80
  34cf5b:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34cf62:	00 00 
  34cf64:	48 8d 35 2c 23 00 01 	lea    rsi,[rip+0x100232c]        # 0x134f297
  34cf6b:	31 d2                	xor    edx,edx
  34cf6d:	e8 6e d4 8c 00       	call   0xc1a3e0
  34cf72:	48 8d 7d d0          	lea    rdi,[rbp-0x30]
  34cf76:	ba 10 00 00 00       	mov    edx,0x10
  34cf7b:	48 89 de             	mov    rsi,rbx
  34cf7e:	e8 4d c2 f0 ff       	call   0x2591d0
  34cf83:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  34cf86:	48 3b 4d e0          	cmp    rcx,QWORD PTR [rbp-0x20]
  34cf8a:	75 0b                	jne    0x34cf97
  34cf8c:	48 83 c4 28          	add    rsp,0x28
  34cf90:	5b                   	pop    rbx
  34cf91:	41 5e                	pop    r14
  34cf93:	41 5f                	pop    r15
  34cf95:	5d                   	pop    rbp
  34cf96:	c3                   	ret
  34cf97:	e8 14 07 3b 00       	call   0x6fd6b0
  34cf9c:	0f 0b                	ud2
  34cf9e:	90                   	nop
  34cf9f:	90                   	nop
  34cfa0:	55                   	push   rbp
  34cfa1:	48 89 e5             	mov    rbp,rsp
  34cfa4:	41 57                	push   r15
  34cfa6:	41 56                	push   r14
  34cfa8:	41 54                	push   r12
  34cfaa:	53                   	push   rbx
  34cfab:	48 83 ec 10          	sub    rsp,0x10
  34cfaf:	4c 8d 3d 5a f3 5c 03 	lea    r15,[rip+0x35cf35a]        # 0x391c310
  34cfb6:	49 8b 07             	mov    rax,QWORD PTR [r15]
  34cfb9:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  34cfbd:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  34cfc4:	00 00 
  34cfc6:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34cfca:	4c 8b a0 e8 03 00 00 	mov    r12,QWORD PTR [rax+0x3e8]
  34cfd1:	4d 85 e4             	test   r12,r12
  34cfd4:	74 6e                	je     0x34d044
  34cfd6:	49 8b 44 24 10       	mov    rax,QWORD PTR [r12+0x10]
  34cfdb:	48 83 b8 48 01 00 00 	cmp    QWORD PTR [rax+0x148],0x0
  34cfe2:	00 
  34cfe3:	74 5f                	je     0x34d044
  34cfe5:	4d 8d 74 24 70       	lea    r14,[r12+0x70]
  34cfea:	48 89 f3             	mov    rbx,rsi
  34cfed:	31 f6                	xor    esi,esi
  34cfef:	31 d2                	xor    edx,edx
  34cff1:	31 c9                	xor    ecx,ecx
  34cff3:	4c 89 f7             	mov    rdi,r14
  34cff6:	e8 25 eb 8f 00       	call   0xc4bb20
  34cffb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  34d000:	4d 8b 24 24          	mov    r12,QWORD PTR [r12]
  34d004:	4d 85 e4             	test   r12,r12
  34d007:	74 66                	je     0x34d06f
  34d009:	48 63 03             	movsxd rax,DWORD PTR [rbx]
  34d00c:	49 39 44 24 28       	cmp    QWORD PTR [r12+0x28],rax
  34d011:	75 ed                	jne    0x34d000
  34d013:	0f b6 43 08          	movzx  eax,BYTE PTR [rbx+0x8]
  34d017:	ff c8                	dec    eax
  34d019:	83 f8 07             	cmp    eax,0x7
  34d01c:	77 75                	ja     0x34d093
  34d01e:	48 8d 0d 8b 32 17 01 	lea    rcx,[rip+0x117328b]        # 0x14c02b0
  34d025:	48 63 04 81          	movsxd rax,DWORD PTR [rcx+rax*4]
  34d029:	48 01 c8             	add    rax,rcx
  34d02c:	ff e0                	jmp    rax
  34d02e:	41 f6 84 24 1d 01 00 	test   BYTE PTR [r12+0x11d],0x10
  34d035:	00 10 
  34d037:	b8 e8 00 00 00       	mov    eax,0xe8
  34d03c:	0f 84 84 00 00 00    	je     0x34d0c6
  34d042:	eb 72                	jmp    0x34d0b6
  34d044:	48 8d 3d e2 e9 fc 00 	lea    rdi,[rip+0xfce9e2]        # 0x131ba2d
  34d04b:	48 8d 15 38 ed fa 00 	lea    rdx,[rip+0xfaed38]        # 0x12fbd8a
  34d052:	48 8d 0d d7 dd 00 01 	lea    rcx,[rip+0x100ddd7]        # 0x135ae30
  34d059:	be c4 07 00 00       	mov    esi,0x7c4
  34d05e:	31 c0                	xor    eax,eax
  34d060:	e8 cb 59 7d 00       	call   0xb22a30
  34d065:	b8 16 00 00 00       	mov    eax,0x16
  34d06a:	e9 97 00 00 00       	jmp    0x34d106
  34d06f:	4c 89 f7             	mov    rdi,r14
  34d072:	31 f6                	xor    esi,esi
  34d074:	31 d2                	xor    edx,edx
  34d076:	e8 35 f4 8f 00       	call   0xc4c4b0
  34d07b:	b8 03 00 00 00       	mov    eax,0x3
  34d080:	e9 81 00 00 00       	jmp    0x34d106
  34d085:	b8 f8 00 00 00       	mov    eax,0xf8
  34d08a:	eb 3a                	jmp    0x34d0c6
  34d08c:	b8 68 01 00 00       	mov    eax,0x168
  34d091:	eb 33                	jmp    0x34d0c6
  34d093:	4c 89 f7             	mov    rdi,r14
  34d096:	31 f6                	xor    esi,esi
  34d098:	31 d2                	xor    edx,edx
  34d09a:	e8 11 f4 8f 00       	call   0xc4c4b0
  34d09f:	b8 16 00 00 00       	mov    eax,0x16
  34d0a4:	eb 60                	jmp    0x34d106
  34d0a6:	41 f6 84 24 1d 01 00 	test   BYTE PTR [r12+0x11d],0x10
  34d0ad:	00 10 
  34d0af:	b8 f0 00 00 00       	mov    eax,0xf0
  34d0b4:	74 10                	je     0x34d0c6
  34d0b6:	31 c0                	xor    eax,eax
  34d0b8:	eb 10                	jmp    0x34d0ca
  34d0ba:	b8 08 01 00 00       	mov    eax,0x108
  34d0bf:	eb 05                	jmp    0x34d0c6
  34d0c1:	b8 78 00 00 00       	mov    eax,0x78
  34d0c6:	49 8b 04 04          	mov    rax,QWORD PTR [r12+rax*1]
  34d0ca:	4c 89 f7             	mov    rdi,r14
  34d0cd:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34d0d1:	31 f6                	xor    esi,esi
  34d0d3:	31 d2                	xor    edx,edx
  34d0d5:	e8 d6 f3 8f 00       	call   0xc4c4b0
  34d0da:	48 8b 5b 10          	mov    rbx,QWORD PTR [rbx+0x10]
  34d0de:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34d0e5:	00 00 
  34d0e7:	48 8d 35 a9 21 00 01 	lea    rsi,[rip+0x10021a9]        # 0x134f297
  34d0ee:	31 d2                	xor    edx,edx
  34d0f0:	e8 eb d2 8c 00       	call   0xc1a3e0
  34d0f5:	48 8d 7d d0          	lea    rdi,[rbp-0x30]
  34d0f9:	ba 08 00 00 00       	mov    edx,0x8
  34d0fe:	48 89 de             	mov    rsi,rbx
  34d101:	e8 ca c0 f0 ff       	call   0x2591d0
  34d106:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  34d109:	48 3b 4d d8          	cmp    rcx,QWORD PTR [rbp-0x28]
  34d10d:	75 0d                	jne    0x34d11c
  34d10f:	48 83 c4 10          	add    rsp,0x10
  34d113:	5b                   	pop    rbx
  34d114:	41 5c                	pop    r12
  34d116:	41 5e                	pop    r14
  34d118:	41 5f                	pop    r15
  34d11a:	5d                   	pop    rbp
  34d11b:	c3                   	ret
  34d11c:	e8 8f 05 3b 00       	call   0x6fd6b0
  34d121:	0f 0b                	ud2
  34d123:	90                   	nop
  34d124:	90                   	nop
  34d125:	90                   	nop
  34d126:	90                   	nop
  34d127:	90                   	nop
  34d128:	90                   	nop
  34d129:	90                   	nop
  34d12a:	90                   	nop
  34d12b:	90                   	nop
  34d12c:	90                   	nop
  34d12d:	90                   	nop
  34d12e:	90                   	nop
  34d12f:	90                   	nop
  34d130:	55                   	push   rbp
  34d131:	48 89 e5             	mov    rbp,rsp
  34d134:	41 57                	push   r15
  34d136:	41 56                	push   r14
  34d138:	41 54                	push   r12
  34d13a:	53                   	push   rbx
  34d13b:	48 81 ec 40 01 00 00 	sub    rsp,0x140
  34d142:	4c 8d 25 c7 f1 5c 03 	lea    r12,[rip+0x35cf1c7]        # 0x391c310
  34d149:	48 89 cb             	mov    rbx,rcx
  34d14c:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  34d150:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  34d154:	48 c7 45 c0 00 00 00 	mov    QWORD PTR [rbp-0x40],0x0
  34d15b:	00 
  34d15c:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
  34d163:	00 
  34d164:	c7 85 a4 fe ff ff 00 	mov    DWORD PTR [rbp-0x15c],0x0
  34d16b:	00 00 00 
  34d16e:	65 4c 8b 34 25 00 00 	mov    r14,QWORD PTR gs:0x0
  34d175:	00 00 
  34d177:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  34d17e:	e8 1d ff f1 ff       	call   0x26d0a0
  34d183:	83 f8 01             	cmp    eax,0x1
  34d186:	75 6a                	jne    0x34d1f2
  34d188:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  34d18f:	00 00 
  34d191:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34d195:	48 83 b8 e8 03 00 00 	cmp    QWORD PTR [rax+0x3e8],0x0
  34d19c:	00 
  34d19d:	0f 84 5a 02 00 00    	je     0x34d3fd
  34d1a3:	48 8b 88 a0 05 00 00 	mov    rcx,QWORD PTR [rax+0x5a0]
  34d1aa:	48 89 8d 10 ff ff ff 	mov    QWORD PTR [rbp-0xf0],rcx
  34d1b1:	48 8b 80 a8 05 00 00 	mov    rax,QWORD PTR [rax+0x5a8]
  34d1b8:	48 89 85 18 ff ff ff 	mov    QWORD PTR [rbp-0xe8],rax
  34d1bf:	48 8d 05 72 c1 f1 ff 	lea    rax,[rip+0xfffffffffff1c172]        # 0x269338
  34d1c6:	4c 8b 73 28          	mov    r14,QWORD PTR [rbx+0x28]
  34d1ca:	4c 29 f0             	sub    rax,r14
  34d1cd:	48 c1 c8 03          	ror    rax,0x3
  34d1d1:	48 83 f8 03          	cmp    rax,0x3
  34d1d5:	0f 87 ee 03 00 00    	ja     0x34d5c9
  34d1db:	48 8d b5 10 ff ff ff 	lea    rsi,[rbp-0xf0]
  34d1e2:	ba 10 00 00 00       	mov    edx,0x10
  34d1e7:	48 89 df             	mov    rdi,rbx
  34d1ea:	41 ff d6             	call   r14
  34d1ed:	e9 17 03 00 00       	jmp    0x34d509
  34d1f2:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  34d1f9:	e8 92 bd 2b 00       	call   0x608f90
  34d1fe:	83 f8 01             	cmp    eax,0x1
  34d201:	0f 85 a5 00 00 00    	jne    0x34d2ac
  34d207:	e8 74 dc 2b 00       	call   0x60ae80
  34d20c:	83 f8 01             	cmp    eax,0x1
  34d20f:	0f 85 c3 02 00 00    	jne    0x34d4d8
  34d215:	48 8d b5 a4 fe ff ff 	lea    rsi,[rbp-0x15c]
  34d21c:	bf 00 be 02 78       	mov    edi,0x7802be00
  34d221:	c7 85 a4 fe ff ff 00 	mov    DWORD PTR [rbp-0x15c],0x0
  34d228:	00 00 00 
  34d22b:	e8 90 9e 79 00       	call   0xae70c0
  34d230:	85 c0                	test   eax,eax
  34d232:	0f 85 a0 02 00 00    	jne    0x34d4d8
  34d238:	83 bd a4 fe ff ff 00 	cmp    DWORD PTR [rbp-0x15c],0x0
  34d23f:	0f 84 93 02 00 00    	je     0x34d4d8
  34d245:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  34d24c:	00 00 
  34d24e:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34d252:	48 83 b8 e8 03 00 00 	cmp    QWORD PTR [rax+0x3e8],0x0
  34d259:	00 
  34d25a:	0f 84 9d 01 00 00    	je     0x34d3fd
  34d260:	48 8b 88 a0 05 00 00 	mov    rcx,QWORD PTR [rax+0x5a0]
  34d267:	48 89 8d 10 ff ff ff 	mov    QWORD PTR [rbp-0xf0],rcx
  34d26e:	48 8b 80 a8 05 00 00 	mov    rax,QWORD PTR [rax+0x5a8]
  34d275:	48 89 85 18 ff ff ff 	mov    QWORD PTR [rbp-0xe8],rax
  34d27c:	48 8d 05 b5 c0 f1 ff 	lea    rax,[rip+0xfffffffffff1c0b5]        # 0x269338
  34d283:	4c 8b 73 28          	mov    r14,QWORD PTR [rbx+0x28]
  34d287:	4c 29 f0             	sub    rax,r14
  34d28a:	48 c1 c8 03          	ror    rax,0x3
  34d28e:	48 83 f8 03          	cmp    rax,0x3
  34d292:	0f 86 43 ff ff ff    	jbe    0x34d1db
  34d298:	48 8d 3d f1 f7 74 01 	lea    rdi,[rip+0x174f7f1]        # 0x1a9ca90
  34d29f:	4c 89 f6             	mov    rsi,r14
  34d2a2:	e8 19 26 10 00       	call   0x44f8c0
  34d2a7:	e9 2f ff ff ff       	jmp    0x34d1db
  34d2ac:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  34d2b3:	e8 b8 bf 2b 00       	call   0x609270
  34d2b8:	83 f8 01             	cmp    eax,0x1
  34d2bb:	75 54                	jne    0x34d311
  34d2bd:	e8 4e fb 77 00       	call   0xacce10
  34d2c2:	89 c1                	mov    ecx,eax
  34d2c4:	b8 03 00 00 00       	mov    eax,0x3
  34d2c9:	83 f9 01             	cmp    ecx,0x1
  34d2cc:	0f 85 06 02 00 00    	jne    0x34d4d8
  34d2d2:	e8 a9 db 2b 00       	call   0x60ae80
  34d2d7:	83 f8 01             	cmp    eax,0x1
  34d2da:	0f 85 f8 01 00 00    	jne    0x34d4d8
  34d2e0:	48 8d b5 a4 fe ff ff 	lea    rsi,[rbp-0x15c]
  34d2e7:	bf 00 be 02 78       	mov    edi,0x7802be00
  34d2ec:	c7 85 a4 fe ff ff 00 	mov    DWORD PTR [rbp-0x15c],0x0
  34d2f3:	00 00 00 
  34d2f6:	e8 c5 9d 79 00       	call   0xae70c0
  34d2fb:	85 c0                	test   eax,eax
  34d2fd:	0f 85 d5 01 00 00    	jne    0x34d4d8
  34d303:	83 bd a4 fe ff ff 00 	cmp    DWORD PTR [rbp-0x15c],0x0
  34d30a:	75 41                	jne    0x34d34d
  34d30c:	e9 c7 01 00 00       	jmp    0x34d4d8
  34d311:	e8 6a db 2b 00       	call   0x60ae80
  34d316:	83 f8 01             	cmp    eax,0x1
  34d319:	75 3f                	jne    0x34d35a
  34d31b:	e8 f0 fa 77 00       	call   0xacce10
  34d320:	83 f8 01             	cmp    eax,0x1
  34d323:	75 35                	jne    0x34d35a
  34d325:	48 8d b5 a4 fe ff ff 	lea    rsi,[rbp-0x15c]
  34d32c:	bf 00 b7 02 78       	mov    edi,0x7802b700
  34d331:	c7 85 a4 fe ff ff 00 	mov    DWORD PTR [rbp-0x15c],0x0
  34d338:	00 00 00 
  34d33b:	e8 80 9d 79 00       	call   0xae70c0
  34d340:	85 c0                	test   eax,eax
  34d342:	75 16                	jne    0x34d35a
  34d344:	83 bd a4 fe ff ff 00 	cmp    DWORD PTR [rbp-0x15c],0x0
  34d34b:	74 0d                	je     0x34d35a
  34d34d:	48 89 df             	mov    rdi,rbx
  34d350:	e8 8b 02 00 00       	call   0x34d5e0
  34d355:	e9 af 01 00 00       	jmp    0x34d509
  34d35a:	e8 b1 fa 77 00       	call   0xacce10
  34d35f:	83 f8 01             	cmp    eax,0x1
  34d362:	74 0e                	je     0x34d372
  34d364:	e8 e7 fa 77 00       	call   0xacce50
  34d369:	83 f8 01             	cmp    eax,0x1
  34d36c:	0f 85 95 00 00 00    	jne    0x34d407
  34d372:	48 8d b5 a4 fe ff ff 	lea    rsi,[rbp-0x15c]
  34d379:	bf 00 bf 02 78       	mov    edi,0x7802bf00
  34d37e:	c7 85 a4 fe ff ff 00 	mov    DWORD PTR [rbp-0x15c],0x0
  34d385:	00 00 00 
  34d388:	e8 33 9d 79 00       	call   0xae70c0
  34d38d:	85 c0                	test   eax,eax
  34d38f:	75 76                	jne    0x34d407
  34d391:	83 bd a4 fe ff ff 00 	cmp    DWORD PTR [rbp-0x15c],0x0
  34d398:	74 6d                	je     0x34d407
  34d39a:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  34d3a1:	00 00 
  34d3a3:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34d3a7:	48 83 b8 e8 03 00 00 	cmp    QWORD PTR [rax+0x3e8],0x0
  34d3ae:	00 
  34d3af:	74 4c                	je     0x34d3fd
  34d3b1:	48 8b 88 a0 05 00 00 	mov    rcx,QWORD PTR [rax+0x5a0]
  34d3b8:	48 89 8d 10 ff ff ff 	mov    QWORD PTR [rbp-0xf0],rcx
  34d3bf:	48 8b 80 a8 05 00 00 	mov    rax,QWORD PTR [rax+0x5a8]
  34d3c6:	48 89 85 18 ff ff ff 	mov    QWORD PTR [rbp-0xe8],rax
  34d3cd:	48 8d 05 64 bf f1 ff 	lea    rax,[rip+0xfffffffffff1bf64]        # 0x269338
  34d3d4:	4c 8b 73 28          	mov    r14,QWORD PTR [rbx+0x28]
  34d3d8:	4c 29 f0             	sub    rax,r14
  34d3db:	48 c1 c8 03          	ror    rax,0x3
  34d3df:	48 83 f8 03          	cmp    rax,0x3
  34d3e3:	0f 86 f2 fd ff ff    	jbe    0x34d1db
  34d3e9:	48 8d 3d a0 f6 74 01 	lea    rdi,[rip+0x174f6a0]        # 0x1a9ca90
  34d3f0:	4c 89 f6             	mov    rsi,r14
  34d3f3:	e8 c8 24 10 00       	call   0x44f8c0
  34d3f8:	e9 de fd ff ff       	jmp    0x34d1db
  34d3fd:	b8 16 00 00 00       	mov    eax,0x16
  34d402:	e9 02 01 00 00       	jmp    0x34d509
  34d407:	4d 8b 76 08          	mov    r14,QWORD PTR [r14+0x8]
  34d40b:	48 8d bd 10 ff ff ff 	lea    rdi,[rbp-0xf0]
  34d412:	be a8 00 00 00       	mov    esi,0xa8
  34d417:	e8 d4 bb f0 ff       	call   0x258ff0
  34d41c:	48 8d b5 a8 fe ff ff 	lea    rsi,[rbp-0x158]
  34d423:	4c 89 f7             	mov    rdi,r14
  34d426:	e8 95 f4 ff ff       	call   0x34c8c0
  34d42b:	85 c0                	test   eax,eax
  34d42d:	0f 85 a5 00 00 00    	jne    0x34d4d8
  34d433:	83 bd b4 fe ff ff 00 	cmp    DWORD PTR [rbp-0x14c],0x0
  34d43a:	4c 8b b5 e0 fe ff ff 	mov    r14,QWORD PTR [rbp-0x120]
  34d441:	0f 94 c0             	sete   al
  34d444:	48 83 bd a8 fe ff ff 	cmp    QWORD PTR [rbp-0x158],0x40
  34d44b:	40 
  34d44c:	0f 92 c1             	setb   cl
  34d44f:	4d 85 f6             	test   r14,r14
  34d452:	0f 94 c2             	sete   dl
  34d455:	08 c2                	or     dl,al
  34d457:	b8 08 00 00 00       	mov    eax,0x8
  34d45c:	08 ca                	or     dl,cl
  34d45e:	75 78                	jne    0x34d4d8
  34d460:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34d467:	00 00 
  34d469:	48 8d 35 cd aa 04 01 	lea    rsi,[rip+0x104aacd]        # 0x1397f3d
  34d470:	31 d2                	xor    edx,edx
  34d472:	e8 69 cf 8c 00       	call   0xc1a3e0
  34d477:	48 8d b5 08 ff ff ff 	lea    rsi,[rbp-0xf8]
  34d47e:	ba 08 00 00 00       	mov    edx,0x8
  34d483:	4c 89 f7             	mov    rdi,r14
  34d486:	e8 f5 bd f0 ff       	call   0x259280
  34d48b:	85 c0                	test   eax,eax
  34d48d:	75 49                	jne    0x34d4d8
  34d48f:	4c 8b b5 08 ff ff ff 	mov    r14,QWORD PTR [rbp-0xf8]
  34d496:	b8 16 00 00 00       	mov    eax,0x16
  34d49b:	49 81 fe a9 00 00 00 	cmp    r14,0xa9
  34d4a2:	73 34                	jae    0x34d4d8
  34d4a4:	4c 8b bd e0 fe ff ff 	mov    r15,QWORD PTR [rbp-0x120]
  34d4ab:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34d4b2:	00 00 
  34d4b4:	48 8d 35 82 aa 04 01 	lea    rsi,[rip+0x104aa82]        # 0x1397f3d
  34d4bb:	31 d2                	xor    edx,edx
  34d4bd:	e8 1e cf 8c 00       	call   0xc1a3e0
  34d4c2:	48 8d b5 10 ff ff ff 	lea    rsi,[rbp-0xf0]
  34d4c9:	4c 89 ff             	mov    rdi,r15
  34d4cc:	4c 89 f2             	mov    rdx,r14
  34d4cf:	e8 ac bd f0 ff       	call   0x259280
  34d4d4:	85 c0                	test   eax,eax
  34d4d6:	74 4f                	je     0x34d527
  34d4d8:	4c 8b 73 28          	mov    r14,QWORD PTR [rbx+0x28]
  34d4dc:	41 89 c7             	mov    r15d,eax
  34d4df:	48 8d 05 52 be f1 ff 	lea    rax,[rip+0xfffffffffff1be52]        # 0x269338
  34d4e6:	4c 29 f0             	sub    rax,r14
  34d4e9:	48 c1 c8 03          	ror    rax,0x3
  34d4ed:	48 83 f8 03          	cmp    rax,0x3
  34d4f1:	0f 87 be 00 00 00    	ja     0x34d5b5
  34d4f7:	48 8d 75 c0          	lea    rsi,[rbp-0x40]
  34d4fb:	ba 10 00 00 00       	mov    edx,0x10
  34d500:	48 89 df             	mov    rdi,rbx
  34d503:	41 ff d6             	call   r14
  34d506:	44 89 f8             	mov    eax,r15d
  34d509:	49 8b 0c 24          	mov    rcx,QWORD PTR [r12]
  34d50d:	48 3b 4d d8          	cmp    rcx,QWORD PTR [rbp-0x28]
  34d511:	0f 85 97 00 00 00    	jne    0x34d5ae
  34d517:	48 81 c4 40 01 00 00 	add    rsp,0x140
  34d51e:	5b                   	pop    rbx
  34d51f:	41 5c                	pop    r12
  34d521:	41 5e                	pop    r14
  34d523:	41 5f                	pop    r15
  34d525:	5d                   	pop    rbp
  34d526:	c3                   	ret
  34d527:	83 bd 18 ff ff ff 09 	cmp    DWORD PTR [rbp-0xe8],0x9
  34d52e:	72 36                	jb     0x34d566
  34d530:	83 bd 1c ff ff ff 01 	cmp    DWORD PTR [rbp-0xe4],0x1
  34d537:	b8 00 00 00 00       	mov    eax,0x0
  34d53c:	75 2a                	jne    0x34d568
  34d53e:	48 8b 7d 80          	mov    rdi,QWORD PTR [rbp-0x80]
  34d542:	48 8d b5 a8 fe ff ff 	lea    rsi,[rbp-0x158]
  34d549:	e8 c2 e3 ff ff       	call   0x34b910
  34d54e:	85 c0                	test   eax,eax
  34d550:	75 16                	jne    0x34d568
  34d552:	f6 85 a8 fe ff ff 08 	test   BYTE PTR [rbp-0x158],0x8
  34d559:	b8 00 00 00 00       	mov    eax,0x0
  34d55e:	0f 85 e9 fd ff ff    	jne    0x34d34d
  34d564:	eb 02                	jmp    0x34d568
  34d566:	31 c0                	xor    eax,eax
  34d568:	83 bd 18 ff ff ff 0c 	cmp    DWORD PTR [rbp-0xe8],0xc
  34d56f:	0f 82 63 ff ff ff    	jb     0x34d4d8
  34d575:	83 bd 1c ff ff ff 01 	cmp    DWORD PTR [rbp-0xe4],0x1
  34d57c:	0f 85 56 ff ff ff    	jne    0x34d4d8
  34d582:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  34d586:	48 8d b5 a8 fe ff ff 	lea    rsi,[rbp-0x158]
  34d58d:	e8 7e e3 ff ff       	call   0x34b910
  34d592:	85 c0                	test   eax,eax
  34d594:	0f 85 3e ff ff ff    	jne    0x34d4d8
  34d59a:	31 c0                	xor    eax,eax
  34d59c:	f6 85 a8 fe ff ff 08 	test   BYTE PTR [rbp-0x158],0x8
  34d5a3:	0f 85 a4 fd ff ff    	jne    0x34d34d
  34d5a9:	e9 2a ff ff ff       	jmp    0x34d4d8
  34d5ae:	e8 fd 00 3b 00       	call   0x6fd6b0
  34d5b3:	0f 0b                	ud2
  34d5b5:	48 8d 3d 94 f4 74 01 	lea    rdi,[rip+0x174f494]        # 0x1a9ca50
  34d5bc:	4c 89 f6             	mov    rsi,r14
  34d5bf:	e8 fc 22 10 00       	call   0x44f8c0
  34d5c4:	e9 2e ff ff ff       	jmp    0x34d4f7
  34d5c9:	48 8d 3d c0 f4 74 01 	lea    rdi,[rip+0x174f4c0]        # 0x1a9ca90
  34d5d0:	4c 89 f6             	mov    rsi,r14
  34d5d3:	e8 e8 22 10 00       	call   0x44f8c0
  34d5d8:	e9 fe fb ff ff       	jmp    0x34d1db
  34d5dd:	90                   	nop
  34d5de:	90                   	nop
  34d5df:	90                   	nop
  34d5e0:	55                   	push   rbp
  34d5e1:	48 89 e5             	mov    rbp,rsp
  34d5e4:	41 57                	push   r15
  34d5e6:	41 56                	push   r14
  34d5e8:	53                   	push   rbx
  34d5e9:	48 83 ec 18          	sub    rsp,0x18
  34d5ed:	4c 8d 35 1c ed 5c 03 	lea    r14,[rip+0x35ced1c]        # 0x391c310
  34d5f4:	49 8b 06             	mov    rax,QWORD PTR [r14]
  34d5f7:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  34d5fb:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  34d602:	00 00 
  34d604:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34d608:	48 83 b8 e8 03 00 00 	cmp    QWORD PTR [rax+0x3e8],0x0
  34d60f:	00 
  34d610:	74 3b                	je     0x34d64d
  34d612:	48 8b 88 a0 05 00 00 	mov    rcx,QWORD PTR [rax+0x5a0]
  34d619:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
  34d61d:	48 8b 80 a8 05 00 00 	mov    rax,QWORD PTR [rax+0x5a8]
  34d624:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  34d628:	48 8d 05 09 bd f1 ff 	lea    rax,[rip+0xfffffffffff1bd09]        # 0x269338
  34d62f:	48 8b 5f 28          	mov    rbx,QWORD PTR [rdi+0x28]
  34d633:	48 29 d8             	sub    rax,rbx
  34d636:	48 c1 c8 03          	ror    rax,0x3
  34d63a:	48 83 f8 03          	cmp    rax,0x3
  34d63e:	77 2d                	ja     0x34d66d
  34d640:	48 8d 75 d0          	lea    rsi,[rbp-0x30]
  34d644:	ba 10 00 00 00       	mov    edx,0x10
  34d649:	ff d3                	call   rbx
  34d64b:	eb 05                	jmp    0x34d652
  34d64d:	b8 16 00 00 00       	mov    eax,0x16
  34d652:	49 8b 0e             	mov    rcx,QWORD PTR [r14]
  34d655:	48 3b 4d e0          	cmp    rcx,QWORD PTR [rbp-0x20]
  34d659:	75 0b                	jne    0x34d666
  34d65b:	48 83 c4 18          	add    rsp,0x18
  34d65f:	5b                   	pop    rbx
  34d660:	41 5e                	pop    r14
  34d662:	41 5f                	pop    r15
  34d664:	5d                   	pop    rbp
  34d665:	c3                   	ret
  34d666:	e8 45 00 3b 00       	call   0x6fd6b0
  34d66b:	0f 0b                	ud2
  34d66d:	48 8d 05 1c f4 74 01 	lea    rax,[rip+0x174f41c]        # 0x1a9ca90
  34d674:	49 89 ff             	mov    r15,rdi
  34d677:	48 89 de             	mov    rsi,rbx
  34d67a:	48 89 c7             	mov    rdi,rax
  34d67d:	e8 3e 22 10 00       	call   0x44f8c0
  34d682:	4c 89 ff             	mov    rdi,r15
  34d685:	eb b9                	jmp    0x34d640
  34d687:	90                   	nop
  34d688:	90                   	nop
  34d689:	90                   	nop
  34d68a:	90                   	nop
  34d68b:	90                   	nop
  34d68c:	90                   	nop
  34d68d:	90                   	nop
  34d68e:	90                   	nop
  34d68f:	90                   	nop
  34d690:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  34d697:	00 00 
  34d699:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  34d69d:	80 b8 81 0c 00 00 00 	cmp    BYTE PTR [rax+0xc81],0x0
  34d6a4:	74 0e                	je     0x34d6b4
  34d6a6:	be 00 01 00 00       	mov    esi,0x100
  34d6ab:	48 03 b0 e8 03 00 00 	add    rsi,QWORD PTR [rax+0x3e8]
  34d6b2:	eb 07                	jmp    0x34d6bb
  34d6b4:	48 8d 35 1d 2c 17 01 	lea    rsi,[rip+0x1172c1d]        # 0x14c02d8
  34d6bb:	4c 8b 41 28          	mov    r8,QWORD PTR [rcx+0x28]
  34d6bf:	48 8d 05 72 bc f1 ff 	lea    rax,[rip+0xfffffffffff1bc72]        # 0x269338
  34d6c6:	4c 29 c0             	sub    rax,r8
  34d6c9:	48 c1 c8 03          	ror    rax,0x3
  34d6cd:	48 83 f8 03          	cmp    rax,0x3
  34d6d1:	77 0b                	ja     0x34d6de
  34d6d3:	ba 18 00 00 00       	mov    edx,0x18
  34d6d8:	48 89 cf             	mov    rdi,rcx
  34d6db:	41 ff e0             	jmp    r8
  34d6de:	55                   	push   rbp
  34d6df:	48 89 e5             	mov    rbp,rsp
  34d6e2:	41 57                	push   r15
  34d6e4:	41 56                	push   r14
  34d6e6:	53                   	push   rbx
  34d6e7:	50                   	push   rax
  34d6e8:	48 89 f3             	mov    rbx,rsi
  34d6eb:	48 8d 3d 7e f3 74 01 	lea    rdi,[rip+0x174f37e]        # 0x1a9ca70
  34d6f2:	4c 89 c6             	mov    rsi,r8
  34d6f5:	49 89 ce             	mov    r14,rcx
  34d6f8:	4d 89 c7             	mov    r15,r8
  34d6fb:	e8 c0 21 10 00       	call   0x44f8c0
  34d700:	4d 89 f8             	mov    r8,r15
  34d703:	48 89 de             	mov    rsi,rbx
  34d706:	4c 89 f1             	mov    rcx,r14
  34d709:	48 83 c4 08          	add    rsp,0x8
  34d70d:	5b                   	pop    rbx
  34d70e:	41 5e                	pop    r14
  34d710:	41 5f                	pop    r15
  34d712:	5d                   	pop    rbp
  34d713:	eb be                	jmp    0x34d6d3
  34d715:	90                   	nop
  34d716:	90                   	nop
  34d717:	90                   	nop
  34d718:	90                   	nop
  34d719:	90                   	nop
  34d71a:	90                   	nop
  34d71b:	90                   	nop
  34d71c:	90                   	nop
  34d71d:	90                   	nop
  34d71e:	90                   	nop
  34d71f:	90                   	nop
  34d720:	55                   	push   rbp
  34d721:	48 89 e5             	mov    rbp,rsp
  34d724:	41 57                	push   r15
  34d726:	41 56                	push   r14
  34d728:	53                   	push   rbx
  34d729:	50                   	push   rax
  34d72a:	48 89 f3             	mov    rbx,rsi
  34d72d:	49 89 fe             	mov    r14,rdi
  34d730:	be 00 04 00 00       	mov    esi,0x400
  34d735:	48 89 df             	mov    rdi,rbx
  34d738:	e8 73 77 0f 00       	call   0x444eb0
  34d73d:	be 00 04 00 00       	mov    esi,0x400
  34d742:	4c 89 f7             	mov    rdi,r14
  34d745:	49 89 c7             	mov    r15,rax
  34d748:	e8 63 77 0f 00       	call   0x444eb0
  34d74d:	49 8d 8c 07 fa fb ff 	lea    rcx,[r15+rax*1-0x406]
  34d754:	ff 
  34d755:	b8 ff ff ff ff       	mov    eax,0xffffffff
  34d75a:	48 81 f9 ff fb ff ff 	cmp    rcx,0xfffffffffffffbff
  34d761:	72 3e                	jb     0x34d7a1
  34d763:	49 83 c6 06          	add    r14,0x6
  34d767:	ba 00 04 00 00       	mov    edx,0x400
  34d76c:	48 89 df             	mov    rdi,rbx
  34d76f:	4c 89 f6             	mov    rsi,r14
  34d772:	e8 e9 8d 53 00       	call   0x886560
  34d777:	b9 06 00 00 00       	mov    ecx,0x6
  34d77c:	eb 12                	jmp    0x34d790
  34d77e:	66 90                	xchg   ax,ax
  34d780:	c6 04 0b 5c          	mov    BYTE PTR [rbx+rcx*1],0x5c
  34d784:	48 ff c1             	inc    rcx
  34d787:	48 81 f9 00 04 00 00 	cmp    rcx,0x400
  34d78e:	74 0f                	je     0x34d79f
  34d790:	0f b6 04 0b          	movzx  eax,BYTE PTR [rbx+rcx*1]
  34d794:	83 f8 2f             	cmp    eax,0x2f
  34d797:	74 e7                	je     0x34d780
  34d799:	85 c0                	test   eax,eax
  34d79b:	75 e7                	jne    0x34d784
  34d79d:	eb 02                	jmp    0x34d7a1
  34d79f:	31 c0                	xor    eax,eax
  34d7a1:	48 83 c4 08          	add    rsp,0x8
  34d7a5:	5b                   	pop    rbx
  34d7a6:	41 5e                	pop    r14
  34d7a8:	41 5f                	pop    r15
  34d7aa:	5d                   	pop    rbp
  34d7ab:	c3                   	ret
  34d7ac:	90                   	nop
  34d7ad:	90                   	nop
  34d7ae:	90                   	nop
  34d7af:	90                   	nop
  34d7b0:	55                   	push   rbp
  34d7b1:	48 89 e5             	mov    rbp,rsp
  34d7b4:	41 57                	push   r15
  34d7b6:	41 56                	push   r14
  34d7b8:	41 55                	push   r13
  34d7ba:	41 54                	push   r12
  34d7bc:	53                   	push   rbx
  34d7bd:	48 83 ec 28          	sub    rsp,0x28
  34d7c1:	4c 8d 25 48 eb 5c 03 	lea    r12,[rip+0x35ceb48]        # 0x391c310
  34d7c8:	31 db                	xor    ebx,ebx
  34d7ca:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  34d7ce:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34d7d2:	f6 86 1c 01 00 00 01 	test   BYTE PTR [rsi+0x11c],0x1
  34d7d9:	75 6e                	jne    0x34d849
  34d7db:	44 8b af d8 05 00 00 	mov    r13d,DWORD PTR [rdi+0x5d8]
  34d7e2:	4c 8d 7d b0          	lea    r15,[rbp-0x50]
  34d7e6:	49 89 f6             	mov    r14,rsi
  34d7e9:	be 20 00 00 00       	mov    esi,0x20
  34d7ee:	4c 89 ff             	mov    rdi,r15
  34d7f1:	e8 fa b7 f0 ff       	call   0x258ff0
  34d7f6:	4d 8b b6 68 01 00 00 	mov    r14,QWORD PTR [r14+0x168]
  34d7fd:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  34d804:	00 00 
  34d806:	48 8d 35 30 a7 04 01 	lea    rsi,[rip+0x104a730]        # 0x1397f3d
  34d80d:	31 d2                	xor    edx,edx
  34d80f:	31 db                	xor    ebx,ebx
  34d811:	e8 ca cb 8c 00       	call   0xc1a3e0
  34d816:	ba 18 00 00 00       	mov    edx,0x18
  34d81b:	4c 89 f7             	mov    rdi,r14
  34d81e:	4c 89 fe             	mov    rsi,r15
  34d821:	e8 5a ba f0 ff       	call   0x259280
  34d826:	85 c0                	test   eax,eax
  34d828:	75 1f                	jne    0x34d849
  34d82a:	81 7d b8 bf f4 13 3c 	cmp    DWORD PTR [rbp-0x48],0x3c13f4bf
  34d831:	75 16                	jne    0x34d849
  34d833:	83 7d bc 02          	cmp    DWORD PTR [rbp-0x44],0x2
  34d837:	72 10                	jb     0x34d849
  34d839:	44 33 6d c4          	xor    r13d,DWORD PTR [rbp-0x3c]
  34d83d:	31 db                	xor    ebx,ebx
  34d83f:	41 81 fd 00 00 01 00 	cmp    r13d,0x10000
  34d846:	0f 92 c3             	setb   bl
  34d849:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  34d84d:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  34d851:	75 11                	jne    0x34d864
  34d853:	89 d8                	mov    eax,ebx
  34d855:	48 83 c4 28          	add    rsp,0x28
  34d859:	5b                   	pop    rbx
  34d85a:	41 5c                	pop    r12
  34d85c:	41 5d                	pop    r13
  34d85e:	41 5e                	pop    r14
  34d860:	41 5f                	pop    r15
  34d862:	5d                   	pop    rbp
  34d863:	c3                   	ret
  34d864:	e8 47 fe 3a 00       	call   0x6fd6b0
  34d869:	0f 0b                	ud2
  34d86b:	90                   	nop
  34d86c:	90                   	nop
  34d86d:	90                   	nop
  34d86e:	90                   	nop
  34d86f:	90                   	nop
  34d870:	55                   	push   rbp
  34d871:	48 89 e5             	mov    rbp,rsp
  34d874:	41 57                	push   r15
  34d876:	41 56                	push   r14
  34d878:	41 55                	push   r13
  34d87a:	41 54                	push   r12
  34d87c:	53                   	push   rbx
  34d87d:	48 83 ec 48          	sub    rsp,0x48
  34d881:	4c 8d 25 88 ea 5c 03 	lea    r12,[rip+0x35cea88]        # 0x391c310
  34d888:	49 89 fe             	mov    r14,rdi
  34d88b:	bf 00 08 00 00       	mov    edi,0x800
  34d890:	31 f6                	xor    esi,esi
  34d892:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  34d896:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34d89a:	e8 c1 d3 7d 00       	call   0xb2ac60
  34d89f:	48 85 c0             	test   rax,rax
  34d8a2:	0f 84 62 03 00 00    	je     0x34dc0a
  34d8a8:	be 00 08 00 00       	mov    esi,0x800
  34d8ad:	48 89 c7             	mov    rdi,rax
  34d8b0:	49 89 c5             	mov    r13,rax
  34d8b3:	e8 38 b7 f0 ff       	call   0x258ff0
  34d8b8:	48 8d 35 4c 2b f3 00 	lea    rsi,[rip+0xf32b4c]        # 0x128040b
  34d8bf:	ba 1b 00 00 00       	mov    edx,0x1b
  34d8c4:	4c 89 ef             	mov    rdi,r13
  34d8c7:	41 c7 45 44 00 00 00 	mov    DWORD PTR [r13+0x44],0x0
  34d8ce:	00 
  34d8cf:	e8 6c 6b 63 00       	call   0x984440
  34d8d4:	4d 8d 7e 18          	lea    r15,[r14+0x18]
  34d8d8:	be 25 00 00 00       	mov    esi,0x25
  34d8dd:	4c 89 ff             	mov    rdi,r15
  34d8e0:	e8 cb 75 0f 00       	call   0x444eb0
  34d8e5:	48 83 f8 24          	cmp    rax,0x24
  34d8e9:	75 35                	jne    0x34d920
  34d8eb:	49 8d 7d 48          	lea    rdi,[r13+0x48]
  34d8ef:	48 8d 35 7c 8b fd 00 	lea    rsi,[rip+0xfd8b7c]        # 0x1326472
  34d8f6:	b9 25 00 00 00       	mov    ecx,0x25
  34d8fb:	4c 89 fa             	mov    rdx,r15
  34d8fe:	e8 3d 03 00 00       	call   0x34dc40
  34d903:	41 ff 45 44          	inc    DWORD PTR [r13+0x44]
  34d907:	49 8b 5e 08          	mov    rbx,QWORD PTR [r14+0x8]
  34d90b:	48 89 d9             	mov    rcx,rbx
  34d90e:	48 c1 e9 20          	shr    rcx,0x20
  34d912:	75 22                	jne    0x34d936
  34d914:	48 8d 3d 74 a9 f7 00 	lea    rdi,[rip+0xf7a974]        # 0x12c828f
  34d91b:	48 89 de             	mov    rsi,rbx
  34d91e:	eb 0a                	jmp    0x34d92a
  34d920:	48 8d 3d 76 b6 04 01 	lea    rdi,[rip+0x104b676]        # 0x1398f9d
  34d927:	4c 89 fe             	mov    rsi,r15
  34d92a:	31 c0                	xor    eax,eax
  34d92c:	e8 df fa f0 ff       	call   0x25d410
  34d931:	e9 0e 01 00 00       	jmp    0x34da44
  34d936:	48 8d 7d b0          	lea    rdi,[rbp-0x50]
  34d93a:	be 19 00 00 00       	mov    esi,0x19
  34d93f:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
  34d943:	e8 a8 b6 f0 ff       	call   0x258ff0
  34d948:	b8 30 08 00 00       	mov    eax,0x830
  34d94d:	41 89 db             	mov    r11d,ebx
  34d950:	48 89 d9             	mov    rcx,rbx
  34d953:	48 8d 15 3b 0f 06 01 	lea    rdx,[rip+0x1060f3b]        # 0x13ae895
  34d95a:	be 19 00 00 00       	mov    esi,0x19
  34d95f:	48 8d 7d b0          	lea    rdi,[rbp-0x50]
  34d963:	c4 62 f8 f7 c3       	bextr  r8,rbx,rax
  34d968:	b8 28 08 00 00       	mov    eax,0x828
  34d96d:	48 c1 e9 38          	shr    rcx,0x38
  34d971:	41 c1 eb 18          	shr    r11d,0x18
  34d975:	c4 62 f8 f7 cb       	bextr  r9,rbx,rax
  34d97a:	b8 20 08 00 00       	mov    eax,0x820
  34d97f:	c4 e2 f8 f7 c3       	bextr  rax,rbx,rax
  34d984:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  34d988:	b8 10 08 00 00       	mov    eax,0x810
  34d98d:	c4 e2 78 f7 c3       	bextr  eax,ebx,eax
  34d992:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
  34d996:	0f b6 c7             	movzx  eax,bh
  34d999:	49 89 c4             	mov    r12,rax
  34d99c:	b8 04 04 00 00       	mov    eax,0x404
  34d9a1:	c4 62 78 f7 d3       	bextr  r10d,ebx,eax
  34d9a6:	83 e3 0f             	and    ebx,0xf
  34d9a9:	31 c0                	xor    eax,eax
  34d9ab:	53                   	push   rbx
  34d9ac:	41 52                	push   r10
  34d9ae:	41 54                	push   r12
  34d9b0:	ff 75 a8             	push   QWORD PTR [rbp-0x58]
  34d9b3:	41 53                	push   r11
  34d9b5:	ff 75 a0             	push   QWORD PTR [rbp-0x60]
  34d9b8:	e8 83 14 16 00       	call   0x4aee40
  34d9bd:	48 83 c4 30          	add    rsp,0x30
  34d9c1:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  34d9c5:	48 8d 35 66 fd f6 00 	lea    rsi,[rip+0xf6fd66]        # 0x12bd732
  34d9cc:	b9 19 00 00 00       	mov    ecx,0x19
  34d9d1:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
  34d9d5:	e8 66 02 00 00       	call   0x34dc40
  34d9da:	41 ff 45 44          	inc    DWORD PTR [r13+0x44]
  34d9de:	4d 8d 66 3d          	lea    r12,[r14+0x3d]
  34d9e2:	be 25 00 00 00       	mov    esi,0x25
  34d9e7:	48 89 c3             	mov    rbx,rax
  34d9ea:	4c 89 e7             	mov    rdi,r12
  34d9ed:	e8 be 74 0f 00       	call   0x444eb0
  34d9f2:	48 83 f8 24          	cmp    rax,0x24
  34d9f6:	75 34                	jne    0x34da2c
  34d9f8:	48 8d 35 c8 b5 04 01 	lea    rsi,[rip+0x104b5c8]        # 0x1398fc7
  34d9ff:	b9 25 00 00 00       	mov    ecx,0x25
  34da04:	48 89 df             	mov    rdi,rbx
  34da07:	4c 89 e2             	mov    rdx,r12
  34da0a:	e8 31 02 00 00       	call   0x34dc40
  34da0f:	41 ff 45 44          	inc    DWORD PTR [r13+0x44]
  34da13:	49 8b 5e 10          	mov    rbx,QWORD PTR [r14+0x10]
  34da17:	48 89 d9             	mov    rcx,rbx
  34da1a:	48 c1 e9 20          	shr    rcx,0x20
  34da1e:	75 73                	jne    0x34da93
  34da20:	48 8d 3d a7 bf 02 01 	lea    rdi,[rip+0x102bfa7]        # 0x13799ce
  34da27:	48 89 de             	mov    rsi,rbx
  34da2a:	eb 0a                	jmp    0x34da36
  34da2c:	48 8d 3d 35 fa f8 00 	lea    rdi,[rip+0xf8fa35]        # 0x12dd468
  34da33:	4c 89 e6             	mov    rsi,r12
  34da36:	31 c0                	xor    eax,eax
  34da38:	e8 d3 f9 f0 ff       	call   0x25d410
  34da3d:	4c 8d 25 cc e8 5c 03 	lea    r12,[rip+0x35ce8cc]        # 0x391c310
  34da44:	4d 8b 0e             	mov    r9,QWORD PTR [r14]
  34da47:	49 8b 56 08          	mov    rdx,QWORD PTR [r14+0x8]
  34da4b:	4d 8b 46 10          	mov    r8,QWORD PTR [r14+0x10]
  34da4f:	49 83 c6 3d          	add    r14,0x3d
  34da53:	48 8d 3d b0 0d 04 01 	lea    rdi,[rip+0x1040db0]        # 0x138e80a
  34da5a:	4c 89 fe             	mov    rsi,r15
  34da5d:	31 c0                	xor    eax,eax
  34da5f:	4c 89 f1             	mov    rcx,r14
  34da62:	e8 a9 f9 f0 ff       	call   0x25d410
  34da67:	be 00 08 00 00       	mov    esi,0x800
  34da6c:	4c 89 ef             	mov    rdi,r13
  34da6f:	31 d2                	xor    edx,edx
  34da71:	e8 da 67 7d 00       	call   0xb24250
  34da76:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  34da7a:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  34da7e:	0f 85 ac 01 00 00    	jne    0x34dc30
  34da84:	48 83 c4 48          	add    rsp,0x48
  34da88:	5b                   	pop    rbx
  34da89:	41 5c                	pop    r12
  34da8b:	41 5d                	pop    r13
  34da8d:	41 5e                	pop    r14
  34da8f:	41 5f                	pop    r15
  34da91:	5d                   	pop    rbp
  34da92:	c3                   	ret
  34da93:	48 8d 7d b0          	lea    rdi,[rbp-0x50]
  34da97:	be 19 00 00 00       	mov    esi,0x19
  34da9c:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
  34daa0:	e8 4b b5 f0 ff       	call   0x258ff0
  34daa5:	b8 30 08 00 00       	mov    eax,0x830
  34daaa:	41 89 db             	mov    r11d,ebx
  34daad:	48 89 d9             	mov    rcx,rbx
  34dab0:	48 8d 15 de 0d 06 01 	lea    rdx,[rip+0x1060dde]        # 0x13ae895
  34dab7:	be 19 00 00 00       	mov    esi,0x19
  34dabc:	48 8d 7d b0          	lea    rdi,[rbp-0x50]
  34dac0:	c4 62 f8 f7 c3       	bextr  r8,rbx,rax
  34dac5:	b8 28 08 00 00       	mov    eax,0x828
  34daca:	48 c1 e9 38          	shr    rcx,0x38
  34dace:	41 c1 eb 18          	shr    r11d,0x18
  34dad2:	c4 62 f8 f7 cb       	bextr  r9,rbx,rax
  34dad7:	b8 20 08 00 00       	mov    eax,0x820
  34dadc:	c4 e2 f8 f7 c3       	bextr  rax,rbx,rax
  34dae1:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  34dae5:	b8 10 08 00 00       	mov    eax,0x810
  34daea:	c4 e2 78 f7 c3       	bextr  eax,ebx,eax
  34daef:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
  34daf3:	0f b6 c7             	movzx  eax,bh
  34daf6:	49 89 c4             	mov    r12,rax
  34daf9:	b8 04 04 00 00       	mov    eax,0x404
  34dafe:	c4 62 78 f7 d3       	bextr  r10d,ebx,eax
  34db03:	83 e3 0f             	and    ebx,0xf
  34db06:	31 c0                	xor    eax,eax
  34db08:	53                   	push   rbx
  34db09:	41 52                	push   r10
  34db0b:	41 54                	push   r12
  34db0d:	ff 75 a8             	push   QWORD PTR [rbp-0x58]
  34db10:	41 53                	push   r11
  34db12:	ff 75 a0             	push   QWORD PTR [rbp-0x60]
  34db15:	e8 26 13 16 00       	call   0x4aee40
  34db1a:	48 83 c4 30          	add    rsp,0x30
  34db1e:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  34db22:	48 8d 35 94 a7 f7 00 	lea    rsi,[rip+0xf7a794]        # 0x12c82bd
  34db29:	b9 19 00 00 00       	mov    ecx,0x19
  34db2e:	48 8d 55 b0          	lea    rdx,[rbp-0x50]
  34db32:	e8 09 01 00 00       	call   0x34dc40
  34db37:	41 ff 45 44          	inc    DWORD PTR [r13+0x44]
  34db3b:	49 89 c4             	mov    r12,rax
  34db3e:	49 8b 1e             	mov    rbx,QWORD PTR [r14]
  34db41:	48 85 db             	test   rbx,rbx
  34db44:	74 3b                	je     0x34db81
  34db46:	be 00 04 00 00       	mov    esi,0x400
  34db4b:	48 89 df             	mov    rdi,rbx
  34db4e:	e8 5d 73 0f 00       	call   0x444eb0
  34db53:	48 83 f8 06          	cmp    rax,0x6
  34db57:	72 28                	jb     0x34db81
  34db59:	80 3b 2f             	cmp    BYTE PTR [rbx],0x2f
  34db5c:	75 23                	jne    0x34db81
  34db5e:	80 7b 01 68          	cmp    BYTE PTR [rbx+0x1],0x68
  34db62:	75 1d                	jne    0x34db81
  34db64:	80 7b 02 6f          	cmp    BYTE PTR [rbx+0x2],0x6f
  34db68:	75 17                	jne    0x34db81
  34db6a:	80 7b 03 73          	cmp    BYTE PTR [rbx+0x3],0x73
  34db6e:	75 11                	jne    0x34db81
  34db70:	80 7b 04 74          	cmp    BYTE PTR [rbx+0x4],0x74
  34db74:	75 0b                	jne    0x34db81
  34db76:	80 7b 05 2f          	cmp    BYTE PTR [rbx+0x5],0x2f
  34db7a:	be 5c 00 00 00       	mov    esi,0x5c
  34db7f:	74 05                	je     0x34db86
  34db81:	be 2f 00 00 00       	mov    esi,0x2f
  34db86:	49 8b 1e             	mov    rbx,QWORD PTR [r14]
  34db89:	48 89 df             	mov    rdi,rbx
  34db8c:	e8 6f 46 f2 ff       	call   0x272200
  34db91:	48 8d 50 01          	lea    rdx,[rax+0x1]
  34db95:	48 85 c0             	test   rax,rax
  34db98:	48 8d 35 f8 32 fc 00 	lea    rsi,[rip+0xfc32f8]        # 0x1310e97
  34db9f:	b9 01 04 00 00       	mov    ecx,0x401
  34dba4:	4c 89 e7             	mov    rdi,r12
  34dba7:	48 0f 44 d3          	cmove  rdx,rbx
  34dbab:	e8 90 00 00 00       	call   0x34dc40
  34dbb0:	41 ff 45 44          	inc    DWORD PTR [r13+0x44]
  34dbb4:	4c 29 e8             	sub    rax,r13
  34dbb7:	48 3d 81 00 00 00    	cmp    rax,0x81
  34dbbd:	77 0f                	ja     0x34dbce
  34dbbf:	48 8d 3d 36 be 02 01 	lea    rdi,[rip+0x102be36]        # 0x13799fc
  34dbc6:	48 89 c6             	mov    rsi,rax
  34dbc9:	e9 68 fe ff ff       	jmp    0x34da36
  34dbce:	bf 04 00 00 00       	mov    edi,0x4
  34dbd3:	4c 89 ee             	mov    rsi,r13
  34dbd6:	48 89 c2             	mov    rdx,rax
  34dbd9:	b9 04 00 00 00       	mov    ecx,0x4
  34dbde:	e8 ad 0b 23 00       	call   0x57e790
  34dbe3:	4c 8d 25 26 e7 5c 03 	lea    r12,[rip+0x35ce726]        # 0x391c310
  34dbea:	85 c0                	test   eax,eax
  34dbec:	0f 84 75 fe ff ff    	je     0x34da67
  34dbf2:	49 8b 36             	mov    rsi,QWORD PTR [r14]
  34dbf5:	89 c2                	mov    edx,eax
  34dbf7:	48 8d 3d 8e b3 f5 00 	lea    rdi,[rip+0xf5b38e]        # 0x12a8f8c
  34dbfe:	31 c0                	xor    eax,eax
  34dc00:	e8 0b f8 f0 ff       	call   0x25d410
  34dc05:	e9 3a fe ff ff       	jmp    0x34da44
  34dc0a:	e8 41 3d 4a 00       	call   0x7f1950
  34dc0f:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0x34dc0a
  34dc16:	e8 f5 3b 4a 00       	call   0x7f1810
  34dc1b:	48 8d 35 e4 63 03 01 	lea    rsi,[rip+0x10363e4]        # 0x1384006
  34dc22:	bf 0c 00 00 00       	mov    edi,0xc
  34dc27:	31 c0                	xor    eax,eax
  34dc29:	e8 e2 cd 94 00       	call   0xc9aa10
  34dc2e:	0f 0b                	ud2
  34dc30:	e8 7b fa 3a 00       	call   0x6fd6b0
  34dc35:	0f 0b                	ud2
  34dc37:	90                   	nop
  34dc38:	90                   	nop
  34dc39:	90                   	nop
  34dc3a:	90                   	nop
  34dc3b:	90                   	nop
  34dc3c:	90                   	nop
  34dc3d:	90                   	nop
  34dc3e:	90                   	nop
  34dc3f:	90                   	nop
  34dc40:	55                   	push   rbp
  34dc41:	48 89 e5             	mov    rbp,rsp
  34dc44:	41 57                	push   r15
  34dc46:	41 56                	push   r14
  34dc48:	53                   	push   rbx
  34dc49:	50                   	push   rax
  34dc4a:	48 85 ff             	test   rdi,rdi
  34dc4d:	74 43                	je     0x34dc92
  34dc4f:	49 89 ce             	mov    r14,rcx
  34dc52:	49 89 d7             	mov    r15,rdx
  34dc55:	48 89 fb             	mov    rbx,rdi
  34dc58:	ba 41 00 00 00       	mov    edx,0x41
  34dc5d:	44 89 37             	mov    DWORD PTR [rdi],r14d
  34dc60:	c6 47 04 02          	mov    BYTE PTR [rdi+0x4],0x2
  34dc64:	48 83 c7 05          	add    rdi,0x5
  34dc68:	e8 03 9f 60 00       	call   0x957b70
  34dc6d:	48 8d 7b 46          	lea    rdi,[rbx+0x46]
  34dc71:	4c 89 fe             	mov    rsi,r15
  34dc74:	4c 89 f2             	mov    rdx,r14
  34dc77:	e8 f4 9e 60 00       	call   0x957b70
  34dc7c:	8b 03                	mov    eax,DWORD PTR [rbx]
  34dc7e:	83 c0 49             	add    eax,0x49
  34dc81:	83 e0 fc             	and    eax,0xfffffffc
  34dc84:	48 01 d8             	add    rax,rbx
  34dc87:	48 83 c4 08          	add    rsp,0x8
  34dc8b:	5b                   	pop    rbx
  34dc8c:	41 5e                	pop    r14
  34dc8e:	41 5f                	pop    r15
  34dc90:	5d                   	pop    rbp
  34dc91:	c3                   	ret
  34dc92:	48 89 f3             	mov    rbx,rsi
  34dc95:	e8 b6 3c 4a 00       	call   0x7f1950
  34dc9a:	48 8d 3d f1 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff1]        # 0x34dc92
  34dca1:	48 89 de             	mov    rsi,rbx
  34dca4:	e8 f7 3b 4a 00       	call   0x7f18a0
  34dca9:	48 8d 35 76 27 f3 00 	lea    rsi,[rip+0xf32776]        # 0x1280426
  34dcb0:	bf 04 00 00 00       	mov    edi,0x4
  34dcb5:	48 89 da             	mov    rdx,rbx
  34dcb8:	31 c0                	xor    eax,eax
  34dcba:	e8 51 cd 94 00       	call   0xc9aa10
  34dcbf:	0f 0b                	ud2
  34dcc1:	90                   	nop
  34dcc2:	90                   	nop
  34dcc3:	90                   	nop
  34dcc4:	90                   	nop
  34dcc5:	90                   	nop
  34dcc6:	90                   	nop
  34dcc7:	90                   	nop
  34dcc8:	90                   	nop
  34dcc9:	90                   	nop
  34dcca:	90                   	nop
  34dccb:	90                   	nop
  34dccc:	90                   	nop
  34dccd:	90                   	nop
  34dcce:	90                   	nop
  34dccf:	90                   	nop
  34dcd0:	55                   	push   rbp
  34dcd1:	48 89 e5             	mov    rbp,rsp
  34dcd4:	41 57                	push   r15
  34dcd6:	41 56                	push   r14
  34dcd8:	41 55                	push   r13
  34dcda:	41 54                	push   r12
  34dcdc:	53                   	push   rbx
  34dcdd:	48 83 ec 48          	sub    rsp,0x48
  34dce1:	48 8d 05 28 e6 5c 03 	lea    rax,[rip+0x35ce628]        # 0x391c310
  34dce8:	4c 89 4d a0          	mov    QWORD PTR [rbp-0x60],r9
  34dcec:	4c 89 45 98          	mov    QWORD PTR [rbp-0x68],r8
  34dcf0:	41 89 f5             	mov    r13d,esi
  34dcf3:	48 89 fb             	mov    rbx,rdi
  34dcf6:	48 8d 7d b0          	lea    rdi,[rbp-0x50]
  34dcfa:	be 20 00 00 00       	mov    esi,0x20
  34dcff:	49 89 cf             	mov    r15,rcx
  34dd02:	41 89 d4             	mov    r12d,edx
  34dd05:	48 8b 00             	mov    rax,QWORD PTR [rax]
  34dd08:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34dd0c:	e8 df b2 f0 ff       	call   0x258ff0
  34dd11:	4c 8d 75 a8          	lea    r14,[rbp-0x58]
  34dd15:	be 08 00 00 00       	mov    esi,0x8
  34dd1a:	4c 89 f7             	mov    rdi,r14
  34dd1d:	e8 ce b2 f0 ff       	call   0x258ff0
  34dd22:	48 83 ec 08          	sub    rsp,0x8
  34dd26:	48 89 df             	mov    rdi,rbx
  34dd29:	44 89 ee             	mov    esi,r13d
  34dd2c:	44 89 e2             	mov    edx,r12d
  34dd2f:	48 8d 4d b0          	lea    rcx,[rbp-0x50]
  34dd33:	4d 89 f0             	mov    r8,r14
  34dd36:	4d 89 f9             	mov    r9,r15
  34dd39:	ff 75 18             	push   QWORD PTR [rbp+0x18]
  34dd3c:	ff 75 10             	push   QWORD PTR [rbp+0x10]
  34dd3f:	ff 75 a0             	push   QWORD PTR [rbp-0x60]
  34dd42:	ff 75 98             	push   QWORD PTR [rbp-0x68]
  34dd45:	68 00 40 00 00       	push   0x4000
  34dd4a:	e8 01 a8 fe ff       	call   0x338550
  34dd4f:	48 83 c4 30          	add    rsp,0x30
  34dd53:	48 8d 0d b6 e5 5c 03 	lea    rcx,[rip+0x35ce5b6]        # 0x391c310
  34dd5a:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  34dd5d:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  34dd61:	75 0f                	jne    0x34dd72
  34dd63:	48 83 c4 48          	add    rsp,0x48
  34dd67:	5b                   	pop    rbx
  34dd68:	41 5c                	pop    r12
  34dd6a:	41 5d                	pop    r13
  34dd6c:	41 5e                	pop    r14
  34dd6e:	41 5f                	pop    r15
  34dd70:	5d                   	pop    rbp
  34dd71:	c3                   	ret
  34dd72:	e8 39 f9 3a 00       	call   0x6fd6b0
  34dd77:	0f 0b                	ud2
  34dd79:	90                   	nop
  34dd7a:	90                   	nop
  34dd7b:	90                   	nop
  34dd7c:	90                   	nop
  34dd7d:	90                   	nop
  34dd7e:	90                   	nop
  34dd7f:	90                   	nop
  34dd80:	55                   	push   rbp
  34dd81:	48 89 e5             	mov    rbp,rsp
  34dd84:	b8 dd ff ff ff       	mov    eax,0xffffffdd
  34dd89:	48 83 fe 40          	cmp    rsi,0x40
  34dd8d:	72 19                	jb     0x34dda8
  34dd8f:	0f b7 47 38          	movzx  eax,WORD PTR [rdi+0x38]
  34dd93:	31 c9                	xor    ecx,ecx
  34dd95:	48 6b c0 38          	imul   rax,rax,0x38
  34dd99:	48 83 c0 40          	add    rax,0x40
  34dd9d:	48 39 c6             	cmp    rsi,rax
  34dda0:	b8 dd ff ff ff       	mov    eax,0xffffffdd
  34dda5:	0f 43 c1             	cmovae eax,ecx
  34dda8:	5d                   	pop    rbp
  34dda9:	c3                   	ret
  34ddaa:	90                   	nop
  34ddab:	90                   	nop
  34ddac:	90                   	nop
  34ddad:	90                   	nop
  34ddae:	90                   	nop
  34ddaf:	90                   	nop
  34ddb0:	55                   	push   rbp
  34ddb1:	48 89 e5             	mov    rbp,rsp
  34ddb4:	53                   	push   rbx
  34ddb5:	50                   	push   rax
  34ddb6:	83 3f 01             	cmp    DWORD PTR [rdi],0x1
  34ddb9:	bb ea ff ff ff       	mov    ebx,0xffffffea
  34ddbe:	0f 85 8a 00 00 00    	jne    0x34de4e
  34ddc4:	4c 8b 4f 38          	mov    r9,QWORD PTR [rdi+0x38]
  34ddc8:	4d 85 c9             	test   r9,r9
  34ddcb:	74 4b                	je     0x34de18
  34ddcd:	41 0f b7 41 38       	movzx  eax,WORD PTR [r9+0x38]
  34ddd2:	bb de ff ff ff       	mov    ebx,0xffffffde
  34ddd7:	39 c6                	cmp    esi,eax
  34ddd9:	73 42                	jae    0x34de1d
  34dddb:	89 f0                	mov    eax,esi
  34dddd:	bb da ff ff ff       	mov    ebx,0xffffffda
  34dde2:	48 6b c0 38          	imul   rax,rax,0x38
  34dde6:	4d 8b 4c 01 48       	mov    r9,QWORD PTR [r9+rax*1+0x48]
  34ddeb:	4c 89 0a             	mov    QWORD PTR [rdx],r9
  34ddee:	83 3f 00             	cmp    DWORD PTR [rdi],0x0
  34ddf1:	74 3f                	je     0x34de32
  34ddf3:	48 8b 57 38          	mov    rdx,QWORD PTR [rdi+0x38]
  34ddf7:	48 85 d2             	test   rdx,rdx
  34ddfa:	74 36                	je     0x34de32
  34ddfc:	0f b7 7a 38          	movzx  edi,WORD PTR [rdx+0x38]
  34de00:	bb ea ff ff ff       	mov    ebx,0xffffffea
  34de05:	39 fe                	cmp    esi,edi
  34de07:	73 29                	jae    0x34de32
  34de09:	48 8b 44 02 60       	mov    rax,QWORD PTR [rdx+rax*1+0x60]
  34de0e:	31 db                	xor    ebx,ebx
  34de10:	48 89 01             	mov    QWORD PTR [rcx],rax
  34de13:	49 89 00             	mov    QWORD PTR [r8],rax
  34de16:	eb 36                	jmp    0x34de4e
  34de18:	bb da ff ff ff       	mov    ebx,0xffffffda
  34de1d:	48 8d 3d 20 26 f3 00 	lea    rdi,[rip+0xf32620]        # 0x1280444
  34de24:	48 8d 35 6f d0 00 01 	lea    rsi,[rip+0x100d06f]        # 0x135ae9a
  34de2b:	ba d4 00 00 00       	mov    edx,0xd4
  34de30:	eb 13                	jmp    0x34de45
  34de32:	48 8d 3d c2 70 ff 00 	lea    rdi,[rip+0xff70c2]        # 0x1344efb
  34de39:	48 8d 35 5a d0 00 01 	lea    rsi,[rip+0x100d05a]        # 0x135ae9a
  34de40:	ba e0 00 00 00       	mov    edx,0xe0
  34de45:	89 d9                	mov    ecx,ebx
  34de47:	31 c0                	xor    eax,eax
  34de49:	e8 c2 f5 f0 ff       	call   0x25d410
  34de4e:	89 d8                	mov    eax,ebx
  34de50:	48 83 c4 08          	add    rsp,0x8
  34de54:	5b                   	pop    rbx
  34de55:	5d                   	pop    rbp
  34de56:	c3                   	ret
  34de57:	90                   	nop
  34de58:	90                   	nop
  34de59:	90                   	nop
  34de5a:	90                   	nop
  34de5b:	90                   	nop
  34de5c:	90                   	nop
  34de5d:	90                   	nop
  34de5e:	90                   	nop
  34de5f:	90                   	nop
  34de60:	55                   	push   rbp
  34de61:	48 89 e5             	mov    rbp,rsp
  34de64:	48 8d 35 95 db b1 00 	lea    rsi,[rip+0xb1db95]        # 0xe6ba00
  34de6b:	ba ec ff ff ff       	mov    edx,0xffffffec
  34de70:	5d                   	pop    rbp
  34de71:	e9 2a c8 4c 00       	jmp    0x81a6a0
  34de76:	90                   	nop
  34de77:	90                   	nop
  34de78:	90                   	nop
  34de79:	90                   	nop
  34de7a:	90                   	nop
  34de7b:	90                   	nop
  34de7c:	90                   	nop
  34de7d:	90                   	nop
  34de7e:	90                   	nop
  34de7f:	90                   	nop
  34de80:	55                   	push   rbp
  34de81:	48 89 e5             	mov    rbp,rsp
  34de84:	48 8d 15 95 db b1 00 	lea    rdx,[rip+0xb1db95]        # 0xe6ba20
  34de8b:	be 00 00 10 00       	mov    esi,0x100000
  34de90:	b9 01 00 00 00       	mov    ecx,0x1
  34de95:	e8 96 c8 4c 00       	call   0x81a730
  34de9a:	31 c0                	xor    eax,eax
  34de9c:	5d                   	pop    rbp
  34de9d:	c3                   	ret
  34de9e:	90                   	nop
  34de9f:	90                   	nop
  34dea0:	55                   	push   rbp
  34dea1:	48 89 e5             	mov    rbp,rsp
  34dea4:	41 57                	push   r15
  34dea6:	41 56                	push   r14
  34dea8:	41 54                	push   r12
  34deaa:	53                   	push   rbx
  34deab:	4c 8b 7e 08          	mov    r15,QWORD PTR [rsi+0x8]
  34deaf:	41 89 d6             	mov    r14d,edx
  34deb2:	48 89 fb             	mov    rbx,rdi
  34deb5:	83 fa 01             	cmp    edx,0x1
  34deb8:	74 5f                	je     0x34df19
  34deba:	41 83 fe 02          	cmp    r14d,0x2
  34debe:	0f 85 90 00 00 00    	jne    0x34df54
  34dec4:	48 89 df             	mov    rdi,rbx
  34dec7:	49 89 f4             	mov    r12,rsi
  34deca:	e8 c1 b4 4c 00       	call   0x819390
  34decf:	41 8b 57 10          	mov    edx,DWORD PTR [r15+0x10]
  34ded3:	be 1f 78 00 00       	mov    esi,0x781f
  34ded8:	4c 89 e0             	mov    rax,r12
  34dedb:	89 d1                	mov    ecx,edx
  34dedd:	81 e1 e0 00 00 00    	and    ecx,0xe0
  34dee3:	83 f9 20             	cmp    ecx,0x20
  34dee6:	b9 1f 00 00 00       	mov    ecx,0x1f
  34deeb:	0f 44 ce             	cmove  ecx,esi
  34deee:	21 d1                	and    ecx,edx
  34def0:	83 f9 06             	cmp    ecx,0x6
  34def3:	74 05                	je     0x34defa
  34def5:	83 f9 03             	cmp    ecx,0x3
  34def8:	75 5a                	jne    0x34df54
  34defa:	48 b9 00 00 00 00 22 	movabs rcx,0x2200000000
  34df01:	00 00 00 
  34df04:	48 89 df             	mov    rdi,rbx
  34df07:	be 02 00 00 00       	mov    esi,0x2
  34df0c:	48 89 48 3c          	mov    QWORD PTR [rax+0x3c],rcx
  34df10:	c7 43 68 03 00 00 00 	mov    DWORD PTR [rbx+0x68],0x3
  34df17:	eb 65                	jmp    0x34df7e
  34df19:	48 89 df             	mov    rdi,rbx
  34df1c:	e8 2f bb 4c 00       	call   0x819a50
  34df21:	83 f8 fe             	cmp    eax,0xfffffffe
  34df24:	74 5d                	je     0x34df83
  34df26:	41 8b 47 10          	mov    eax,DWORD PTR [r15+0x10]
  34df2a:	be 1f 78 00 00       	mov    esi,0x781f
  34df2f:	ba 1f 00 00 00       	mov    edx,0x1f
  34df34:	89 c1                	mov    ecx,eax
  34df36:	81 e1 e0 00 00 00    	and    ecx,0xe0
  34df3c:	83 f9 20             	cmp    ecx,0x20
  34df3f:	0f 44 d6             	cmove  edx,esi
  34df42:	85 c2                	test   edx,eax
  34df44:	74 0e                	je     0x34df54
  34df46:	8b 43 68             	mov    eax,DWORD PTR [rbx+0x68]
  34df49:	85 c0                	test   eax,eax
  34df4b:	7e 07                	jle    0x34df54
  34df4d:	ff c8                	dec    eax
  34df4f:	89 43 68             	mov    DWORD PTR [rbx+0x68],eax
  34df52:	eb 2f                	jmp    0x34df83
  34df54:	48 8b 43 38          	mov    rax,QWORD PTR [rbx+0x38]
  34df58:	4c 8b 78 08          	mov    r15,QWORD PTR [rax+0x8]
  34df5c:	48 8d 05 6d 73 f1 ff 	lea    rax,[rip+0xfffffffffff1736d]        # 0x2652d0
  34df63:	4c 29 f8             	sub    rax,r15
  34df66:	48 c1 c8 03          	ror    rax,0x3
  34df6a:	48 3d bc 08 00 00    	cmp    rax,0x8bc
  34df70:	77 1c                	ja     0x34df8e
  34df72:	48 89 df             	mov    rdi,rbx
  34df75:	41 ff d7             	call   r15
  34df78:	48 89 df             	mov    rdi,rbx
  34df7b:	44 89 f6             	mov    esi,r14d
  34df7e:	e8 0d bf 4c 00       	call   0x819e90
  34df83:	31 c0                	xor    eax,eax
  34df85:	5b                   	pop    rbx
  34df86:	41 5c                	pop    r12
  34df88:	41 5e                	pop    r14
  34df8a:	41 5f                	pop    r15
  34df8c:	5d                   	pop    rbp
  34df8d:	c3                   	ret
  34df8e:	48 8d 3d fb eb 74 01 	lea    rdi,[rip+0x174ebfb]        # 0x1a9cb90
  34df95:	4c 89 fe             	mov    rsi,r15
  34df98:	e8 23 19 10 00       	call   0x44f8c0
  34df9d:	eb d3                	jmp    0x34df72
  34df9f:	90                   	nop
  34dfa0:	55                   	push   rbp
  34dfa1:	48 89 e5             	mov    rbp,rsp
  34dfa4:	41 57                	push   r15
  34dfa6:	41 56                	push   r14
  34dfa8:	41 55                	push   r13
  34dfaa:	41 54                	push   r12
  34dfac:	53                   	push   rbx
  34dfad:	48 83 ec 18          	sub    rsp,0x18
  34dfb1:	48 8b 4f 40          	mov    rcx,QWORD PTR [rdi+0x40]
  34dfb5:	48 b8 01 00 00 00 20 	movabs rax,0x2000000001
  34dfbc:	00 00 00 
  34dfbf:	48 8d 35 ea b5 8b 02 	lea    rsi,[rip+0x28bb5ea]        # 0x2c095b0
  34dfc6:	48 89 7d d0          	mov    QWORD PTR [rbp-0x30],rdi
  34dfca:	48 89 41 3c          	mov    QWORD PTR [rcx+0x3c],rax
  34dfce:	48 89 4d c0          	mov    QWORD PTR [rbp-0x40],rcx
  34dfd2:	4c 8b 37             	mov    r14,QWORD PTR [rdi]
  34dfd5:	0f b6 16             	movzx  edx,BYTE PTR [rsi]
  34dfd8:	44 8b 7f 28          	mov    r15d,DWORD PTR [rdi+0x28]
  34dfdc:	49 8b 0e             	mov    rcx,QWORD PTR [r14]
  34dfdf:	48 8b 04 d1          	mov    rax,QWORD PTR [rcx+rdx*8]
  34dfe3:	48 39 30             	cmp    QWORD PTR [rax],rsi
  34dfe6:	74 17                	je     0x34dfff
  34dfe8:	48 8d 34 d1          	lea    rsi,[rcx+rdx*8]
  34dfec:	48 8b b9 00 08 00 00 	mov    rdi,QWORD PTR [rcx+0x800]
  34dff3:	48 8d 15 b6 b5 8b 02 	lea    rdx,[rip+0x28bb5b6]        # 0x2c095b0
  34dffa:	e8 f1 7f fd ff       	call   0x325ff0
  34dfff:	4c 8b 60 08          	mov    r12,QWORD PTR [rax+0x8]
  34e003:	48 8d 1d 36 91 f1 ff 	lea    rbx,[rip+0xfffffffffff19136]        # 0x267140
  34e00a:	48 89 d8             	mov    rax,rbx
  34e00d:	4c 29 e0             	sub    rax,r12
  34e010:	48 c1 c8 03          	ror    rax,0x3
  34e014:	48 83 f8 26          	cmp    rax,0x26
  34e018:	0f 87 d8 01 00 00    	ja     0x34e1f6
  34e01e:	4c 89 f7             	mov    rdi,r14
  34e021:	44 89 fe             	mov    esi,r15d
  34e024:	ba 01 00 00 00       	mov    edx,0x1
  34e029:	41 ff d4             	call   r12
  34e02c:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
  34e030:	48 8d 35 79 b5 8b 02 	lea    rsi,[rip+0x28bb579]        # 0x2c095b0
  34e037:	89 45 c8             	mov    DWORD PTR [rbp-0x38],eax
  34e03a:	4c 8b 39             	mov    r15,QWORD PTR [rcx]
  34e03d:	44 8b 61 28          	mov    r12d,DWORD PTR [rcx+0x28]
  34e041:	0f b6 16             	movzx  edx,BYTE PTR [rsi]
  34e044:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  34e047:	48 8b 04 d1          	mov    rax,QWORD PTR [rcx+rdx*8]
  34e04b:	48 39 30             	cmp    QWORD PTR [rax],rsi
  34e04e:	74 17                	je     0x34e067
  34e050:	48 8d 34 d1          	lea    rsi,[rcx+rdx*8]
  34e054:	48 8b b9 00 08 00 00 	mov    rdi,QWORD PTR [rcx+0x800]
  34e05b:	48 8d 15 4e b5 8b 02 	lea    rdx,[rip+0x28bb54e]        # 0x2c095b0
  34e062:	e8 89 7f fd ff       	call   0x325ff0
  34e067:	4c 8b 70 08          	mov    r14,QWORD PTR [rax+0x8]
  34e06b:	48 89 d8             	mov    rax,rbx
  34e06e:	4c 29 f0             	sub    rax,r14
  34e071:	48 c1 c8 03          	ror    rax,0x3
  34e075:	48 83 f8 26          	cmp    rax,0x26
  34e079:	0f 87 8b 01 00 00    	ja     0x34e20a
  34e07f:	4c 89 ff             	mov    rdi,r15
  34e082:	44 89 e6             	mov    esi,r12d
  34e085:	ba 01 00 00 00       	mov    edx,0x1
  34e08a:	41 ff d6             	call   r14
  34e08d:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
  34e091:	48 8d 35 18 b5 8b 02 	lea    rsi,[rip+0x28bb518]        # 0x2c095b0
  34e098:	89 45 cc             	mov    DWORD PTR [rbp-0x34],eax
  34e09b:	4c 8b 21             	mov    r12,QWORD PTR [rcx]
  34e09e:	44 8b 69 28          	mov    r13d,DWORD PTR [rcx+0x28]
  34e0a2:	0f b6 16             	movzx  edx,BYTE PTR [rsi]
  34e0a5:	49 8b 0c 24          	mov    rcx,QWORD PTR [r12]
  34e0a9:	48 8b 04 d1          	mov    rax,QWORD PTR [rcx+rdx*8]
  34e0ad:	48 39 30             	cmp    QWORD PTR [rax],rsi
  34e0b0:	74 17                	je     0x34e0c9
  34e0b2:	48 8d 34 d1          	lea    rsi,[rcx+rdx*8]
  34e0b6:	48 8b b9 00 08 00 00 	mov    rdi,QWORD PTR [rcx+0x800]
  34e0bd:	48 8d 15 ec b4 8b 02 	lea    rdx,[rip+0x28bb4ec]        # 0x2c095b0
  34e0c4:	e8 27 7f fd ff       	call   0x325ff0
  34e0c9:	4c 8b 70 08          	mov    r14,QWORD PTR [rax+0x8]
  34e0cd:	48 89 d8             	mov    rax,rbx
  34e0d0:	4c 29 f0             	sub    rax,r14
  34e0d3:	48 c1 c8 03          	ror    rax,0x3
  34e0d7:	48 83 f8 26          	cmp    rax,0x26
  34e0db:	0f 87 3d 01 00 00    	ja     0x34e21e
  34e0e1:	4c 89 e7             	mov    rdi,r12
  34e0e4:	44 89 ee             	mov    esi,r13d
  34e0e7:	ba 16 00 00 00       	mov    edx,0x16
  34e0ec:	41 ff d6             	call   r14
  34e0ef:	41 89 c4             	mov    r12d,eax
  34e0f2:	66 45 85 e4          	test   r12w,r12w
  34e0f6:	79 08                	jns    0x34e100
  34e0f8:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  34e0fc:	80 48 3c 02          	or     BYTE PTR [rax+0x3c],0x2
  34e100:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  34e104:	48 8d 35 a5 b4 8b 02 	lea    rsi,[rip+0x28bb4a5]        # 0x2c095b0
  34e10b:	4c 8b 28             	mov    r13,QWORD PTR [rax]
  34e10e:	0f b6 16             	movzx  edx,BYTE PTR [rsi]
  34e111:	44 8b 70 28          	mov    r14d,DWORD PTR [rax+0x28]
  34e115:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  34e119:	48 8b 04 d1          	mov    rax,QWORD PTR [rcx+rdx*8]
  34e11d:	48 39 30             	cmp    QWORD PTR [rax],rsi
  34e120:	74 17                	je     0x34e139
  34e122:	48 8d 34 d1          	lea    rsi,[rcx+rdx*8]
  34e126:	48 8b b9 00 08 00 00 	mov    rdi,QWORD PTR [rcx+0x800]
  34e12d:	48 8d 15 7c b4 8b 02 	lea    rdx,[rip+0x28bb47c]        # 0x2c095b0
  34e134:	e8 b7 7e fd ff       	call   0x325ff0
  34e139:	4c 8b 78 08          	mov    r15,QWORD PTR [rax+0x8]
  34e13d:	4c 29 fb             	sub    rbx,r15
  34e140:	48 c1 cb 03          	ror    rbx,0x3
  34e144:	48 83 fb 26          	cmp    rbx,0x26
  34e148:	0f 87 e4 00 00 00    	ja     0x34e232
  34e14e:	4c 89 ef             	mov    rdi,r13
  34e151:	44 89 f6             	mov    esi,r14d
  34e154:	31 d2                	xor    edx,edx
  34e156:	41 ff d7             	call   r15
  34e159:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  34e15d:	a9 00 04 00 00       	test   eax,0x400
  34e162:	75 23                	jne    0x34e187
  34e164:	a9 00 40 00 00       	test   eax,0x4000
  34e169:	74 04                	je     0x34e16f
  34e16b:	80 4b 43 08          	or     BYTE PTR [rbx+0x43],0x8
  34e16f:	a9 00 10 00 00       	test   eax,0x1000
  34e174:	74 1e                	je     0x34e194
  34e176:	8b 45 cc             	mov    eax,DWORD PTR [rbp-0x34]
  34e179:	0b 45 c8             	or     eax,DWORD PTR [rbp-0x38]
  34e17c:	83 e0 20             	and    eax,0x20
  34e17f:	75 13                	jne    0x34e194
  34e181:	80 4b 40 02          	or     BYTE PTR [rbx+0x40],0x2
  34e185:	eb 60                	jmp    0x34e1e7
  34e187:	80 4b 40 02          	or     BYTE PTR [rbx+0x40],0x2
  34e18b:	c7 43 3c 00 00 00 00 	mov    DWORD PTR [rbx+0x3c],0x0
  34e192:	eb 53                	jmp    0x34e1e7
  34e194:	8b 4b 40             	mov    ecx,DWORD PTR [rbx+0x40]
  34e197:	44 89 e0             	mov    eax,r12d
  34e19a:	25 00 60 00 00       	and    eax,0x6000
  34e19f:	3d 00 20 00 00       	cmp    eax,0x2000
  34e1a4:	74 0b                	je     0x34e1b1
  34e1a6:	85 c0                	test   eax,eax
  34e1a8:	75 37                	jne    0x34e1e1
  34e1aa:	b8 03 00 00 00       	mov    eax,0x3
  34e1af:	eb 05                	jmp    0x34e1b6
  34e1b1:	b8 06 00 00 00       	mov    eax,0x6
  34e1b6:	09 c8                	or     eax,ecx
  34e1b8:	89 43 40             	mov    DWORD PTR [rbx+0x40],eax
  34e1bb:	41 f7 c4 00 10 00 00 	test   r12d,0x1000
  34e1c2:	75 07                	jne    0x34e1cb
  34e1c4:	0d 00 00 20 00       	or     eax,0x200000
  34e1c9:	eb 11                	jmp    0x34e1dc
  34e1cb:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
  34e1cf:	e8 dc c8 4c 00       	call   0x81aab0
  34e1d4:	0b 43 40             	or     eax,DWORD PTR [rbx+0x40]
  34e1d7:	0d 00 00 10 00       	or     eax,0x100000
  34e1dc:	89 43 40             	mov    DWORD PTR [rbx+0x40],eax
  34e1df:	eb 06                	jmp    0x34e1e7
  34e1e1:	83 c9 02             	or     ecx,0x2
  34e1e4:	89 4b 40             	mov    DWORD PTR [rbx+0x40],ecx
  34e1e7:	48 83 c4 18          	add    rsp,0x18
  34e1eb:	5b                   	pop    rbx
  34e1ec:	41 5c                	pop    r12
  34e1ee:	41 5d                	pop    r13
  34e1f0:	41 5e                	pop    r14
  34e1f2:	41 5f                	pop    r15
  34e1f4:	5d                   	pop    rbp
  34e1f5:	c3                   	ret
  34e1f6:	48 8d 3d b3 e9 74 01 	lea    rdi,[rip+0x174e9b3]        # 0x1a9cbb0
  34e1fd:	4c 89 e6             	mov    rsi,r12
  34e200:	e8 bb 16 10 00       	call   0x44f8c0
  34e205:	e9 14 fe ff ff       	jmp    0x34e01e
  34e20a:	48 8d 3d 9f e9 74 01 	lea    rdi,[rip+0x174e99f]        # 0x1a9cbb0
  34e211:	4c 89 f6             	mov    rsi,r14
  34e214:	e8 a7 16 10 00       	call   0x44f8c0
  34e219:	e9 61 fe ff ff       	jmp    0x34e07f
  34e21e:	48 8d 3d 8b e9 74 01 	lea    rdi,[rip+0x174e98b]        # 0x1a9cbb0
  34e225:	4c 89 f6             	mov    rsi,r14
  34e228:	e8 93 16 10 00       	call   0x44f8c0
  34e22d:	e9 af fe ff ff       	jmp    0x34e0e1
  34e232:	48 8d 3d 77 e9 74 01 	lea    rdi,[rip+0x174e977]        # 0x1a9cbb0
  34e239:	4c 89 fe             	mov    rsi,r15
  34e23c:	e8 7f 16 10 00       	call   0x44f8c0
  34e241:	e9 08 ff ff ff       	jmp    0x34e14e
  34e246:	90                   	nop
  34e247:	90                   	nop
  34e248:	90                   	nop
  34e249:	90                   	nop
  34e24a:	90                   	nop
  34e24b:	90                   	nop
  34e24c:	90                   	nop
  34e24d:	90                   	nop
  34e24e:	90                   	nop
  34e24f:	90                   	nop
  34e250:	48 85 f6             	test   rsi,rsi
  34e253:	74 1f                	je     0x34e274
  34e255:	55                   	push   rbp
  34e256:	48 89 e5             	mov    rbp,rsp
  34e259:	49 89 f0             	mov    r8,rsi
  34e25c:	ba 00 80 06 00       	mov    edx,0x68000
  34e261:	b9 05 00 00 00       	mov    ecx,0x5
  34e266:	31 f6                	xor    esi,esi
  34e268:	e8 f3 f0 34 00       	call   0x69d360
  34e26d:	34 01                	xor    al,0x1
  34e26f:	0f b6 c0             	movzx  eax,al
  34e272:	5d                   	pop    rbp
  34e273:	c3                   	ret
  34e274:	b8 01 00 00 00       	mov    eax,0x1
  34e279:	c3                   	ret
  34e27a:	90                   	nop
  34e27b:	90                   	nop
  34e27c:	90                   	nop
  34e27d:	90                   	nop
  34e27e:	90                   	nop
  34e27f:	90                   	nop
  34e280:	48 85 f6             	test   rsi,rsi
  34e283:	74 1f                	je     0x34e2a4
  34e285:	55                   	push   rbp
  34e286:	48 89 e5             	mov    rbp,rsp
  34e289:	49 89 f0             	mov    r8,rsi
  34e28c:	ba 28 80 06 00       	mov    edx,0x68028
  34e291:	b9 01 00 00 00       	mov    ecx,0x1
  34e296:	31 f6                	xor    esi,esi
  34e298:	e8 c3 f0 34 00       	call   0x69d360
  34e29d:	34 01                	xor    al,0x1
  34e29f:	0f b6 c0             	movzx  eax,al
  34e2a2:	5d                   	pop    rbp
  34e2a3:	c3                   	ret
  34e2a4:	b8 01 00 00 00       	mov    eax,0x1
  34e2a9:	c3                   	ret
  34e2aa:	90                   	nop
  34e2ab:	90                   	nop
  34e2ac:	90                   	nop
  34e2ad:	90                   	nop
  34e2ae:	90                   	nop
  34e2af:	90                   	nop
  34e2b0:	48 85 f6             	test   rsi,rsi
  34e2b3:	74 1f                	je     0x34e2d4
  34e2b5:	55                   	push   rbp
  34e2b6:	48 89 e5             	mov    rbp,rsp
  34e2b9:	49 89 f0             	mov    r8,rsi
  34e2bc:	ba 29 80 06 00       	mov    edx,0x68029
  34e2c1:	b9 01 00 00 00       	mov    ecx,0x1
  34e2c6:	31 f6                	xor    esi,esi
  34e2c8:	e8 93 f0 34 00       	call   0x69d360
  34e2cd:	34 01                	xor    al,0x1
  34e2cf:	0f b6 c0             	movzx  eax,al
  34e2d2:	5d                   	pop    rbp
  34e2d3:	c3                   	ret
  34e2d4:	b8 01 00 00 00       	mov    eax,0x1
  34e2d9:	c3                   	ret
  34e2da:	90                   	nop
  34e2db:	90                   	nop
  34e2dc:	90                   	nop
  34e2dd:	90                   	nop
  34e2de:	90                   	nop
  34e2df:	90                   	nop
  34e2e0:	48 85 f6             	test   rsi,rsi
  34e2e3:	74 1f                	je     0x34e304
  34e2e5:	55                   	push   rbp
  34e2e6:	48 89 e5             	mov    rbp,rsp
  34e2e9:	49 89 f0             	mov    r8,rsi
  34e2ec:	ba 05 80 06 00       	mov    edx,0x68005
  34e2f1:	b9 02 00 00 00       	mov    ecx,0x2
  34e2f6:	31 f6                	xor    esi,esi
  34e2f8:	e8 63 f0 34 00       	call   0x69d360
  34e2fd:	34 01                	xor    al,0x1
  34e2ff:	0f b6 c0             	movzx  eax,al
  34e302:	5d                   	pop    rbp
  34e303:	c3                   	ret
  34e304:	b8 01 00 00 00       	mov    eax,0x1
  34e309:	c3                   	ret
  34e30a:	90                   	nop
  34e30b:	90                   	nop
  34e30c:	90                   	nop
  34e30d:	90                   	nop
  34e30e:	90                   	nop
  34e30f:	90                   	nop
  34e310:	48 85 f6             	test   rsi,rsi
  34e313:	74 1f                	je     0x34e334
  34e315:	55                   	push   rbp
  34e316:	48 89 e5             	mov    rbp,rsp
  34e319:	49 89 f0             	mov    r8,rsi
  34e31c:	ba 2c 80 06 00       	mov    edx,0x6802c
  34e321:	b9 0f 00 00 00       	mov    ecx,0xf
  34e326:	31 f6                	xor    esi,esi
  34e328:	e8 33 f0 34 00       	call   0x69d360
  34e32d:	34 01                	xor    al,0x1
  34e32f:	0f b6 c0             	movzx  eax,al
  34e332:	5d                   	pop    rbp
  34e333:	c3                   	ret
  34e334:	b8 01 00 00 00       	mov    eax,0x1
  34e339:	c3                   	ret
  34e33a:	90                   	nop
  34e33b:	90                   	nop
  34e33c:	90                   	nop
  34e33d:	90                   	nop
  34e33e:	90                   	nop
  34e33f:	90                   	nop
  34e340:	55                   	push   rbp
  34e341:	48 89 e5             	mov    rbp,rsp
  34e344:	41 57                	push   r15
  34e346:	41 56                	push   r14
  34e348:	53                   	push   rbx
  34e349:	50                   	push   rax
  34e34a:	bb 01 00 00 00       	mov    ebx,0x1
  34e34f:	48 85 f6             	test   rsi,rsi
  34e352:	0f 84 a7 00 00 00    	je     0x34e3ff
  34e358:	49 89 f6             	mov    r14,rsi
  34e35b:	ba 14 80 06 00       	mov    edx,0x68014
  34e360:	b9 04 00 00 00       	mov    ecx,0x4
  34e365:	41 89 ff             	mov    r15d,edi
  34e368:	31 f6                	xor    esi,esi
  34e36a:	4d 89 f0             	mov    r8,r14
  34e36d:	e8 ee ef 34 00       	call   0x69d360
  34e372:	84 c0                	test   al,al
  34e374:	0f 84 85 00 00 00    	je     0x34e3ff
  34e37a:	4d 89 f0             	mov    r8,r14
  34e37d:	49 83 c0 04          	add    r8,0x4
  34e381:	74 7c                	je     0x34e3ff
  34e383:	44 89 ff             	mov    edi,r15d
  34e386:	ba 18 80 06 00       	mov    edx,0x68018
  34e38b:	b9 04 00 00 00       	mov    ecx,0x4
  34e390:	31 f6                	xor    esi,esi
  34e392:	e8 c9 ef 34 00       	call   0x69d360
  34e397:	84 c0                	test   al,al
  34e399:	74 64                	je     0x34e3ff
  34e39b:	4d 89 f0             	mov    r8,r14
  34e39e:	49 83 c0 08          	add    r8,0x8
  34e3a2:	74 5b                	je     0x34e3ff
  34e3a4:	44 89 ff             	mov    edi,r15d
  34e3a7:	ba 1c 80 06 00       	mov    edx,0x6801c
  34e3ac:	b9 04 00 00 00       	mov    ecx,0x4
  34e3b1:	31 f6                	xor    esi,esi
  34e3b3:	e8 a8 ef 34 00       	call   0x69d360
  34e3b8:	84 c0                	test   al,al
  34e3ba:	74 43                	je     0x34e3ff
  34e3bc:	4d 89 f0             	mov    r8,r14
  34e3bf:	49 83 c0 0c          	add    r8,0xc
  34e3c3:	74 3a                	je     0x34e3ff
  34e3c5:	44 89 ff             	mov    edi,r15d
  34e3c8:	ba 20 80 06 00       	mov    edx,0x68020
  34e3cd:	b9 04 00 00 00       	mov    ecx,0x4
  34e3d2:	31 f6                	xor    esi,esi
  34e3d4:	e8 87 ef 34 00       	call   0x69d360
  34e3d9:	84 c0                	test   al,al
  34e3db:	74 22                	je     0x34e3ff
  34e3dd:	49 83 c6 10          	add    r14,0x10
  34e3e1:	74 1c                	je     0x34e3ff
  34e3e3:	44 89 ff             	mov    edi,r15d
  34e3e6:	ba 24 80 06 00       	mov    edx,0x68024
  34e3eb:	b9 04 00 00 00       	mov    ecx,0x4
  34e3f0:	4d 89 f0             	mov    r8,r14
  34e3f3:	31 f6                	xor    esi,esi
  34e3f5:	e8 66 ef 34 00       	call   0x69d360
  34e3fa:	34 01                	xor    al,0x1
  34e3fc:	0f b6 d8             	movzx  ebx,al
  34e3ff:	89 d8                	mov    eax,ebx
  34e401:	48 83 c4 08          	add    rsp,0x8
  34e405:	5b                   	pop    rbx
  34e406:	41 5e                	pop    r14
  34e408:	41 5f                	pop    r15
  34e40a:	5d                   	pop    rbp
  34e40b:	c3                   	ret
  34e40c:	90                   	nop
  34e40d:	90                   	nop
  34e40e:	90                   	nop
  34e40f:	90                   	nop
  34e410:	48 85 f6             	test   rsi,rsi
  34e413:	74 1f                	je     0x34e434
  34e415:	55                   	push   rbp
  34e416:	48 89 e5             	mov    rbp,rsp
  34e419:	49 89 f0             	mov    r8,rsi
  34e41c:	ba 2a 80 06 00       	mov    edx,0x6802a
  34e421:	b9 02 00 00 00       	mov    ecx,0x2
  34e426:	31 f6                	xor    esi,esi
  34e428:	e8 33 ef 34 00       	call   0x69d360
  34e42d:	34 01                	xor    al,0x1
  34e42f:	0f b6 c0             	movzx  eax,al
  34e432:	5d                   	pop    rbp
  34e433:	c3                   	ret
  34e434:	b8 01 00 00 00       	mov    eax,0x1
  34e439:	c3                   	ret
  34e43a:	90                   	nop
  34e43b:	90                   	nop
  34e43c:	90                   	nop
  34e43d:	90                   	nop
  34e43e:	90                   	nop
  34e43f:	90                   	nop
  34e440:	48 85 f6             	test   rsi,rsi
  34e443:	74 1f                	je     0x34e464
  34e445:	55                   	push   rbp
  34e446:	48 89 e5             	mov    rbp,rsp
  34e449:	49 89 f0             	mov    r8,rsi
  34e44c:	ba 07 80 06 00       	mov    edx,0x68007
  34e451:	b9 05 00 00 00       	mov    ecx,0x5
  34e456:	31 f6                	xor    esi,esi
  34e458:	e8 73 0b 35 00       	call   0x69efd0
  34e45d:	34 01                	xor    al,0x1
  34e45f:	0f b6 c0             	movzx  eax,al
  34e462:	5d                   	pop    rbp
  34e463:	c3                   	ret
  34e464:	b8 01 00 00 00       	mov    eax,0x1
  34e469:	c3                   	ret
  34e46a:	90                   	nop
  34e46b:	90                   	nop
  34e46c:	90                   	nop
  34e46d:	90                   	nop
  34e46e:	90                   	nop
  34e46f:	90                   	nop
  34e470:	48 85 f6             	test   rsi,rsi
  34e473:	74 1f                	je     0x34e494
  34e475:	55                   	push   rbp
  34e476:	48 89 e5             	mov    rbp,rsp
  34e479:	49 89 f0             	mov    r8,rsi
  34e47c:	ba 3b 80 06 00       	mov    edx,0x6803b
  34e481:	b9 01 00 00 00       	mov    ecx,0x1
  34e486:	31 f6                	xor    esi,esi
  34e488:	e8 43 0b 35 00       	call   0x69efd0
  34e48d:	34 01                	xor    al,0x1
  34e48f:	0f b6 c0             	movzx  eax,al
  34e492:	5d                   	pop    rbp
  34e493:	c3                   	ret
  34e494:	b8 01 00 00 00       	mov    eax,0x1
  34e499:	c3                   	ret
  34e49a:	90                   	nop
  34e49b:	90                   	nop
  34e49c:	90                   	nop
  34e49d:	90                   	nop
  34e49e:	90                   	nop
  34e49f:	90                   	nop
  34e4a0:	48 85 f6             	test   rsi,rsi
  34e4a3:	74 1f                	je     0x34e4c4
  34e4a5:	55                   	push   rbp
  34e4a6:	48 89 e5             	mov    rbp,rsp
  34e4a9:	49 89 f0             	mov    r8,rsi
  34e4ac:	ba 0c 80 06 00       	mov    edx,0x6800c
  34e4b1:	b9 08 00 00 00       	mov    ecx,0x8
  34e4b6:	31 f6                	xor    esi,esi
  34e4b8:	e8 13 0b 35 00       	call   0x69efd0
  34e4bd:	34 01                	xor    al,0x1
  34e4bf:	0f b6 c0             	movzx  eax,al
  34e4c2:	5d                   	pop    rbp
  34e4c3:	c3                   	ret
  34e4c4:	b8 01 00 00 00       	mov    eax,0x1
  34e4c9:	c3                   	ret
  34e4ca:	90                   	nop
  34e4cb:	90                   	nop
  34e4cc:	90                   	nop
  34e4cd:	90                   	nop
  34e4ce:	90                   	nop
  34e4cf:	90                   	nop
  34e4d0:	48 85 f6             	test   rsi,rsi
  34e4d3:	74 1f                	je     0x34e4f4
  34e4d5:	55                   	push   rbp
  34e4d6:	48 89 e5             	mov    rbp,rsp
  34e4d9:	49 89 f0             	mov    r8,rsi
  34e4dc:	ba 1d 92 06 00       	mov    edx,0x6921d
  34e4e1:	b9 03 00 00 00       	mov    ecx,0x3
  34e4e6:	31 f6                	xor    esi,esi
  34e4e8:	e8 73 ee 34 00       	call   0x69d360
  34e4ed:	34 01                	xor    al,0x1
  34e4ef:	0f b6 c0             	movzx  eax,al
  34e4f2:	5d                   	pop    rbp
  34e4f3:	c3                   	ret
  34e4f4:	b8 01 00 00 00       	mov    eax,0x1
  34e4f9:	c3                   	ret
  34e4fa:	90                   	nop
  34e4fb:	90                   	nop
  34e4fc:	90                   	nop
  34e4fd:	90                   	nop
  34e4fe:	90                   	nop
  34e4ff:	90                   	nop
  34e500:	48 85 f6             	test   rsi,rsi
  34e503:	74 1f                	je     0x34e524
  34e505:	55                   	push   rbp
  34e506:	48 89 e5             	mov    rbp,rsp
  34e509:	49 89 f0             	mov    r8,rsi
  34e50c:	ba 93 94 06 00       	mov    edx,0x69493
  34e511:	b9 01 00 00 00       	mov    ecx,0x1
  34e516:	31 f6                	xor    esi,esi
  34e518:	e8 43 ee 34 00       	call   0x69d360
  34e51d:	34 01                	xor    al,0x1
  34e51f:	0f b6 c0             	movzx  eax,al
  34e522:	5d                   	pop    rbp
  34e523:	c3                   	ret
  34e524:	b8 01 00 00 00       	mov    eax,0x1
  34e529:	c3                   	ret
  34e52a:	90                   	nop
  34e52b:	90                   	nop
  34e52c:	90                   	nop
  34e52d:	90                   	nop
  34e52e:	90                   	nop
  34e52f:	90                   	nop
  34e530:	55                   	push   rbp
  34e531:	48 89 e5             	mov    rbp,rsp
  34e534:	41 57                	push   r15
  34e536:	41 56                	push   r14
  34e538:	41 55                	push   r13
  34e53a:	41 54                	push   r12
  34e53c:	53                   	push   rbx
  34e53d:	50                   	push   rax
  34e53e:	49 89 f6             	mov    r14,rsi
  34e541:	b8 01 00 00 00       	mov    eax,0x1
  34e546:	49 ff c6             	inc    r14
  34e549:	74 51                	je     0x34e59c
  34e54b:	41 89 ff             	mov    r15d,edi
  34e54e:	41 bd 15 02 00 00    	mov    r13d,0x215
  34e554:	31 db                	xor    ebx,ebx
  34e556:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  34e55d:	00 00 00 
  34e560:	41 83 fd 10          	cmp    r13d,0x10
  34e564:	41 bc 10 00 00 00    	mov    r12d,0x10
  34e56a:	41 89 d8             	mov    r8d,ebx
  34e56d:	8d 93 0b 90 06 00    	lea    edx,[rbx+0x6900b]
  34e573:	44 89 ff             	mov    edi,r15d
  34e576:	45 0f 42 e5          	cmovb  r12d,r13d
  34e57a:	4d 01 f0             	add    r8,r14
  34e57d:	31 f6                	xor    esi,esi
  34e57f:	44 89 e1             	mov    ecx,r12d
  34e582:	e8 d9 ed 34 00       	call   0x69d360
  34e587:	84 c0                	test   al,al
  34e589:	74 0c                	je     0x34e597
  34e58b:	44 01 e3             	add    ebx,r12d
  34e58e:	45 29 e5             	sub    r13d,r12d
  34e591:	75 cd                	jne    0x34e560
  34e593:	31 c0                	xor    eax,eax
  34e595:	eb 05                	jmp    0x34e59c
  34e597:	b8 01 00 00 00       	mov    eax,0x1
  34e59c:	48 83 c4 08          	add    rsp,0x8
  34e5a0:	5b                   	pop    rbx
  34e5a1:	41 5c                	pop    r12
  34e5a3:	41 5d                	pop    r13
  34e5a5:	41 5e                	pop    r14
  34e5a7:	41 5f                	pop    r15
  34e5a9:	5d                   	pop    rbp
  34e5aa:	c3                   	ret
  34e5ab:	90                   	nop
  34e5ac:	90                   	nop
  34e5ad:	90                   	nop
  34e5ae:	90                   	nop
  34e5af:	90                   	nop
  34e5b0:	55                   	push   rbp
  34e5b1:	48 89 e5             	mov    rbp,rsp
  34e5b4:	41 57                	push   r15
  34e5b6:	41 56                	push   r14
  34e5b8:	53                   	push   rbx
  34e5b9:	50                   	push   rax
  34e5ba:	49 89 f0             	mov    r8,rsi
  34e5bd:	41 be 01 00 00 00    	mov    r14d,0x1
  34e5c3:	49 ff c0             	inc    r8
  34e5c6:	74 3c                	je     0x34e604
  34e5c8:	ba c0 92 06 00       	mov    edx,0x692c0
  34e5cd:	b9 10 00 00 00       	mov    ecx,0x10
  34e5d2:	48 89 f3             	mov    rbx,rsi
  34e5d5:	31 f6                	xor    esi,esi
  34e5d7:	41 89 ff             	mov    r15d,edi
  34e5da:	e8 81 ed 34 00       	call   0x69d360
  34e5df:	84 c0                	test   al,al
  34e5e1:	74 21                	je     0x34e604
  34e5e3:	48 83 c3 11          	add    rbx,0x11
  34e5e7:	44 89 ff             	mov    edi,r15d
  34e5ea:	ba d0 92 06 00       	mov    edx,0x692d0
  34e5ef:	b9 10 00 00 00       	mov    ecx,0x10
  34e5f4:	31 f6                	xor    esi,esi
  34e5f6:	49 89 d8             	mov    r8,rbx
  34e5f9:	e8 62 ed 34 00       	call   0x69d360
  34e5fe:	34 01                	xor    al,0x1
  34e600:	44 0f b6 f0          	movzx  r14d,al
  34e604:	44 89 f0             	mov    eax,r14d
  34e607:	48 83 c4 08          	add    rsp,0x8
  34e60b:	5b                   	pop    rbx
  34e60c:	41 5e                	pop    r14
  34e60e:	41 5f                	pop    r15
  34e610:	5d                   	pop    rbp
  34e611:	c3                   	ret
  34e612:	90                   	nop
  34e613:	90                   	nop
  34e614:	90                   	nop
  34e615:	90                   	nop
  34e616:	90                   	nop
  34e617:	90                   	nop
  34e618:	90                   	nop
  34e619:	90                   	nop
  34e61a:	90                   	nop
  34e61b:	90                   	nop
  34e61c:	90                   	nop
  34e61d:	90                   	nop
  34e61e:	90                   	nop
  34e61f:	90                   	nop
  34e620:	49 89 f0             	mov    r8,rsi
  34e623:	49 ff c0             	inc    r8
  34e626:	74 1c                	je     0x34e644
  34e628:	55                   	push   rbp
  34e629:	48 89 e5             	mov    rbp,rsp
  34e62c:	ba e0 92 06 00       	mov    edx,0x692e0
  34e631:	b9 10 00 00 00       	mov    ecx,0x10
  34e636:	31 f6                	xor    esi,esi
  34e638:	e8 23 ed 34 00       	call   0x69d360
  34e63d:	34 01                	xor    al,0x1
  34e63f:	0f b6 c0             	movzx  eax,al
  34e642:	5d                   	pop    rbp
  34e643:	c3                   	ret
  34e644:	b8 01 00 00 00       	mov    eax,0x1
  34e649:	c3                   	ret
  34e64a:	90                   	nop
  34e64b:	90                   	nop
  34e64c:	90                   	nop
  34e64d:	90                   	nop
  34e64e:	90                   	nop
  34e64f:	90                   	nop
  34e650:	55                   	push   rbp
  34e651:	48 89 e5             	mov    rbp,rsp
  34e654:	41 57                	push   r15
  34e656:	41 56                	push   r14
  34e658:	53                   	push   rbx
  34e659:	50                   	push   rax
  34e65a:	49 89 f0             	mov    r8,rsi
  34e65d:	41 be 01 00 00 00    	mov    r14d,0x1
  34e663:	49 ff c0             	inc    r8
  34e666:	74 3c                	je     0x34e6a4
  34e668:	ba f8 92 06 00       	mov    edx,0x692f8
  34e66d:	b9 10 00 00 00       	mov    ecx,0x10
  34e672:	48 89 f3             	mov    rbx,rsi
  34e675:	31 f6                	xor    esi,esi
  34e677:	41 89 ff             	mov    r15d,edi
  34e67a:	e8 e1 ec 34 00       	call   0x69d360
  34e67f:	84 c0                	test   al,al
  34e681:	74 21                	je     0x34e6a4
  34e683:	48 83 c3 11          	add    rbx,0x11
  34e687:	44 89 ff             	mov    edi,r15d
  34e68a:	ba 08 93 06 00       	mov    edx,0x69308
  34e68f:	b9 10 00 00 00       	mov    ecx,0x10
  34e694:	31 f6                	xor    esi,esi
  34e696:	49 89 d8             	mov    r8,rbx
  34e699:	e8 c2 ec 34 00       	call   0x69d360
  34e69e:	34 01                	xor    al,0x1
  34e6a0:	44 0f b6 f0          	movzx  r14d,al
  34e6a4:	44 89 f0             	mov    eax,r14d
  34e6a7:	48 83 c4 08          	add    rsp,0x8
  34e6ab:	5b                   	pop    rbx
  34e6ac:	41 5e                	pop    r14
  34e6ae:	41 5f                	pop    r15
  34e6b0:	5d                   	pop    rbp
  34e6b1:	c3                   	ret
  34e6b2:	90                   	nop
  34e6b3:	90                   	nop
  34e6b4:	90                   	nop
  34e6b5:	90                   	nop
  34e6b6:	90                   	nop
  34e6b7:	90                   	nop
  34e6b8:	90                   	nop
  34e6b9:	90                   	nop
  34e6ba:	90                   	nop
  34e6bb:	90                   	nop
  34e6bc:	90                   	nop
  34e6bd:	90                   	nop
  34e6be:	90                   	nop
  34e6bf:	90                   	nop
  34e6c0:	55                   	push   rbp
  34e6c1:	48 89 e5             	mov    rbp,rsp
  34e6c4:	41 57                	push   r15
  34e6c6:	41 56                	push   r14
  34e6c8:	53                   	push   rbx
  34e6c9:	50                   	push   rax
  34e6ca:	49 89 f0             	mov    r8,rsi
  34e6cd:	bb 01 00 00 00       	mov    ebx,0x1
  34e6d2:	49 ff c0             	inc    r8
  34e6d5:	0f 84 7f 01 00 00    	je     0x34e85a
  34e6db:	ba 30 93 06 00       	mov    edx,0x69330
  34e6e0:	b9 10 00 00 00       	mov    ecx,0x10
  34e6e5:	49 89 f6             	mov    r14,rsi
  34e6e8:	31 f6                	xor    esi,esi
  34e6ea:	41 89 ff             	mov    r15d,edi
  34e6ed:	e8 6e ec 34 00       	call   0x69d360
  34e6f2:	84 c0                	test   al,al
  34e6f4:	0f 84 60 01 00 00    	je     0x34e85a
  34e6fa:	4d 8d 46 11          	lea    r8,[r14+0x11]
  34e6fe:	44 89 ff             	mov    edi,r15d
  34e701:	ba 40 93 06 00       	mov    edx,0x69340
  34e706:	b9 10 00 00 00       	mov    ecx,0x10
  34e70b:	31 f6                	xor    esi,esi
  34e70d:	e8 4e ec 34 00       	call   0x69d360
  34e712:	84 c0                	test   al,al
  34e714:	0f 84 40 01 00 00    	je     0x34e85a
  34e71a:	4d 8d 46 21          	lea    r8,[r14+0x21]
  34e71e:	44 89 ff             	mov    edi,r15d
  34e721:	ba 50 93 06 00       	mov    edx,0x69350
  34e726:	b9 10 00 00 00       	mov    ecx,0x10
  34e72b:	31 f6                	xor    esi,esi
  34e72d:	e8 2e ec 34 00       	call   0x69d360
  34e732:	84 c0                	test   al,al
  34e734:	0f 84 20 01 00 00    	je     0x34e85a
  34e73a:	4d 8d 46 31          	lea    r8,[r14+0x31]
  34e73e:	44 89 ff             	mov    edi,r15d
  34e741:	ba 60 93 06 00       	mov    edx,0x69360
  34e746:	b9 10 00 00 00       	mov    ecx,0x10
  34e74b:	31 f6                	xor    esi,esi
  34e74d:	e8 0e ec 34 00       	call   0x69d360
  34e752:	84 c0                	test   al,al
  34e754:	0f 84 00 01 00 00    	je     0x34e85a
  34e75a:	4d 8d 46 41          	lea    r8,[r14+0x41]
  34e75e:	44 89 ff             	mov    edi,r15d
  34e761:	ba 70 93 06 00       	mov    edx,0x69370
  34e766:	b9 10 00 00 00       	mov    ecx,0x10
  34e76b:	31 f6                	xor    esi,esi
  34e76d:	e8 ee eb 34 00       	call   0x69d360
  34e772:	84 c0                	test   al,al
  34e774:	0f 84 e0 00 00 00    	je     0x34e85a
  34e77a:	4d 8d 46 51          	lea    r8,[r14+0x51]
  34e77e:	44 89 ff             	mov    edi,r15d
  34e781:	ba 80 93 06 00       	mov    edx,0x69380
  34e786:	b9 10 00 00 00       	mov    ecx,0x10
  34e78b:	31 f6                	xor    esi,esi
  34e78d:	e8 ce eb 34 00       	call   0x69d360
  34e792:	84 c0                	test   al,al
  34e794:	0f 84 c0 00 00 00    	je     0x34e85a
  34e79a:	4d 8d 46 61          	lea    r8,[r14+0x61]
  34e79e:	44 89 ff             	mov    edi,r15d
  34e7a1:	ba 90 93 06 00       	mov    edx,0x69390
  34e7a6:	b9 10 00 00 00       	mov    ecx,0x10
  34e7ab:	31 f6                	xor    esi,esi
  34e7ad:	e8 ae eb 34 00       	call   0x69d360
  34e7b2:	84 c0                	test   al,al
  34e7b4:	0f 84 a0 00 00 00    	je     0x34e85a
  34e7ba:	4d 8d 46 71          	lea    r8,[r14+0x71]
  34e7be:	44 89 ff             	mov    edi,r15d
  34e7c1:	ba a0 93 06 00       	mov    edx,0x693a0
  34e7c6:	b9 10 00 00 00       	mov    ecx,0x10
  34e7cb:	31 f6                	xor    esi,esi
  34e7cd:	e8 8e eb 34 00       	call   0x69d360
  34e7d2:	84 c0                	test   al,al
  34e7d4:	0f 84 80 00 00 00    	je     0x34e85a
  34e7da:	4d 8d 86 81 00 00 00 	lea    r8,[r14+0x81]
  34e7e1:	44 89 ff             	mov    edi,r15d
  34e7e4:	ba b0 93 06 00       	mov    edx,0x693b0
  34e7e9:	b9 10 00 00 00       	mov    ecx,0x10
  34e7ee:	31 f6                	xor    esi,esi
  34e7f0:	e8 6b eb 34 00       	call   0x69d360
  34e7f5:	84 c0                	test   al,al
  34e7f7:	74 61                	je     0x34e85a
  34e7f9:	4d 8d 86 91 00 00 00 	lea    r8,[r14+0x91]
  34e800:	44 89 ff             	mov    edi,r15d
  34e803:	ba c0 93 06 00       	mov    edx,0x693c0
  34e808:	b9 10 00 00 00       	mov    ecx,0x10
  34e80d:	31 f6                	xor    esi,esi
  34e80f:	e8 4c eb 34 00       	call   0x69d360
  34e814:	84 c0                	test   al,al
  34e816:	74 42                	je     0x34e85a
  34e818:	4d 8d 86 a1 00 00 00 	lea    r8,[r14+0xa1]
  34e81f:	44 89 ff             	mov    edi,r15d
  34e822:	ba d0 93 06 00       	mov    edx,0x693d0
  34e827:	b9 10 00 00 00       	mov    ecx,0x10
  34e82c:	31 f6                	xor    esi,esi
  34e82e:	e8 2d eb 34 00       	call   0x69d360
  34e833:	84 c0                	test   al,al
  34e835:	74 23                	je     0x34e85a
  34e837:	49 81 c6 b1 00 00 00 	add    r14,0xb1
  34e83e:	44 89 ff             	mov    edi,r15d
  34e841:	ba e0 93 06 00       	mov    edx,0x693e0
  34e846:	b9 01 00 00 00       	mov    ecx,0x1
  34e84b:	31 f6                	xor    esi,esi
  34e84d:	4d 89 f0             	mov    r8,r14
  34e850:	e8 0b eb 34 00       	call   0x69d360
  34e855:	34 01                	xor    al,0x1
  34e857:	0f b6 d8             	movzx  ebx,al
  34e85a:	89 d8                	mov    eax,ebx
  34e85c:	48 83 c4 08          	add    rsp,0x8
  34e860:	5b                   	pop    rbx
  34e861:	41 5e                	pop    r14
  34e863:	41 5f                	pop    r15
  34e865:	5d                   	pop    rbp
  34e866:	c3                   	ret
  34e867:	90                   	nop
  34e868:	90                   	nop
  34e869:	90                   	nop
  34e86a:	90                   	nop
  34e86b:	90                   	nop
  34e86c:	90                   	nop
  34e86d:	90                   	nop
  34e86e:	90                   	nop
  34e86f:	90                   	nop
  34e870:	55                   	push   rbp
  34e871:	48 89 e5             	mov    rbp,rsp
  34e874:	41 57                	push   r15
  34e876:	41 56                	push   r14
  34e878:	53                   	push   rbx
  34e879:	50                   	push   rax
  34e87a:	49 89 f0             	mov    r8,rsi
  34e87d:	41 be 01 00 00 00    	mov    r14d,0x1
  34e883:	49 ff c0             	inc    r8
  34e886:	74 3c                	je     0x34e8c4
  34e888:	ba 73 94 06 00       	mov    edx,0x69473
  34e88d:	b9 10 00 00 00       	mov    ecx,0x10
  34e892:	48 89 f3             	mov    rbx,rsi
  34e895:	31 f6                	xor    esi,esi
  34e897:	41 89 ff             	mov    r15d,edi
  34e89a:	e8 c1 ea 34 00       	call   0x69d360
  34e89f:	84 c0                	test   al,al
  34e8a1:	74 21                	je     0x34e8c4
  34e8a3:	48 83 c3 11          	add    rbx,0x11
  34e8a7:	44 89 ff             	mov    edi,r15d
  34e8aa:	ba 83 94 06 00       	mov    edx,0x69483
  34e8af:	b9 10 00 00 00       	mov    ecx,0x10
  34e8b4:	31 f6                	xor    esi,esi
  34e8b6:	49 89 d8             	mov    r8,rbx
  34e8b9:	e8 a2 ea 34 00       	call   0x69d360
  34e8be:	34 01                	xor    al,0x1
  34e8c0:	44 0f b6 f0          	movzx  r14d,al
  34e8c4:	44 89 f0             	mov    eax,r14d
  34e8c7:	48 83 c4 08          	add    rsp,0x8
  34e8cb:	5b                   	pop    rbx
  34e8cc:	41 5e                	pop    r14
  34e8ce:	41 5f                	pop    r15
  34e8d0:	5d                   	pop    rbp
  34e8d1:	c3                   	ret
  34e8d2:	90                   	nop
  34e8d3:	90                   	nop
  34e8d4:	90                   	nop
  34e8d5:	90                   	nop
  34e8d6:	90                   	nop
  34e8d7:	90                   	nop
  34e8d8:	90                   	nop
  34e8d9:	90                   	nop
  34e8da:	90                   	nop
  34e8db:	90                   	nop
  34e8dc:	90                   	nop
  34e8dd:	90                   	nop
  34e8de:	90                   	nop
  34e8df:	90                   	nop
  34e8e0:	49 89 f0             	mov    r8,rsi
  34e8e3:	49 ff c0             	inc    r8
  34e8e6:	74 1c                	je     0x34e904
  34e8e8:	55                   	push   rbp
  34e8e9:	48 89 e5             	mov    rbp,rsp
  34e8ec:	ba 00 90 06 00       	mov    edx,0x69000
  34e8f1:	b9 0b 00 00 00       	mov    ecx,0xb
  34e8f6:	31 f6                	xor    esi,esi
  34e8f8:	e8 d3 06 35 00       	call   0x69efd0
  34e8fd:	34 01                	xor    al,0x1
  34e8ff:	0f b6 c0             	movzx  eax,al
  34e902:	5d                   	pop    rbp
  34e903:	c3                   	ret
  34e904:	b8 01 00 00 00       	mov    eax,0x1
  34e909:	c3                   	ret
  34e90a:	90                   	nop
  34e90b:	90                   	nop
  34e90c:	90                   	nop
  34e90d:	90                   	nop
  34e90e:	90                   	nop
  34e90f:	90                   	nop
  34e910:	55                   	push   rbp
  34e911:	48 89 e5             	mov    rbp,rsp
  34e914:	41 57                	push   r15
  34e916:	41 56                	push   r14
  34e918:	53                   	push   rbx
  34e919:	50                   	push   rax
  34e91a:	49 89 f0             	mov    r8,rsi
  34e91d:	bb 01 00 00 00       	mov    ebx,0x1
  34e922:	49 ff c0             	inc    r8
  34e925:	0f 84 ef 00 00 00    	je     0x34ea1a
  34e92b:	ba 20 92 06 00       	mov    edx,0x69220
  34e930:	b9 10 00 00 00       	mov    ecx,0x10
  34e935:	49 89 f6             	mov    r14,rsi
  34e938:	31 f6                	xor    esi,esi
  34e93a:	41 89 ff             	mov    r15d,edi
  34e93d:	e8 8e 06 35 00       	call   0x69efd0
  34e942:	84 c0                	test   al,al
  34e944:	0f 84 d0 00 00 00    	je     0x34ea1a
  34e94a:	4d 8d 46 11          	lea    r8,[r14+0x11]
  34e94e:	44 89 ff             	mov    edi,r15d
  34e951:	ba 30 92 06 00       	mov    edx,0x69230
  34e956:	b9 10 00 00 00       	mov    ecx,0x10
  34e95b:	31 f6                	xor    esi,esi
  34e95d:	e8 6e 06 35 00       	call   0x69efd0
  34e962:	84 c0                	test   al,al
  34e964:	0f 84 b0 00 00 00    	je     0x34ea1a
  34e96a:	4d 8d 46 21          	lea    r8,[r14+0x21]
  34e96e:	44 89 ff             	mov    edi,r15d
  34e971:	ba 40 92 06 00       	mov    edx,0x69240
  34e976:	b9 10 00 00 00       	mov    ecx,0x10
  34e97b:	31 f6                	xor    esi,esi
  34e97d:	e8 4e 06 35 00       	call   0x69efd0
  34e982:	84 c0                	test   al,al
  34e984:	0f 84 90 00 00 00    	je     0x34ea1a
  34e98a:	4d 8d 46 31          	lea    r8,[r14+0x31]
  34e98e:	44 89 ff             	mov    edi,r15d
  34e991:	ba 50 92 06 00       	mov    edx,0x69250
  34e996:	b9 10 00 00 00       	mov    ecx,0x10
  34e99b:	31 f6                	xor    esi,esi
  34e99d:	e8 2e 06 35 00       	call   0x69efd0
  34e9a2:	84 c0                	test   al,al
  34e9a4:	74 74                	je     0x34ea1a
  34e9a6:	4d 8d 46 41          	lea    r8,[r14+0x41]
  34e9aa:	44 89 ff             	mov    edi,r15d
  34e9ad:	ba 60 92 06 00       	mov    edx,0x69260
  34e9b2:	b9 10 00 00 00       	mov    ecx,0x10
  34e9b7:	31 f6                	xor    esi,esi
  34e9b9:	e8 12 06 35 00       	call   0x69efd0
  34e9be:	84 c0                	test   al,al
  34e9c0:	74 58                	je     0x34ea1a
  34e9c2:	4d 8d 46 51          	lea    r8,[r14+0x51]
  34e9c6:	44 89 ff             	mov    edi,r15d
  34e9c9:	ba 70 92 06 00       	mov    edx,0x69270
  34e9ce:	b9 10 00 00 00       	mov    ecx,0x10
  34e9d3:	31 f6                	xor    esi,esi
  34e9d5:	e8 f6 05 35 00       	call   0x69efd0
  34e9da:	84 c0                	test   al,al
  34e9dc:	74 3c                	je     0x34ea1a
  34e9de:	4d 8d 46 61          	lea    r8,[r14+0x61]
  34e9e2:	44 89 ff             	mov    edi,r15d
  34e9e5:	ba 80 92 06 00       	mov    edx,0x69280
  34e9ea:	b9 10 00 00 00       	mov    ecx,0x10
  34e9ef:	31 f6                	xor    esi,esi
  34e9f1:	e8 da 05 35 00       	call   0x69efd0
  34e9f6:	84 c0                	test   al,al
  34e9f8:	74 20                	je     0x34ea1a
  34e9fa:	49 83 c6 71          	add    r14,0x71
  34e9fe:	44 89 ff             	mov    edi,r15d
  34ea01:	ba 90 92 06 00       	mov    edx,0x69290
  34ea06:	b9 10 00 00 00       	mov    ecx,0x10
  34ea0b:	31 f6                	xor    esi,esi
  34ea0d:	4d 89 f0             	mov    r8,r14
  34ea10:	e8 bb 05 35 00       	call   0x69efd0
  34ea15:	34 01                	xor    al,0x1
  34ea17:	0f b6 d8             	movzx  ebx,al
  34ea1a:	89 d8                	mov    eax,ebx
  34ea1c:	48 83 c4 08          	add    rsp,0x8
  34ea20:	5b                   	pop    rbx
  34ea21:	41 5e                	pop    r14
  34ea23:	41 5f                	pop    r15
  34ea25:	5d                   	pop    rbp
  34ea26:	c3                   	ret
  34ea27:	90                   	nop
  34ea28:	90                   	nop
  34ea29:	90                   	nop
  34ea2a:	90                   	nop
  34ea2b:	90                   	nop
  34ea2c:	90                   	nop
  34ea2d:	90                   	nop
  34ea2e:	90                   	nop
  34ea2f:	90                   	nop
  34ea30:	55                   	push   rbp
  34ea31:	48 89 e5             	mov    rbp,rsp
  34ea34:	41 57                	push   r15
  34ea36:	41 56                	push   r14
  34ea38:	53                   	push   rbx
  34ea39:	50                   	push   rax
  34ea3a:	49 89 f0             	mov    r8,rsi
  34ea3d:	41 be 01 00 00 00    	mov    r14d,0x1
  34ea43:	49 ff c0             	inc    r8
  34ea46:	74 3c                	je     0x34ea84
  34ea48:	ba a0 92 06 00       	mov    edx,0x692a0
  34ea4d:	b9 10 00 00 00       	mov    ecx,0x10
  34ea52:	48 89 f3             	mov    rbx,rsi
  34ea55:	31 f6                	xor    esi,esi
  34ea57:	41 89 ff             	mov    r15d,edi
  34ea5a:	e8 71 05 35 00       	call   0x69efd0
  34ea5f:	84 c0                	test   al,al
  34ea61:	74 21                	je     0x34ea84
  34ea63:	48 83 c3 11          	add    rbx,0x11
  34ea67:	44 89 ff             	mov    edi,r15d
  34ea6a:	ba b0 92 06 00       	mov    edx,0x692b0
  34ea6f:	b9 10 00 00 00       	mov    ecx,0x10
  34ea74:	31 f6                	xor    esi,esi
  34ea76:	49 89 d8             	mov    r8,rbx
  34ea79:	e8 52 05 35 00       	call   0x69efd0
  34ea7e:	34 01                	xor    al,0x1
  34ea80:	44 0f b6 f0          	movzx  r14d,al
  34ea84:	44 89 f0             	mov    eax,r14d
  34ea87:	48 83 c4 08          	add    rsp,0x8
  34ea8b:	5b                   	pop    rbx
  34ea8c:	41 5e                	pop    r14
  34ea8e:	41 5f                	pop    r15
  34ea90:	5d                   	pop    rbp
  34ea91:	c3                   	ret
  34ea92:	90                   	nop
  34ea93:	90                   	nop
  34ea94:	90                   	nop
  34ea95:	90                   	nop
  34ea96:	90                   	nop
  34ea97:	90                   	nop
  34ea98:	90                   	nop
  34ea99:	90                   	nop
  34ea9a:	90                   	nop
  34ea9b:	90                   	nop
  34ea9c:	90                   	nop
  34ea9d:	90                   	nop
  34ea9e:	90                   	nop
  34ea9f:	90                   	nop
  34eaa0:	49 89 f0             	mov    r8,rsi
  34eaa3:	49 ff c0             	inc    r8
  34eaa6:	74 1c                	je     0x34eac4
  34eaa8:	55                   	push   rbp
  34eaa9:	48 89 e5             	mov    rbp,rsp
  34eaac:	ba f0 92 06 00       	mov    edx,0x692f0
  34eab1:	b9 08 00 00 00       	mov    ecx,0x8
  34eab6:	31 f6                	xor    esi,esi
  34eab8:	e8 13 05 35 00       	call   0x69efd0
  34eabd:	34 01                	xor    al,0x1
  34eabf:	0f b6 c0             	movzx  eax,al
  34eac2:	5d                   	pop    rbp
  34eac3:	c3                   	ret
  34eac4:	b8 01 00 00 00       	mov    eax,0x1
  34eac9:	c3                   	ret
  34eaca:	90                   	nop
  34eacb:	90                   	nop
  34eacc:	90                   	nop
  34eacd:	90                   	nop
  34eace:	90                   	nop
  34eacf:	90                   	nop
  34ead0:	55                   	push   rbp
  34ead1:	48 89 e5             	mov    rbp,rsp
  34ead4:	41 57                	push   r15
  34ead6:	41 56                	push   r14
  34ead8:	53                   	push   rbx
  34ead9:	50                   	push   rax
  34eada:	49 89 f0             	mov    r8,rsi
  34eadd:	41 be 01 00 00 00    	mov    r14d,0x1
  34eae3:	49 ff c0             	inc    r8
  34eae6:	74 3c                	je     0x34eb24
  34eae8:	ba 18 93 06 00       	mov    edx,0x69318
  34eaed:	b9 10 00 00 00       	mov    ecx,0x10
  34eaf2:	48 89 f3             	mov    rbx,rsi
  34eaf5:	31 f6                	xor    esi,esi
  34eaf7:	41 89 ff             	mov    r15d,edi
  34eafa:	e8 d1 04 35 00       	call   0x69efd0
  34eaff:	84 c0                	test   al,al
  34eb01:	74 21                	je     0x34eb24
  34eb03:	48 83 c3 11          	add    rbx,0x11
  34eb07:	44 89 ff             	mov    edi,r15d
  34eb0a:	ba 28 93 06 00       	mov    edx,0x69328
  34eb0f:	b9 08 00 00 00       	mov    ecx,0x8
  34eb14:	31 f6                	xor    esi,esi
  34eb16:	49 89 d8             	mov    r8,rbx
  34eb19:	e8 b2 04 35 00       	call   0x69efd0
  34eb1e:	34 01                	xor    al,0x1
  34eb20:	44 0f b6 f0          	movzx  r14d,al
  34eb24:	44 89 f0             	mov    eax,r14d
  34eb27:	48 83 c4 08          	add    rsp,0x8
  34eb2b:	5b                   	pop    rbx
  34eb2c:	41 5e                	pop    r14
  34eb2e:	41 5f                	pop    r15
  34eb30:	5d                   	pop    rbp
  34eb31:	c3                   	ret
  34eb32:	90                   	nop
  34eb33:	90                   	nop
  34eb34:	90                   	nop
  34eb35:	90                   	nop
  34eb36:	90                   	nop
  34eb37:	90                   	nop
  34eb38:	90                   	nop
  34eb39:	90                   	nop
  34eb3a:	90                   	nop
  34eb3b:	90                   	nop
  34eb3c:	90                   	nop
  34eb3d:	90                   	nop
  34eb3e:	90                   	nop
  34eb3f:	90                   	nop
  34eb40:	49 89 f0             	mov    r8,rsi
  34eb43:	49 ff c0             	inc    r8
  34eb46:	74 1c                	je     0x34eb64
  34eb48:	55                   	push   rbp
  34eb49:	48 89 e5             	mov    rbp,rsp
  34eb4c:	ba e0 93 06 00       	mov    edx,0x693e0
  34eb51:	b9 10 00 00 00       	mov    ecx,0x10
  34eb56:	31 f6                	xor    esi,esi
  34eb58:	e8 73 04 35 00       	call   0x69efd0
  34eb5d:	34 01                	xor    al,0x1
  34eb5f:	0f b6 c0             	movzx  eax,al
  34eb62:	5d                   	pop    rbp
  34eb63:	c3                   	ret
  34eb64:	b8 01 00 00 00       	mov    eax,0x1
  34eb69:	c3                   	ret
  34eb6a:	90                   	nop
  34eb6b:	90                   	nop
  34eb6c:	90                   	nop
  34eb6d:	90                   	nop
  34eb6e:	90                   	nop
  34eb6f:	90                   	nop
  34eb70:	49 89 f0             	mov    r8,rsi
  34eb73:	49 ff c0             	inc    r8
  34eb76:	74 1c                	je     0x34eb94
  34eb78:	55                   	push   rbp
  34eb79:	48 89 e5             	mov    rbp,rsp
  34eb7c:	ba f0 93 06 00       	mov    edx,0x693f0
  34eb81:	b9 07 00 00 00       	mov    ecx,0x7
  34eb86:	31 f6                	xor    esi,esi
  34eb88:	e8 43 04 35 00       	call   0x69efd0
  34eb8d:	34 01                	xor    al,0x1
  34eb8f:	0f b6 c0             	movzx  eax,al
  34eb92:	5d                   	pop    rbp
  34eb93:	c3                   	ret
  34eb94:	b8 01 00 00 00       	mov    eax,0x1
  34eb99:	c3                   	ret
  34eb9a:	90                   	nop
  34eb9b:	90                   	nop
  34eb9c:	90                   	nop
  34eb9d:	90                   	nop
  34eb9e:	90                   	nop
  34eb9f:	90                   	nop
  34eba0:	48 85 f6             	test   rsi,rsi
  34eba3:	74 1f                	je     0x34ebc4
  34eba5:	55                   	push   rbp
  34eba6:	48 89 e5             	mov    rbp,rsp
  34eba9:	49 89 f0             	mov    r8,rsi
  34ebac:	ba 94 94 06 00       	mov    edx,0x69494
  34ebb1:	b9 01 00 00 00       	mov    ecx,0x1
  34ebb6:	31 f6                	xor    esi,esi
  34ebb8:	e8 13 04 35 00       	call   0x69efd0
  34ebbd:	34 01                	xor    al,0x1
  34ebbf:	0f b6 c0             	movzx  eax,al
  34ebc2:	5d                   	pop    rbp
  34ebc3:	c3                   	ret
  34ebc4:	b8 01 00 00 00       	mov    eax,0x1
  34ebc9:	c3                   	ret
  34ebca:	90                   	nop
  34ebcb:	90                   	nop
  34ebcc:	90                   	nop
  34ebcd:	90                   	nop
  34ebce:	90                   	nop
  34ebcf:	90                   	nop
  34ebd0:	55                   	push   rbp
  34ebd1:	48 89 e5             	mov    rbp,rsp
  34ebd4:	41 57                	push   r15
  34ebd6:	41 56                	push   r14
  34ebd8:	41 55                	push   r13
  34ebda:	41 54                	push   r12
  34ebdc:	53                   	push   rbx
  34ebdd:	48 81 ec d8 00 00 00 	sub    rsp,0xd8
  34ebe4:	48 8d 05 25 d7 5c 03 	lea    rax,[rip+0x35cd725]        # 0x391c310
  34ebeb:	49 89 fe             	mov    r14,rdi
  34ebee:	48 8b 00             	mov    rax,QWORD PTR [rax]
  34ebf1:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34ebf5:	8b 3f                	mov    edi,DWORD PTR [rdi]
  34ebf7:	e8 e4 c5 04 00       	call   0x39b1e0
  34ebfc:	4c 8d bd 10 ff ff ff 	lea    r15,[rbp-0xf0]
  34ec03:	48 8d 1d 65 2f fa 00 	lea    rbx,[rip+0xfa2f65]        # 0x12f1b6f
  34ec0a:	4c 8d 2d bd 0a 02 01 	lea    r13,[rip+0x1020abd]        # 0x136f6ce
  34ec11:	45 31 e4             	xor    r12d,r12d
  34ec14:	eb 24                	jmp    0x34ec3a
  34ec16:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  34ec1d:	00 00 00 
  34ec20:	48 89 df             	mov    rdi,rbx
  34ec23:	4c 89 ee             	mov    rsi,r13
  34ec26:	31 c0                	xor    eax,eax
  34ec28:	e8 e3 e7 f0 ff       	call   0x25d410
  34ec2d:	41 ff c4             	inc    r12d
  34ec30:	41 83 fc 10          	cmp    r12d,0x10
  34ec34:	0f 84 d1 00 00 00    	je     0x34ed0b
  34ec3a:	41 8b 3e             	mov    edi,DWORD PTR [r14]
  34ec3d:	44 89 e6             	mov    esi,r12d
  34ec40:	e8 2b 4d f5 ff       	call   0x2a3970
  34ec45:	48 85 c0             	test   rax,rax
  34ec48:	0f 84 9f 00 00 00    	je     0x34eced
  34ec4e:	41 8b 3e             	mov    edi,DWORD PTR [r14]
  34ec51:	b9 c0 00 00 00       	mov    ecx,0xc0
  34ec56:	48 89 c6             	mov    rsi,rax
  34ec59:	4c 89 fa             	mov    rdx,r15
  34ec5c:	e8 ff 63 84 00       	call   0xb95060
  34ec61:	84 c0                	test   al,al
  34ec63:	74 bb                	je     0x34ec20
  34ec65:	83 bd 10 ff ff ff 03 	cmp    DWORD PTR [rbp-0xf0],0x3
  34ec6c:	75 bf                	jne    0x34ec2d
  34ec6e:	49 8d 7e 08          	lea    rdi,[r14+0x8]
  34ec72:	48 8d b5 18 ff ff ff 	lea    rsi,[rbp-0xe8]
  34ec79:	ba b8 00 00 00       	mov    edx,0xb8
  34ec7e:	45 89 66 04          	mov    DWORD PTR [r14+0x4],r12d
  34ec82:	e8 29 a4 f0 ff       	call   0x2590b0
  34ec87:	45 8b 36             	mov    r14d,DWORD PTR [r14]
  34ec8a:	44 89 f7             	mov    edi,r14d
  34ec8d:	e8 9e 4c f5 ff       	call   0x2a3930
  34ec92:	48 85 c0             	test   rax,rax
  34ec95:	0f 84 83 00 00 00    	je     0x34ed1e
  34ec9b:	49 89 c7             	mov    r15,rax
  34ec9e:	48 8d 95 08 ff ff ff 	lea    rdx,[rbp-0xf8]
  34eca5:	b9 08 00 00 00       	mov    ecx,0x8
  34ecaa:	44 89 f7             	mov    edi,r14d
  34ecad:	49 83 c7 30          	add    r15,0x30
  34ecb1:	4c 89 fe             	mov    rsi,r15
  34ecb4:	e8 a7 63 84 00       	call   0xb95060
  34ecb9:	4c 8d 25 50 d6 5c 03 	lea    r12,[rip+0x35cd650]        # 0x391c310
  34ecc0:	84 c0                	test   al,al
  34ecc2:	74 7f                	je     0x34ed43
  34ecc4:	48 ff 85 08 ff ff ff 	inc    QWORD PTR [rbp-0xf8]
  34eccb:	48 8d 95 08 ff ff ff 	lea    rdx,[rbp-0xf8]
  34ecd2:	b9 08 00 00 00       	mov    ecx,0x8
  34ecd7:	44 89 f7             	mov    edi,r14d
  34ecda:	4c 89 fe             	mov    rsi,r15
  34ecdd:	e8 de 64 84 00       	call   0xb951c0
  34ece2:	84 c0                	test   al,al
  34ece4:	74 56                	je     0x34ed3c
  34ece6:	31 c0                	xor    eax,eax
  34ece8:	e9 86 00 00 00       	jmp    0x34ed73
  34eced:	48 8d 3d 95 e6 f1 00 	lea    rdi,[rip+0xf1e695]        # 0x126d389
  34ecf4:	48 8d 35 d3 09 02 01 	lea    rsi,[rip+0x10209d3]        # 0x136f6ce
  34ecfb:	31 c0                	xor    eax,eax
  34ecfd:	e8 0e e7 f0 ff       	call   0x25d410
  34ed02:	4c 8d 25 07 d6 5c 03 	lea    r12,[rip+0x35cd607]        # 0x391c310
  34ed09:	eb 63                	jmp    0x34ed6e
  34ed0b:	4c 8d 25 fe d5 5c 03 	lea    r12,[rip+0x35cd5fe]        # 0x391c310
  34ed12:	41 c7 46 04 ff ff ff 	mov    DWORD PTR [r14+0x4],0xffffffff
  34ed19:	ff 
  34ed1a:	31 c0                	xor    eax,eax
  34ed1c:	eb 55                	jmp    0x34ed73
  34ed1e:	48 8d 3d 8d c3 fa 00 	lea    rdi,[rip+0xfac38d]        # 0x12fb0b2
  34ed25:	48 8d 35 01 06 f5 00 	lea    rsi,[rip+0xf50601]        # 0x129f32d
  34ed2c:	31 c0                	xor    eax,eax
  34ed2e:	e8 dd e6 f0 ff       	call   0x25d410
  34ed33:	4c 8d 25 d6 d5 5c 03 	lea    r12,[rip+0x35cd5d6]        # 0x391c310
  34ed3a:	eb 18                	jmp    0x34ed54
  34ed3c:	48 8d 1d b7 e6 f1 00 	lea    rbx,[rip+0xf1e6b7]        # 0x126d3fa
  34ed43:	48 8d 35 e3 05 f5 00 	lea    rsi,[rip+0xf505e3]        # 0x129f32d
  34ed4a:	48 89 df             	mov    rdi,rbx
  34ed4d:	31 c0                	xor    eax,eax
  34ed4f:	e8 bc e6 f0 ff       	call   0x25d410
  34ed54:	48 8d 3d 63 e6 f1 00 	lea    rdi,[rip+0xf1e663]        # 0x126d3be
  34ed5b:	48 8d 35 6c 09 02 01 	lea    rsi,[rip+0x102096c]        # 0x136f6ce
  34ed62:	ba 01 00 00 00       	mov    edx,0x1
  34ed67:	31 c0                	xor    eax,eax
  34ed69:	e8 a2 e6 f0 ff       	call   0x25d410
  34ed6e:	b8 01 00 00 00       	mov    eax,0x1
  34ed73:	49 8b 0c 24          	mov    rcx,QWORD PTR [r12]
  34ed77:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  34ed7b:	75 12                	jne    0x34ed8f
  34ed7d:	48 81 c4 d8 00 00 00 	add    rsp,0xd8
  34ed84:	5b                   	pop    rbx
  34ed85:	41 5c                	pop    r12
  34ed87:	41 5d                	pop    r13
  34ed89:	41 5e                	pop    r14
  34ed8b:	41 5f                	pop    r15
  34ed8d:	5d                   	pop    rbp
  34ed8e:	c3                   	ret
  34ed8f:	e8 1c e9 3a 00       	call   0x6fd6b0
  34ed94:	0f 0b                	ud2
  34ed96:	90                   	nop
  34ed97:	90                   	nop
  34ed98:	90                   	nop
  34ed99:	90                   	nop
  34ed9a:	90                   	nop
  34ed9b:	90                   	nop
  34ed9c:	90                   	nop
  34ed9d:	90                   	nop
  34ed9e:	90                   	nop
  34ed9f:	90                   	nop
  34eda0:	55                   	push   rbp
  34eda1:	48 89 e5             	mov    rbp,rsp
  34eda4:	41 57                	push   r15
  34eda6:	41 56                	push   r14
  34eda8:	53                   	push   rbx
  34eda9:	48 83 ec 18          	sub    rsp,0x18
  34edad:	4c 8d 3d 5c d5 5c 03 	lea    r15,[rip+0x35cd55c]        # 0x391c310
  34edb4:	49 8b 07             	mov    rax,QWORD PTR [r15]
  34edb7:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  34edbb:	b8 16 00 00 00       	mov    eax,0x16
  34edc0:	8b 77 04             	mov    esi,DWORD PTR [rdi+0x4]
  34edc3:	83 fe 0f             	cmp    esi,0xf
  34edc6:	0f 87 de 00 00 00    	ja     0x34eeaa
  34edcc:	48 89 fb             	mov    rbx,rdi
  34edcf:	8b 3f                	mov    edi,DWORD PTR [rdi]
  34edd1:	e8 9a 4b f5 ff       	call   0x2a3970
  34edd6:	48 85 c0             	test   rax,rax
  34edd9:	74 69                	je     0x34ee44
  34eddb:	c7 45 d4 02 00 00 00 	mov    DWORD PTR [rbp-0x2c],0x2
  34ede2:	48 8d 55 d4          	lea    rdx,[rbp-0x2c]
  34ede6:	b9 04 00 00 00       	mov    ecx,0x4
  34edeb:	48 89 c6             	mov    rsi,rax
  34edee:	8b 3b                	mov    edi,DWORD PTR [rbx]
  34edf0:	e8 cb 63 84 00       	call   0xb951c0
  34edf5:	84 c0                	test   al,al
  34edf7:	74 54                	je     0x34ee4d
  34edf9:	8b 1b                	mov    ebx,DWORD PTR [rbx]
  34edfb:	89 df                	mov    edi,ebx
  34edfd:	e8 2e 4b f5 ff       	call   0x2a3930
  34ee02:	48 85 c0             	test   rax,rax
  34ee05:	74 5d                	je     0x34ee64
  34ee07:	49 89 c6             	mov    r14,rax
  34ee0a:	48 8d 55 d8          	lea    rdx,[rbp-0x28]
  34ee0e:	b9 08 00 00 00       	mov    ecx,0x8
  34ee13:	89 df                	mov    edi,ebx
  34ee15:	49 83 c6 38          	add    r14,0x38
  34ee19:	4c 89 f6             	mov    rsi,r14
  34ee1c:	e8 3f 62 84 00       	call   0xb95060
  34ee21:	84 c0                	test   al,al
  34ee23:	74 48                	je     0x34ee6d
  34ee25:	48 ff 45 d8          	inc    QWORD PTR [rbp-0x28]
  34ee29:	48 8d 55 d8          	lea    rdx,[rbp-0x28]
  34ee2d:	b9 08 00 00 00       	mov    ecx,0x8
  34ee32:	89 df                	mov    edi,ebx
  34ee34:	4c 89 f6             	mov    rsi,r14
  34ee37:	e8 84 63 84 00       	call   0xb951c0
  34ee3c:	84 c0                	test   al,al
  34ee3e:	74 36                	je     0x34ee76
  34ee40:	31 c0                	xor    eax,eax
  34ee42:	eb 66                	jmp    0x34eeaa
  34ee44:	48 8d 3d 3e e5 f1 00 	lea    rdi,[rip+0xf1e53e]        # 0x126d389
  34ee4b:	eb 07                	jmp    0x34ee54
  34ee4d:	48 8d 3d a6 e5 f1 00 	lea    rdi,[rip+0xf1e5a6]        # 0x126d3fa
  34ee54:	48 8d 35 30 2d fa 00 	lea    rsi,[rip+0xfa2d30]        # 0x12f1b8b
  34ee5b:	31 c0                	xor    eax,eax
  34ee5d:	e8 ae e5 f0 ff       	call   0x25d410
  34ee62:	eb 41                	jmp    0x34eea5
  34ee64:	48 8d 3d 47 c2 fa 00 	lea    rdi,[rip+0xfac247]        # 0x12fb0b2
  34ee6b:	eb 10                	jmp    0x34ee7d
  34ee6d:	48 8d 3d fb 2c fa 00 	lea    rdi,[rip+0xfa2cfb]        # 0x12f1b6f
  34ee74:	eb 07                	jmp    0x34ee7d
  34ee76:	48 8d 3d 7d e5 f1 00 	lea    rdi,[rip+0xf1e57d]        # 0x126d3fa
  34ee7d:	48 8d 35 a9 04 f5 00 	lea    rsi,[rip+0xf504a9]        # 0x129f32d
  34ee84:	31 c0                	xor    eax,eax
  34ee86:	e8 85 e5 f0 ff       	call   0x25d410
  34ee8b:	48 8d 3d 2c e5 f1 00 	lea    rdi,[rip+0xf1e52c]        # 0x126d3be
  34ee92:	48 8d 35 f2 2c fa 00 	lea    rsi,[rip+0xfa2cf2]        # 0x12f1b8b
  34ee99:	ba 01 00 00 00       	mov    edx,0x1
  34ee9e:	31 c0                	xor    eax,eax
  34eea0:	e8 6b e5 f0 ff       	call   0x25d410
  34eea5:	b8 01 00 00 00       	mov    eax,0x1
  34eeaa:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  34eead:	48 3b 4d e0          	cmp    rcx,QWORD PTR [rbp-0x20]
  34eeb1:	75 0b                	jne    0x34eebe
  34eeb3:	48 83 c4 18          	add    rsp,0x18
  34eeb7:	5b                   	pop    rbx
  34eeb8:	41 5e                	pop    r14
  34eeba:	41 5f                	pop    r15
  34eebc:	5d                   	pop    rbp
  34eebd:	c3                   	ret
  34eebe:	e8 ed e7 3a 00       	call   0x6fd6b0
  34eec3:	0f 0b                	ud2
  34eec5:	90                   	nop
  34eec6:	90                   	nop
  34eec7:	90                   	nop
  34eec8:	90                   	nop
  34eec9:	90                   	nop
  34eeca:	90                   	nop
  34eecb:	90                   	nop
  34eecc:	90                   	nop
  34eecd:	90                   	nop
  34eece:	90                   	nop
  34eecf:	90                   	nop
  34eed0:	55                   	push   rbp
  34eed1:	48 89 e5             	mov    rbp,rsp
  34eed4:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  34eedb:	00 00 
  34eedd:	48 8b b8 40 01 00 00 	mov    rdi,QWORD PTR [rax+0x140]
  34eee4:	e8 b7 77 8e 00       	call   0xc366a0
  34eee9:	85 c0                	test   eax,eax
  34eeeb:	74 23                	je     0x34ef10
  34eeed:	48 8d 3d 04 05 11 03 	lea    rdi,[rip+0x3110504]        # 0x345f3f8
  34eef4:	be 18 00 00 00       	mov    esi,0x18
  34eef9:	e8 f2 a0 f0 ff       	call   0x258ff0
  34eefe:	48 8d 3d 0b 05 11 03 	lea    rdi,[rip+0x311050b]        # 0x345f410
  34ef05:	be 18 00 00 00       	mov    esi,0x18
  34ef0a:	5d                   	pop    rbp
  34ef0b:	e9 e0 a0 f0 ff       	jmp    0x258ff0
  34ef10:	5d                   	pop    rbp
  34ef11:	c3                   	ret
  34ef12:	90                   	nop
  34ef13:	90                   	nop
  34ef14:	90                   	nop
  34ef15:	90                   	nop
  34ef16:	90                   	nop
  34ef17:	90                   	nop
  34ef18:	90                   	nop
  34ef19:	90                   	nop
  34ef1a:	90                   	nop
  34ef1b:	90                   	nop
  34ef1c:	90                   	nop
  34ef1d:	90                   	nop
  34ef1e:	90                   	nop
  34ef1f:	90                   	nop
  34ef20:	55                   	push   rbp
  34ef21:	48 89 e5             	mov    rbp,rsp
  34ef24:	48 8d 35 cd 04 11 03 	lea    rsi,[rip+0x31104cd]        # 0x345f3f8
  34ef2b:	ba 18 00 00 00       	mov    edx,0x18
  34ef30:	5d                   	pop    rbp
  34ef31:	e9 7a a1 f0 ff       	jmp    0x2590b0
  34ef36:	90                   	nop
  34ef37:	90                   	nop
  34ef38:	90                   	nop
  34ef39:	90                   	nop
  34ef3a:	90                   	nop
  34ef3b:	90                   	nop
  34ef3c:	90                   	nop
  34ef3d:	90                   	nop
  34ef3e:	90                   	nop
  34ef3f:	90                   	nop
  34ef40:	55                   	push   rbp
  34ef41:	48 89 e5             	mov    rbp,rsp
  34ef44:	48 8d 35 c5 04 11 03 	lea    rsi,[rip+0x31104c5]        # 0x345f410
  34ef4b:	ba 18 00 00 00       	mov    edx,0x18
  34ef50:	5d                   	pop    rbp
  34ef51:	e9 5a a1 f0 ff       	jmp    0x2590b0
  34ef56:	90                   	nop
  34ef57:	90                   	nop
  34ef58:	90                   	nop
  34ef59:	90                   	nop
  34ef5a:	90                   	nop
  34ef5b:	90                   	nop
  34ef5c:	90                   	nop
  34ef5d:	90                   	nop
  34ef5e:	90                   	nop
  34ef5f:	90                   	nop
  34ef60:	55                   	push   rbp
  34ef61:	48 89 e5             	mov    rbp,rsp
  34ef64:	f6 87 10 05 00 00 01 	test   BYTE PTR [rdi+0x510],0x1
  34ef6b:	0f 84 ab 00 00 00    	je     0x34f01c
  34ef71:	83 3d b0 04 11 03 00 	cmp    DWORD PTR [rip+0x31104b0],0x0        # 0x345f428
  34ef78:	74 10                	je     0x34ef8a
  34ef7a:	48 c7 87 30 04 00 00 	mov    QWORD PTR [rdi+0x430],0x0
  34ef81:	00 00 00 00 
  34ef85:	e9 87 00 00 00       	jmp    0x34f011
  34ef8a:	48 8b 97 30 04 00 00 	mov    rdx,QWORD PTR [rdi+0x430]
  34ef91:	48 be 17 fc ff ff e7 	movabs rsi,0x3e7fffffc17
  34ef98:	03 00 00 
  34ef9b:	b8 ff ff ff ff       	mov    eax,0xffffffff
  34efa0:	48 b9 cf f7 53 e3 a5 	movabs rcx,0x20c49ba5e353f7cf
  34efa7:	9b c4 20 
  34efaa:	41 b8 ff ff ff ff    	mov    r8d,0xffffffff
  34efb0:	48 c1 e2 03          	shl    rdx,0x3
  34efb4:	48 39 f2             	cmp    rdx,rsi
  34efb7:	77 0d                	ja     0x34efc6
  34efb9:	48 c1 ea 03          	shr    rdx,0x3
  34efbd:	c4 62 bb f6 c1       	mulx   r8,r8,rcx
  34efc2:	49 c1 e8 04          	shr    r8,0x4
  34efc6:	8b 97 28 04 00 00    	mov    edx,DWORD PTR [rdi+0x428]
  34efcc:	49 39 d0             	cmp    r8,rdx
  34efcf:	76 07                	jbe    0x34efd8
  34efd1:	44 89 87 28 04 00 00 	mov    DWORD PTR [rdi+0x428],r8d
  34efd8:	48 c7 87 30 04 00 00 	mov    QWORD PTR [rdi+0x430],0x0
  34efdf:	00 00 00 00 
  34efe3:	48 8b 97 38 04 00 00 	mov    rdx,QWORD PTR [rdi+0x438]
  34efea:	48 c1 e2 03          	shl    rdx,0x3
  34efee:	48 39 f2             	cmp    rdx,rsi
  34eff1:	77 0d                	ja     0x34f000
  34eff3:	48 c1 ea 03          	shr    rdx,0x3
  34eff7:	c4 e2 fb f6 c1       	mulx   rax,rax,rcx
  34effc:	48 c1 e8 04          	shr    rax,0x4
  34f000:	8b 8f 2c 04 00 00    	mov    ecx,DWORD PTR [rdi+0x42c]
  34f006:	48 39 c8             	cmp    rax,rcx
  34f009:	76 06                	jbe    0x34f011
  34f00b:	89 87 2c 04 00 00    	mov    DWORD PTR [rdi+0x42c],eax
  34f011:	48 c7 87 38 04 00 00 	mov    QWORD PTR [rdi+0x438],0x0
  34f018:	00 00 00 00 
  34f01c:	5d                   	pop    rbp
  34f01d:	c3                   	ret
  34f01e:	90                   	nop
  34f01f:	90                   	nop
  34f020:	55                   	push   rbp
  34f021:	48 89 e5             	mov    rbp,rsp
  34f024:	f6 47 1f 20          	test   BYTE PTR [rdi+0x1f],0x20
  34f028:	74 3d                	je     0x34f067
  34f02a:	39 ca                	cmp    edx,ecx
  34f02c:	b8 01 00 00 00       	mov    eax,0x1
  34f031:	40 0f 9e c7          	setle  dil
  34f035:	85 c9                	test   ecx,ecx
  34f037:	41 0f 9e c0          	setle  r8b
  34f03b:	41 08 f8             	or     r8b,dil
  34f03e:	75 11                	jne    0x34f051
  34f040:	89 d0                	mov    eax,edx
  34f042:	89 d7                	mov    edi,edx
  34f044:	99                   	cdq
  34f045:	f7 f9                	idiv   ecx
  34f047:	89 d1                	mov    ecx,edx
  34f049:	89 fa                	mov    edx,edi
  34f04b:	83 f9 01             	cmp    ecx,0x1
  34f04e:	83 d8 ff             	sbb    eax,0xffffffff
  34f051:	48 63 ca             	movsxd rcx,edx
  34f054:	01 86 20 04 00 00    	add    DWORD PTR [rsi+0x420],eax
  34f05a:	01 86 18 04 00 00    	add    DWORD PTR [rsi+0x418],eax
  34f060:	48 01 8e 38 04 00 00 	add    QWORD PTR [rsi+0x438],rcx
  34f067:	5d                   	pop    rbp
  34f068:	c3                   	ret
  34f069:	90                   	nop
  34f06a:	90                   	nop
  34f06b:	90                   	nop
  34f06c:	90                   	nop
  34f06d:	90                   	nop
  34f06e:	90                   	nop
  34f06f:	90                   	nop
  34f070:	55                   	push   rbp
  34f071:	48 89 e5             	mov    rbp,rsp
  34f074:	83 3d ad 03 11 03 00 	cmp    DWORD PTR [rip+0x31103ad],0x0        # 0x345f428
  34f07b:	74 0d                	je     0x34f08a
  34f07d:	48 c7 87 1c 04 00 00 	mov    QWORD PTR [rdi+0x41c],0x0
  34f084:	00 00 00 00 
  34f088:	5d                   	pop    rbp
  34f089:	c3                   	ret
  34f08a:	8b 87 1c 04 00 00    	mov    eax,DWORD PTR [rdi+0x41c]
  34f090:	39 87 0c 04 00 00    	cmp    DWORD PTR [rdi+0x40c],eax
  34f096:	73 06                	jae    0x34f09e
  34f098:	89 87 0c 04 00 00    	mov    DWORD PTR [rdi+0x40c],eax
  34f09e:	c7 87 1c 04 00 00 00 	mov    DWORD PTR [rdi+0x41c],0x0
  34f0a5:	00 00 00 
  34f0a8:	8b 87 20 04 00 00    	mov    eax,DWORD PTR [rdi+0x420]
  34f0ae:	39 87 10 04 00 00    	cmp    DWORD PTR [rdi+0x410],eax
  34f0b4:	73 06                	jae    0x34f0bc
  34f0b6:	89 87 10 04 00 00    	mov    DWORD PTR [rdi+0x410],eax
  34f0bc:	c7 87 20 04 00 00 00 	mov    DWORD PTR [rdi+0x420],0x0
  34f0c3:	00 00 00 
  34f0c6:	5d                   	pop    rbp
  34f0c7:	c3                   	ret
  34f0c8:	90                   	nop
  34f0c9:	90                   	nop
  34f0ca:	90                   	nop
  34f0cb:	90                   	nop
  34f0cc:	90                   	nop
  34f0cd:	90                   	nop
  34f0ce:	90                   	nop
  34f0cf:	90                   	nop
  34f0d0:	55                   	push   rbp
  34f0d1:	48 89 e5             	mov    rbp,rsp
  34f0d4:	41 57                	push   r15
  34f0d6:	41 56                	push   r14
  34f0d8:	41 54                	push   r12
  34f0da:	53                   	push   rbx
  34f0db:	48 81 ec d0 00 00 00 	sub    rsp,0xd0
  34f0e2:	4c 8d 25 27 d2 5c 03 	lea    r12,[rip+0x35cd227]        # 0x391c310
  34f0e9:	48 8d 35 90 cf 8a 02 	lea    rsi,[rip+0x28acf90]        # 0x2bfc080
  34f0f0:	49 89 fe             	mov    r14,rdi
  34f0f3:	bf 38 0a 00 00       	mov    edi,0xa38
  34f0f8:	ba 01 01 00 00       	mov    edx,0x101
  34f0fd:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  34f101:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  34f105:	e8 46 9a 8b 00       	call   0xc08b50
  34f10a:	48 85 c0             	test   rax,rax
  34f10d:	0f 84 30 01 00 00    	je     0x34f243
  34f113:	41 8b be bc 00 00 00 	mov    edi,DWORD PTR [r14+0xbc]
  34f11a:	48 89 c3             	mov    rbx,rax
  34f11d:	31 f6                	xor    esi,esi
  34f11f:	31 d2                	xor    edx,edx
  34f121:	31 c9                	xor    ecx,ecx
  34f123:	89 7b 10             	mov    DWORD PTR [rbx+0x10],edi
  34f126:	48 8d 3d 1b 03 11 03 	lea    rdi,[rip+0x311031b]        # 0x345f448
  34f12d:	e8 ce 78 17 00       	call   0x4c6a00
  34f132:	48 8b 05 17 03 11 03 	mov    rax,QWORD PTR [rip+0x3110317]        # 0x345f450
  34f139:	48 89 03             	mov    QWORD PTR [rbx],rax
  34f13c:	48 85 c0             	test   rax,rax
  34f13f:	74 04                	je     0x34f145
  34f141:	48 89 58 08          	mov    QWORD PTR [rax+0x8],rbx
  34f145:	48 8d 05 04 03 11 03 	lea    rax,[rip+0x3110304]        # 0x345f450
  34f14c:	48 8d 3d f5 02 11 03 	lea    rdi,[rip+0x31102f5]        # 0x345f448
  34f153:	48 89 1d f6 02 11 03 	mov    QWORD PTR [rip+0x31102f6],rbx        # 0x345f450
  34f15a:	31 f6                	xor    esi,esi
  34f15c:	31 d2                	xor    edx,edx
  34f15e:	31 c9                	xor    ecx,ecx
  34f160:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
  34f164:	31 db                	xor    ebx,ebx
  34f166:	e8 35 7e 17 00       	call   0x4c6fa0
  34f16b:	4c 8d bd 38 ff ff ff 	lea    r15,[rbp-0xc8]
  34f172:	48 8d 35 e7 02 11 03 	lea    rsi,[rip+0x31102e7]        # 0x345f460
  34f179:	ba a0 00 00 00       	mov    edx,0xa0
  34f17e:	4c 89 ff             	mov    rdi,r15
  34f181:	e8 2a 9f f0 ff       	call   0x2590b0
  34f186:	80 8d 3e ff ff ff 02 	or     BYTE PTR [rbp-0xc2],0x2
  34f18d:	4c 89 fe             	mov    rsi,r15
  34f190:	ba 01 00 00 00       	mov    edx,0x1
  34f195:	65 4c 8b 34 25 00 00 	mov    r14,QWORD PTR gs:0x0
  34f19c:	00 00 
  34f19e:	4c 89 f7             	mov    rdi,r14
  34f1a1:	e8 ca 00 00 00       	call   0x34f270
  34f1a6:	48 8d bd 18 ff ff ff 	lea    rdi,[rbp-0xe8]
  34f1ad:	be 20 00 00 00       	mov    esi,0x20
  34f1b2:	e8 39 9e f0 ff       	call   0x258ff0
  34f1b7:	c7 85 18 ff ff ff 00 	mov    DWORD PTR [rbp-0xe8],0x0
  34f1be:	00 00 00 
  34f1c1:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  34f1c8:	e8 03 75 8e 00       	call   0xc366d0
  34f1cd:	b9 1d 00 00 00       	mov    ecx,0x1d
  34f1d2:	85 c0                	test   eax,eax
  34f1d4:	75 1b                	jne    0x34f1f1
  34f1d6:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  34f1dd:	e8 2e 75 8e 00       	call   0xc36710
  34f1e2:	85 c0                	test   eax,eax
  34f1e4:	b8 10 00 00 00       	mov    eax,0x10
  34f1e9:	b9 1d 00 00 00       	mov    ecx,0x1d
  34f1ee:	0f 44 c8             	cmove  ecx,eax
  34f1f1:	48 8d b5 18 ff ff ff 	lea    rsi,[rbp-0xe8]
  34f1f8:	4c 89 f7             	mov    rdi,r14
  34f1fb:	89 8d 1c ff ff ff    	mov    DWORD PTR [rbp-0xe4],ecx
  34f201:	e8 ea 06 00 00       	call   0x34f8f0
  34f206:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  34f20d:	00 00 
  34f20f:	48 8b b8 40 01 00 00 	mov    rdi,QWORD PTR [rax+0x140]
  34f216:	e8 85 74 8e 00       	call   0xc366a0
  34f21b:	85 c0                	test   eax,eax
  34f21d:	74 29                	je     0x34f248
  34f21f:	48 8d 3d d2 01 11 03 	lea    rdi,[rip+0x31101d2]        # 0x345f3f8
  34f226:	be 18 00 00 00       	mov    esi,0x18
  34f22b:	e8 c0 9d f0 ff       	call   0x258ff0
  34f230:	48 8d 3d d9 01 11 03 	lea    rdi,[rip+0x31101d9]        # 0x345f410
  34f237:	be 18 00 00 00       	mov    esi,0x18
  34f23c:	e8 af 9d f0 ff       	call   0x258ff0
  34f241:	eb 05                	jmp    0x34f248
  34f243:	bb 0c 00 00 00       	mov    ebx,0xc
  34f248:	49 8b 04 24          	mov    rax,QWORD PTR [r12]
  34f24c:	48 3b 45 d8          	cmp    rax,QWORD PTR [rbp-0x28]
  34f250:	75 12                	jne    0x34f264
  34f252:	89 d8                	mov    eax,ebx
  34f254:	48 81 c4 d0 00 00 00 	add    rsp,0xd0
  34f25b:	5b                   	pop    rbx
  34f25c:	41 5c                	pop    r12
  34f25e:	41 5e                	pop    r14
  34f260:	41 5f                	pop    r15
  34f262:	5d                   	pop    rbp
  34f263:	c3                   	ret
  34f264:	e8 47 e4 3a 00       	call   0x6fd6b0
  34f269:	0f 0b                	ud2
  34f26b:	90                   	nop
  34f26c:	90                   	nop
  34f26d:	90                   	nop
  34f26e:	90                   	nop
  34f26f:	90                   	nop
  34f270:	55                   	push   rbp
  34f271:	48 89 e5             	mov    rbp,rsp
  34f274:	41 57                	push   r15
  34f276:	41 56                	push   r14
  34f278:	41 55                	push   r13
  34f27a:	41 54                	push   r12
  34f27c:	53                   	push   rbx
  34f27d:	48 83 ec 28          	sub    rsp,0x28
  34f281:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
  34f285:	49 89 fe             	mov    r14,rdi
  34f288:	41 89 d4             	mov    r12d,edx
  34f28b:	49 89 f7             	mov    r15,rsi
  34f28e:	31 ff                	xor    edi,edi
  34f290:	8b 98 bc 00 00 00    	mov    ebx,DWORD PTR [rax+0xbc]
  34f296:	e8 05 d7 77 00       	call   0xacc9a0
  34f29b:	85 c0                	test   eax,eax
  34f29d:	75 14                	jne    0x34f2b3
  34f29f:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  34f2a6:	e8 65 74 8e 00       	call   0xc36710
  34f2ab:	85 c0                	test   eax,eax
  34f2ad:	0f 84 6a 01 00 00    	je     0x34f41d
  34f2b3:	45 85 e4             	test   r12d,r12d
  34f2b6:	75 1d                	jne    0x34f2d5
  34f2b8:	f6 05 ad 01 11 03 01 	test   BYTE PTR [rip+0x31101ad],0x1        # 0x345f46c
  34f2bf:	74 14                	je     0x34f2d5
  34f2c1:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  34f2c8:	e8 43 74 8e 00       	call   0xc36710
  34f2cd:	85 c0                	test   eax,eax
  34f2cf:	0f 84 48 01 00 00    	je     0x34f41d
  34f2d5:	41 83 bf 90 00 00 00 	cmp    DWORD PTR [r15+0x90],0x0
  34f2dc:	00 
  34f2dd:	41 8b 4f 04          	mov    ecx,DWORD PTR [r15+0x4]
  34f2e1:	44 89 65 b8          	mov    DWORD PTR [rbp-0x48],r12d
  34f2e5:	89 4d c8             	mov    DWORD PTR [rbp-0x38],ecx
  34f2e8:	74 0f                	je     0x34f2f9
  34f2ea:	4d 89 fd             	mov    r13,r15
  34f2ed:	41 89 cf             	mov    r15d,ecx
  34f2f0:	41 81 e7 00 00 00 01 	and    r15d,0x1000000
  34f2f7:	eb 29                	jmp    0x34f322
  34f2f9:	41 83 7f 08 00       	cmp    DWORD PTR [r15+0x8],0x0
  34f2fe:	4d 89 fd             	mov    r13,r15
  34f301:	41 89 cf             	mov    r15d,ecx
  34f304:	41 bc 16 00 00 00    	mov    r12d,0x16
  34f30a:	0f 94 c0             	sete   al
  34f30d:	41 81 e7 00 00 00 01 	and    r15d,0x1000000
  34f314:	0f 94 c1             	sete   cl
  34f317:	08 c1                	or     cl,al
  34f319:	80 f9 01             	cmp    cl,0x1
  34f31c:	0f 85 57 02 00 00    	jne    0x34f579
  34f322:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  34f329:	e8 a2 73 8e 00       	call   0xc366d0
  34f32e:	85 c0                	test   eax,eax
  34f330:	41 bc 16 00 00 00    	mov    r12d,0x16
  34f336:	0f 95 c0             	setne  al
  34f339:	45 85 ff             	test   r15d,r15d
  34f33c:	0f 94 c1             	sete   cl
  34f33f:	20 c1                	and    cl,al
  34f341:	0f b6 c1             	movzx  eax,cl
  34f344:	8d 04 85 0f 00 00 00 	lea    eax,[rax*4+0xf]
  34f34b:	41 39 45 08          	cmp    DWORD PTR [r13+0x8],eax
  34f34f:	0f 87 24 02 00 00    	ja     0x34f579
  34f355:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  34f35c:	e8 6f 73 8e 00       	call   0xc366d0
  34f361:	85 c0                	test   eax,eax
  34f363:	0f 84 ca 00 00 00    	je     0x34f433
  34f369:	48 8d 3d d8 00 11 03 	lea    rdi,[rip+0x31100d8]        # 0x345f448
  34f370:	44 89 7d cc          	mov    DWORD PTR [rbp-0x34],r15d
  34f374:	31 f6                	xor    esi,esi
  34f376:	31 d2                	xor    edx,edx
  34f378:	31 c9                	xor    ecx,ecx
  34f37a:	e8 81 76 17 00       	call   0x4c6a00
  34f37f:	4c 8d 3d ca 00 11 03 	lea    r15,[rip+0x31100ca]        # 0x345f450
  34f386:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  34f38d:	00 00 00 
  34f390:	4d 8b 3f             	mov    r15,QWORD PTR [r15]
  34f393:	4d 85 ff             	test   r15,r15
  34f396:	0f 84 8c 00 00 00    	je     0x34f428
  34f39c:	41 39 5f 10          	cmp    DWORD PTR [r15+0x10],ebx
  34f3a0:	75 ee                	jne    0x34f390
  34f3a2:	41 8b 5d 08          	mov    ebx,DWORD PTR [r13+0x8]
  34f3a6:	45 0f b7 65 00       	movzx  r12d,WORD PTR [r13+0x0]
  34f3ab:	48 8d 15 4e 01 11 03 	lea    rdx,[rip+0x311014e]        # 0x345f500
  34f3b2:	4c 89 ef             	mov    rdi,r13
  34f3b5:	8d 43 f0             	lea    eax,[rbx-0x10]
  34f3b8:	48 8d 0c 9b          	lea    rcx,[rbx+rbx*4]
  34f3bc:	48 8d 04 80          	lea    rax,[rax+rax*4]
  34f3c0:	48 c1 e1 05          	shl    rcx,0x5
  34f3c4:	48 c1 e0 05          	shl    rax,0x5
  34f3c8:	49 8d 4c 0f 14       	lea    rcx,[r15+rcx*1+0x14]
  34f3cd:	48 01 d0             	add    rax,rdx
  34f3d0:	83 fb 10             	cmp    ebx,0x10
  34f3d3:	48 0f 43 c8          	cmovae rcx,rax
  34f3d7:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
  34f3db:	45 85 e4             	test   r12d,r12d
  34f3de:	0f 84 89 00 00 00    	je     0x34f46d
  34f3e4:	8b 87 90 00 00 00    	mov    eax,DWORD PTR [rdi+0x90]
  34f3ea:	be a0 00 00 00       	mov    esi,0xa0
  34f3ef:	49 89 fd             	mov    r13,rdi
  34f3f2:	89 45 c0             	mov    DWORD PTR [rbp-0x40],eax
  34f3f5:	e8 f6 9b f0 ff       	call   0x258ff0
  34f3fa:	41 83 fc 03          	cmp    r12d,0x3
  34f3fe:	74 53                	je     0x34f453
  34f400:	41 83 fc 02          	cmp    r12d,0x2
  34f404:	74 40                	je     0x34f446
  34f406:	41 83 fc 01          	cmp    r12d,0x1
  34f40a:	0f 85 7b 01 00 00    	jne    0x34f58b
  34f410:	4c 89 ef             	mov    rdi,r13
  34f413:	41 c7 45 16 64 00 00 	mov    DWORD PTR [r13+0x16],0x64
  34f41a:	00 
  34f41b:	eb 40                	jmp    0x34f45d
  34f41d:	41 bc 2d 00 00 00    	mov    r12d,0x2d
  34f423:	e9 51 01 00 00       	jmp    0x34f579
  34f428:	41 bc 0c 00 00 00    	mov    r12d,0xc
  34f42e:	e9 34 01 00 00       	jmp    0x34f567
  34f433:	41 83 bd 90 00 00 00 	cmp    DWORD PTR [r13+0x90],0x0
  34f43a:	00 
  34f43b:	0f 85 38 01 00 00    	jne    0x34f579
  34f441:	e9 23 ff ff ff       	jmp    0x34f369
  34f446:	4c 89 ef             	mov    rdi,r13
  34f449:	41 c7 45 20 00 00 02 	mov    DWORD PTR [r13+0x20],0x20000
  34f450:	00 
  34f451:	eb 0a                	jmp    0x34f45d
  34f453:	4c 89 ef             	mov    rdi,r13
  34f456:	66 41 c7 45 10 05 00 	mov    WORD PTR [r13+0x10],0x5
  34f45d:	8b 45 c0             	mov    eax,DWORD PTR [rbp-0x40]
  34f460:	66 44 89 27          	mov    WORD PTR [rdi],r12w
  34f464:	89 5f 08             	mov    DWORD PTR [rdi+0x8],ebx
  34f467:	89 87 90 00 00 00    	mov    DWORD PTR [rdi+0x90],eax
  34f46d:	66 83 7f 02 00       	cmp    WORD PTR [rdi+0x2],0x0
  34f472:	48 89 fb             	mov    rbx,rdi
  34f475:	74 06                	je     0x34f47d
  34f477:	66 c7 43 02 00 00    	mov    WORD PTR [rbx+0x2],0x0
  34f47d:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  34f484:	e8 47 72 8e 00       	call   0xc366d0
  34f489:	0b 45 b8             	or     eax,DWORD PTR [rbp-0x48]
  34f48c:	74 11                	je     0x34f49f
  34f48e:	8b 55 c8             	mov    edx,DWORD PTR [rbp-0x38]
  34f491:	f7 c2 ff fe fc fe    	test   edx,0xfefcfeff
  34f497:	0f 85 b5 00 00 00    	jne    0x34f552
  34f49d:	eb 0f                	jmp    0x34f4ae
  34f49f:	8b 55 c8             	mov    edx,DWORD PTR [rbp-0x38]
  34f4a2:	f7 c2 ff fe ff ff    	test   edx,0xfffffeff
  34f4a8:	0f 85 a4 00 00 00    	jne    0x34f552
  34f4ae:	83 7d cc 00          	cmp    DWORD PTR [rbp-0x34],0x0
  34f4b2:	74 1b                	je     0x34f4cf
  34f4b4:	83 bb 90 00 00 00 00 	cmp    DWORD PTR [rbx+0x90],0x0
  34f4bb:	0f 94 c0             	sete   al
  34f4be:	f7 c2 00 00 03 00    	test   edx,0x30000
  34f4c4:	0f 94 c1             	sete   cl
  34f4c7:	08 c1                	or     cl,al
  34f4c9:	0f 84 83 00 00 00    	je     0x34f552
  34f4cf:	80 bb 94 00 00 00 00 	cmp    BYTE PTR [rbx+0x94],0x0
  34f4d6:	75 63                	jne    0x34f53b
  34f4d8:	80 bb 95 00 00 00 00 	cmp    BYTE PTR [rbx+0x95],0x0
  34f4df:	75 5a                	jne    0x34f53b
  34f4e1:	80 bb 96 00 00 00 00 	cmp    BYTE PTR [rbx+0x96],0x0
  34f4e8:	75 51                	jne    0x34f53b
  34f4ea:	80 bb 97 00 00 00 00 	cmp    BYTE PTR [rbx+0x97],0x0
  34f4f1:	75 48                	jne    0x34f53b
  34f4f3:	80 bb 98 00 00 00 00 	cmp    BYTE PTR [rbx+0x98],0x0
  34f4fa:	75 3f                	jne    0x34f53b
  34f4fc:	80 bb 99 00 00 00 00 	cmp    BYTE PTR [rbx+0x99],0x0
  34f503:	75 36                	jne    0x34f53b
  34f505:	80 bb 9a 00 00 00 00 	cmp    BYTE PTR [rbx+0x9a],0x0
  34f50c:	75 2d                	jne    0x34f53b
  34f50e:	80 bb 9b 00 00 00 00 	cmp    BYTE PTR [rbx+0x9b],0x0
  34f515:	75 24                	jne    0x34f53b
  34f517:	80 bb 9c 00 00 00 00 	cmp    BYTE PTR [rbx+0x9c],0x0
  34f51e:	75 1b                	jne    0x34f53b
  34f520:	80 bb 9d 00 00 00 00 	cmp    BYTE PTR [rbx+0x9d],0x0
  34f527:	75 12                	jne    0x34f53b
  34f529:	80 bb 9e 00 00 00 00 	cmp    BYTE PTR [rbx+0x9e],0x0
  34f530:	75 09                	jne    0x34f53b
  34f532:	80 bb 9f 00 00 00 00 	cmp    BYTE PTR [rbx+0x9f],0x0
  34f539:	74 67                	je     0x34f5a2
  34f53b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  34f53f:	41 bc 1c 00 00 00    	mov    r12d,0x1c
  34f545:	48 85 c0             	test   rax,rax
  34f548:	74 1d                	je     0x34f567
  34f54a:	66 c7 40 02 94 00    	mov    WORD PTR [rax+0x2],0x94
  34f550:	eb 15                	jmp    0x34f567
  34f552:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  34f556:	41 bc 1c 00 00 00    	mov    r12d,0x1c
  34f55c:	48 85 c0             	test   rax,rax
  34f55f:	74 06                	je     0x34f567
  34f561:	66 c7 40 02 04 00    	mov    WORD PTR [rax+0x2],0x4
  34f567:	48 8d 3d da fe 10 03 	lea    rdi,[rip+0x310feda]        # 0x345f448
  34f56e:	31 f6                	xor    esi,esi
  34f570:	31 d2                	xor    edx,edx
  34f572:	31 c9                	xor    ecx,ecx
  34f574:	e8 27 7a 17 00       	call   0x4c6fa0
  34f579:	44 89 e0             	mov    eax,r12d
  34f57c:	48 83 c4 28          	add    rsp,0x28
  34f580:	5b                   	pop    rbx
  34f581:	41 5c                	pop    r12
  34f583:	41 5d                	pop    r13
  34f585:	41 5e                	pop    r14
  34f587:	41 5f                	pop    r15
  34f589:	5d                   	pop    rbp
  34f58a:	c3                   	ret
  34f58b:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  34f58f:	41 bc 1c 00 00 00    	mov    r12d,0x1c
  34f595:	48 85 c0             	test   rax,rax
  34f598:	74 cd                	je     0x34f567
  34f59a:	66 c7 40 02 00 00    	mov    WORD PTR [rax+0x2],0x0
  34f5a0:	eb c5                	jmp    0x34f567
  34f5a2:	48 8b 75 d0          	mov    rsi,QWORD PTR [rbp-0x30]
  34f5a6:	48 89 df             	mov    rdi,rbx
  34f5a9:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  34f5ad:	e8 4e 0a 00 00       	call   0x350000
  34f5b2:	41 89 c4             	mov    r12d,eax
  34f5b5:	85 c0                	test   eax,eax
  34f5b7:	75 ae                	jne    0x34f567
  34f5b9:	49 8b be 40 01 00 00 	mov    rdi,QWORD PTR [r14+0x140]
  34f5c0:	e8 4b 71 8e 00       	call   0xc36710
  34f5c5:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  34f5c9:	48 89 df             	mov    rdi,rbx
  34f5cc:	e8 1f 0e 00 00       	call   0x3503f0
  34f5d1:	8b 45 c8             	mov    eax,DWORD PTR [rbp-0x38]
  34f5d4:	89 43 04             	mov    DWORD PTR [rbx+0x4],eax
  34f5d7:	a9 00 00 03 00       	test   eax,0x30000
  34f5dc:	0f 84 da 01 00 00    	je     0x34f7bc
  34f5e2:	48 8b 05 67 fe 10 03 	mov    rax,QWORD PTR [rip+0x310fe67]        # 0x345f450
  34f5e9:	eb 07                	jmp    0x34f5f2
  34f5eb:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  34f5ef:	48 8b 00             	mov    rax,QWORD PTR [rax]
  34f5f2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  34f5f6:	48 85 c0             	test   rax,rax
  34f5f9:	0f 84 fd 00 00 00    	je     0x34f6fc
  34f5ff:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  34f603:	45 31 e4             	xor    r12d,r12d
  34f606:	48 8d 48 14          	lea    rcx,[rax+0x14]
  34f60a:	4c 8d 70 24          	lea    r14,[rax+0x24]
  34f60e:	4c 8d 68 64          	lea    r13,[rax+0x64]
  34f612:	48 89 4d b8          	mov    QWORD PTR [rbp-0x48],rcx
  34f616:	eb 3a                	jmp    0x34f652
  34f618:	48 8d 7b 10          	lea    rdi,[rbx+0x10]
  34f61c:	be 40 00 00 00       	mov    esi,0x40
  34f621:	e8 ca 99 f0 ff       	call   0x258ff0
  34f626:	48 8d 7b 50          	lea    rdi,[rbx+0x50]
  34f62a:	be 40 00 00 00       	mov    esi,0x40
  34f62f:	e8 bc 99 f0 ff       	call   0x258ff0
  34f634:	81 63 0c fe ff fe ff 	and    DWORD PTR [rbx+0xc],0xfffefffe
  34f63b:	49 ff c4             	inc    r12
  34f63e:	49 81 c6 a0 00 00 00 	add    r14,0xa0
  34f645:	49 81 c5 a0 00 00 00 	add    r13,0xa0
  34f64c:	49 83 fc 10          	cmp    r12,0x10
  34f650:	74 99                	je     0x34f5eb
  34f652:	4b 8d 1c a4          	lea    rbx,[r12+r12*4]
  34f656:	48 c1 e3 05          	shl    rbx,0x5
  34f65a:	48 03 5d b8          	add    rbx,QWORD PTR [rbp-0x48]
  34f65e:	83 7d cc 00          	cmp    DWORD PTR [rbp-0x34],0x0
  34f662:	75 b4                	jne    0x34f618
  34f664:	8b 4b 0c             	mov    ecx,DWORD PTR [rbx+0xc]
  34f667:	f7 c1 00 00 01 00    	test   ecx,0x10000
  34f66d:	74 cc                	je     0x34f63b
  34f66f:	48 8d 15 ea fd 10 03 	lea    rdx,[rip+0x310fdea]        # 0x345f460
  34f676:	31 c0                	xor    eax,eax
  34f678:	eb 09                	jmp    0x34f683
  34f67a:	48 ff c0             	inc    rax
  34f67d:	48 83 f8 40          	cmp    rax,0x40
  34f681:	74 0e                	je     0x34f691
  34f683:	80 7c 10 10 00       	cmp    BYTE PTR [rax+rdx*1+0x10],0x0
  34f688:	74 f0                	je     0x34f67a
  34f68a:	41 c6 04 06 00       	mov    BYTE PTR [r14+rax*1],0x0
  34f68f:	eb e9                	jmp    0x34f67a
  34f691:	31 c0                	xor    eax,eax
  34f693:	eb 09                	jmp    0x34f69e
  34f695:	48 ff c0             	inc    rax
  34f698:	48 83 f8 40          	cmp    rax,0x40
  34f69c:	74 0f                	je     0x34f6ad
  34f69e:	80 7c 10 50 00       	cmp    BYTE PTR [rax+rdx*1+0x50],0x0
  34f6a3:	74 f0                	je     0x34f695
  34f6a5:	41 c6 44 05 00 00    	mov    BYTE PTR [r13+rax*1+0x0],0x0
  34f6ab:	eb e8                	jmp    0x34f695
  34f6ad:	89 c8                	mov    eax,ecx
  34f6af:	81 e1 fe ff fe ff    	and    ecx,0xfffefffe
  34f6b5:	89 4b 0c             	mov    DWORD PTR [rbx+0xc],ecx
  34f6b8:	25 ff ff fe ff       	and    eax,0xfffeffff
  34f6bd:	31 c9                	xor    ecx,ecx
  34f6bf:	41 80 3c 0e 00       	cmp    BYTE PTR [r14+rcx*1],0x0
  34f6c4:	75 10                	jne    0x34f6d6
  34f6c6:	48 ff c1             	inc    rcx
  34f6c9:	48 83 f9 40          	cmp    rcx,0x40
  34f6cd:	75 f0                	jne    0x34f6bf
  34f6cf:	83 c8 01             	or     eax,0x1
  34f6d2:	31 c9                	xor    ecx,ecx
  34f6d4:	eb 08                	jmp    0x34f6de
  34f6d6:	83 c8 01             	or     eax,0x1
  34f6d9:	31 c9                	xor    ecx,ecx
  34f6db:	89 43 0c             	mov    DWORD PTR [rbx+0xc],eax
  34f6de:	41 80 7c 0d 00 00    	cmp    BYTE PTR [r13+rcx*1+0x0],0x0
  34f6e4:	75 0e                	jne    0x34f6f4
  34f6e6:	48 ff c1             	inc    rcx
  34f6e9:	48 83 f9 40          	cmp    rcx,0x40
  34f6ed:	75 ef                	jne    0x34f6de
  34f6ef:	e9 47 ff ff ff       	jmp    0x34f63b
  34f6f4:	89 43 0c             	mov    DWORD PTR [rbx+0xc],eax
  34f6f7:	e9 3f ff ff ff       	jmp    0x34f63b
  34f6fc:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  34f700:	48 8d 3d 59 fd 10 03 	lea    rdi,[rip+0x310fd59]        # 0x345f460
  34f707:	ba a0 00 00 00       	mov    edx,0xa0
  34f70c:	e8 9f 99 f0 ff       	call   0x2590b0
  34f711:	c7 05 4d fd 10 03 00 	mov    DWORD PTR [rip+0x310fd4d],0x0        # 0x345f468
  34f718:	00 00 00 
  34f71b:	c7 05 cb fd 10 03 00 	mov    DWORD PTR [rip+0x310fdcb],0x0        # 0x345f4f0
  34f722:	00 00 00 
  34f725:	45 31 e4             	xor    r12d,r12d
  34f728:	f6 05 3d fd 10 03 01 	test   BYTE PTR [rip+0x310fd3d],0x1        # 0x345f46c
  34f72f:	0f 84 32 fe ff ff    	je     0x34f567
  34f735:	f7 45 c8 00 00 01 00 	test   DWORD PTR [rbp-0x38],0x10000
  34f73c:	0f 85 2d 01 00 00    	jne    0x34f86f
  34f742:	f7 45 c8 00 00 02 00 	test   DWORD PTR [rbp-0x38],0x20000
  34f749:	4c 8b 3d 00 fd 10 03 	mov    r15,QWORD PTR [rip+0x310fd00]        # 0x345f450
  34f750:	0f 94 c0             	sete   al
  34f753:	4d 85 ff             	test   r15,r15
  34f756:	0f 94 c1             	sete   cl
  34f759:	08 c1                	or     cl,al
  34f75b:	0f 85 06 fe ff ff    	jne    0x34f567
  34f761:	48 8d 1d f8 fc 10 03 	lea    rbx,[rip+0x310fcf8]        # 0x345f460
  34f768:	eb 0c                	jmp    0x34f776
  34f76a:	4d 8b 3f             	mov    r15,QWORD PTR [r15]
  34f76d:	4d 85 ff             	test   r15,r15
  34f770:	0f 84 f1 fd ff ff    	je     0x34f567
  34f776:	4d 8d 77 14          	lea    r14,[r15+0x14]
  34f77a:	41 bd 10 00 00 00    	mov    r13d,0x10
  34f780:	eb 14                	jmp    0x34f796
  34f782:	4c 89 f7             	mov    rdi,r14
  34f785:	e8 c6 0c 00 00       	call   0x350450
  34f78a:	49                   	rex.WB
  34f78b:	81                   	.byte 0x81
  34f78c:	c6                   	(bad)
  34f78d:	a0                   	.byte 0xa0
  34f78e:	00 00                	add    BYTE PTR [rax],al

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
