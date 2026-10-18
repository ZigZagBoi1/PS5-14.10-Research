
/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/deep_532.bin:     file format binary


Disassembly of section .data:

0000000000af0040 <.data>:
  af0040:	55                                              	push   rbp
  af0041:	48 89 e5                                        	mov    rbp,rsp
  af0044:	41 57                                           	push   r15
  af0046:	41 56                                           	push   r14
  af0048:	41 55                                           	push   r13
  af004a:	41 54                                           	push   r12
  af004c:	53                                              	push   rbx
  af004d:	48 81 ec 58 08 00 00                            	sub    rsp,0x858
  af0054:	48 8d 05 b5 c2 e2 02                            	lea    rax,[rip+0x2e2c2b5]        # 0x391c310
  af005b:	48 89 fb                                        	mov    rbx,rdi
  af005e:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  af0061:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  af0065:	48 8b 4e 18                                     	mov    rcx,QWORD PTR [rsi+0x18]
  af0069:	8b 46 08                                        	mov    eax,DWORD PTR [rsi+0x8]
  af006c:	48 8b 56 20                                     	mov    rdx,QWORD PTR [rsi+0x20]
  af0070:	44 8b 36                                        	mov    r14d,DWORD PTR [rsi]
  af0073:	4c 8b 6f 08                                     	mov    r13,QWORD PTR [rdi+0x8]
  af0077:	48 89 8d 90 f7 ff ff                            	mov    QWORD PTR [rbp-0x870],rcx
  af007e:	48 8b 4e 10                                     	mov    rcx,QWORD PTR [rsi+0x10]
  af0082:	89 85 9c f7 ff ff                               	mov    DWORD PTR [rbp-0x864],eax
  af0088:	48 89 95 88 f7 ff ff                            	mov    QWORD PTR [rbp-0x878],rdx
  af008f:	48 89 8d a0 f7 ff ff                            	mov    QWORD PTR [rbp-0x860],rcx
  af0096:	4d 85 ed                                        	test   r13,r13
  af0099:	74 3a                                           	je     0xaf00d5
  af009b:	4d 8d bd 48 01 00 00                            	lea    r15,[r13+0x148]
  af00a2:	31 f6                                           	xor    esi,esi
  af00a4:	31 d2                                           	xor    edx,edx
  af00a6:	31 c9                                           	xor    ecx,ecx
  af00a8:	4c 89 ff                                        	mov    rdi,r15
  af00ab:	e8 50 69 9d ff                                  	call   0x4c6a00
  af00b0:	45 31 e4                                        	xor    r12d,r12d
  af00b3:	41 80 bd 81 0c 00 00 00                         	cmp    BYTE PTR [r13+0xc81],0x0
  af00bb:	4c 89 ff                                        	mov    rdi,r15
  af00be:	41 0f 94 c4                                     	sete   r12b
  af00c2:	31 f6                                           	xor    esi,esi
  af00c4:	31 d2                                           	xor    edx,edx
  af00c6:	31 c9                                           	xor    ecx,ecx
  af00c8:	e8 d3 6e 9d ff                                  	call   0x4c6fa0
  af00cd:	45 89 e5                                        	mov    r13d,r12d
  af00d0:	41 ff c5                                        	inc    r13d
  af00d3:	eb 09                                           	jmp    0xaf00de
  af00d5:	41 bd 01 00 00 00                               	mov    r13d,0x1
  af00db:	45 31 e4                                        	xor    r12d,r12d
  af00de:	48 89 df                                        	mov    rdi,rbx
  af00e1:	be aa 02 00 00                                  	mov    esi,0x2aa
  af00e6:	e8 45 f9 fe ff                                  	call   0xadfa30
  af00eb:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af00f2:	85 c0                                           	test   eax,eax
  af00f4:	74 26                                           	je     0xaf011c
  af00f6:	41 8d 4e e8                                     	lea    ecx,[r14-0x18]
  af00fa:	83 f9 07                                        	cmp    ecx,0x7
  af00fd:	0f 82 a3 01 00 00                               	jb     0xaf02a6
  af0103:	41 83 fe 2f                                     	cmp    r14d,0x2f
  af0107:	0f 84 99 01 00 00                               	je     0xaf02a6
  af010d:	41 83 fe 20                                     	cmp    r14d,0x20
  af0111:	0f 84 8f 01 00 00                               	je     0xaf02a6
  af0117:	e9 07 11 00 00                                  	jmp    0xaf1223
  af011c:	48 8b bb 40 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x140]
  af0123:	e8 58 8f b1 ff                                  	call   0x609080
  af0128:	83 f8 01                                        	cmp    eax,0x1
  af012b:	0f 85 75 01 00 00                               	jne    0xaf02a6
  af0131:	41 83 fe 20                                     	cmp    r14d,0x20
  af0135:	0f 87 b6 03 00 00                               	ja     0xaf04f1
  af013b:	44 89 f0                                        	mov    eax,r14d
  af013e:	b9 d4 03 00 80                                  	mov    ecx,0x800003d4
  af0143:	48 0f a3 c1                                     	bt     rcx,rax
  af0147:	0f 83 92 00 00 00                               	jae    0xaf01df
  af014d:	0f b7 35 ec 7c 20 03                            	movzx  esi,WORD PTR [rip+0x3207cec]        # 0x3cf7e40
  af0154:	b8 03 02 0d 80                                  	mov    eax,0x800d0203
  af0159:	48 85 f6                                        	test   rsi,rsi
  af015c:	0f 84 90 10 00 00                               	je     0xaf11f2
  af0162:	48 8d 0d cf 7c 20 03                            	lea    rcx,[rip+0x3207ccf]        # 0x3cf7e38
  af0169:	31 d2                                           	xor    edx,edx
  af016b:	eb 0f                                           	jmp    0xaf017c
  af016d:	0f 1f 00                                        	nop    DWORD PTR [rax]
  af0170:	48 ff c2                                        	inc    rdx
  af0173:	48 39 f2                                        	cmp    rdx,rsi
  af0176:	0f 84 76 10 00 00                               	je     0xaf11f2
  af017c:	4c 8d 04 92                                     	lea    r8,[rdx+rdx*4]
  af0180:	42 8b 7c c1 18                                  	mov    edi,DWORD PTR [rcx+r8*8+0x18]
  af0185:	39 bd 9c f7 ff ff                               	cmp    DWORD PTR [rbp-0x864],edi
  af018b:	0f 84 de 00 00 00                               	je     0xaf026f
  af0191:	4e 8d 4c c1 18                                  	lea    r9,[rcx+r8*8+0x18]
  af0196:	45 0f b6 41 15                                  	movzx  r8d,BYTE PTR [r9+0x15]
  af019b:	45 85 c0                                        	test   r8d,r8d
  af019e:	74 d0                                           	je     0xaf0170
  af01a0:	41 83 f8 01                                     	cmp    r8d,0x1
  af01a4:	74 ca                                           	je     0xaf0170
  af01a6:	45 0f b6 49 16                                  	movzx  r9d,BYTE PTR [r9+0x16]
  af01ab:	41 ba 01 00 00 00                               	mov    r10d,0x1
  af01b1:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  af01c0:	c4 42 31 f7 da                                  	shlx   r11d,r10d,r9d
  af01c5:	41 01 fb                                        	add    r11d,edi
  af01c8:	44 39 9d 9c f7 ff ff                            	cmp    DWORD PTR [rbp-0x864],r11d
  af01cf:	0f 84 9a 00 00 00                               	je     0xaf026f
  af01d5:	41 ff c2                                        	inc    r10d
  af01d8:	45 39 d0                                        	cmp    r8d,r10d
  af01db:	75 e3                                           	jne    0xaf01c0
  af01dd:	eb 91                                           	jmp    0xaf0170
  af01df:	b9 2a 00 00 00                                  	mov    ecx,0x2a
  af01e4:	48 0f a3 c1                                     	bt     rcx,rax
  af01e8:	0f 83 a4 00 00 00                               	jae    0xaf0292
  af01ee:	0f b7 35 4b 7c 20 03                            	movzx  esi,WORD PTR [rip+0x3207c4b]        # 0x3cf7e40
  af01f5:	b8 03 02 0d 80                                  	mov    eax,0x800d0203
  af01fa:	48 85 f6                                        	test   rsi,rsi
  af01fd:	0f 84 ef 0f 00 00                               	je     0xaf11f2
  af0203:	48 8d 0d 2e 7c 20 03                            	lea    rcx,[rip+0x3207c2e]        # 0x3cf7e38
  af020a:	31 d2                                           	xor    edx,edx
  af020c:	eb 0c                                           	jmp    0xaf021a
  af020e:	48 ff c2                                        	inc    rdx
  af0211:	48 39 f2                                        	cmp    rdx,rsi
  af0214:	0f 84 d8 0f 00 00                               	je     0xaf11f2
  af021a:	4c 8d 04 92                                     	lea    r8,[rdx+rdx*4]
  af021e:	42 8b 7c c1 18                                  	mov    edi,DWORD PTR [rcx+r8*8+0x18]
  af0223:	39 bd 9c f7 ff ff                               	cmp    DWORD PTR [rbp-0x864],edi
  af0229:	0f 84 7c 01 00 00                               	je     0xaf03ab
  af022f:	4e 8d 4c c1 18                                  	lea    r9,[rcx+r8*8+0x18]
  af0234:	45 0f b6 41 15                                  	movzx  r8d,BYTE PTR [r9+0x15]
  af0239:	45 85 c0                                        	test   r8d,r8d
  af023c:	74 d0                                           	je     0xaf020e
  af023e:	41 83 f8 01                                     	cmp    r8d,0x1
  af0242:	74 ca                                           	je     0xaf020e
  af0244:	45 0f b6 49 16                                  	movzx  r9d,BYTE PTR [r9+0x16]
  af0249:	41 ba 01 00 00 00                               	mov    r10d,0x1
  af024f:	90                                              	nop
  af0250:	c4 42 31 f7 da                                  	shlx   r11d,r10d,r9d
  af0255:	41 01 fb                                        	add    r11d,edi
  af0258:	44 39 9d 9c f7 ff ff                            	cmp    DWORD PTR [rbp-0x864],r11d
  af025f:	0f 84 46 01 00 00                               	je     0xaf03ab
  af0265:	41 ff c2                                        	inc    r10d
  af0268:	45 39 d0                                        	cmp    r8d,r10d
  af026b:	75 e3                                           	jne    0xaf0250
  af026d:	eb 9f                                           	jmp    0xaf020e
  af026f:	85 d2                                           	test   edx,edx
  af0271:	0f 88 7b 0f 00 00                               	js     0xaf11f2
  af0277:	81 e2 ff ff ff 7f                               	and    edx,0x7fffffff
  af027d:	b8 18 02 0d 80                                  	mov    eax,0x800d0218
  af0282:	48 8d 14 92                                     	lea    rdx,[rdx+rdx*4]
  af0286:	f6 44 d1 35 01                                  	test   BYTE PTR [rcx+rdx*8+0x35],0x1
  af028b:	75 19                                           	jne    0xaf02a6
  af028d:	e9 60 0f 00 00                                  	jmp    0xaf11f2
  af0292:	48 b9 00 10 00 00 01 00 00 00                   	movabs rcx,0x100001000
  af029c:	48 0f a3 c1                                     	bt     rcx,rax
  af02a0:	0f 83 4b 02 00 00                               	jae    0xaf04f1
  af02a6:	31 c0                                           	xor    eax,eax
  af02a8:	b9 02 02 0d 80                                  	mov    ecx,0x800d0202
  af02ad:	4d 85 ff                                        	test   r15,r15
  af02b0:	ba 00 00 00 00                                  	mov    edx,0x0
  af02b5:	0f 44 d1                                        	cmove  edx,ecx
  af02b8:	89 95 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],edx
  af02be:	0f 84 34 0f 00 00                               	je     0xaf11f8
  af02c4:	48 83 bd 90 f7 ff ff 00                         	cmp    QWORD PTR [rbp-0x870],0x0
  af02cc:	45 89 f7                                        	mov    r15d,r14d
  af02cf:	0f 44 c1                                        	cmove  eax,ecx
  af02d2:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af02d8:	75 1a                                           	jne    0xaf02f4
  af02da:	41 83 fe 46                                     	cmp    r14d,0x46
  af02de:	0f 87 d5 04 00 00                               	ja     0xaf07b9
  af02e4:	48 8d 05 45 df de 00                            	lea    rax,[rip+0xdedf45]        # 0x18de230
  af02eb:	4a 63 0c b8                                     	movsxd rcx,DWORD PTR [rax+r15*4]
  af02ef:	48 01 c1                                        	add    rcx,rax
  af02f2:	ff e1                                           	jmp    rcx
  af02f4:	48 8b 8d 88 f7 ff ff                            	mov    rcx,QWORD PTR [rbp-0x878]
  af02fb:	48 81 f9 01 08 00 00                            	cmp    rcx,0x801
  af0302:	72 41                                           	jb     0xaf0345
  af0304:	41 8d 46 e6                                     	lea    eax,[r14-0x1a]
  af0308:	83 f8 03                                        	cmp    eax,0x3
  af030b:	77 1f                                           	ja     0xaf032c
  af030d:	48 81 f9 19 08 00 00                            	cmp    rcx,0x819
  af0314:	72 2f                                           	jb     0xaf0345
  af0316:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af031d:	c7 85 a8 f7 ff ff 08 02 0d 80                   	mov    DWORD PTR [rbp-0x858],0x800d0208
  af0327:	e9 cc 0e 00 00                                  	jmp    0xaf11f8
  af032c:	41 8d 46 e0                                     	lea    eax,[r14-0x20]
  af0330:	83 f8 20                                        	cmp    eax,0x20
  af0333:	77 e1                                           	ja     0xaf0316
  af0335:	48 b9 01 91 40 50 01 00 00 00                   	movabs rcx,0x150409101
  af033f:	48 0f a3 c1                                     	bt     rcx,rax
  af0343:	73 d1                                           	jae    0xaf0316
  af0345:	48 8d bd b0 f7 ff ff                            	lea    rdi,[rbp-0x850]
  af034c:	be 18 08 00 00                                  	mov    esi,0x818
  af0351:	e8 9a 8c 76 ff                                  	call   0x258ff0
  af0356:	41 83 fe 46                                     	cmp    r14d,0x46
  af035a:	77 10                                           	ja     0xaf036c
  af035c:	48 8d 05 e9 df de 00                            	lea    rax,[rip+0xdedfe9]        # 0x18de34c
  af0363:	4a 63 0c b8                                     	movsxd rcx,DWORD PTR [rax+r15*4]
  af0367:	48 01 c1                                        	add    rcx,rax
  af036a:	ff e1                                           	jmp    rcx
  af036c:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0373:	c7 85 a8 f7 ff ff 19 02 0d 80                   	mov    DWORD PTR [rbp-0x858],0x800d0219
  af037d:	e9 76 0e 00 00                                  	jmp    0xaf11f8
  af0382:	41 83 fe 20                                     	cmp    r14d,0x20
  af0386:	75 4a                                           	jne    0xaf03d2
  af0388:	48 8b 95 88 f7 ff ff                            	mov    rdx,QWORD PTR [rbp-0x878]
  af038f:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0396:	48 83 fa 30                                     	cmp    rdx,0x30
  af039a:	74 4d                                           	je     0xaf03e9
  af039c:	c7 85 a8 f7 ff ff 08 02 0d 80                   	mov    DWORD PTR [rbp-0x858],0x800d0208
  af03a6:	e9 4d 0e 00 00                                  	jmp    0xaf11f8
  af03ab:	85 d2                                           	test   edx,edx
  af03ad:	0f 88 3f 0e 00 00                               	js     0xaf11f2
  af03b3:	81 e2 ff ff ff 7f                               	and    edx,0x7fffffff
  af03b9:	b8 18 02 0d 80                                  	mov    eax,0x800d0218
  af03be:	48 8d 14 92                                     	lea    rdx,[rdx+rdx*4]
  af03c2:	f6 44 d1 35 02                                  	test   BYTE PTR [rcx+rdx*8+0x35],0x2
  af03c7:	0f 85 d9 fe ff ff                               	jne    0xaf02a6
  af03cd:	e9 20 0e 00 00                                  	jmp    0xaf11f2
  af03d2:	48 8b 95 88 f7 ff ff                            	mov    rdx,QWORD PTR [rbp-0x878]
  af03d9:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af03e0:	48 81 fa 18 08 00 00                            	cmp    rdx,0x818
  af03e7:	75 b3                                           	jne    0xaf039c
  af03e9:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af03f0:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af03f7:	e8 44 0f 00 00                                  	call   0xaf1340
  af03fc:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0402:	85 c0                                           	test   eax,eax
  af0404:	0f 85 ff 0b 00 00                               	jne    0xaf1009
  af040a:	41 83 fe 2c                                     	cmp    r14d,0x2c
  af040e:	0f 84 aa 0d 00 00                               	je     0xaf11be
  af0414:	41 83 fe 36                                     	cmp    r14d,0x36
  af0418:	c7 85 a8 f7 ff ff 19 02 0d 80                   	mov    DWORD PTR [rbp-0x858],0x800d0219
  af0422:	e9 d1 0d 00 00                                  	jmp    0xaf11f8
  af0427:	45 84 e4                                        	test   r12b,r12b
  af042a:	0f 85 3c ff ff ff                               	jne    0xaf036c
  af0430:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0437:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af043e:	ba 18 00 00 00                                  	mov    edx,0x18
  af0443:	e8 f8 0e 00 00                                  	call   0xaf1340
  af0448:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af044f:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0455:	85 c0                                           	test   eax,eax
  af0457:	0f 85 ac 0b 00 00                               	jne    0xaf1009
  af045d:	48 83 bd b8 f7 ff ff 00                         	cmp    QWORD PTR [rbp-0x848],0x0
  af0465:	0f 84 6a 0d 00 00                               	je     0xaf11d5
  af046b:	48 8b 9d c0 f7 ff ff                            	mov    rbx,QWORD PTR [rbp-0x840]
  af0472:	48 8d 35 67 db dd 01                            	lea    rsi,[rip+0x1dddb67]        # 0x28cdfe0
  af0479:	ba 01 01 00 00                                  	mov    edx,0x101
  af047e:	48 89 df                                        	mov    rdi,rbx
  af0481:	e8 ca 86 11 00                                  	call   0xc08b50
  af0486:	48 85 c0                                        	test   rax,rax
  af0489:	0f 84 b5 0c 00 00                               	je     0xaf1144
  af048f:	44 8b a5 b0 f7 ff ff                            	mov    r12d,DWORD PTR [rbp-0x850]
  af0496:	44 8b ad b4 f7 ff ff                            	mov    r13d,DWORD PTR [rbp-0x84c]
  af049d:	49 89 c7                                        	mov    r15,rax
  af04a0:	41 83 fe 42                                     	cmp    r14d,0x42
  af04a4:	0f 84 01 0e 00 00                               	je     0xaf12ab
  af04aa:	41 83 fe 43                                     	cmp    r14d,0x43
  af04ae:	0f 85 26 0e 00 00                               	jne    0xaf12da
  af04b4:	48 8b bd b8 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x848]
  af04bb:	4c 89 fe                                        	mov    rsi,r15
  af04be:	48 89 da                                        	mov    rdx,rbx
  af04c1:	e8 7a 0e 00 00                                  	call   0xaf1340
  af04c6:	89 c1                                           	mov    ecx,eax
  af04c8:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af04ce:	b8 0f 02 0d 80                                  	mov    eax,0x800d020f
  af04d3:	85 c9                                           	test   ecx,ecx
  af04d5:	0f 85 48 0c 00 00                               	jne    0xaf1123
  af04db:	44 89 e7                                        	mov    edi,r12d
  af04de:	4c 89 fe                                        	mov    rsi,r15
  af04e1:	48 89 da                                        	mov    rdx,rbx
  af04e4:	44 89 e9                                        	mov    ecx,r13d
  af04e7:	e8 f4 4b 85 ff                                  	call   0x3450e0
  af04ec:	e9 32 0c 00 00                                  	jmp    0xaf1123
  af04f1:	c7 85 a8 f7 ff ff 18 02 0d 80                   	mov    DWORD PTR [rbp-0x858],0x800d0218
  af04fb:	e9 f8 0c 00 00                                  	jmp    0xaf11f8
  af0500:	45 84 e4                                        	test   r12b,r12b
  af0503:	0f 85 63 fe ff ff                               	jne    0xaf036c
  af0509:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0510:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0517:	ba 18 00 00 00                                  	mov    edx,0x18
  af051c:	e8 1f 0e 00 00                                  	call   0xaf1340
  af0521:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0528:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af052e:	85 c0                                           	test   eax,eax
  af0530:	0f 85 d3 0a 00 00                               	jne    0xaf1009
  af0536:	8b bd b0 f7 ff ff                               	mov    edi,DWORD PTR [rbp-0x850]
  af053c:	8b b5 b4 f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x84c]
  af0542:	41 83 fe 41                                     	cmp    r14d,0x41
  af0546:	0f 85 fd 0c 00 00                               	jne    0xaf1249
  af054c:	e8 6f 40 85 ff                                  	call   0x3445c0
  af0551:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0557:	e9 9c 0c 00 00                                  	jmp    0xaf11f8
  af055c:	45 84 e4                                        	test   r12b,r12b
  af055f:	0f 85 07 fe ff ff                               	jne    0xaf036c
  af0565:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af056c:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0573:	ba 18 00 00 00                                  	mov    edx,0x18
  af0578:	e8 c3 0d 00 00                                  	call   0xaf1340
  af057d:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0584:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af058a:	85 c0                                           	test   eax,eax
  af058c:	0f 85 77 0a 00 00                               	jne    0xaf1009
  af0592:	48 83 bd b8 f7 ff ff 00                         	cmp    QWORD PTR [rbp-0x848],0x0
  af059a:	0f 84 35 0c 00 00                               	je     0xaf11d5
  af05a0:	48 8b 9d c0 f7 ff ff                            	mov    rbx,QWORD PTR [rbp-0x840]
  af05a7:	48 8d 35 32 da dd 01                            	lea    rsi,[rip+0x1ddda32]        # 0x28cdfe0
  af05ae:	ba 01 01 00 00                                  	mov    edx,0x101
  af05b3:	48 89 df                                        	mov    rdi,rbx
  af05b6:	e8 95 85 11 00                                  	call   0xc08b50
  af05bb:	48 85 c0                                        	test   rax,rax
  af05be:	0f 84 80 0b 00 00                               	je     0xaf1144
  af05c4:	49 89 c7                                        	mov    r15,rax
  af05c7:	41 83 fe 27                                     	cmp    r14d,0x27
  af05cb:	0f 85 2b 0d 00 00                               	jne    0xaf12fc
  af05d1:	48 8b bd b8 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x848]
  af05d8:	4c 89 fe                                        	mov    rsi,r15
  af05db:	48 89 da                                        	mov    rdx,rbx
  af05de:	e8 5d 0d 00 00                                  	call   0xaf1340
  af05e3:	89 c1                                           	mov    ecx,eax
  af05e5:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af05eb:	b8 0f 02 0d 80                                  	mov    eax,0x800d020f
  af05f0:	85 c9                                           	test   ecx,ecx
  af05f2:	0f 85 2b 0b 00 00                               	jne    0xaf1123
  af05f8:	4c 89 ff                                        	mov    rdi,r15
  af05fb:	48 89 de                                        	mov    rsi,rbx
  af05fe:	e8 ad 5d 85 ff                                  	call   0x3463b0
  af0603:	e9 1b 0b 00 00                                  	jmp    0xaf1123
  af0608:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af060f:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0616:	ba 04 00 00 00                                  	mov    edx,0x4
  af061b:	e8 20 0d 00 00                                  	call   0xaf1340
  af0620:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0626:	85 c0                                           	test   eax,eax
  af0628:	0f 85 d4 09 00 00                               	jne    0xaf1002
  af062e:	8b bd b0 f7 ff ff                               	mov    edi,DWORD PTR [rbp-0x850]
  af0634:	e8 a7 86 ff ff                                  	call   0xae8ce0
  af0639:	e9 2f 0b 00 00                                  	jmp    0xaf116d
  af063e:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0645:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af064c:	ba 08 00 00 00                                  	mov    edx,0x8
  af0651:	e8 ea 0c 00 00                                  	call   0xaf1340
  af0656:	85 c0                                           	test   eax,eax
  af0658:	0f 85 a4 09 00 00                               	jne    0xaf1002
  af065e:	8b bd b0 f7 ff ff                               	mov    edi,DWORD PTR [rbp-0x850]
  af0664:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af066b:	45 84 e4                                        	test   r12b,r12b
  af066e:	74 0e                                           	je     0xaf067e
  af0670:	83 ff 01                                        	cmp    edi,0x1
  af0673:	bf 02 00 00 00                                  	mov    edi,0x2
  af0678:	0f 85 f7 05 00 00                               	jne    0xaf0c75
  af067e:	c7 85 a8 f7 ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x858],0x0
  af0688:	41 83 fe 31                                     	cmp    r14d,0x31
  af068c:	0f 85 4f 0b 00 00                               	jne    0xaf11e1
  af0692:	31 c0                                           	xor    eax,eax
  af0694:	83 3d 65 75 20 03 00                            	cmp    DWORD PTR [rip+0x3207565],0x0        # 0x3cf7c00
  af069b:	0f 84 51 0b 00 00                               	je     0xaf11f2
  af06a1:	83 3d 5c 75 20 03 00                            	cmp    DWORD PTR [rip+0x320755c],0x0        # 0x3cf7c04
  af06a8:	74 0d                                           	je     0xaf06b7
  af06aa:	83 3d 0f 75 20 03 01                            	cmp    DWORD PTR [rip+0x320750f],0x1        # 0x3cf7bc0
  af06b1:	0f 85 3b 0b 00 00                               	jne    0xaf11f2
  af06b7:	8b 8d 9c f7 ff ff                               	mov    ecx,DWORD PTR [rbp-0x864]
  af06bd:	83 c1 f0                                        	add    ecx,0xfffffff0
  af06c0:	83 f9 06                                        	cmp    ecx,0x6
  af06c3:	0f 87 29 0b 00 00                               	ja     0xaf11f2
  af06c9:	89 c8                                           	mov    eax,ecx
  af06cb:	48 8d 15 76 13 3a 00                            	lea    rdx,[rip+0x3a1376]        # 0xe91a48
  af06d2:	48 63 cf                                        	movsxd rcx,edi
  af06d5:	48 8b 04 c2                                     	mov    rax,QWORD PTR [rdx+rax*8]
  af06d9:	0f b7 44 48 04                                  	movzx  eax,WORD PTR [rax+rcx*2+0x4]
  af06de:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af06e4:	e9 0f 0b 00 00                                  	jmp    0xaf11f8
  af06e9:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af06f0:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af06f7:	ba 18 00 00 00                                  	mov    edx,0x18
  af06fc:	e8 3f 0c 00 00                                  	call   0xaf1340
  af0701:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0707:	85 c0                                           	test   eax,eax
  af0709:	0f 85 f3 08 00 00                               	jne    0xaf1002
  af070f:	48 83 bd b8 f7 ff ff 00                         	cmp    QWORD PTR [rbp-0x848],0x0
  af0717:	0f 84 9c 00 00 00                               	je     0xaf07b9
  af071d:	48 8b 9d c0 f7 ff ff                            	mov    rbx,QWORD PTR [rbp-0x840]
  af0724:	48 8d 35 b5 d8 dd 01                            	lea    rsi,[rip+0x1ddd8b5]        # 0x28cdfe0
  af072b:	ba 01 01 00 00                                  	mov    edx,0x101
  af0730:	48 89 df                                        	mov    rdi,rbx
  af0733:	e8 18 84 11 00                                  	call   0xc08b50
  af0738:	48 85 c0                                        	test   rax,rax
  af073b:	0f 84 03 0a 00 00                               	je     0xaf1144
  af0741:	44 8b ad b0 f7 ff ff                            	mov    r13d,DWORD PTR [rbp-0x850]
  af0748:	8b 8d b4 f7 ff ff                               	mov    ecx,DWORD PTR [rbp-0x84c]
  af074e:	49 89 c7                                        	mov    r15,rax
  af0751:	41 83 fe 35                                     	cmp    r14d,0x35
  af0755:	0f 85 fb 0a 00 00                               	jne    0xaf1256
  af075b:	48 8b bd b8 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x848]
  af0762:	4c 89 fe                                        	mov    rsi,r15
  af0765:	48 89 da                                        	mov    rdx,rbx
  af0768:	41 89 ce                                        	mov    r14d,ecx
  af076b:	e8 d0 0b 00 00                                  	call   0xaf1340
  af0770:	89 c1                                           	mov    ecx,eax
  af0772:	b8 0f 02 0d 80                                  	mov    eax,0x800d020f
  af0777:	85 c9                                           	test   ecx,ecx
  af0779:	0f 85 a4 09 00 00                               	jne    0xaf1123
  af077f:	45 84 e4                                        	test   r12b,r12b
  af0782:	74 15                                           	je     0xaf0799
  af0784:	b8 19 02 0d 80                                  	mov    eax,0x800d0219
  af0789:	41 83 fd 01                                     	cmp    r13d,0x1
  af078d:	41 bd 02 00 00 00                               	mov    r13d,0x2
  af0793:	0f 85 8a 09 00 00                               	jne    0xaf1123
  af0799:	44 89 ef                                        	mov    edi,r13d
  af079c:	4c 89 fe                                        	mov    rsi,r15
  af079f:	48 89 da                                        	mov    rdx,rbx
  af07a2:	44 89 f1                                        	mov    ecx,r14d
  af07a5:	c7 85 a8 f7 ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x858],0x0
  af07af:	e8 7c 52 85 ff                                  	call   0x345a30
  af07b4:	e9 6a 09 00 00                                  	jmp    0xaf1123
  af07b9:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af07c0:	c7 85 a8 f7 ff ff 02 02 0d 80                   	mov    DWORD PTR [rbp-0x858],0x800d0202
  af07ca:	e9 29 0a 00 00                                  	jmp    0xaf11f8
  af07cf:	e8 6c 40 1c 00                                  	call   0xcb4840
  af07d4:	e9 94 09 00 00                                  	jmp    0xaf116d
  af07d9:	e8 92 86 ff ff                                  	call   0xae8e70
  af07de:	e9 8a 09 00 00                                  	jmp    0xaf116d
  af07e3:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af07ea:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af07f1:	ba 18 08 00 00                                  	mov    edx,0x818
  af07f6:	e8 45 0b 00 00                                  	call   0xaf1340
  af07fb:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0801:	85 c0                                           	test   eax,eax
  af0803:	0f 85 f9 07 00 00                               	jne    0xaf1002
  af0809:	48 8b b5 b0 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x850]
  af0810:	8b 95 b8 f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x848]
  af0816:	48 8b 8b 40 01 00 00                            	mov    rcx,QWORD PTR [rbx+0x140]
  af081d:	4c 8d 8d ac f7 ff ff                            	lea    r9,[rbp-0x854]
  af0824:	44 89 ef                                        	mov    edi,r13d
  af0827:	41 b8 01 00 00 00                               	mov    r8d,0x1
  af082d:	e8 ae 0b 00 00                                  	call   0xaf13e0
  af0832:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0839:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af083f:	85 c0                                           	test   eax,eax
  af0841:	0f 85 b1 09 00 00                               	jne    0xaf11f8
  af0847:	8b b5 ac f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x854]
  af084d:	48 8b 8d c0 f7 ff ff                            	mov    rcx,QWORD PTR [rbp-0x840]
  af0854:	48 8d 95 c8 f7 ff ff                            	lea    rdx,[rbp-0x838]
  af085b:	44 89 ef                                        	mov    edi,r13d
  af085e:	e8 3d 71 ff ff                                  	call   0xae79a0
  af0863:	e9 e8 02 00 00                                  	jmp    0xaf0b50
  af0868:	e8 b3 85 ff ff                                  	call   0xae8e20
  af086d:	e9 fb 08 00 00                                  	jmp    0xaf116d
  af0872:	e8 a9 3f 1c 00                                  	call   0xcb4820
  af0877:	e9 f1 08 00 00                                  	jmp    0xaf116d
  af087c:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0883:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af088a:	ba 18 08 00 00                                  	mov    edx,0x818
  af088f:	e8 ac 0a 00 00                                  	call   0xaf1340
  af0894:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af089a:	85 c0                                           	test   eax,eax
  af089c:	0f 85 60 07 00 00                               	jne    0xaf1002
  af08a2:	48 8b b5 b0 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x850]
  af08a9:	8b 95 b8 f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x848]
  af08af:	48 8b 8b 40 01 00 00                            	mov    rcx,QWORD PTR [rbx+0x140]
  af08b6:	4c 8d 8d ac f7 ff ff                            	lea    r9,[rbp-0x854]
  af08bd:	44 89 ef                                        	mov    edi,r13d
  af08c0:	41 b8 02 00 00 00                               	mov    r8d,0x2
  af08c6:	e8 15 0b 00 00                                  	call   0xaf13e0
  af08cb:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af08d2:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af08d8:	85 c0                                           	test   eax,eax
  af08da:	0f 85 18 09 00 00                               	jne    0xaf11f8
  af08e0:	8b b5 ac f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x854]
  af08e6:	48 8b 8d c0 f7 ff ff                            	mov    rcx,QWORD PTR [rbp-0x840]
  af08ed:	48 8d 95 c8 f7 ff ff                            	lea    rdx,[rbp-0x838]
  af08f4:	44 89 ef                                        	mov    edi,r13d
  af08f7:	e8 04 69 ff ff                                  	call   0xae7200
  af08fc:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0902:	e9 f1 08 00 00                                  	jmp    0xaf11f8
  af0907:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af090e:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0915:	ba 04 00 00 00                                  	mov    edx,0x4
  af091a:	e8 21 0a 00 00                                  	call   0xaf1340
  af091f:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0925:	85 c0                                           	test   eax,eax
  af0927:	0f 85 d5 06 00 00                               	jne    0xaf1002
  af092d:	8b 95 b0 f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x850]
  af0933:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0939:	44 89 ef                                        	mov    edi,r13d
  af093c:	e8 7f 81 ff ff                                  	call   0xae8ac0
  af0941:	e9 27 08 00 00                                  	jmp    0xaf116d
  af0946:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af094d:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0954:	ba 04 00 00 00                                  	mov    edx,0x4
  af0959:	e8 e2 09 00 00                                  	call   0xaf1340
  af095e:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0964:	85 c0                                           	test   eax,eax
  af0966:	0f 85 96 06 00 00                               	jne    0xaf1002
  af096c:	8b 95 b0 f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x850]
  af0972:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0978:	44 89 ef                                        	mov    edi,r13d
  af097b:	e8 b0 71 ff ff                                  	call   0xae7b30
  af0980:	e9 e8 07 00 00                                  	jmp    0xaf116d
  af0985:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af098c:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0993:	ba 00 08 00 00                                  	mov    edx,0x800
  af0998:	e8 a3 09 00 00                                  	call   0xaf1340
  af099d:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af09a3:	85 c0                                           	test   eax,eax
  af09a5:	0f 85 57 06 00 00                               	jne    0xaf1002
  af09ab:	48 8d bd b0 f7 ff ff                            	lea    rdi,[rbp-0x850]
  af09b2:	e8 a9 a3 b1 ff                                  	call   0x60ad60
  af09b7:	e9 b1 07 00 00                                  	jmp    0xaf116d
  af09bc:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af09c3:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af09ca:	ba 18 00 00 00                                  	mov    edx,0x18
  af09cf:	e8 6c 09 00 00                                  	call   0xaf1340
  af09d4:	85 c0                                           	test   eax,eax
  af09d6:	0f 85 26 06 00 00                               	jne    0xaf1002
  af09dc:	8b bd b0 f7 ff ff                               	mov    edi,DWORD PTR [rbp-0x850]
  af09e2:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af09e9:	45 84 e4                                        	test   r12b,r12b
  af09ec:	74 0e                                           	je     0xaf09fc
  af09ee:	83 ff 01                                        	cmp    edi,0x1
  af09f1:	bf 02 00 00 00                                  	mov    edi,0x2
  af09f6:	0f 85 79 02 00 00                               	jne    0xaf0c75
  af09fc:	8b b5 b4 f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x84c]
  af0a02:	c7 85 a8 f7 ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x858],0x0
  af0a0c:	e8 5f 3b 85 ff                                  	call   0x344570
  af0a11:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0a17:	e9 dc 07 00 00                                  	jmp    0xaf11f8
  af0a1c:	e8 df 3d 1c 00                                  	call   0xcb4800
  af0a21:	e9 47 07 00 00                                  	jmp    0xaf116d
  af0a26:	8b bd 9c f7 ff ff                               	mov    edi,DWORD PTR [rbp-0x864]
  af0a2c:	48 8b 95 88 f7 ff ff                            	mov    rdx,QWORD PTR [rbp-0x878]
  af0a33:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0a3a:	e8 61 a2 b1 ff                                  	call   0x60aca0
  af0a3f:	e9 e4 03 00 00                                  	jmp    0xaf0e28
  af0a44:	e8 f7 86 ff ff                                  	call   0xae9140
  af0a49:	e9 1f 07 00 00                                  	jmp    0xaf116d
  af0a4e:	45 84 e4                                        	test   r12b,r12b
  af0a51:	0f 85 15 f9 ff ff                               	jne    0xaf036c
  af0a57:	e8 94 51 85 ff                                  	call   0x345bf0
  af0a5c:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0a63:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0a69:	e9 8a 07 00 00                                  	jmp    0xaf11f8
  af0a6e:	48 8b 9d 88 f7 ff ff                            	mov    rbx,QWORD PTR [rbp-0x878]
  af0a75:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0a7c:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0a83:	48 89 da                                        	mov    rdx,rbx
  af0a86:	e8 b5 08 00 00                                  	call   0xaf1340
  af0a8b:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0a91:	85 c0                                           	test   eax,eax
  af0a93:	0f 85 69 05 00 00                               	jne    0xaf1002
  af0a99:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0a9f:	48 8d 95 b0 f7 ff ff                            	lea    rdx,[rbp-0x850]
  af0aa6:	44 89 ef                                        	mov    edi,r13d
  af0aa9:	48 89 d9                                        	mov    rcx,rbx
  af0aac:	e8 4f 67 ff ff                                  	call   0xae7200
  af0ab1:	e9 b7 06 00 00                                  	jmp    0xaf116d
  af0ab6:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0abc:	48 8d 95 b0 f7 ff ff                            	lea    rdx,[rbp-0x850]
  af0ac3:	44 89 ef                                        	mov    edi,r13d
  af0ac6:	e8 b5 71 ff ff                                  	call   0xae7c80
  af0acb:	e9 14 01 00 00                                  	jmp    0xaf0be4
  af0ad0:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0ad7:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0ade:	ba 18 08 00 00                                  	mov    edx,0x818
  af0ae3:	e8 58 08 00 00                                  	call   0xaf1340
  af0ae8:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0aee:	85 c0                                           	test   eax,eax
  af0af0:	0f 85 0c 05 00 00                               	jne    0xaf1002
  af0af6:	48 8b b5 b0 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x850]
  af0afd:	8b 95 b8 f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x848]
  af0b03:	48 8b 8b 40 01 00 00                            	mov    rcx,QWORD PTR [rbx+0x140]
  af0b0a:	4c 8d 8d ac f7 ff ff                            	lea    r9,[rbp-0x854]
  af0b11:	44 89 ef                                        	mov    edi,r13d
  af0b14:	41 b8 01 00 00 00                               	mov    r8d,0x1
  af0b1a:	e8 c1 08 00 00                                  	call   0xaf13e0
  af0b1f:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0b26:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0b2c:	85 c0                                           	test   eax,eax
  af0b2e:	0f 85 c4 06 00 00                               	jne    0xaf11f8
  af0b34:	8b b5 ac f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x854]
  af0b3a:	48 8b 8d c0 f7 ff ff                            	mov    rcx,QWORD PTR [rbp-0x840]
  af0b41:	48 8d 95 c8 f7 ff ff                            	lea    rdx,[rbp-0x838]
  af0b48:	44 89 ef                                        	mov    edi,r13d
  af0b4b:	e8 00 69 ff ff                                  	call   0xae7450
  af0b50:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0b56:	85 c0                                           	test   eax,eax
  af0b58:	0f 85 9a 06 00 00                               	jne    0xaf11f8
  af0b5e:	48 8d bd b0 f7 ff ff                            	lea    rdi,[rbp-0x850]
  af0b65:	ba 18 08 00 00                                  	mov    edx,0x818
  af0b6a:	e9 96 00 00 00                                  	jmp    0xaf0c05
  af0b6f:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0b76:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0b7d:	ba 04 00 00 00                                  	mov    edx,0x4
  af0b82:	e8 b9 07 00 00                                  	call   0xaf1340
  af0b87:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0b8d:	85 c0                                           	test   eax,eax
  af0b8f:	0f 85 6d 04 00 00                               	jne    0xaf1002
  af0b95:	8b 95 b0 f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x850]
  af0b9b:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0ba1:	44 89 ef                                        	mov    edi,r13d
  af0ba4:	e8 e7 63 ff ff                                  	call   0xae6f90
  af0ba9:	e9 bf 05 00 00                                  	jmp    0xaf116d
  af0bae:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0bb4:	48 8b 8d 88 f7 ff ff                            	mov    rcx,QWORD PTR [rbp-0x878]
  af0bbb:	48 8d 95 b0 f7 ff ff                            	lea    rdx,[rbp-0x850]
  af0bc2:	44 89 ef                                        	mov    edi,r13d
  af0bc5:	e8 86 68 ff ff                                  	call   0xae7450
  af0bca:	e9 59 02 00 00                                  	jmp    0xaf0e28
  af0bcf:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0bd5:	48 8d 95 b0 f7 ff ff                            	lea    rdx,[rbp-0x850]
  af0bdc:	44 89 ef                                        	mov    edi,r13d
  af0bdf:	e8 fc 64 ff ff                                  	call   0xae70e0
  af0be4:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0beb:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0bf1:	85 c0                                           	test   eax,eax
  af0bf3:	0f 85 ff 05 00 00                               	jne    0xaf11f8
  af0bf9:	48 8d bd b0 f7 ff ff                            	lea    rdi,[rbp-0x850]
  af0c00:	ba 04 00 00 00                                  	mov    edx,0x4
  af0c05:	48 8b b5 90 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x870]
  af0c0c:	e9 41 02 00 00                                  	jmp    0xaf0e52
  af0c11:	41 80 f4 01                                     	xor    r12b,0x1
  af0c15:	41 0f b6 c4                                     	movzx  eax,r12b
  af0c19:	8d 3c 40                                        	lea    edi,[rax+rax*2]
  af0c1c:	e8 cf de fc ff                                  	call   0xabeaf0
  af0c21:	e9 47 05 00 00                                  	jmp    0xaf116d
  af0c26:	48 8b b5 88 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x878]
  af0c2d:	48 8d bd b0 f7 ff ff                            	lea    rdi,[rbp-0x850]
  af0c34:	e8 c7 9f b1 ff                                  	call   0x60ac00
  af0c39:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0c40:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0c46:	85 c0                                           	test   eax,eax
  af0c48:	0f 8f ef 01 00 00                               	jg     0xaf0e3d
  af0c4e:	e9 a5 05 00 00                                  	jmp    0xaf11f8
  af0c53:	45 84 e4                                        	test   r12b,r12b
  af0c56:	0f 84 20 05 00 00                               	je     0xaf117c
  af0c5c:	83 bd 9c f7 ff ff 01                            	cmp    DWORD PTR [rbp-0x864],0x1
  af0c63:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0c6a:	bf 02 00 00 00                                  	mov    edi,0x2
  af0c6f:	0f 84 14 05 00 00                               	je     0xaf1189
  af0c75:	c7 85 a8 f7 ff ff 19 02 0d 80                   	mov    DWORD PTR [rbp-0x858],0x800d0219
  af0c7f:	e9 74 05 00 00                                  	jmp    0xaf11f8
  af0c84:	e8 57 a1 b1 ff                                  	call   0x60ade0
  af0c89:	e9 df 04 00 00                                  	jmp    0xaf116d
  af0c8e:	e8 dd 80 ff ff                                  	call   0xae8d70
  af0c93:	e9 d5 04 00 00                                  	jmp    0xaf116d
  af0c98:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0c9e:	48 8b 8d 88 f7 ff ff                            	mov    rcx,QWORD PTR [rbp-0x878]
  af0ca5:	48 8d 95 b0 f7 ff ff                            	lea    rdx,[rbp-0x850]
  af0cac:	44 89 ef                                        	mov    edi,r13d
  af0caf:	e8 ec 6c ff ff                                  	call   0xae79a0
  af0cb4:	e9 6f 01 00 00                                  	jmp    0xaf0e28
  af0cb9:	48 8b 9d 88 f7 ff ff                            	mov    rbx,QWORD PTR [rbp-0x878]
  af0cc0:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0cc7:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0cce:	48 89 da                                        	mov    rdx,rbx
  af0cd1:	e8 6a 06 00 00                                  	call   0xaf1340
  af0cd6:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0cdc:	85 c0                                           	test   eax,eax
  af0cde:	0f 85 1e 03 00 00                               	jne    0xaf1002
  af0ce4:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0cea:	48 8d 95 b0 f7 ff ff                            	lea    rdx,[rbp-0x850]
  af0cf1:	44 89 ef                                        	mov    edi,r13d
  af0cf4:	48 89 d9                                        	mov    rcx,rbx
  af0cf7:	e8 a4 6a ff ff                                  	call   0xae77a0
  af0cfc:	e9 6c 04 00 00                                  	jmp    0xaf116d
  af0d01:	e8 7a a1 b1 ff                                  	call   0x60ae80
  af0d06:	e9 62 04 00 00                                  	jmp    0xaf116d
  af0d0b:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0d12:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0d19:	ba 10 00 00 00                                  	mov    edx,0x10
  af0d1e:	e8 1d 06 00 00                                  	call   0xaf1340
  af0d23:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0d29:	85 c0                                           	test   eax,eax
  af0d2b:	0f 85 d1 02 00 00                               	jne    0xaf1002
  af0d31:	48 8b b5 b0 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x850]
  af0d38:	8b 95 b8 f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x848]
  af0d3e:	48 8b 8b 40 01 00 00                            	mov    rcx,QWORD PTR [rbx+0x140]
  af0d45:	4c 8d 8d ac f7 ff ff                            	lea    r9,[rbp-0x854]
  af0d4c:	44 89 ef                                        	mov    edi,r13d
  af0d4f:	41 b8 01 00 00 00                               	mov    r8d,0x1
  af0d55:	e8 86 06 00 00                                  	call   0xaf13e0
  af0d5a:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0d61:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0d67:	85 c0                                           	test   eax,eax
  af0d69:	0f 85 89 04 00 00                               	jne    0xaf11f8
  af0d6f:	8b b5 ac f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x854]
  af0d75:	48 8d 95 bc f7 ff ff                            	lea    rdx,[rbp-0x844]
  af0d7c:	44 89 ef                                        	mov    edi,r13d
  af0d7f:	e8 5c 63 ff ff                                  	call   0xae70e0
  af0d84:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0d8a:	85 c0                                           	test   eax,eax
  af0d8c:	0f 85 66 04 00 00                               	jne    0xaf11f8
  af0d92:	48 8d bd b0 f7 ff ff                            	lea    rdi,[rbp-0x850]
  af0d99:	ba 10 00 00 00                                  	mov    edx,0x10
  af0d9e:	e9 62 fe ff ff                                  	jmp    0xaf0c05
  af0da3:	48 8b 9d 88 f7 ff ff                            	mov    rbx,QWORD PTR [rbp-0x878]
  af0daa:	48 8d 35 2f d2 dd 01                            	lea    rsi,[rip+0x1ddd22f]        # 0x28cdfe0
  af0db1:	ba 01 01 00 00                                  	mov    edx,0x101
  af0db6:	48 89 df                                        	mov    rdi,rbx
  af0db9:	e8 92 7d 11 00                                  	call   0xc08b50
  af0dbe:	48 85 c0                                        	test   rax,rax
  af0dc1:	0f 84 7d 03 00 00                               	je     0xaf1144
  af0dc7:	8b bd 9c f7 ff ff                               	mov    edi,DWORD PTR [rbp-0x864]
  af0dcd:	48 89 c6                                        	mov    rsi,rax
  af0dd0:	48 89 da                                        	mov    rdx,rbx
  af0dd3:	49 89 c7                                        	mov    r15,rax
  af0dd6:	e8 55 de fc ff                                  	call   0xabec30
  af0ddb:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0de1:	85 c0                                           	test   eax,eax
  af0de3:	0f 85 40 03 00 00                               	jne    0xaf1129
  af0de9:	e9 17 03 00 00                                  	jmp    0xaf1105
  af0dee:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0df4:	48 8b 8d 88 f7 ff ff                            	mov    rcx,QWORD PTR [rbp-0x878]
  af0dfb:	48 8d 95 b0 f7 ff ff                            	lea    rdx,[rbp-0x850]
  af0e02:	44 89 ef                                        	mov    edi,r13d
  af0e05:	e8 56 6f ff ff                                  	call   0xae7d60
  af0e0a:	eb 1c                                           	jmp    0xaf0e28
  af0e0c:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0e12:	48 8b 8d 88 f7 ff ff                            	mov    rcx,QWORD PTR [rbp-0x878]
  af0e19:	48 8d 95 b0 f7 ff ff                            	lea    rdx,[rbp-0x850]
  af0e20:	44 89 ef                                        	mov    edi,r13d
  af0e23:	e8 08 72 ff ff                                  	call   0xae8030
  af0e28:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0e2f:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0e35:	85 c0                                           	test   eax,eax
  af0e37:	0f 85 bb 03 00 00                               	jne    0xaf11f8
  af0e3d:	48 8b b5 90 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x870]
  af0e44:	48 8b 95 88 f7 ff ff                            	mov    rdx,QWORD PTR [rbp-0x878]
  af0e4b:	48 8d bd b0 f7 ff ff                            	lea    rdi,[rbp-0x850]
  af0e52:	e8 39 05 00 00                                  	call   0xaf1390
  af0e57:	85 c0                                           	test   eax,eax
  af0e59:	b9 10 02 0d 80                                  	mov    ecx,0x800d0210
  af0e5e:	0f 44 c8                                        	cmove  ecx,eax
  af0e61:	89 8d a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],ecx
  af0e67:	e9 8c 03 00 00                                  	jmp    0xaf11f8
  af0e6c:	e8 2f 83 ff ff                                  	call   0xae91a0
  af0e71:	e9 35 03 00 00                                  	jmp    0xaf11ab
  af0e76:	e8 15 9d b1 ff                                  	call   0x60ab90
  af0e7b:	e9 ed 02 00 00                                  	jmp    0xaf116d
  af0e80:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0e87:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0e8e:	ba 10 00 00 00                                  	mov    edx,0x10
  af0e93:	e8 a8 04 00 00                                  	call   0xaf1340
  af0e98:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0e9e:	85 c0                                           	test   eax,eax
  af0ea0:	0f 85 5c 01 00 00                               	jne    0xaf1002
  af0ea6:	48 8b b5 b0 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x850]
  af0ead:	8b 95 b8 f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x848]
  af0eb3:	48 8b 8b 40 01 00 00                            	mov    rcx,QWORD PTR [rbx+0x140]
  af0eba:	4c 8d 8d ac f7 ff ff                            	lea    r9,[rbp-0x854]
  af0ec1:	44 89 ef                                        	mov    edi,r13d
  af0ec4:	41 b8 02 00 00 00                               	mov    r8d,0x2
  af0eca:	e8 11 05 00 00                                  	call   0xaf13e0
  af0ecf:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0ed6:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0edc:	85 c0                                           	test   eax,eax
  af0ede:	0f 85 14 03 00 00                               	jne    0xaf11f8
  af0ee4:	8b b5 ac f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x854]
  af0eea:	8b 95 bc f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x844]
  af0ef0:	44 89 ef                                        	mov    edi,r13d
  af0ef3:	e8 98 60 ff ff                                  	call   0xae6f90
  af0ef8:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0efe:	e9 f5 02 00 00                                  	jmp    0xaf11f8
  af0f03:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0f0a:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0f11:	ba 04 00 00 00                                  	mov    edx,0x4
  af0f16:	e8 25 04 00 00                                  	call   0xaf1340
  af0f1b:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0f21:	85 c0                                           	test   eax,eax
  af0f23:	0f 85 d9 00 00 00                               	jne    0xaf1002
  af0f29:	8b 95 b0 f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x850]
  af0f2f:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af0f35:	44 89 ef                                        	mov    edi,r13d
  af0f38:	31 c9                                           	xor    ecx,ecx
  af0f3a:	45 31 c0                                        	xor    r8d,r8d
  af0f3d:	e8 2e 75 ff ff                                  	call   0xae8470
  af0f42:	e9 26 02 00 00                                  	jmp    0xaf116d
  af0f47:	e8 c4 38 1c 00                                  	call   0xcb4810
  af0f4c:	e9 1c 02 00 00                                  	jmp    0xaf116d
  af0f51:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0f58:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0f5f:	ba 18 08 00 00                                  	mov    edx,0x818
  af0f64:	e8 d7 03 00 00                                  	call   0xaf1340
  af0f69:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0f6f:	85 c0                                           	test   eax,eax
  af0f71:	0f 85 8b 00 00 00                               	jne    0xaf1002
  af0f77:	48 8b b5 b0 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x850]
  af0f7e:	8b 95 b8 f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x848]
  af0f84:	48 8b 8b 40 01 00 00                            	mov    rcx,QWORD PTR [rbx+0x140]
  af0f8b:	4c 8d 8d ac f7 ff ff                            	lea    r9,[rbp-0x854]
  af0f92:	44 89 ef                                        	mov    edi,r13d
  af0f95:	41 b8 02 00 00 00                               	mov    r8d,0x2
  af0f9b:	e8 40 04 00 00                                  	call   0xaf13e0
  af0fa0:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af0fa7:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0fad:	85 c0                                           	test   eax,eax
  af0faf:	0f 85 43 02 00 00                               	jne    0xaf11f8
  af0fb5:	8b b5 ac f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x854]
  af0fbb:	48 8b 8d c0 f7 ff ff                            	mov    rcx,QWORD PTR [rbp-0x840]
  af0fc2:	48 8d 95 c8 f7 ff ff                            	lea    rdx,[rbp-0x838]
  af0fc9:	44 89 ef                                        	mov    edi,r13d
  af0fcc:	e8 cf 67 ff ff                                  	call   0xae77a0
  af0fd1:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0fd7:	e9 1c 02 00 00                                  	jmp    0xaf11f8
  af0fdc:	48 8b bd 90 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x870]
  af0fe3:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af0fea:	ba 04 00 00 00                                  	mov    edx,0x4
  af0fef:	e8 4c 03 00 00                                  	call   0xaf1340
  af0ff4:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af0ffa:	85 c0                                           	test   eax,eax
  af0ffc:	0f 84 9e 01 00 00                               	je     0xaf11a0
  af1002:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af1009:	c7 85 a8 f7 ff ff 0f 02 0d 80                   	mov    DWORD PTR [rbp-0x858],0x800d020f
  af1013:	e9 e0 01 00 00                                  	jmp    0xaf11f8
  af1018:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af101e:	48 8d bd b0 f7 ff ff                            	lea    rdi,[rbp-0x850]
  af1025:	e8 56 63 e1 ff                                  	call   0x907380
  af102a:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af1031:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af1037:	85 c0                                           	test   eax,eax
  af1039:	0f 88 b9 01 00 00                               	js     0xaf11f8
  af103f:	48 8b b5 90 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x870]
  af1046:	48 8b 95 88 f7 ff ff                            	mov    rdx,QWORD PTR [rbp-0x878]
  af104d:	48 8d bd b0 f7 ff ff                            	lea    rdi,[rbp-0x850]
  af1054:	e8 37 03 00 00                                  	call   0xaf1390
  af1059:	85 c0                                           	test   eax,eax
  af105b:	0f 84 97 01 00 00                               	je     0xaf11f8
  af1061:	c7 85 a8 f7 ff ff 10 02 0d 80                   	mov    DWORD PTR [rbp-0x858],0x800d0210
  af106b:	e9 88 01 00 00                                  	jmp    0xaf11f8
  af1070:	48 8b bd 88 f7 ff ff                            	mov    rdi,QWORD PTR [rbp-0x878]
  af1077:	48 8d 35 62 cf dd 01                            	lea    rsi,[rip+0x1ddcf62]        # 0x28cdfe0
  af107e:	ba 01 01 00 00                                  	mov    edx,0x101
  af1083:	e8 c8 7a 11 00                                  	call   0xc08b50
  af1088:	48 85 c0                                        	test   rax,rax
  af108b:	0f 84 b3 00 00 00                               	je     0xaf1144
  af1091:	8b bd 9c f7 ff ff                               	mov    edi,DWORD PTR [rbp-0x864]
  af1097:	48 89 c6                                        	mov    rsi,rax
  af109a:	49 89 c7                                        	mov    r15,rax
  af109d:	e8 ee 62 e1 ff                                  	call   0x907390
  af10a2:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af10a8:	85 c0                                           	test   eax,eax
  af10aa:	75 7d                                           	jne    0xaf1129
  af10ac:	48 8b b5 90 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x870]
  af10b3:	48 8b 95 88 f7 ff ff                            	mov    rdx,QWORD PTR [rbp-0x878]
  af10ba:	4c 89 ff                                        	mov    rdi,r15
  af10bd:	eb 53                                           	jmp    0xaf1112
  af10bf:	48 83 bd 90 f7 ff ff 00                         	cmp    QWORD PTR [rbp-0x870],0x0
  af10c7:	0f 84 de 00 00 00                               	je     0xaf11ab
  af10cd:	48 8b 9d 88 f7 ff ff                            	mov    rbx,QWORD PTR [rbp-0x878]
  af10d4:	48 8d 35 05 cf dd 01                            	lea    rsi,[rip+0x1ddcf05]        # 0x28cdfe0
  af10db:	ba 01 01 00 00                                  	mov    edx,0x101
  af10e0:	48 89 df                                        	mov    rdi,rbx
  af10e3:	e8 68 7a 11 00                                  	call   0xc08b50
  af10e8:	48 85 c0                                        	test   rax,rax
  af10eb:	74 57                                           	je     0xaf1144
  af10ed:	48 89 c7                                        	mov    rdi,rax
  af10f0:	48 89 de                                        	mov    rsi,rbx
  af10f3:	49 89 c7                                        	mov    r15,rax
  af10f6:	e8 f5 7e 76 ff                                  	call   0x258ff0
  af10fb:	c7 85 a8 f7 ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x858],0x0
  af1105:	48 8b b5 90 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x870]
  af110c:	4c 89 ff                                        	mov    rdi,r15
  af110f:	48 89 da                                        	mov    rdx,rbx
  af1112:	e8 79 02 00 00                                  	call   0xaf1390
  af1117:	89 c1                                           	mov    ecx,eax
  af1119:	85 c0                                           	test   eax,eax
  af111b:	b8 10 02 0d 80                                  	mov    eax,0x800d0210
  af1120:	0f 44 c1                                        	cmove  eax,ecx
  af1123:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af1129:	48 8d 35 b0 ce dd 01                            	lea    rsi,[rip+0x1ddceb0]        # 0x28cdfe0
  af1130:	4c 89 ff                                        	mov    rdi,r15
  af1133:	e8 b8 7c 11 00                                  	call   0xc08df0
  af1138:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af113f:	e9 b4 00 00 00                                  	jmp    0xaf11f8
  af1144:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af114b:	c7 85 a8 f7 ff ff 11 02 0d 80                   	mov    DWORD PTR [rbp-0x858],0x800d0211
  af1155:	e9 9e 00 00 00                                  	jmp    0xaf11f8
  af115a:	e8 a1 9d b1 ff                                  	call   0x60af00
  af115f:	eb 0c                                           	jmp    0xaf116d
  af1161:	e8 7a 7f ff ff                                  	call   0xae90e0
  af1166:	eb 05                                           	jmp    0xaf116d
  af1168:	e8 e3 80 ff ff                                  	call   0xae9250
  af116d:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af1174:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af117a:	eb 7c                                           	jmp    0xaf11f8
  af117c:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af1183:	8b bd 9c f7 ff ff                               	mov    edi,DWORD PTR [rbp-0x864]
  af1189:	c7 85 a8 f7 ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x858],0x0
  af1193:	e8 98 78 ff ff                                  	call   0xae8a30
  af1198:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af119e:	eb 58                                           	jmp    0xaf11f8
  af11a0:	8b bd b0 f7 ff ff                               	mov    edi,DWORD PTR [rbp-0x850]
  af11a6:	e8 15 70 ff ff                                  	call   0xae81c0
  af11ab:	4c 8b bd a0 f7 ff ff                            	mov    r15,QWORD PTR [rbp-0x860]
  af11b2:	c7 85 a8 f7 ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x858],0x0
  af11bc:	eb 3a                                           	jmp    0xaf11f8
  af11be:	8b bd 9c f7 ff ff                               	mov    edi,DWORD PTR [rbp-0x864]
  af11c4:	48 8d b5 b0 f7 ff ff                            	lea    rsi,[rbp-0x850]
  af11cb:	e8 60 36 1c 00                                  	call   0xcb4830
  af11d0:	e9 5a fc ff ff                                  	jmp    0xaf0e2f
  af11d5:	c7 85 a8 f7 ff ff 02 02 0d 80                   	mov    DWORD PTR [rbp-0x858],0x800d0202
  af11df:	eb 17                                           	jmp    0xaf11f8
  af11e1:	8b 95 b4 f7 ff ff                               	mov    edx,DWORD PTR [rbp-0x84c]
  af11e7:	8b b5 9c f7 ff ff                               	mov    esi,DWORD PTR [rbp-0x864]
  af11ed:	e8 6e 7a ff ff                                  	call   0xae8c60
  af11f2:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af11f8:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  af1201:	48 8d 35 8f e0 85 00                            	lea    rsi,[rip+0x85e08f]        # 0x134f297
  af1208:	31 d2                                           	xor    edx,edx
  af120a:	e8 d1 91 12 00                                  	call   0xc1a3e0
  af120f:	48 8d bd a8 f7 ff ff                            	lea    rdi,[rbp-0x858]
  af1216:	ba 04 00 00 00                                  	mov    edx,0x4
  af121b:	4c 89 fe                                        	mov    rsi,r15
  af121e:	e8 ad 7f 76 ff                                  	call   0x2591d0
  af1223:	48 8d 0d e6 b0 e2 02                            	lea    rcx,[rip+0x2e2b0e6]        # 0x391c310
  af122a:	48 8b 09                                        	mov    rcx,QWORD PTR [rcx]
  af122d:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  af1231:	0f 85 00 01 00 00                               	jne    0xaf1337
  af1237:	48 81 c4 58 08 00 00                            	add    rsp,0x858
  af123e:	5b                                              	pop    rbx
  af123f:	41 5c                                           	pop    r12
  af1241:	41 5d                                           	pop    r13
  af1243:	41 5e                                           	pop    r14
  af1245:	41 5f                                           	pop    r15
  af1247:	5d                                              	pop    rbp
  af1248:	c3                                              	ret
  af1249:	e8 82 49 85 ff                                  	call   0x345bd0
  af124e:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af1254:	eb a2                                           	jmp    0xaf11f8
  af1256:	45 84 e4                                        	test   r12b,r12b
  af1259:	74 15                                           	je     0xaf1270
  af125b:	b8 19 02 0d 80                                  	mov    eax,0x800d0219
  af1260:	41 83 fd 01                                     	cmp    r13d,0x1
  af1264:	41 bd 02 00 00 00                               	mov    r13d,0x2
  af126a:	0f 85 b3 fe ff ff                               	jne    0xaf1123
  af1270:	44 89 ef                                        	mov    edi,r13d
  af1273:	89 ce                                           	mov    esi,ecx
  af1275:	c7 85 a8 f7 ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x858],0x0
  af127f:	41 89 ce                                        	mov    r14d,ecx
  af1282:	e8 e9 32 85 ff                                  	call   0x344570
  af1287:	48 89 c1                                        	mov    rcx,rax
  af128a:	b8 08 02 0d 80                                  	mov    eax,0x800d0208
  af128f:	48 39 d9                                        	cmp    rcx,rbx
  af1292:	0f 85 8b fe ff ff                               	jne    0xaf1123
  af1298:	44 89 ef                                        	mov    edi,r13d
  af129b:	4c 89 fe                                        	mov    rsi,r15
  af129e:	48 89 da                                        	mov    rdx,rbx
  af12a1:	44 89 f1                                        	mov    ecx,r14d
  af12a4:	e8 57 47 85 ff                                  	call   0x345a00
  af12a9:	eb 72                                           	jmp    0xaf131d
  af12ab:	44 89 e7                                        	mov    edi,r12d
  af12ae:	44 89 ee                                        	mov    esi,r13d
  af12b1:	e8 0a 33 85 ff                                  	call   0x3445c0
  af12b6:	48 89 c1                                        	mov    rcx,rax
  af12b9:	b8 08 02 0d 80                                  	mov    eax,0x800d0208
  af12be:	48 39 d9                                        	cmp    rcx,rbx
  af12c1:	0f 85 5c fe ff ff                               	jne    0xaf1123
  af12c7:	44 89 e7                                        	mov    edi,r12d
  af12ca:	4c 89 fe                                        	mov    rsi,r15
  af12cd:	48 89 da                                        	mov    rdx,rbx
  af12d0:	44 89 e9                                        	mov    ecx,r13d
  af12d3:	e8 58 33 85 ff                                  	call   0x344630
  af12d8:	eb 43                                           	jmp    0xaf131d
  af12da:	b8 08 02 0d 80                                  	mov    eax,0x800d0208
  af12df:	48 83 fb 40                                     	cmp    rbx,0x40
  af12e3:	0f 82 3a fe ff ff                               	jb     0xaf1123
  af12e9:	44 89 e7                                        	mov    edi,r12d
  af12ec:	4c 89 fe                                        	mov    rsi,r15
  af12ef:	48 89 da                                        	mov    rdx,rbx
  af12f2:	44 89 e9                                        	mov    ecx,r13d
  af12f5:	e8 16 33 85 ff                                  	call   0x344610
  af12fa:	eb 21                                           	jmp    0xaf131d
  af12fc:	e8 ef 48 85 ff                                  	call   0x345bf0
  af1301:	48 89 c1                                        	mov    rcx,rax
  af1304:	b8 08 02 0d 80                                  	mov    eax,0x800d0208
  af1309:	48 39 d9                                        	cmp    rcx,rbx
  af130c:	0f 85 11 fe ff ff                               	jne    0xaf1123
  af1312:	4c 89 ff                                        	mov    rdi,r15
  af1315:	48 89 de                                        	mov    rsi,rbx
  af1318:	e8 f3 48 85 ff                                  	call   0x345c10
  af131d:	89 85 a8 f7 ff ff                               	mov    DWORD PTR [rbp-0x858],eax
  af1323:	85 c0                                           	test   eax,eax
  af1325:	0f 85 fe fd ff ff                               	jne    0xaf1129
  af132b:	48 8b b5 b8 f7 ff ff                            	mov    rsi,QWORD PTR [rbp-0x848]
  af1332:	e9 d5 fd ff ff                                  	jmp    0xaf110c
  af1337:	e8 74 c3 c0 ff                                  	call   0x6fd6b0
  af133c:	0f 0b                                           	ud2
  af133e:	90                                              	nop
  af133f:	90                                              	nop
  af1340:	55                                              	push   rbp
  af1341:	48 89 e5                                        	mov    rbp,rsp
  af1344:	41 57                                           	push   r15
  af1346:	41 56                                           	push   r14
  af1348:	53                                              	push   rbx
  af1349:	50                                              	push   rax
  af134a:	49 89 ff                                        	mov    r15,rdi
  af134d:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  af1356:	49 89 f6                                        	mov    r14,rsi
  af1359:	48 8d 35 dd 6b 8a 00                            	lea    rsi,[rip+0x8a6bdd]        # 0x1397f3d
  af1360:	48 89 d3                                        	mov    rbx,rdx
  af1363:	31 d2                                           	xor    edx,edx
  af1365:	e8 76 90 12 00                                  	call   0xc1a3e0
  af136a:	4c 89 ff                                        	mov    rdi,r15
  af136d:	4c 89 f6                                        	mov    rsi,r14
  af1370:	48 89 da                                        	mov    rdx,rbx
  af1373:	48 83 c4 08                                     	add    rsp,0x8
  af1377:	5b                                              	pop    rbx
  af1378:	41 5e                                           	pop    r14
  af137a:	41 5f                                           	pop    r15
  af137c:	5d                                              	pop    rbp
  af137d:	e9 fe 7e 76 ff                                  	jmp    0x259280
  af1382:	90                                              	nop
  af1383:	90                                              	nop
  af1384:	90                                              	nop
  af1385:	90                                              	nop
  af1386:	90                                              	nop
  af1387:	90                                              	nop
  af1388:	90                                              	nop
  af1389:	90                                              	nop
  af138a:	90                                              	nop
  af138b:	90                                              	nop
  af138c:	90                                              	nop
  af138d:	90                                              	nop
  af138e:	90                                              	nop
  af138f:	90                                              	nop
  af1390:	55                                              	push   rbp
  af1391:	48 89 e5                                        	mov    rbp,rsp
  af1394:	41 57                                           	push   r15
  af1396:	41 56                                           	push   r14
  af1398:	53                                              	push   rbx
  af1399:	50                                              	push   rax
  af139a:	49 89 ff                                        	mov    r15,rdi
  af139d:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  af13a6:	49 89 f6                                        	mov    r14,rsi
  af13a9:	48 8d 35 e7 de 85 00                            	lea    rsi,[rip+0x85dee7]        # 0x134f297
  af13b0:	48 89 d3                                        	mov    rbx,rdx
  af13b3:	31 d2                                           	xor    edx,edx
  af13b5:	e8 26 90 12 00                                  	call   0xc1a3e0
  af13ba:	4c 89 ff                                        	mov    rdi,r15
  af13bd:	4c 89 f6                                        	mov    rsi,r14
  af13c0:	48 89 da                                        	mov    rdx,rbx
  af13c3:	48 83 c4 08                                     	add    rsp,0x8
  af13c7:	5b                                              	pop    rbx
  af13c8:	41 5e                                           	pop    r14
  af13ca:	41 5f                                           	pop    r15
  af13cc:	5d                                              	pop    rbp
  af13cd:	e9 fe 7d 76 ff                                  	jmp    0x2591d0
  af13d2:	90                                              	nop
  af13d3:	90                                              	nop
  af13d4:	90                                              	nop
  af13d5:	90                                              	nop
  af13d6:	90                                              	nop
  af13d7:	90                                              	nop
  af13d8:	90                                              	nop
  af13d9:	90                                              	nop
  af13da:	90                                              	nop
  af13db:	90                                              	nop
  af13dc:	90                                              	nop
  af13dd:	90                                              	nop
  af13de:	90                                              	nop
  af13df:	90                                              	nop
  af13e0:	48 85 c9                                        	test   rcx,rcx
  af13e3:	74 7e                                           	je     0xaf1463
  af13e5:	55                                              	push   rbp
  af13e6:	48 89 e5                                        	mov    rbp,rsp
  af13e9:	41 57                                           	push   r15
  af13eb:	41 56                                           	push   r14
  af13ed:	41 55                                           	push   r13
  af13ef:	41 54                                           	push   r12
  af13f1:	53                                              	push   rbx
  af13f2:	48 83 ec 28                                     	sub    rsp,0x28
  af13f6:	48 89 f0                                        	mov    rax,rsi
  af13f9:	49 89 f2                                        	mov    r10,rsi
  af13fc:	48 c1 ee 28                                     	shr    rsi,0x28
  af1400:	41 89 c7                                        	mov    r15d,eax
  af1403:	49 c1 ea 20                                     	shr    r10,0x20
  af1407:	44 0f b6 de                                     	movzx  r11d,sil
  af140b:	be 10 08 00 00                                  	mov    esi,0x810
  af1410:	44 0f b6 f0                                     	movzx  r14d,al
  af1414:	49 89 c4                                        	mov    r12,rax
  af1417:	0f b6 dc                                        	movzx  ebx,ah
  af141a:	45 0f b6 ea                                     	movzx  r13d,r10b
  af141e:	41 c1 ef 18                                     	shr    r15d,0x18
  af1422:	c4 e2 48 f7 f0                                  	bextr  esi,eax,esi
  af1427:	49 c1 ec 30                                     	shr    r12,0x30
  af142b:	43 8d 04 37                                     	lea    eax,[r15+r14*1]
  af142f:	45 0f af eb                                     	imul   r13d,r11d
  af1433:	01 d8                                           	add    eax,ebx
  af1435:	01 f0                                           	add    eax,esi
  af1437:	44 01 e8                                        	add    eax,r13d
  af143a:	44 0f b7 e8                                     	movzx  r13d,ax
  af143e:	b8 04 02 0d 80                                  	mov    eax,0x800d0204
  af1443:	45 39 e5                                        	cmp    r13d,r12d
  af1446:	0f 85 cb 02 00 00                               	jne    0xaf1717
  af144c:	45 89 db                                        	mov    r11d,r11d
  af144f:	49 83 f3 6b                                     	xor    r11,0x6b
  af1453:	41 83 fb 0c                                     	cmp    r11d,0xc
  af1457:	76 10                                           	jbe    0xaf1469
  af1459:	b8 03 02 0d 80                                  	mov    eax,0x800d0203
  af145e:	e9 b4 02 00 00                                  	jmp    0xaf1717
  af1463:	b8 02 02 0d 80                                  	mov    eax,0x800d0202
  af1468:	c3                                              	ret
  af1469:	4c 8d 25 90 88 8c 00                            	lea    r12,[rip+0x8c8890]        # 0x13b9d00
  af1470:	4c 89 e0                                        	mov    rax,r12
  af1473:	4c 29 d8                                        	sub    rax,r11
  af1476:	44 32 50 0f                                     	xor    r10b,BYTE PTR [rax+0xf]
  af147a:	41 80 fa 19                                     	cmp    r10b,0x19
  af147e:	74 14                                           	je     0xaf1494
  af1480:	45 0f b6 d2                                     	movzx  r10d,r10b
  af1484:	b8 05 02 0d 80                                  	mov    eax,0x800d0205
  af1489:	41 83 fa 72                                     	cmp    r10d,0x72
  af148d:	74 0c                                           	je     0xaf149b
  af148f:	e9 83 02 00 00                                  	jmp    0xaf1717
  af1494:	4c 8d 25 35 8b 8c 00                            	lea    r12,[rip+0x8c8b35]        # 0x13b9fd0
  af149b:	0f b7 05 9e 69 20 03                            	movzx  eax,WORD PTR [rip+0x320699e]        # 0x3cf7e40
  af14a2:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  af14a6:	48 85 c0                                        	test   rax,rax
  af14a9:	74 ae                                           	je     0xaf1459
  af14ab:	43 0f b6 04 1c                                  	movzx  eax,BYTE PTR [r12+r11*1]
  af14b0:	47 0f b6 54 1c 01                               	movzx  r10d,BYTE PTR [r12+r11*1+0x1]
  af14b6:	45 31 d7                                        	xor    r15d,r10d
  af14b9:	31 c3                                           	xor    ebx,eax
  af14bb:	89 45 c8                                        	mov    DWORD PTR [rbp-0x38],eax
  af14be:	44 89 55 d0                                     	mov    DWORD PTR [rbp-0x30],r10d
  af14c2:	89 d8                                           	mov    eax,ebx
  af14c4:	45 89 fd                                        	mov    r13d,r15d
  af14c7:	c1 e0 18                                        	shl    eax,0x18
  af14ca:	41 c1 e5 10                                     	shl    r13d,0x10
  af14ce:	41 09 c5                                        	or     r13d,eax
  af14d1:	43 0f b6 44 1c 02                               	movzx  eax,BYTE PTR [r12+r11*1+0x2]
  af14d7:	31 c6                                           	xor    esi,eax
  af14d9:	43 0f b6 44 1c 03                               	movzx  eax,BYTE PTR [r12+r11*1+0x3]
  af14df:	c1 e6 08                                        	shl    esi,0x8
  af14e2:	41 31 c6                                        	xor    r14d,eax
  af14e5:	31 c0                                           	xor    eax,eax
  af14e7:	41 09 f6                                        	or     r14d,esi
  af14ea:	45 09 ee                                        	or     r14d,r13d
  af14ed:	eb 0e                                           	jmp    0xaf14fd
  af14ef:	90                                              	nop
  af14f0:	48 ff c0                                        	inc    rax
  af14f3:	48 3b 45 c0                                     	cmp    rax,QWORD PTR [rbp-0x40]
  af14f7:	0f 84 5c ff ff ff                               	je     0xaf1459
  af14fd:	48 8d 34 80                                     	lea    rsi,[rax+rax*4]
  af1501:	4c 8d 15 30 69 20 03                            	lea    r10,[rip+0x3206930]        # 0x3cf7e38
  af1508:	45 8b 5c f2 18                                  	mov    r11d,DWORD PTR [r10+rsi*8+0x18]
  af150d:	45 39 de                                        	cmp    r14d,r11d
  af1510:	74 44                                           	je     0xaf1556
  af1512:	4c 8d 15 1f 69 20 03                            	lea    r10,[rip+0x320691f]        # 0x3cf7e38
  af1519:	49 8d 74 f2 18                                  	lea    rsi,[r10+rsi*8+0x18]
  af151e:	44 0f b6 66 15                                  	movzx  r12d,BYTE PTR [rsi+0x15]
  af1523:	45 85 e4                                        	test   r12d,r12d
  af1526:	74 c8                                           	je     0xaf14f0
  af1528:	41 83 fc 01                                     	cmp    r12d,0x1
  af152c:	74 c2                                           	je     0xaf14f0
  af152e:	44 0f b6 6e 16                                  	movzx  r13d,BYTE PTR [rsi+0x16]
  af1533:	be 01 00 00 00                                  	mov    esi,0x1
  af1538:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  af1540:	c4 62 11 f7 d6                                  	shlx   r10d,esi,r13d
  af1545:	45 01 da                                        	add    r10d,r11d
  af1548:	45 39 d6                                        	cmp    r14d,r10d
  af154b:	74 09                                           	je     0xaf1556
  af154d:	ff c6                                           	inc    esi
  af154f:	41 39 f4                                        	cmp    r12d,esi
  af1552:	75 ec                                           	jne    0xaf1540
  af1554:	eb 9a                                           	jmp    0xaf14f0
  af1556:	85 c0                                           	test   eax,eax
  af1558:	0f 88 b9 01 00 00                               	js     0xaf1717
  af155e:	25 ff ff ff 7f                                  	and    eax,0x7fffffff
  af1563:	89 7d c0                                        	mov    DWORD PTR [rbp-0x40],edi
  af1566:	89 55 cc                                        	mov    DWORD PTR [rbp-0x34],edx
  af1569:	48 89 cf                                        	mov    rdi,rcx
  af156c:	48 8d 15 c5 68 20 03                            	lea    rdx,[rip+0x32068c5]        # 0x3cf7e38
  af1573:	44 89 45 bc                                     	mov    DWORD PTR [rbp-0x44],r8d
  af1577:	4c 89 4d b0                                     	mov    QWORD PTR [rbp-0x50],r9
  af157b:	49 89 cc                                        	mov    r12,rcx
  af157e:	48 8d 04 80                                     	lea    rax,[rax+rax*4]
  af1582:	4c 8d 6c c2 18                                  	lea    r13,[rdx+rax*8+0x18]
  af1587:	e8 44 7d b1 ff                                  	call   0x6092d0
  af158c:	83 f8 01                                        	cmp    eax,0x1
  af158f:	74 0f                                           	je     0xaf15a0
  af1591:	4c 89 e7                                        	mov    rdi,r12
  af1594:	e8 77 7d b1 ff                                  	call   0x609310
  af1599:	31 c9                                           	xor    ecx,ecx
  af159b:	83 f8 01                                        	cmp    eax,0x1
  af159e:	75 05                                           	jne    0xaf15a5
  af15a0:	b9 01 00 00 00                                  	mov    ecx,0x1
  af15a5:	4c 89 e7                                        	mov    rdi,r12
  af15a8:	89 4d d4                                        	mov    DWORD PTR [rbp-0x2c],ecx
  af15ab:	e8 20 7a b1 ff                                  	call   0x608fd0
  af15b0:	83 7d bc 01                                     	cmp    DWORD PTR [rbp-0x44],0x1
  af15b4:	41 8b 75 1c                                     	mov    esi,DWORD PTR [r13+0x1c]
  af15b8:	75 35                                           	jne    0xaf15ef
  af15ba:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  af15be:	8b 55 cc                                        	mov    edx,DWORD PTR [rbp-0x34]
  af15c1:	8b 7d c0                                        	mov    edi,DWORD PTR [rbp-0x40]
  af15c4:	83 f8 01                                        	cmp    eax,0x1
  af15c7:	75 53                                           	jne    0xaf161c
  af15c9:	40 f6 c6 10                                     	test   sil,0x10
  af15cd:	0f 85 b0 00 00 00                               	jne    0xaf1683
  af15d3:	b8 16 02 0d 80                                  	mov    eax,0x800d0216
  af15d8:	83 ff 01                                        	cmp    edi,0x1
  af15db:	0f 85 36 01 00 00                               	jne    0xaf1717
  af15e1:	83 e6 01                                        	and    esi,0x1
  af15e4:	0f 85 99 00 00 00                               	jne    0xaf1683
  af15ea:	e9 28 01 00 00                                  	jmp    0xaf1717
  af15ef:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  af15f3:	8b 55 cc                                        	mov    edx,DWORD PTR [rbp-0x34]
  af15f6:	8b 7d c0                                        	mov    edi,DWORD PTR [rbp-0x40]
  af15f9:	83 f8 01                                        	cmp    eax,0x1
  af15fc:	75 53                                           	jne    0xaf1651
  af15fe:	40 f6 c6 20                                     	test   sil,0x20
  af1602:	75 7f                                           	jne    0xaf1683
  af1604:	b8 16 02 0d 80                                  	mov    eax,0x800d0216
  af1609:	83 ff 01                                        	cmp    edi,0x1
  af160c:	0f 85 05 01 00 00                               	jne    0xaf1717
  af1612:	83 e6 02                                        	and    esi,0x2
  af1615:	75 6c                                           	jne    0xaf1683
  af1617:	e9 fb 00 00 00                                  	jmp    0xaf1717
  af161c:	40 f6 c6 01                                     	test   sil,0x1
  af1620:	75 19                                           	jne    0xaf163b
  af1622:	b8 14 02 0d 80                                  	mov    eax,0x800d0214
  af1627:	83 ff 01                                        	cmp    edi,0x1
  af162a:	0f 85 e7 00 00 00                               	jne    0xaf1717
  af1630:	89 f7                                           	mov    edi,esi
  af1632:	83 e7 10                                        	and    edi,0x10
  af1635:	0f 84 dc 00 00 00                               	je     0xaf1717
  af163b:	c1 ee 0c                                        	shr    esi,0xc
  af163e:	c4 e2 48 f2 45 d4                               	andn   eax,esi,DWORD PTR [rbp-0x2c]
  af1644:	b8 1f 02 0d 80                                  	mov    eax,0x800d021f
  af1649:	0f 85 c8 00 00 00                               	jne    0xaf1717
  af164f:	eb 32                                           	jmp    0xaf1683
  af1651:	40 f6 c6 02                                     	test   sil,0x2
  af1655:	75 19                                           	jne    0xaf1670
  af1657:	b8 14 02 0d 80                                  	mov    eax,0x800d0214
  af165c:	83 ff 01                                        	cmp    edi,0x1
  af165f:	0f 85 b2 00 00 00                               	jne    0xaf1717
  af1665:	89 f7                                           	mov    edi,esi
  af1667:	83 e7 20                                        	and    edi,0x20
  af166a:	0f 84 a7 00 00 00                               	je     0xaf1717
  af1670:	f7 d6                                           	not    esi
  af1672:	b8 1f 02 0d 80                                  	mov    eax,0x800d021f
  af1677:	c1 ee 0d                                        	shr    esi,0xd
  af167a:	85 75 d4                                        	test   DWORD PTR [rbp-0x2c],esi
  af167d:	0f 85 94 00 00 00                               	jne    0xaf1717
  af1683:	41 0f b6 45 16                                  	movzx  eax,BYTE PTR [r13+0x16]
  af1688:	83 f8 08                                        	cmp    eax,0x8
  af168b:	74 48                                           	je     0xaf16d5
  af168d:	83 f8 10                                        	cmp    eax,0x10
  af1690:	75 73                                           	jne    0xaf1705
  af1692:	b8 06 02 0d 80                                  	mov    eax,0x800d0206
  af1697:	38 55 c8                                        	cmp    BYTE PTR [rbp-0x38],dl
  af169a:	75 7b                                           	jne    0xaf1717
  af169c:	0f b6 d6                                        	movzx  edx,dh
  af169f:	33 55 d0                                        	xor    edx,DWORD PTR [rbp-0x30]
  af16a2:	74 73                                           	je     0xaf1717
  af16a4:	41 0f b6 75 15                                  	movzx  esi,BYTE PTR [r13+0x15]
  af16a9:	39 f2                                           	cmp    edx,esi
  af16ab:	77 6a                                           	ja     0xaf1717
  af16ad:	83 fb 07                                        	cmp    ebx,0x7
  af16b0:	75 18                                           	jne    0xaf16ca
  af16b2:	41 83 c7 80                                     	add    r15d,0xffffff80
  af16b6:	41 83 ff 14                                     	cmp    r15d,0x14
  af16ba:	40 0f 92 c6                                     	setb   sil
  af16be:	83 fa 11                                        	cmp    edx,0x11
  af16c1:	40 0f 93 c7                                     	setae  dil
  af16c5:	40 84 fe                                        	test   sil,dil
  af16c8:	75 4d                                           	jne    0xaf1717
  af16ca:	c1 e2 10                                        	shl    edx,0x10
  af16cd:	81 c2 00 00 ff ff                               	add    edx,0xffff0000
  af16d3:	eb 3b                                           	jmp    0xaf1710
  af16d5:	8b 7d c8                                        	mov    edi,DWORD PTR [rbp-0x38]
  af16d8:	89 d6                                           	mov    esi,edx
  af16da:	b8 06 02 0d 80                                  	mov    eax,0x800d0206
  af16df:	c1 ee 08                                        	shr    esi,0x8
  af16e2:	f7 d7                                           	not    edi
  af16e4:	40 84 fe                                        	test   sil,dil
  af16e7:	75 2e                                           	jne    0xaf1717
  af16e9:	0f b6 d2                                        	movzx  edx,dl
  af16ec:	33 55 d0                                        	xor    edx,DWORD PTR [rbp-0x30]
  af16ef:	74 26                                           	je     0xaf1717
  af16f1:	41 0f b6 75 15                                  	movzx  esi,BYTE PTR [r13+0x15]
  af16f6:	39 f2                                           	cmp    edx,esi
  af16f8:	77 1d                                           	ja     0xaf1717
  af16fa:	c1 e2 08                                        	shl    edx,0x8
  af16fd:	81 c2 00 ff ff ff                               	add    edx,0xffffff00
  af1703:	eb 0b                                           	jmp    0xaf1710
  af1705:	b8 06 02 0d 80                                  	mov    eax,0x800d0206
  af170a:	85 d2                                           	test   edx,edx
  af170c:	75 09                                           	jne    0xaf1717
  af170e:	31 d2                                           	xor    edx,edx
  af1710:	44 01 f2                                        	add    edx,r14d
  af1713:	31 c0                                           	xor    eax,eax
  af1715:	89 11                                           	mov    DWORD PTR [rcx],edx
  af1717:	48 83 c4 28                                     	add    rsp,0x28
  af171b:	5b                                              	pop    rbx
  af171c:	41 5c                                           	pop    r12
  af171e:	41 5d                                           	pop    r13
  af1720:	41 5e                                           	pop    r14
  af1722:	41 5f                                           	pop    r15
  af1724:	5d                                              	pop    rbp
  af1725:	c3                                              	ret
  af1726:	90                                              	nop
  af1727:	90                                              	nop
  af1728:	90                                              	nop
  af1729:	90                                              	nop
  af172a:	90                                              	nop
  af172b:	90                                              	nop
  af172c:	90                                              	nop
  af172d:	90                                              	nop
  af172e:	90                                              	nop
  af172f:	90                                              	nop
  af1730:	55                                              	push   rbp
  af1731:	48 89 e5                                        	mov    rbp,rsp
  af1734:	41 57                                           	push   r15
  af1736:	41 56                                           	push   r14
  af1738:	41 55                                           	push   r13
  af173a:	41 54                                           	push   r12
  af173c:	53                                              	push   rbx
  af173d:	48 83 ec 28                                     	sub    rsp,0x28
  af1741:	4c 8d 25 c8 ab e2 02                            	lea    r12,[rip+0x2e2abc8]        # 0x391c310
  af1748:	48 85 f6                                        	test   rsi,rsi
  af174b:	bb 02 02 0d 80                                  	mov    ebx,0x800d0202
  af1750:	41 0f 94 c1                                     	sete   r9b
  af1754:	48 85 c9                                        	test   rcx,rcx
  af1757:	41 0f 94 c0                                     	sete   r8b
  af175b:	45 08 c8                                        	or     r8b,r9b
  af175e:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  af1762:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  af1766:	0f 85 d0 01 00 00                               	jne    0xaf193c
  af176c:	48 8d 42 ff                                     	lea    rax,[rdx-0x1]
  af1770:	bb 08 02 0d 80                                  	mov    ebx,0x800d0208
  af1775:	48 39 c8                                        	cmp    rax,rcx
  af1778:	0f 83 be 01 00 00                               	jae    0xaf193c
  af177e:	48 39 ca                                        	cmp    rdx,rcx
  af1781:	75 3a                                           	jne    0xaf17bd
  af1783:	83 3d 76 64 20 03 00                            	cmp    DWORD PTR [rip+0x3206476],0x0        # 0x3cf7c00
  af178a:	0f 84 9b 00 00 00                               	je     0xaf182b
  af1790:	8b 05 6e 64 20 03                               	mov    eax,DWORD PTR [rip+0x320646e]        # 0x3cf7c04
  af1796:	41 89 fe                                        	mov    r14d,edi
  af1799:	85 c0                                           	test   eax,eax
  af179b:	0f 84 a1 00 00 00                               	je     0xaf1842
  af17a1:	83 3d 18 64 20 03 01                            	cmp    DWORD PTR [rip+0x3206418],0x1        # 0x3cf7bc0
  af17a8:	0f 84 94 00 00 00                               	je     0xaf1842
  af17ae:	85 c0                                           	test   eax,eax
  af17b0:	bb 0d 02 0d 80                                  	mov    ebx,0x800d020d
  af17b5:	0f 48 d8                                        	cmovs  ebx,eax
  af17b8:	e9 4c 01 00 00                                  	jmp    0xaf1909
  af17bd:	48 89 d3                                        	mov    rbx,rdx
  af17c0:	49 89 f5                                        	mov    r13,rsi
  af17c3:	41 89 ff                                        	mov    r15d,edi
  af17c6:	48 8d 35 13 c8 dd 01                            	lea    rsi,[rip+0x1ddc813]        # 0x28cdfe0
  af17cd:	48 89 cf                                        	mov    rdi,rcx
  af17d0:	ba 01 01 00 00                                  	mov    edx,0x101
  af17d5:	48 89 4d c0                                     	mov    QWORD PTR [rbp-0x40],rcx
  af17d9:	e8 72 73 11 00                                  	call   0xc08b50
  af17de:	48 85 c0                                        	test   rax,rax
  af17e1:	74 55                                           	je     0xaf1838
  af17e3:	48 89 c7                                        	mov    rdi,rax
  af17e6:	4c 89 ee                                        	mov    rsi,r13
  af17e9:	48 89 da                                        	mov    rdx,rbx
  af17ec:	49 89 c6                                        	mov    r14,rax
  af17ef:	e8 bc 78 76 ff                                  	call   0x2590b0
  af17f4:	83 3d 05 64 20 03 00                            	cmp    DWORD PTR [rip+0x3206405],0x0        # 0x3cf7c00
  af17fb:	0f 84 a8 00 00 00                               	je     0xaf18a9
  af1801:	8b 05 fd 63 20 03                               	mov    eax,DWORD PTR [rip+0x32063fd]        # 0x3cf7c04
  af1807:	85 c0                                           	test   eax,eax
  af1809:	0f 84 a1 00 00 00                               	je     0xaf18b0
  af180f:	83 3d aa 63 20 03 01                            	cmp    DWORD PTR [rip+0x32063aa],0x1        # 0x3cf7bc0
  af1816:	0f 84 94 00 00 00                               	je     0xaf18b0
  af181c:	85 c0                                           	test   eax,eax
  af181e:	bb 0d 02 0d 80                                  	mov    ebx,0x800d020d
  af1823:	0f 48 d8                                        	cmovs  ebx,eax
  af1826:	e9 f2 00 00 00                                  	jmp    0xaf191d
  af182b:	41 89 fe                                        	mov    r14d,edi
  af182e:	bb 01 02 0d 80                                  	mov    ebx,0x800d0201
  af1833:	e9 d1 00 00 00                                  	jmp    0xaf1909
  af1838:	bb 11 02 0d 80                                  	mov    ebx,0x800d0211
  af183d:	e9 fa 00 00 00                                  	jmp    0xaf193c
  af1842:	49 89 c8                                        	mov    r8,rcx
  af1845:	49 89 f7                                        	mov    r15,rsi
  af1848:	48 8d 45 cc                                     	lea    rax,[rbp-0x34]
  af184c:	bf 01 00 00 00                                  	mov    edi,0x1
  af1851:	be 05 00 00 00                                  	mov    esi,0x5
  af1856:	44 89 f2                                        	mov    edx,r14d
  af1859:	b9 02 00 00 00                                  	mov    ecx,0x2
  af185e:	45 31 c9                                        	xor    r9d,r9d
  af1861:	31 db                                           	xor    ebx,ebx
  af1863:	48 89 04 24                                     	mov    QWORD PTR [rsp],rax
  af1867:	4d 89 c5                                        	mov    r13,r8
  af186a:	e8 f1 cb ff ff                                  	call   0xaee460
  af186f:	85 c0                                           	test   eax,eax
  af1871:	0f 88 90 00 00 00                               	js     0xaf1907
  af1877:	b8 f0 00 0d 80                                  	mov    eax,0x800d00f0
  af187c:	23 45 cc                                        	and    eax,DWORD PTR [rbp-0x34]
  af187f:	3d 00 00 0d 80                                  	cmp    eax,0x800d0000
  af1884:	0f 84 b2 00 00 00                               	je     0xaf193c
  af188a:	bf 01 00 00 00                                  	mov    edi,0x1
  af188f:	44 89 f6                                        	mov    esi,r14d
  af1892:	4c 89 fa                                        	mov    rdx,r15
  af1895:	4c 89 e9                                        	mov    rcx,r13
  af1898:	e8 d3 b4 ff ff                                  	call   0xaecd70
  af189d:	89 c3                                           	mov    ebx,eax
  af189f:	85 c0                                           	test   eax,eax
  af18a1:	0f 89 95 00 00 00                               	jns    0xaf193c
  af18a7:	eb 60                                           	jmp    0xaf1909
  af18a9:	bb 01 02 0d 80                                  	mov    ebx,0x800d0201
  af18ae:	eb 6d                                           	jmp    0xaf191d
  af18b0:	4c 8b 45 c0                                     	mov    r8,QWORD PTR [rbp-0x40]
  af18b4:	48 8d 45 cc                                     	lea    rax,[rbp-0x34]
  af18b8:	bf 01 00 00 00                                  	mov    edi,0x1
  af18bd:	be 05 00 00 00                                  	mov    esi,0x5
  af18c2:	44 89 fa                                        	mov    edx,r15d
  af18c5:	b9 02 00 00 00                                  	mov    ecx,0x2
  af18ca:	45 31 c9                                        	xor    r9d,r9d
  af18cd:	31 db                                           	xor    ebx,ebx
  af18cf:	48 89 04 24                                     	mov    QWORD PTR [rsp],rax
  af18d3:	e8 88 cb ff ff                                  	call   0xaee460
  af18d8:	85 c0                                           	test   eax,eax
  af18da:	78 3f                                           	js     0xaf191b
  af18dc:	b8 f0 00 0d 80                                  	mov    eax,0x800d00f0
  af18e1:	23 45 cc                                        	and    eax,DWORD PTR [rbp-0x34]
  af18e4:	3d 00 00 0d 80                                  	cmp    eax,0x800d0000
  af18e9:	74 42                                           	je     0xaf192d
  af18eb:	48 8b 4d c0                                     	mov    rcx,QWORD PTR [rbp-0x40]
  af18ef:	bf 01 00 00 00                                  	mov    edi,0x1
  af18f4:	44 89 fe                                        	mov    esi,r15d
  af18f7:	4c 89 f2                                        	mov    rdx,r14
  af18fa:	e8 71 b4 ff ff                                  	call   0xaecd70
  af18ff:	89 c3                                           	mov    ebx,eax
  af1901:	85 c0                                           	test   eax,eax
  af1903:	79 28                                           	jns    0xaf192d
  af1905:	eb 16                                           	jmp    0xaf191d
  af1907:	89 c3                                           	mov    ebx,eax
  af1909:	0f b7 d3                                        	movzx  edx,bx
  af190c:	bf 05 00 00 00                                  	mov    edi,0x5
  af1911:	44 89 f6                                        	mov    esi,r14d
  af1914:	e8 e7 8b bb ff                                  	call   0x6aa500
  af1919:	eb 21                                           	jmp    0xaf193c
  af191b:	89 c3                                           	mov    ebx,eax
  af191d:	0f b7 d3                                        	movzx  edx,bx
  af1920:	bf 05 00 00 00                                  	mov    edi,0x5
  af1925:	44 89 fe                                        	mov    esi,r15d
  af1928:	e8 d3 8b bb ff                                  	call   0x6aa500
  af192d:	48 8d 35 ac c6 dd 01                            	lea    rsi,[rip+0x1ddc6ac]        # 0x28cdfe0
  af1934:	4c 89 f7                                        	mov    rdi,r14
  af1937:	e8 b4 74 11 00                                  	call   0xc08df0
  af193c:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  af1940:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  af1944:	75 11                                           	jne    0xaf1957
  af1946:	89 d8                                           	mov    eax,ebx
  af1948:	48 83 c4 28                                     	add    rsp,0x28
  af194c:	5b                                              	pop    rbx
  af194d:	41 5c                                           	pop    r12
  af194f:	41 5d                                           	pop    r13
  af1951:	41 5e                                           	pop    r14
  af1953:	41 5f                                           	pop    r15
  af1955:	5d                                              	pop    rbp
  af1956:	c3                                              	ret
  af1957:	e8 54 bd c0 ff                                  	call   0x6fd6b0
  af195c:	0f 0b                                           	ud2
  af195e:	90                                              	nop
  af195f:	90                                              	nop
  af1960:	55                                              	push   rbp
  af1961:	48 89 e5                                        	mov    rbp,rsp
  af1964:	41 57                                           	push   r15
  af1966:	41 56                                           	push   r14
  af1968:	41 55                                           	push   r13
  af196a:	41 54                                           	push   r12
  af196c:	53                                              	push   rbx
  af196d:	48 83 ec 28                                     	sub    rsp,0x28
  af1971:	4c 8d 2d 98 a9 e2 02                            	lea    r13,[rip+0x2e2a998]        # 0x391c310
  af1978:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  af197c:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  af1980:	83 3d 79 62 20 03 00                            	cmp    DWORD PTR [rip+0x3206279],0x0        # 0x3cf7c00
  af1987:	74 22                                           	je     0xaf19ab
  af1989:	8b 05 75 62 20 03                               	mov    eax,DWORD PTR [rip+0x3206275]        # 0x3cf7c04
  af198f:	85 c0                                           	test   eax,eax
  af1991:	74 22                                           	je     0xaf19b5
  af1993:	83 3d 26 62 20 03 01                            	cmp    DWORD PTR [rip+0x3206226],0x1        # 0x3cf7bc0
  af199a:	74 19                                           	je     0xaf19b5
  af199c:	85 c0                                           	test   eax,eax
  af199e:	bb 0d 02 0d 80                                  	mov    ebx,0x800d020d
  af19a3:	0f 48 d8                                        	cmovs  ebx,eax
  af19a6:	e9 a8 00 00 00                                  	jmp    0xaf1a53
  af19ab:	bb 01 02 0d 80                                  	mov    ebx,0x800d0201
  af19b0:	e9 9e 00 00 00                                  	jmp    0xaf1a53
  af19b5:	48 85 d2                                        	test   rdx,rdx
  af19b8:	74 76                                           	je     0xaf1a30
  af19ba:	49 89 c8                                        	mov    r8,rcx
  af19bd:	49 89 d6                                        	mov    r14,rdx
  af19c0:	89 f2                                           	mov    edx,esi
  af19c2:	48 8d 45 b8                                     	lea    rax,[rbp-0x48]
  af19c6:	4c 8d 4d bc                                     	lea    r9,[rbp-0x44]
  af19ca:	be 06 00 00 00                                  	mov    esi,0x6
  af19cf:	b9 02 00 00 00                                  	mov    ecx,0x2
  af19d4:	48 89 04 24                                     	mov    QWORD PTR [rsp],rax
  af19d8:	41 89 d4                                        	mov    r12d,edx
  af19db:	4d 89 c7                                        	mov    r15,r8
  af19de:	e8 7d ca ff ff                                  	call   0xaee460
  af19e3:	89 c3                                           	mov    ebx,eax
  af19e5:	85 c0                                           	test   eax,eax
  af19e7:	78 4e                                           	js     0xaf1a37
  af19e9:	b8 f0 00 0d 80                                  	mov    eax,0x800d00f0
  af19ee:	23 45 b8                                        	and    eax,DWORD PTR [rbp-0x48]
  af19f1:	3d 00 00 0d 80                                  	cmp    eax,0x800d0000
  af19f6:	75 44                                           	jne    0xaf1a3c
  af19f8:	48 8d 7d c0                                     	lea    rdi,[rbp-0x40]
  af19fc:	be 10 00 00 00                                  	mov    esi,0x10
  af1a01:	e8 ea 75 76 ff                                  	call   0x258ff0
  af1a06:	8b 55 bc                                        	mov    edx,DWORD PTR [rbp-0x44]
  af1a09:	89 df                                           	mov    edi,ebx
  af1a0b:	48 8d 75 c0                                     	lea    rsi,[rbp-0x40]
  af1a0f:	e8 0c c2 ff ff                                  	call   0xaedc20
  af1a14:	89 c3                                           	mov    ebx,eax
  af1a16:	44 89 e6                                        	mov    esi,r12d
  af1a19:	85 c0                                           	test   eax,eax
  af1a1b:	75 36                                           	jne    0xaf1a53
  af1a1d:	48 8b 75 c0                                     	mov    rsi,QWORD PTR [rbp-0x40]
  af1a21:	4c 89 f7                                        	mov    rdi,r14
  af1a24:	4c 89 fa                                        	mov    rdx,r15
  af1a27:	e8 84 76 76 ff                                  	call   0x2590b0
  af1a2c:	31 db                                           	xor    ebx,ebx
  af1a2e:	eb 30                                           	jmp    0xaf1a60
  af1a30:	bb 02 02 0d 80                                  	mov    ebx,0x800d0202
  af1a35:	eb 1c                                           	jmp    0xaf1a53
  af1a37:	44 89 e6                                        	mov    esi,r12d
  af1a3a:	eb 17                                           	jmp    0xaf1a53
  af1a3c:	44 89 e7                                        	mov    edi,r12d
  af1a3f:	4c 89 f6                                        	mov    rsi,r14
  af1a42:	4c 89 fa                                        	mov    rdx,r15
  af1a45:	e8 26 a6 ff ff                                  	call   0xaec070
  af1a4a:	44 89 e6                                        	mov    esi,r12d
  af1a4d:	89 c3                                           	mov    ebx,eax
  af1a4f:	85 c0                                           	test   eax,eax
  af1a51:	79 0d                                           	jns    0xaf1a60
  af1a53:	0f b7 d3                                        	movzx  edx,bx
  af1a56:	bf 05 00 00 00                                  	mov    edi,0x5
  af1a5b:	e8 a0 8a bb ff                                  	call   0x6aa500
  af1a60:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  af1a64:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  af1a68:	75 11                                           	jne    0xaf1a7b
  af1a6a:	89 d8                                           	mov    eax,ebx
  af1a6c:	48 83 c4 28                                     	add    rsp,0x28
  af1a70:	5b                                              	pop    rbx
  af1a71:	41 5c                                           	pop    r12
  af1a73:	41 5d                                           	pop    r13
  af1a75:	41 5e                                           	pop    r14
  af1a77:	41 5f                                           	pop    r15
  af1a79:	5d                                              	pop    rbp
  af1a7a:	c3                                              	ret
  af1a7b:	e8 30 bc c0 ff                                  	call   0x6fd6b0
  af1a80:	0f 0b                                           	ud2
  af1a82:	90                                              	nop
  af1a83:	90                                              	nop
  af1a84:	90                                              	nop
  af1a85:	90                                              	nop
  af1a86:	90                                              	nop
  af1a87:	90                                              	nop
  af1a88:	90                                              	nop
  af1a89:	90                                              	nop
  af1a8a:	90                                              	nop
  af1a8b:	90                                              	nop
  af1a8c:	90                                              	nop
  af1a8d:	90                                              	nop
  af1a8e:	90                                              	nop
  af1a8f:	90                                              	nop
  af1a90:	55                                              	push   rbp
  af1a91:	48 89 e5                                        	mov    rbp,rsp
  af1a94:	41 57                                           	push   r15
  af1a96:	41 56                                           	push   r14
  af1a98:	41 55                                           	push   r13
  af1a9a:	41 54                                           	push   r12
  af1a9c:	53                                              	push   rbx
  af1a9d:	48 83 ec 38                                     	sub    rsp,0x38
  af1aa1:	4c 8d 2d 68 a8 e2 02                            	lea    r13,[rip+0x2e2a868]        # 0x391c310
  af1aa8:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  af1aac:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  af1ab0:	83 3d 49 61 20 03 00                            	cmp    DWORD PTR [rip+0x3206149],0x0        # 0x3cf7c00
  af1ab7:	74 24                                           	je     0xaf1add
  af1ab9:	8b 05 45 61 20 03                               	mov    eax,DWORD PTR [rip+0x3206145]        # 0x3cf7c04
  af1abf:	48 89 cb                                        	mov    rbx,rcx
  af1ac2:	85 c0                                           	test   eax,eax
  af1ac4:	74 1f                                           	je     0xaf1ae5
  af1ac6:	83 3d f3 60 20 03 01                            	cmp    DWORD PTR [rip+0x32060f3],0x1        # 0x3cf7bc0
  af1acd:	74 16                                           	je     0xaf1ae5
  af1acf:	85 c0                                           	test   eax,eax
  af1ad1:	41 be 0d 02 0d 80                               	mov    r14d,0x800d020d
  af1ad7:	44 0f 48 f0                                     	cmovs  r14d,eax
  af1adb:	eb 77                                           	jmp    0xaf1b54
  af1add:	41 be 01 02 0d 80                               	mov    r14d,0x800d0201
  af1ae3:	eb 6f                                           	jmp    0xaf1b54
  af1ae5:	48 89 55 b0                                     	mov    QWORD PTR [rbp-0x50],rdx
  af1ae9:	89 f2                                           	mov    edx,esi
  af1aeb:	4c 8d 4d bc                                     	lea    r9,[rbp-0x44]
  af1aef:	be 09 00 00 00                                  	mov    esi,0x9
  af1af4:	b9 02 00 00 00                                  	mov    ecx,0x2
  af1af9:	49 89 d8                                        	mov    r8,rbx
  af1afc:	48 c7 04 24 00 00 00 00                         	mov    QWORD PTR [rsp],0x0
  af1b04:	41 89 d7                                        	mov    r15d,edx
  af1b07:	e8 54 c9 ff ff                                  	call   0xaee460
  af1b0c:	41 89 c6                                        	mov    r14d,eax
  af1b0f:	85 c0                                           	test   eax,eax
  af1b11:	78 3e                                           	js     0xaf1b51
  af1b13:	4c 8d 65 c0                                     	lea    r12,[rbp-0x40]
  af1b17:	be 10 00 00 00                                  	mov    esi,0x10
  af1b1c:	4c 89 e7                                        	mov    rdi,r12
  af1b1f:	e8 cc 74 76 ff                                  	call   0x258ff0
  af1b24:	8b 55 bc                                        	mov    edx,DWORD PTR [rbp-0x44]
  af1b27:	44 89 f7                                        	mov    edi,r14d
  af1b2a:	4c 89 e6                                        	mov    rsi,r12
  af1b2d:	e8 ee c0 ff ff                                  	call   0xaedc20
  af1b32:	41 89 c6                                        	mov    r14d,eax
  af1b35:	44 89 fe                                        	mov    esi,r15d
  af1b38:	85 c0                                           	test   eax,eax
  af1b3a:	75 18                                           	jne    0xaf1b54
  af1b3c:	48 8b 75 c0                                     	mov    rsi,QWORD PTR [rbp-0x40]
  af1b40:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  af1b44:	48 89 da                                        	mov    rdx,rbx
  af1b47:	e8 64 75 76 ff                                  	call   0x2590b0
  af1b4c:	45 31 f6                                        	xor    r14d,r14d
  af1b4f:	eb 11                                           	jmp    0xaf1b62
  af1b51:	44 89 fe                                        	mov    esi,r15d
  af1b54:	41 0f b7 d6                                     	movzx  edx,r14w
  af1b58:	bf 05 00 00 00                                  	mov    edi,0x5
  af1b5d:	e8 9e 89 bb ff                                  	call   0x6aa500
  af1b62:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  af1b66:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  af1b6a:	75 12                                           	jne    0xaf1b7e
  af1b6c:	44 89 f0                                        	mov    eax,r14d
  af1b6f:	48 83 c4 38                                     	add    rsp,0x38
  af1b73:	5b                                              	pop    rbx
  af1b74:	41 5c                                           	pop    r12
  af1b76:	41 5d                                           	pop    r13
  af1b78:	41 5e                                           	pop    r14
  af1b7a:	41 5f                                           	pop    r15
  af1b7c:	5d                                              	pop    rbp
  af1b7d:	c3                                              	ret
  af1b7e:	e8 2d bb c0 ff                                  	call   0x6fd6b0
  af1b83:	0f 0b                                           	ud2
  af1b85:	90                                              	nop
  af1b86:	90                                              	nop
  af1b87:	90                                              	nop
  af1b88:	90                                              	nop
  af1b89:	90                                              	nop
  af1b8a:	90                                              	nop
  af1b8b:	90                                              	nop
  af1b8c:	90                                              	nop
  af1b8d:	90                                              	nop
  af1b8e:	90                                              	nop
  af1b8f:	90                                              	nop
  af1b90:	55                                              	push   rbp
  af1b91:	48 89 e5                                        	mov    rbp,rsp
  af1b94:	41 57                                           	push   r15
  af1b96:	41 56                                           	push   r14
  af1b98:	41 55                                           	push   r13
  af1b9a:	41 54                                           	push   r12
  af1b9c:	53                                              	push   rbx
  af1b9d:	50                                              	push   rax
  af1b9e:	48 8d 3d 30 5a 88 00                            	lea    rdi,[rip+0x885a30]        # 0x13775d5
  af1ba5:	be 44 00 00 00                                  	mov    esi,0x44
  af1baa:	ba 00 00 00 22                                  	mov    edx,0x22000000
  af1baf:	31 c9                                           	xor    ecx,ecx
  af1bb1:	e8 aa 48 e3 ff                                  	call   0x926460
  af1bb6:	48 8d 1d cb 60 20 03                            	lea    rbx,[rip+0x32060cb]        # 0x3cf7c88
  af1bbd:	4c 8d 3d 65 ce 81 00                            	lea    r15,[rip+0x81ce65]        # 0x130ea29
  af1bc4:	b9 04 00 00 00                                  	mov    ecx,0x4
  af1bc9:	31 d2                                           	xor    edx,edx
  af1bcb:	48 89 df                                        	mov    rdi,rbx
  af1bce:	4c 89 fe                                        	mov    rsi,r15
  af1bd1:	e8 fa 61 9d ff                                  	call   0x4c7dd0
  af1bd6:	4c 8d 35 b3 60 20 03                            	lea    r14,[rip+0x32060b3]        # 0x3cf7c90
  af1bdd:	4c 89 fe                                        	mov    rsi,r15
  af1be0:	4c 89 f7                                        	mov    rdi,r14
  af1be3:	e8 38 c9 c4 ff                                  	call   0x73e520
  af1be8:	e8 43 38 8e ff                                  	call   0x3d5430
  af1bed:	4c 8d 3d 7c 60 20 03                            	lea    r15,[rip+0x320607c]        # 0x3cf7c70
  af1bf4:	eb 0f                                           	jmp    0xaf1c05
  af1bf6:	66 2e 0f 1f 84 00 00 00 00 00                   	cs nop WORD PTR [rax+rax*1+0x0]
  af1c00:	e8 ab 45 e3 ff                                  	call   0x9261b0
  af1c05:	e8 06 5b 8c ff                                  	call   0x3b7710
  af1c0a:	c7 05 50 60 20 03 01 00 00 00                   	mov    DWORD PTR [rip+0x3206050],0x1        # 0x3cf7c64
  af1c14:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  af1c20:	48 89 df                                        	mov    rdi,rbx
  af1c23:	31 f6                                           	xor    esi,esi
  af1c25:	31 d2                                           	xor    edx,edx
  af1c27:	31 c9                                           	xor    ecx,ecx
  af1c29:	e8 d2 4d 9d ff                                  	call   0x4c6a00
  af1c2e:	4c 89 f7                                        	mov    rdi,r14
  af1c31:	4c 89 fe                                        	mov    rsi,r15
  af1c34:	e8 07 c9 c4 ff                                  	call   0x73e540
  af1c39:	48 89 df                                        	mov    rdi,rbx
  af1c3c:	31 f6                                           	xor    esi,esi
  af1c3e:	31 d2                                           	xor    edx,edx
  af1c40:	31 c9                                           	xor    ecx,ecx
  af1c42:	e8 59 53 9d ff                                  	call   0x4c6fa0
  af1c47:	8b 05 17 60 20 03                               	mov    eax,DWORD PTR [rip+0x3206017]        # 0x3cf7c64
  af1c4d:	83 f8 02                                        	cmp    eax,0x2
  af1c50:	74 ae                                           	je     0xaf1c00
  af1c52:	83 f8 03                                        	cmp    eax,0x3
  af1c55:	74 7d                                           	je     0xaf1cd4
  af1c57:	45 31 ed                                        	xor    r13d,r13d
  af1c5a:	66 0f 1f 44 00 00                               	nop    WORD PTR [rax+rax*1+0x0]
  af1c60:	48 89 df                                        	mov    rdi,rbx
  af1c63:	31 f6                                           	xor    esi,esi
  af1c65:	31 d2                                           	xor    edx,edx
  af1c67:	31 c9                                           	xor    ecx,ecx
  af1c69:	e8 92 4d 9d ff                                  	call   0x4c6a00
  af1c6e:	48 69 15 57 e7 e2 02 f4 01 00 00                	imul   rdx,QWORD PTR [rip+0x2e2e757],0x1f4        # 0x39203d0
  af1c79:	4c 89 f7                                        	mov    rdi,r14
  af1c7c:	4c 89 fe                                        	mov    rsi,r15
  af1c7f:	41 b8 00 01 00 00                               	mov    r8d,0x100
  af1c85:	31 c9                                           	xor    ecx,ecx
  af1c87:	e8 74 cd c4 ff                                  	call   0x73ea00
  af1c8c:	48 89 df                                        	mov    rdi,rbx
  af1c8f:	41 89 c4                                        	mov    r12d,eax
  af1c92:	31 f6                                           	xor    esi,esi
  af1c94:	31 d2                                           	xor    edx,edx
  af1c96:	31 c9                                           	xor    ecx,ecx
  af1c98:	e8 03 53 9d ff                                  	call   0x4c6fa0
  af1c9d:	45 85 e4                                        	test   r12d,r12d
  af1ca0:	75 15                                           	jne    0xaf1cb7
  af1ca2:	41 81 fd e7 03 00 00                            	cmp    r13d,0x3e7
  af1ca9:	77 0c                                           	ja     0xaf1cb7
  af1cab:	41 ff c5                                        	inc    r13d
  af1cae:	83 3d af 5f 20 03 01                            	cmp    DWORD PTR [rip+0x3205faf],0x1        # 0x3cf7c64
  af1cb5:	74 a9                                           	je     0xaf1c60
  af1cb7:	e8 54 5a 8c ff                                  	call   0x3b7710
  af1cbc:	8b 05 a2 5f 20 03                               	mov    eax,DWORD PTR [rip+0x3205fa2]        # 0x3cf7c64
  af1cc2:	83 f8 02                                        	cmp    eax,0x2
  af1cc5:	0f 84 35 ff ff ff                               	je     0xaf1c00
  af1ccb:	83 f8 03                                        	cmp    eax,0x3
  af1cce:	0f 85 4c ff ff ff                               	jne    0xaf1c20
  af1cd4:	48 8d 3d b5 5f 20 03                            	lea    rdi,[rip+0x3205fb5]        # 0x3cf7c90
  af1cdb:	e8 50 c8 c4 ff                                  	call   0x73e530
  af1ce0:	48 8d 3d a1 5f 20 03                            	lea    rdi,[rip+0x3205fa1]        # 0x3cf7c88
  af1ce7:	e8 64 61 9d ff                                  	call   0x4c7e50
  af1cec:	48 8d 3d 71 5f 20 03                            	lea    rdi,[rip+0x3205f71]        # 0x3cf7c64
  af1cf3:	e8 18 4c 11 00                                  	call   0xc06910
  af1cf8:	e8 83 40 e3 ff                                  	call   0x925d80
  af1cfd:	0f 0b                                           	ud2
  af1cff:	90                                              	nop
  af1d00:	55                                              	push   rbp
  af1d01:	48 89 e5                                        	mov    rbp,rsp
  af1d04:	41 57                                           	push   r15
  af1d06:	41 56                                           	push   r14
  af1d08:	53                                              	push   rbx
  af1d09:	50                                              	push   rax
  af1d0a:	4c 8d 35 4f ad 21 03                            	lea    r14,[rip+0x321ad4f]        # 0x3d0ca60
  af1d11:	b8 05 01 0d 80                                  	mov    eax,0x800d0105
  af1d16:	31 db                                           	xor    ebx,ebx
  af1d18:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  af1d20:	42 0f b6 8c 33 08 14 00 00                      	movzx  ecx,BYTE PTR [rbx+r14*1+0x1408]
  af1d29:	80 f9 3d                                        	cmp    cl,0x3d
  af1d2c:	74 1a                                           	je     0xaf1d48
  af1d2e:	84 c9                                           	test   cl,cl
  af1d30:	0f 84 79 01 00 00                               	je     0xaf1eaf
  af1d36:	48 81 fb ff 07 00 00                            	cmp    rbx,0x7ff
  af1d3d:	48 8d 5b 01                                     	lea    rbx,[rbx+0x1]
  af1d41:	72 dd                                           	jb     0xaf1d20
  af1d43:	e9 67 01 00 00                                  	jmp    0xaf1eaf
  af1d48:	48 8d 4b ff                                     	lea    rcx,[rbx-0x1]
  af1d4c:	b8 05 01 0d 80                                  	mov    eax,0x800d0105
  af1d51:	48 81 f9 fe 00 00 00                            	cmp    rcx,0xfe
  af1d58:	0f 87 51 01 00 00                               	ja     0xaf1eaf
  af1d5e:	41 89 ff                                        	mov    r15d,edi
  af1d61:	48 8d 3d 04 c9 21 03                            	lea    rdi,[rip+0x321c904]        # 0x3d0e66c
  af1d68:	48 8d 35 f9 c0 21 03                            	lea    rsi,[rip+0x321c0f9]        # 0x3d0de68
  af1d6f:	48 89 da                                        	mov    rdx,rbx
  af1d72:	e8 39 73 76 ff                                  	call   0x2590b0
  af1d77:	31 d2                                           	xor    edx,edx
  af1d79:	42 c6 84 33 0c 1c 00 00 00                      	mov    BYTE PTR [rbx+r14*1+0x1c0c],0x0
  af1d82:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  af1d90:	42 0f b6 8c 32 0c 1c 00 00                      	movzx  ecx,BYTE PTR [rdx+r14*1+0x1c0c]
  af1d99:	83 f9 20                                        	cmp    ecx,0x20
  af1d9c:	75 11                                           	jne    0xaf1daf
  af1d9e:	48 ff c2                                        	inc    rdx
  af1da1:	48 81 fa 00 01 00 00                            	cmp    rdx,0x100
  af1da8:	75 e6                                           	jne    0xaf1d90
  af1daa:	e9 fe 00 00 00                                  	jmp    0xaf1ead
  af1daf:	83 f9 30                                        	cmp    ecx,0x30
  af1db2:	75 7c                                           	jne    0xaf1e30
  af1db4:	42 0f b6 8c 32 0d 1c 00 00                      	movzx  ecx,BYTE PTR [rdx+r14*1+0x1c0d]
  af1dbd:	31 c0                                           	xor    eax,eax
  af1dbf:	83 c9 20                                        	or     ecx,0x20
  af1dc2:	83 f9 78                                        	cmp    ecx,0x78
  af1dc5:	44 89 f9                                        	mov    ecx,r15d
  af1dc8:	75 7a                                           	jne    0xaf1e44
  af1dca:	48 81 fa fd 00 00 00                            	cmp    rdx,0xfd
  af1dd1:	0f 87 d8 00 00 00                               	ja     0xaf1eaf
  af1dd7:	31 ff                                           	xor    edi,edi
  af1dd9:	eb 18                                           	jmp    0xaf1df3
  af1ddb:	0f 1f 44 00 00                                  	nop    DWORD PTR [rax+rax*1+0x0]
  af1de0:	c1 e7 04                                        	shl    edi,0x4
  af1de3:	48 ff c2                                        	inc    rdx
  af1de6:	01 f7                                           	add    edi,esi
  af1de8:	01 c7                                           	add    edi,eax
  af1dea:	48 81 fa fe 00 00 00                            	cmp    rdx,0xfe
  af1df1:	74 36                                           	je     0xaf1e29
  af1df3:	42 0f b6 84 32 0e 1c 00 00                      	movzx  eax,BYTE PTR [rdx+r14*1+0x1c0e]
  af1dfc:	be d0 ff ff ff                                  	mov    esi,0xffffffd0
  af1e01:	44 8d 40 d0                                     	lea    r8d,[rax-0x30]
  af1e05:	41 80 f8 0a                                     	cmp    r8b,0xa
  af1e09:	72 d5                                           	jb     0xaf1de0
  af1e0b:	44 8d 40 9f                                     	lea    r8d,[rax-0x61]
  af1e0f:	be a9 ff ff ff                                  	mov    esi,0xffffffa9
  af1e14:	41 80 f8 06                                     	cmp    r8b,0x6
  af1e18:	72 c6                                           	jb     0xaf1de0
  af1e1a:	44 8d 40 bf                                     	lea    r8d,[rax-0x41]
  af1e1e:	be c9 ff ff ff                                  	mov    esi,0xffffffc9
  af1e23:	41 80 f8 05                                     	cmp    r8b,0x5
  af1e27:	76 b7                                           	jbe    0xaf1de0
  af1e29:	be 01 00 00 00                                  	mov    esi,0x1
  af1e2e:	eb 5c                                           	jmp    0xaf1e8c
  af1e30:	31 c0                                           	xor    eax,eax
  af1e32:	80 f9 2d                                        	cmp    cl,0x2d
  af1e35:	44 89 f9                                        	mov    ecx,r15d
  af1e38:	0f 94 c0                                        	sete   al
  af1e3b:	89 c6                                           	mov    esi,eax
  af1e3d:	f7 de                                           	neg    esi
  af1e3f:	83 ce 01                                        	or     esi,0x1
  af1e42:	eb 05                                           	jmp    0xaf1e49
  af1e44:	be 01 00 00 00                                  	mov    esi,0x1
  af1e49:	0f b6 c0                                        	movzx  eax,al
  af1e4c:	8d 3c 10                                        	lea    edi,[rax+rdx*1]
  af1e4f:	81 ff ff 00 00 00                               	cmp    edi,0xff
  af1e55:	77 56                                           	ja     0xaf1ead
  af1e57:	48 0d 0c 1c 00 00                               	or     rax,0x1c0c
  af1e5d:	31 ff                                           	xor    edi,edi
  af1e5f:	90                                              	nop
  af1e60:	4c 8d 04 10                                     	lea    r8,[rax+rdx*1]
  af1e64:	47 0f b6 04 06                                  	movzx  r8d,BYTE PTR [r14+r8*1]
  af1e69:	45 8d 48 d0                                     	lea    r9d,[r8-0x30]
  af1e6d:	41 80 f9 09                                     	cmp    r9b,0x9
  af1e71:	77 19                                           	ja     0xaf1e8c
  af1e73:	8d 3c bf                                        	lea    edi,[rdi+rdi*4]
  af1e76:	4c 8d 4c 10 01                                  	lea    r9,[rax+rdx*1+0x1]
  af1e7b:	48 ff c2                                        	inc    rdx
  af1e7e:	41 8d 7c 78 d0                                  	lea    edi,[r8+rdi*2-0x30]
  af1e83:	49 81 f9 0c 1d 00 00                            	cmp    r9,0x1d0c
  af1e8a:	75 d4                                           	jne    0xaf1e60
  af1e8c:	31 c0                                           	xor    eax,eax
  af1e8e:	85 ff                                           	test   edi,edi
  af1e90:	74 1d                                           	je     0xaf1eaf
  af1e92:	44 0f b7 05 a6 5f 20 03                         	movzx  r8d,WORD PTR [rip+0x3205fa6]        # 0x3cf7e40
  af1e9a:	4d 85 c0                                        	test   r8,r8
  af1e9d:	74 10                                           	je     0xaf1eaf
  af1e9f:	0f af f7                                        	imul   esi,edi
  af1ea2:	48 8d 15 8f 5f 20 03                            	lea    rdx,[rip+0x3205f8f]        # 0x3cf7e38
  af1ea9:	31 ff                                           	xor    edi,edi
  af1eab:	eb 17                                           	jmp    0xaf1ec4
  af1ead:	31 c0                                           	xor    eax,eax
  af1eaf:	48 83 c4 08                                     	add    rsp,0x8
  af1eb3:	5b                                              	pop    rbx
  af1eb4:	41 5e                                           	pop    r14
  af1eb6:	41 5f                                           	pop    r15
  af1eb8:	5d                                              	pop    rbp
  af1eb9:	c3                                              	ret
  af1eba:	48 ff c7                                        	inc    rdi
  af1ebd:	31 c0                                           	xor    eax,eax
  af1ebf:	4c 39 c7                                        	cmp    rdi,r8
  af1ec2:	74 eb                                           	je     0xaf1eaf
  af1ec4:	4c 8d 0c bf                                     	lea    r9,[rdi+rdi*4]
  af1ec8:	42 8b 44 ca 18                                  	mov    eax,DWORD PTR [rdx+r9*8+0x18]
  af1ecd:	39 c6                                           	cmp    esi,eax
  af1ecf:	74 46                                           	je     0xaf1f17
  af1ed1:	4e 8d 54 ca 18                                  	lea    r10,[rdx+r9*8+0x18]
  af1ed6:	45 0f b6 4a 15                                  	movzx  r9d,BYTE PTR [r10+0x15]
  af1edb:	45 85 c9                                        	test   r9d,r9d
  af1ede:	74 da                                           	je     0xaf1eba
  af1ee0:	41 83 f9 01                                     	cmp    r9d,0x1
  af1ee4:	74 d4                                           	je     0xaf1eba
  af1ee6:	45 0f b6 52 16                                  	movzx  r10d,BYTE PTR [r10+0x16]
  af1eeb:	41 bb 01 00 00 00                               	mov    r11d,0x1
  af1ef1:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  af1f00:	c4 42 29 f7 fb                                  	shlx   r15d,r11d,r10d
  af1f05:	41 01 c7                                        	add    r15d,eax
  af1f08:	44 39 fe                                        	cmp    esi,r15d
  af1f0b:	74 0a                                           	je     0xaf1f17
  af1f0d:	41 ff c3                                        	inc    r11d
  af1f10:	45 39 d9                                        	cmp    r9d,r11d
  af1f13:	75 eb                                           	jne    0xaf1f00
  af1f15:	eb a3                                           	jmp    0xaf1eba
  af1f17:	31 c0                                           	xor    eax,eax
  af1f19:	85 ff                                           	test   edi,edi
  af1f1b:	78 92                                           	js     0xaf1eaf
  af1f1d:	85 c9                                           	test   ecx,ecx
  af1f1f:	75 37                                           	jne    0xaf1f58
  af1f21:	83 3d 90 5c 20 03 01                            	cmp    DWORD PTR [rip+0x3205c90],0x1        # 0x3cf7bb8
  af1f28:	74 2e                                           	je     0xaf1f58
  af1f2a:	89 f9                                           	mov    ecx,edi
  af1f2c:	81 e1 ff ff ff 7f                               	and    ecx,0x7fffffff
  af1f32:	48 8d 0c 89                                     	lea    rcx,[rcx+rcx*4]
  af1f36:	0f b7 4c ca 20                                  	movzx  ecx,WORD PTR [rdx+rcx*8+0x20]
  af1f3b:	89 ca                                           	mov    edx,ecx
  af1f3d:	81 e2 ff 19 00 00                               	and    edx,0x19ff
  af1f43:	66 83 fa 10                                     	cmp    dx,0x10
  af1f47:	0f 94 c2                                        	sete   dl
  af1f4a:	66 85 c9                                        	test   cx,cx
  af1f4d:	0f 98 c1                                        	sets   cl
  af1f50:	08 d1                                           	or     cl,dl
  af1f52:	0f 85 57 ff ff ff                               	jne    0xaf1eaf
  af1f58:	ba ff 07 00 00                                  	mov    edx,0x7ff
  af1f5d:	4a 8d b4 33 09 14 00 00                         	lea    rsi,[rbx+r14*1+0x1409]
  af1f65:	31 c9                                           	xor    ecx,ecx
  af1f67:	48 29 da                                        	sub    rdx,rbx
  af1f6a:	e8 d1 01 00 00                                  	call   0xaf2140
  af1f6f:	89 c1                                           	mov    ecx,eax
  af1f71:	83 f8 01                                        	cmp    eax,0x1
  af1f74:	b8 0e 02 0d 80                                  	mov    eax,0x800d020e
  af1f79:	0f 45 c1                                        	cmovne eax,ecx
  af1f7c:	e9 2e ff ff ff                                  	jmp    0xaf1eaf
  af1f81:	90                                              	nop
  af1f82:	90                                              	nop
  af1f83:	90                                              	nop
  af1f84:	90                                              	nop
  af1f85:	90                                              	nop
  af1f86:	90                                              	nop
  af1f87:	90                                              	nop
  af1f88:	90                                              	nop
  af1f89:	90                                              	nop
  af1f8a:	90                                              	nop
  af1f8b:	90                                              	nop
  af1f8c:	90                                              	nop
  af1f8d:	90                                              	nop
  af1f8e:	90                                              	nop
  af1f8f:	90                                              	nop
  af1f90:	55                                              	push   rbp
  af1f91:	48 89 e5                                        	mov    rbp,rsp
  af1f94:	48 85 f6                                        	test   rsi,rsi
  af1f97:	0f 84 b5 00 00 00                               	je     0xaf2052
  af1f9d:	ba 01 00 00 00                                  	mov    edx,0x1
  af1fa2:	31 c9                                           	xor    ecx,ecx
  af1fa4:	31 c0                                           	xor    eax,eax
  af1fa6:	66 2e 0f 1f 84 00 00 00 00 00                   	cs nop WORD PTR [rax+rax*1+0x0]
  af1fb0:	0f b6 04 07                                     	movzx  eax,BYTE PTR [rdi+rax*1]
  af1fb4:	83 f8 20                                        	cmp    eax,0x20
  af1fb7:	75 13                                           	jne    0xaf1fcc
  af1fb9:	89 d0                                           	mov    eax,edx
  af1fbb:	ff c2                                           	inc    edx
  af1fbd:	48 39 c6                                        	cmp    rsi,rax
  af1fc0:	77 ee                                           	ja     0xaf1fb0
  af1fc2:	b8 01 00 00 00                                  	mov    eax,0x1
  af1fc7:	e9 eb 00 00 00                                  	jmp    0xaf20b7
  af1fcc:	83 f8 30                                        	cmp    eax,0x30
  af1fcf:	0f 85 84 00 00 00                               	jne    0xaf2059
  af1fd5:	89 d0                                           	mov    eax,edx
  af1fd7:	0f b6 04 07                                     	movzx  eax,BYTE PTR [rdi+rax*1]
  af1fdb:	83 c8 20                                        	or     eax,0x20
  af1fde:	83 f8 78                                        	cmp    eax,0x78
  af1fe1:	0f 85 85 00 00 00                               	jne    0xaf206c
  af1fe7:	44 8d 42 01                                     	lea    r8d,[rdx+0x1]
  af1feb:	b8 01 00 00 00                                  	mov    eax,0x1
  af1ff0:	4c 39 c6                                        	cmp    rsi,r8
  af1ff3:	0f 86 bc 00 00 00                               	jbe    0xaf20b5
  af1ff9:	83 c2 02                                        	add    edx,0x2
  af1ffc:	31 c9                                           	xor    ecx,ecx
  af1ffe:	eb 18                                           	jmp    0xaf2018
  af2000:	48 c1 e1 04                                     	shl    rcx,0x4
  af2004:	4c 01 c9                                        	add    rcx,r9
  af2007:	4c 01 c1                                        	add    rcx,r8
  af200a:	41 89 d0                                        	mov    r8d,edx
  af200d:	ff c2                                           	inc    edx
  af200f:	4c 39 c6                                        	cmp    rsi,r8
  af2012:	0f 86 9f 00 00 00                               	jbe    0xaf20b7
  af2018:	46 0f b6 04 07                                  	movzx  r8d,BYTE PTR [rdi+r8*1]
  af201d:	49 c7 c1 d0 ff ff ff                            	mov    r9,0xffffffffffffffd0
  af2024:	45 8d 50 d0                                     	lea    r10d,[r8-0x30]
  af2028:	41 80 fa 0a                                     	cmp    r10b,0xa
  af202c:	72 d2                                           	jb     0xaf2000
  af202e:	45 8d 50 9f                                     	lea    r10d,[r8-0x61]
  af2032:	49 c7 c1 a9 ff ff ff                            	mov    r9,0xffffffffffffffa9
  af2039:	41 80 fa 06                                     	cmp    r10b,0x6
  af203d:	72 c1                                           	jb     0xaf2000
  af203f:	45 8d 50 bf                                     	lea    r10d,[r8-0x41]
  af2043:	49 c7 c1 c9 ff ff ff                            	mov    r9,0xffffffffffffffc9
  af204a:	41 80 fa 05                                     	cmp    r10b,0x5
  af204e:	76 b0                                           	jbe    0xaf2000
  af2050:	eb 65                                           	jmp    0xaf20b7
  af2052:	b8 01 00 00 00                                  	mov    eax,0x1
  af2057:	eb 5c                                           	jmp    0xaf20b5
  af2059:	45 31 c0                                        	xor    r8d,r8d
  af205c:	3c 2d                                           	cmp    al,0x2d
  af205e:	41 0f 94 c0                                     	sete   r8b
  af2062:	44 89 c0                                        	mov    eax,r8d
  af2065:	f7 d8                                           	neg    eax
  af2067:	83 c8 01                                        	or     eax,0x1
  af206a:	eb 08                                           	jmp    0xaf2074
  af206c:	b8 01 00 00 00                                  	mov    eax,0x1
  af2071:	45 31 c0                                        	xor    r8d,r8d
  af2074:	45 8d 4c 10 ff                                  	lea    r9d,[r8+rdx*1-0x1]
  af2079:	4c 39 ce                                        	cmp    rsi,r9
  af207c:	76 37                                           	jbe    0xaf20b5
  af207e:	41 01 d0                                        	add    r8d,edx
  af2081:	31 c9                                           	xor    ecx,ecx
  af2083:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  af2090:	42 0f b6 14 0f                                  	movzx  edx,BYTE PTR [rdi+r9*1]
  af2095:	44 8d 4a d0                                     	lea    r9d,[rdx-0x30]
  af2099:	41 80 f9 09                                     	cmp    r9b,0x9
  af209d:	77 18                                           	ja     0xaf20b7
  af209f:	48 8d 0c 89                                     	lea    rcx,[rcx+rcx*4]
  af20a3:	45 89 c1                                        	mov    r9d,r8d
  af20a6:	41 ff c0                                        	inc    r8d
  af20a9:	48 8d 4c 4a d0                                  	lea    rcx,[rdx+rcx*2-0x30]
  af20ae:	4c 39 ce                                        	cmp    rsi,r9
  af20b1:	77 dd                                           	ja     0xaf2090
  af20b3:	eb 02                                           	jmp    0xaf20b7
  af20b5:	31 c9                                           	xor    ecx,ecx
  af20b7:	48 98                                           	cdqe
  af20b9:	48 0f af c1                                     	imul   rax,rcx
  af20bd:	5d                                              	pop    rbp
  af20be:	c3                                              	ret
  af20bf:	90                                              	nop
  af20c0:	b8 ff ff ff ff                                  	mov    eax,0xffffffff
  af20c5:	85 f6                                           	test   esi,esi
  af20c7:	7e 6e                                           	jle    0xaf2137
  af20c9:	55                                              	push   rbp
  af20ca:	48 89 e5                                        	mov    rbp,rsp
  af20cd:	53                                              	push   rbx
  af20ce:	50                                              	push   rax
  af20cf:	81 e6 ff ff ff 7f                               	and    esi,0x7fffffff
  af20d5:	31 db                                           	xor    ebx,ebx
  af20d7:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  af20e0:	0f b6 0c 1f                                     	movzx  ecx,BYTE PTR [rdi+rbx*1]
  af20e4:	80 f9 3a                                        	cmp    cl,0x3a
  af20e7:	74 0e                                           	je     0xaf20f7
  af20e9:	84 c9                                           	test   cl,cl
  af20eb:	74 44                                           	je     0xaf2131
  af20ed:	48 ff c3                                        	inc    rbx
  af20f0:	48 39 f3                                        	cmp    rbx,rsi
  af20f3:	72 eb                                           	jb     0xaf20e0
  af20f5:	eb 3a                                           	jmp    0xaf2131
  af20f7:	48 85 db                                        	test   rbx,rbx
  af20fa:	74 33                                           	je     0xaf212f
  af20fc:	48 81 fb ff 00 00 00                            	cmp    rbx,0xff
  af2103:	77 2c                                           	ja     0xaf2131
  af2105:	48 8d 05 60 c5 21 03                            	lea    rax,[rip+0x321c560]        # 0x3d0e66c
  af210c:	48 89 fe                                        	mov    rsi,rdi
  af210f:	48 89 da                                        	mov    rdx,rbx
  af2112:	48 89 c7                                        	mov    rdi,rax
  af2115:	e8 96 6f 76 ff                                  	call   0x2590b0
  af211a:	48 8d 05 3f a9 21 03                            	lea    rax,[rip+0x321a93f]        # 0x3d0ca60
  af2121:	c6 84 03 0c 1c 00 00 00                         	mov    BYTE PTR [rbx+rax*1+0x1c0c],0x0
  af2129:	ff c3                                           	inc    ebx
  af212b:	89 d8                                           	mov    eax,ebx
  af212d:	eb 02                                           	jmp    0xaf2131
  af212f:	31 c0                                           	xor    eax,eax
  af2131:	48 83 c4 08                                     	add    rsp,0x8
  af2135:	5b                                              	pop    rbx
  af2136:	5d                                              	pop    rbp
  af2137:	c3                                              	ret
  af2138:	90                                              	nop
  af2139:	90                                              	nop
  af213a:	90                                              	nop
  af213b:	90                                              	nop
  af213c:	90                                              	nop
  af213d:	90                                              	nop
  af213e:	90                                              	nop
  af213f:	90                                              	nop
  af2140:	b8 06 01 0d 80                                  	mov    eax,0x800d0106
  af2145:	48 85 d2                                        	test   rdx,rdx
  af2148:	0f 84 03 06 00 00                               	je     0xaf2751
  af214e:	55                                              	push   rbp
  af214f:	48 89 e5                                        	mov    rbp,rsp
  af2152:	41 57                                           	push   r15
  af2154:	41 56                                           	push   r14
  af2156:	41 55                                           	push   r13
  af2158:	41 54                                           	push   r12
  af215a:	53                                              	push   rbx
  af215b:	48 81 ec a8 00 00 00                            	sub    rsp,0xa8
  af2162:	89 ff                                           	mov    edi,edi
  af2164:	4c 8d 05 cd 5c 20 03                            	lea    r8,[rip+0x3205ccd]        # 0x3cf7e38
  af216b:	48 8d 5a fb                                     	lea    rbx,[rdx-0x5]
  af216f:	45 31 f6                                        	xor    r14d,r14d
  af2172:	48 8d 3c bf                                     	lea    rdi,[rdi+rdi*4]
  af2176:	4d 8d 7c f8 18                                  	lea    r15,[r8+rdi*8+0x18]
  af217b:	0f 1f 44 00 00                                  	nop    DWORD PTR [rax+rax*1+0x0]
  af2180:	42 0f b6 3c 36                                  	movzx  edi,BYTE PTR [rsi+r14*1]
  af2185:	40 80 ff 3a                                     	cmp    dil,0x3a
  af2189:	74 19                                           	je     0xaf21a4
  af218b:	40 84 ff                                        	test   dil,dil
  af218e:	0f 84 ac 05 00 00                               	je     0xaf2740
  af2194:	49 ff c6                                        	inc    r14
  af2197:	48 ff cb                                        	dec    rbx
  af219a:	49 39 d6                                        	cmp    r14,rdx
  af219d:	72 e1                                           	jb     0xaf2180
  af219f:	e9 9c 05 00 00                                  	jmp    0xaf2740
  af21a4:	49 8d 7e ff                                     	lea    rdi,[r14-0x1]
  af21a8:	48 81 ff fe 00 00 00                            	cmp    rdi,0xfe
  af21af:	0f 87 8b 05 00 00                               	ja     0xaf2740
  af21b5:	48 89 55 c0                                     	mov    QWORD PTR [rbp-0x40],rdx
  af21b9:	48 8d 3d ac c4 21 03                            	lea    rdi,[rip+0x321c4ac]        # 0x3d0e66c
  af21c0:	4c 89 f2                                        	mov    rdx,r14
  af21c3:	89 4d 84                                        	mov    DWORD PTR [rbp-0x7c],ecx
  af21c6:	48 89 75 a0                                     	mov    QWORD PTR [rbp-0x60],rsi
  af21ca:	e8 e1 6e 76 ff                                  	call   0x2590b0
  af21cf:	83 3d de 59 20 03 01                            	cmp    DWORD PTR [rip+0x32059de],0x1        # 0x3cf7bb4
  af21d6:	48 8b 4d c0                                     	mov    rcx,QWORD PTR [rbp-0x40]
  af21da:	4c 8d 25 7f a8 21 03                            	lea    r12,[rip+0x321a87f]        # 0x3d0ca60
  af21e1:	41 bd f7 ff f7 ff                               	mov    r13d,0xfff7fff7
  af21e7:	43 c6 84 26 0c 1c 00 00 00                      	mov    BYTE PTR [r14+r12*1+0x1c0c],0x0
  af21f0:	0f 85 59 01 00 00                               	jne    0xaf234f
  af21f6:	31 f6                                           	xor    esi,esi
  af21f8:	31 d2                                           	xor    edx,edx
  af21fa:	66 0f 1f 44 00 00                               	nop    WORD PTR [rax+rax*1+0x0]
  af2200:	42 0f b6 84 22 0c 1c 00 00                      	movzx  eax,BYTE PTR [rdx+r12*1+0x1c0c]
  af2209:	83 f8 20                                        	cmp    eax,0x20
  af220c:	75 16                                           	jne    0xaf2224
  af220e:	48 ff c2                                        	inc    rdx
  af2211:	48 81 fa 00 01 00 00                            	cmp    rdx,0x100
  af2218:	75 e6                                           	jne    0xaf2200
  af221a:	b8 01 00 00 00                                  	mov    eax,0x1
  af221f:	e9 ed 00 00 00                                  	jmp    0xaf2311
  af2224:	83 f8 30                                        	cmp    eax,0x30
  af2227:	75 7f                                           	jne    0xaf22a8
  af2229:	42 0f b6 84 22 0d 1c 00 00                      	movzx  eax,BYTE PTR [rdx+r12*1+0x1c0d]
  af2232:	83 c8 20                                        	or     eax,0x20
  af2235:	83 f8 78                                        	cmp    eax,0x78
  af2238:	75 7f                                           	jne    0xaf22b9
  af223a:	b8 01 00 00 00                                  	mov    eax,0x1
  af223f:	31 f6                                           	xor    esi,esi
  af2241:	48 81 fa fd 00 00 00                            	cmp    rdx,0xfd
  af2248:	76 20                                           	jbe    0xaf226a
  af224a:	e9 c2 00 00 00                                  	jmp    0xaf2311
  af224f:	90                                              	nop
  af2250:	48 c1 e6 04                                     	shl    rsi,0x4
  af2254:	48 ff c2                                        	inc    rdx
  af2257:	4c 01 c6                                        	add    rsi,r8
  af225a:	48 01 fe                                        	add    rsi,rdi
  af225d:	48 81 fa fe 00 00 00                            	cmp    rdx,0xfe
  af2264:	0f 84 a7 00 00 00                               	je     0xaf2311
  af226a:	42 0f b6 bc 22 0e 1c 00 00                      	movzx  edi,BYTE PTR [rdx+r12*1+0x1c0e]
  af2273:	49 c7 c0 d0 ff ff ff                            	mov    r8,0xffffffffffffffd0
  af227a:	44 8d 4f d0                                     	lea    r9d,[rdi-0x30]
  af227e:	41 80 f9 0a                                     	cmp    r9b,0xa
  af2282:	72 cc                                           	jb     0xaf2250
  af2284:	44 8d 4f 9f                                     	lea    r9d,[rdi-0x61]
  af2288:	49 c7 c0 a9 ff ff ff                            	mov    r8,0xffffffffffffffa9
  af228f:	41 80 f9 06                                     	cmp    r9b,0x6
  af2293:	72 bb                                           	jb     0xaf2250
  af2295:	44 8d 4f bf                                     	lea    r9d,[rdi-0x41]
  af2299:	49 c7 c0 c9 ff ff ff                            	mov    r8,0xffffffffffffffc9
  af22a0:	41 80 f9 05                                     	cmp    r9b,0x5
  af22a4:	76 aa                                           	jbe    0xaf2250
  af22a6:	eb 69                                           	jmp    0xaf2311
  af22a8:	31 f6                                           	xor    esi,esi
  af22aa:	3c 2d                                           	cmp    al,0x2d
  af22ac:	40 0f 94 c6                                     	sete   sil
  af22b0:	89 f0                                           	mov    eax,esi
  af22b2:	f7 d8                                           	neg    eax
  af22b4:	83 c8 01                                        	or     eax,0x1
  af22b7:	eb 07                                           	jmp    0xaf22c0
  af22b9:	b8 01 00 00 00                                  	mov    eax,0x1
  af22be:	31 f6                                           	xor    esi,esi
  af22c0:	40 0f b6 fe                                     	movzx  edi,sil
  af22c4:	8d 34 17                                        	lea    esi,[rdi+rdx*1]
  af22c7:	81 fe ff 00 00 00                               	cmp    esi,0xff
  af22cd:	77 40                                           	ja     0xaf230f
  af22cf:	48 81 cf 0c 1c 00 00                            	or     rdi,0x1c0c
  af22d6:	31 f6                                           	xor    esi,esi
  af22d8:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  af22e0:	4c 8d 04 17                                     	lea    r8,[rdi+rdx*1]
  af22e4:	47 0f b6 04 04                                  	movzx  r8d,BYTE PTR [r12+r8*1]
  af22e9:	45 8d 48 d0                                     	lea    r9d,[r8-0x30]
  af22ed:	41 80 f9 09                                     	cmp    r9b,0x9
  af22f1:	77 1e                                           	ja     0xaf2311
  af22f3:	48 8d 34 b6                                     	lea    rsi,[rsi+rsi*4]
  af22f7:	4c 8d 4c 17 01                                  	lea    r9,[rdi+rdx*1+0x1]
  af22fc:	48 ff c2                                        	inc    rdx
  af22ff:	49 8d 74 70 d0                                  	lea    rsi,[r8+rsi*2-0x30]
  af2304:	49 81 f9 0c 1d 00 00                            	cmp    r9,0x1d0c
  af230b:	75 d3                                           	jne    0xaf22e0
  af230d:	eb 02                                           	jmp    0xaf2311
  af230f:	31 f6                                           	xor    esi,esi
  af2311:	4c 63 e8                                        	movsxd r13,eax
  af2314:	41 8b 07                                        	mov    eax,DWORD PTR [r15]
  af2317:	4c 0f af ee                                     	imul   r13,rsi
  af231b:	3d 00 00 01 39                                  	cmp    eax,0x39010000
  af2320:	74 1b                                           	je     0xaf233d
  af2322:	3d 00 05 80 58                                  	cmp    eax,0x58800500
  af2327:	75 26                                           	jne    0xaf234f
  af2329:	83 3d 88 58 20 03 01                            	cmp    DWORD PTR [rip+0x3205888],0x1        # 0x3cf7bb8
  af2330:	75 1d                                           	jne    0xaf234f
  af2332:	31 c0                                           	xor    eax,eax
  af2334:	83 3d a1 58 20 03 01                            	cmp    DWORD PTR [rip+0x32058a1],0x1        # 0x3cf7bdc
  af233b:	eb 0e                                           	jmp    0xaf234b
  af233d:	83 3d 74 58 20 03 01                            	cmp    DWORD PTR [rip+0x3205874],0x1        # 0x3cf7bb8
  af2344:	48 c7 c0 ff ff ff ff                            	mov    rax,0xffffffffffffffff
  af234b:	4c 0f 44 e8                                     	cmove  r13,rax
  af234f:	44 89 f0                                        	mov    eax,r14d
  af2352:	f7 d0                                           	not    eax
  af2354:	01 c8                                           	add    eax,ecx
  af2356:	85 c0                                           	test   eax,eax
  af2358:	b8 06 01 0d 80                                  	mov    eax,0x800d0106
  af235d:	0f 8e dd 03 00 00                               	jle    0xaf2740
  af2363:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  af2367:	4c 89 f2                                        	mov    rdx,r14
  af236a:	4c 89 7d d0                                     	mov    QWORD PTR [rbp-0x30],r15
  af236e:	45 31 ff                                        	xor    r15d,r15d
  af2371:	48 f7 d2                                        	not    rdx
  af2374:	48 01 ca                                        	add    rdx,rcx
  af2377:	81 e2 ff ff ff 7f                               	and    edx,0x7fffffff
  af237d:	4a 8d 74 37 01                                  	lea    rsi,[rdi+r14*1+0x1]
  af2382:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  af2390:	4a 8d 0c 3f                                     	lea    rcx,[rdi+r15*1]
  af2394:	41 0f b6 4c 0e 01                               	movzx  ecx,BYTE PTR [r14+rcx*1+0x1]
  af239a:	80 f9 3a                                        	cmp    cl,0x3a
  af239d:	74 15                                           	je     0xaf23b4
  af239f:	84 c9                                           	test   cl,cl
  af23a1:	0f 84 99 03 00 00                               	je     0xaf2740
  af23a7:	49 ff c7                                        	inc    r15
  af23aa:	49 39 d7                                        	cmp    r15,rdx
  af23ad:	72 e1                                           	jb     0xaf2390
  af23af:	e9 8c 03 00 00                                  	jmp    0xaf2740
  af23b4:	49 8d 4f ff                                     	lea    rcx,[r15-0x1]
  af23b8:	48 81 f9 fe 00 00 00                            	cmp    rcx,0xfe
  af23bf:	0f 87 7b 03 00 00                               	ja     0xaf2740
  af23c5:	48 8d 3d a0 c2 21 03                            	lea    rdi,[rip+0x321c2a0]        # 0x3d0e66c
  af23cc:	4c 89 fa                                        	mov    rdx,r15
  af23cf:	e8 dc 6c 76 ff                                  	call   0x2590b0
  af23d4:	83 3d d9 57 20 03 03                            	cmp    DWORD PTR [rip+0x32057d9],0x3        # 0x3cf7bb4
  af23db:	48 8b 4d a0                                     	mov    rcx,QWORD PTR [rbp-0x60]
  af23df:	43 c6 84 27 0c 1c 00 00 00                      	mov    BYTE PTR [r15+r12*1+0x1c0c],0x0
  af23e8:	0f 85 13 01 00 00                               	jne    0xaf2501
  af23ee:	31 f6                                           	xor    esi,esi
  af23f0:	31 d2                                           	xor    edx,edx
  af23f2:	42 0f b6 84 22 0c 1c 00 00                      	movzx  eax,BYTE PTR [rdx+r12*1+0x1c0c]
  af23fb:	83 f8 20                                        	cmp    eax,0x20
  af23fe:	75 16                                           	jne    0xaf2416
  af2400:	48 ff c2                                        	inc    rdx
  af2403:	48 81 fa 00 01 00 00                            	cmp    rdx,0x100
  af240a:	75 e6                                           	jne    0xaf23f2
  af240c:	b8 01 00 00 00                                  	mov    eax,0x1
  af2411:	e9 e4 00 00 00                                  	jmp    0xaf24fa
  af2416:	83 f8 30                                        	cmp    eax,0x30
  af2419:	75 7e                                           	jne    0xaf2499
  af241b:	42 0f b6 84 22 0d 1c 00 00                      	movzx  eax,BYTE PTR [rdx+r12*1+0x1c0d]
  af2424:	83 c8 20                                        	or     eax,0x20
  af2427:	83 f8 78                                        	cmp    eax,0x78
  af242a:	75 7e                                           	jne    0xaf24aa
  af242c:	b8 01 00 00 00                                  	mov    eax,0x1
  af2431:	31 f6                                           	xor    esi,esi
  af2433:	48 81 fa fd 00 00 00                            	cmp    rdx,0xfd
  af243a:	76 1f                                           	jbe    0xaf245b
  af243c:	e9 b9 00 00 00                                  	jmp    0xaf24fa
  af2441:	48 c1 e6 04                                     	shl    rsi,0x4
  af2445:	48 ff c2                                        	inc    rdx
  af2448:	4c 01 c6                                        	add    rsi,r8
  af244b:	48 01 fe                                        	add    rsi,rdi
  af244e:	48 81 fa fe 00 00 00                            	cmp    rdx,0xfe
  af2455:	0f 84 9f 00 00 00                               	je     0xaf24fa
  af245b:	42 0f b6 bc 22 0e 1c 00 00                      	movzx  edi,BYTE PTR [rdx+r12*1+0x1c0e]
  af2464:	49 c7 c0 d0 ff ff ff                            	mov    r8,0xffffffffffffffd0
  af246b:	44 8d 4f d0                                     	lea    r9d,[rdi-0x30]
  af246f:	41 80 f9 0a                                     	cmp    r9b,0xa
  af2473:	72 cc                                           	jb     0xaf2441
  af2475:	44 8d 4f 9f                                     	lea    r9d,[rdi-0x61]
  af2479:	49 c7 c0 a9 ff ff ff                            	mov    r8,0xffffffffffffffa9
  af2480:	41 80 f9 06                                     	cmp    r9b,0x6
  af2484:	72 bb                                           	jb     0xaf2441
  af2486:	44 8d 4f bf                                     	lea    r9d,[rdi-0x41]
  af248a:	49 c7 c0 c9 ff ff ff                            	mov    r8,0xffffffffffffffc9
  af2491:	41 80 f9 05                                     	cmp    r9b,0x5
  af2495:	76 aa                                           	jbe    0xaf2441
  af2497:	eb 61                                           	jmp    0xaf24fa
  af2499:	31 f6                                           	xor    esi,esi
  af249b:	3c 2d                                           	cmp    al,0x2d
  af249d:	40 0f 94 c6                                     	sete   sil
  af24a1:	89 f0                                           	mov    eax,esi
  af24a3:	f7 d8                                           	neg    eax
  af24a5:	83 c8 01                                        	or     eax,0x1
  af24a8:	eb 07                                           	jmp    0xaf24b1
  af24aa:	b8 01 00 00 00                                  	mov    eax,0x1
  af24af:	31 f6                                           	xor    esi,esi
  af24b1:	40 0f b6 fe                                     	movzx  edi,sil
  af24b5:	8d 34 17                                        	lea    esi,[rdi+rdx*1]
  af24b8:	81 fe ff 00 00 00                               	cmp    esi,0xff
  af24be:	77 38                                           	ja     0xaf24f8
  af24c0:	48 81 cf 0c 1c 00 00                            	or     rdi,0x1c0c
  af24c7:	31 f6                                           	xor    esi,esi
  af24c9:	4c 8d 04 17                                     	lea    r8,[rdi+rdx*1]
  af24cd:	47 0f b6 04 04                                  	movzx  r8d,BYTE PTR [r12+r8*1]
  af24d2:	45 8d 48 d0                                     	lea    r9d,[r8-0x30]
  af24d6:	41 80 f9 09                                     	cmp    r9b,0x9
  af24da:	77 1e                                           	ja     0xaf24fa
  af24dc:	48 8d 34 b6                                     	lea    rsi,[rsi+rsi*4]
  af24e0:	4c 8d 4c 17 01                                  	lea    r9,[rdi+rdx*1+0x1]
  af24e5:	48 ff c2                                        	inc    rdx
  af24e8:	49 8d 74 70 d0                                  	lea    rsi,[r8+rsi*2-0x30]
  af24ed:	49 81 f9 0c 1d 00 00                            	cmp    r9,0x1d0c
  af24f4:	75 d3                                           	jne    0xaf24c9
  af24f6:	eb 02                                           	jmp    0xaf24fa
  af24f8:	31 f6                                           	xor    esi,esi
  af24fa:	4c 63 e8                                        	movsxd r13,eax
  af24fd:	4c 0f af ee                                     	imul   r13,rsi
  af2501:	89 d8                                           	mov    eax,ebx
  af2503:	44 29 f8                                        	sub    eax,r15d
  af2506:	83 c0 03                                        	add    eax,0x3
  af2509:	85 c0                                           	test   eax,eax
  af250b:	b8 06 01 0d 80                                  	mov    eax,0x800d0106
  af2510:	0f 8e 2a 02 00 00                               	jle    0xaf2740
  af2516:	48 89 da                                        	mov    rdx,rbx
  af2519:	4a 8d 34 31                                     	lea    rsi,[rcx+r14*1]
  af251d:	4d 01 fe                                        	add    r14,r15
  af2520:	4c 29 fb                                        	sub    rbx,r15
  af2523:	4c 29 fa                                        	sub    rdx,r15
  af2526:	49 8d 74 37 02                                  	lea    rsi,[r15+rsi*1+0x2]
  af252b:	45 31 ff                                        	xor    r15d,r15d
  af252e:	48 83 c2 03                                     	add    rdx,0x3
  af2532:	81 e2 ff ff ff 7f                               	and    edx,0x7fffffff
  af2538:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  af2540:	42 0f b6 7c 31 02                               	movzx  edi,BYTE PTR [rcx+r14*1+0x2]
  af2546:	40 80 ff 3a                                     	cmp    dil,0x3a
  af254a:	74 1c                                           	je     0xaf2568
  af254c:	40 84 ff                                        	test   dil,dil
  af254f:	0f 84 eb 01 00 00                               	je     0xaf2740
  af2555:	49 ff c7                                        	inc    r15
  af2558:	48 ff cb                                        	dec    rbx
  af255b:	49 ff c6                                        	inc    r14
  af255e:	49 39 d7                                        	cmp    r15,rdx
  af2561:	72 dd                                           	jb     0xaf2540
  af2563:	e9 d8 01 00 00                                  	jmp    0xaf2740
  af2568:	49 8d 4f ff                                     	lea    rcx,[r15-0x1]
  af256c:	48 81 f9 fe 00 00 00                            	cmp    rcx,0xfe
  af2573:	0f 87 c7 01 00 00                               	ja     0xaf2740
  af2579:	48 8d 3d ec c0 21 03                            	lea    rdi,[rip+0x321c0ec]        # 0x3d0e66c
  af2580:	4c 89 fa                                        	mov    rdx,r15
  af2583:	e8 28 6b 76 ff                                  	call   0x2590b0
  af2588:	83 3d 25 56 20 03 02                            	cmp    DWORD PTR [rip+0x3205625],0x2        # 0x3cf7bb4
  af258f:	4c 8b 4d d0                                     	mov    r9,QWORD PTR [rbp-0x30]
  af2593:	43 c6 84 27 0c 1c 00 00 00                      	mov    BYTE PTR [r15+r12*1+0x1c0c],0x0
  af259c:	0f 85 11 01 00 00                               	jne    0xaf26b3
  af25a2:	31 d2                                           	xor    edx,edx
  af25a4:	31 c9                                           	xor    ecx,ecx
  af25a6:	42 0f b6 84 21 0c 1c 00 00                      	movzx  eax,BYTE PTR [rcx+r12*1+0x1c0c]
  af25af:	83 f8 20                                        	cmp    eax,0x20
  af25b2:	75 16                                           	jne    0xaf25ca
  af25b4:	48 ff c1                                        	inc    rcx
  af25b7:	48 81 f9 00 01 00 00                            	cmp    rcx,0x100
  af25be:	75 e6                                           	jne    0xaf25a6
  af25c0:	b8 01 00 00 00                                  	mov    eax,0x1
  af25c5:	e9 e2 00 00 00                                  	jmp    0xaf26ac
  af25ca:	83 f8 30                                        	cmp    eax,0x30
  af25cd:	75 7e                                           	jne    0xaf264d
  af25cf:	42 0f b6 84 21 0d 1c 00 00                      	movzx  eax,BYTE PTR [rcx+r12*1+0x1c0d]
  af25d8:	83 c8 20                                        	or     eax,0x20
  af25db:	83 f8 78                                        	cmp    eax,0x78
  af25de:	75 7d                                           	jne    0xaf265d
  af25e0:	b8 01 00 00 00                                  	mov    eax,0x1
  af25e5:	31 d2                                           	xor    edx,edx
  af25e7:	48 81 f9 fd 00 00 00                            	cmp    rcx,0xfd
  af25ee:	76 1f                                           	jbe    0xaf260f
  af25f0:	e9 b7 00 00 00                                  	jmp    0xaf26ac
  af25f5:	48 c1 e2 04                                     	shl    rdx,0x4
  af25f9:	48 ff c1                                        	inc    rcx
  af25fc:	48 01 fa                                        	add    rdx,rdi
  af25ff:	48 01 f2                                        	add    rdx,rsi
  af2602:	48 81 f9 fe 00 00 00                            	cmp    rcx,0xfe
  af2609:	0f 84 9d 00 00 00                               	je     0xaf26ac
  af260f:	42 0f b6 b4 21 0e 1c 00 00                      	movzx  esi,BYTE PTR [rcx+r12*1+0x1c0e]
  af2618:	48 c7 c7 d0 ff ff ff                            	mov    rdi,0xffffffffffffffd0
  af261f:	44 8d 46 d0                                     	lea    r8d,[rsi-0x30]
  af2623:	41 80 f8 0a                                     	cmp    r8b,0xa
  af2627:	72 cc                                           	jb     0xaf25f5
  af2629:	44 8d 46 9f                                     	lea    r8d,[rsi-0x61]
  af262d:	48 c7 c7 a9 ff ff ff                            	mov    rdi,0xffffffffffffffa9
  af2634:	41 80 f8 06                                     	cmp    r8b,0x6
  af2638:	72 bb                                           	jb     0xaf25f5
  af263a:	44 8d 46 bf                                     	lea    r8d,[rsi-0x41]
  af263e:	48 c7 c7 c9 ff ff ff                            	mov    rdi,0xffffffffffffffc9
  af2645:	41 80 f8 05                                     	cmp    r8b,0x5
  af2649:	76 aa                                           	jbe    0xaf25f5
  af264b:	eb 5f                                           	jmp    0xaf26ac
  af264d:	31 d2                                           	xor    edx,edx
  af264f:	3c 2d                                           	cmp    al,0x2d
  af2651:	0f 94 c2                                        	sete   dl
  af2654:	89 d0                                           	mov    eax,edx
  af2656:	f7 d8                                           	neg    eax
  af2658:	83 c8 01                                        	or     eax,0x1
  af265b:	eb 07                                           	jmp    0xaf2664
  af265d:	b8 01 00 00 00                                  	mov    eax,0x1
  af2662:	31 d2                                           	xor    edx,edx
  af2664:	0f b6 f2                                        	movzx  esi,dl
  af2667:	8d 14 0e                                        	lea    edx,[rsi+rcx*1]
  af266a:	81 fa ff 00 00 00                               	cmp    edx,0xff
  af2670:	77 38                                           	ja     0xaf26aa
  af2672:	48 81 ce 0c 1c 00 00                            	or     rsi,0x1c0c
  af2679:	31 d2                                           	xor    edx,edx
  af267b:	48 8d 3c 0e                                     	lea    rdi,[rsi+rcx*1]
  af267f:	41 0f b6 3c 3c                                  	movzx  edi,BYTE PTR [r12+rdi*1]
  af2684:	44 8d 47 d0                                     	lea    r8d,[rdi-0x30]
  af2688:	41 80 f8 09                                     	cmp    r8b,0x9
  af268c:	77 1e                                           	ja     0xaf26ac
  af268e:	48 8d 14 92                                     	lea    rdx,[rdx+rdx*4]
  af2692:	4c 8d 44 0e 01                                  	lea    r8,[rsi+rcx*1+0x1]
  af2697:	48 ff c1                                        	inc    rcx
  af269a:	48 8d 54 57 d0                                  	lea    rdx,[rdi+rdx*2-0x30]
  af269f:	49 81 f8 0c 1d 00 00                            	cmp    r8,0x1d0c
  af26a6:	75 d3                                           	jne    0xaf267b
  af26a8:	eb 02                                           	jmp    0xaf26ac
  af26aa:	31 d2                                           	xor    edx,edx
  af26ac:	4c 63 e8                                        	movsxd r13,eax
  af26af:	4c 0f af ea                                     	imul   r13,rdx
  af26b3:	83 3d fe 54 20 03 03                            	cmp    DWORD PTR [rip+0x32054fe],0x3        # 0x3cf7bb8
  af26ba:	b8 06 01 0d 80                                  	mov    eax,0x800d0106
  af26bf:	75 61                                           	jne    0xaf2722
  af26c1:	41 8b 09                                        	mov    ecx,DWORD PTR [r9]
  af26c4:	81 f9 ff 36 02 78                               	cmp    ecx,0x780236ff
  af26ca:	7f 1a                                           	jg     0xaf26e6
  af26cc:	81 f9 ff ff c3 41                               	cmp    ecx,0x41c3ffff
  af26d2:	7f 2c                                           	jg     0xaf2700
  af26d4:	81 f9 00 83 28 14                               	cmp    ecx,0x14288300
  af26da:	74 5f                                           	je     0xaf273b
  af26dc:	81 f9 00 00 84 14                               	cmp    ecx,0x14840000
  af26e2:	74 57                                           	je     0xaf273b
  af26e4:	eb 3c                                           	jmp    0xaf2722
  af26e6:	81 f9 ff 3f 02 78                               	cmp    ecx,0x78023fff
  af26ec:	7f 24                                           	jg     0xaf2712
  af26ee:	81 f9 00 37 02 78                               	cmp    ecx,0x78023700
  af26f4:	74 45                                           	je     0xaf273b
  af26f6:	81 f9 00 3d 02 78                               	cmp    ecx,0x78023d00
  af26fc:	74 3d                                           	je     0xaf273b
  af26fe:	eb 22                                           	jmp    0xaf2722
  af2700:	81 f9 00 00 c4 41                               	cmp    ecx,0x41c40000
  af2706:	74 33                                           	je     0xaf273b
  af2708:	81 f9 00 22 02 78                               	cmp    ecx,0x78022200
  af270e:	74 2b                                           	je     0xaf273b
  af2710:	eb 10                                           	jmp    0xaf2722
  af2712:	81 f9 00 40 02 78                               	cmp    ecx,0x78024000
  af2718:	74 21                                           	je     0xaf273b
  af271a:	81 f9 00 55 02 78                               	cmp    ecx,0x78025500
  af2720:	74 19                                           	je     0xaf273b
  af2722:	b9 f7 ff f7 ff                                  	mov    ecx,0xfff7fff7
  af2727:	49 39 cd                                        	cmp    r13,rcx
  af272a:	74 14                                           	je     0xaf2740
  af272c:	4d 85 ed                                        	test   r13,r13
  af272f:	0f 84 d4 00 00 00                               	je     0xaf2809
  af2735:	49 83 fd ff                                     	cmp    r13,0xffffffffffffffff
  af2739:	75 17                                           	jne    0xaf2752
  af273b:	b8 01 00 00 00                                  	mov    eax,0x1
  af2740:	48 81 c4 a8 00 00 00                            	add    rsp,0xa8
  af2747:	5b                                              	pop    rbx
  af2748:	41 5c                                           	pop    r12
  af274a:	41 5d                                           	pop    r13
  af274c:	41 5e                                           	pop    r14
  af274e:	41 5f                                           	pop    r15
  af2750:	5d                                              	pop    rbp
  af2751:	c3                                              	ret
  af2752:	4c 89 e9                                        	mov    rcx,r13
  af2755:	b8 01 00 00 00                                  	mov    eax,0x1
  af275a:	48 c1 f9 08                                     	sar    rcx,0x8
  af275e:	83 3d 5f 54 20 03 01                            	cmp    DWORD PTR [rip+0x320545f],0x1        # 0x3cf7bc4
  af2765:	49 0f 45 cd                                     	cmovne rcx,r13
  af2769:	f6 c1 01                                        	test   cl,0x1
  af276c:	74 d2                                           	je     0xaf2740
  af276e:	f6 c1 10                                        	test   cl,0x10
  af2771:	74 09                                           	je     0xaf277c
  af2773:	83 3d 5e 54 20 03 01                            	cmp    DWORD PTR [rip+0x320545e],0x1        # 0x3cf7bd8
  af277a:	75 c4                                           	jne    0xaf2740
  af277c:	f6 c1 40                                        	test   cl,0x40
  af277f:	74 09                                           	je     0xaf278a
  af2781:	83 3d 28 54 20 03 0e                            	cmp    DWORD PTR [rip+0x3205428],0xe        # 0x3cf7bb0
  af2788:	75 b6                                           	jne    0xaf2740
  af278a:	31 c0                                           	xor    eax,eax
  af278c:	f6 c1 08                                        	test   cl,0x8
  af278f:	74 0e                                           	je     0xaf279f
  af2791:	83 3d 34 54 20 03 01                            	cmp    DWORD PTR [rip+0x3205434],0x1        # 0x3cf7bcc
  af2798:	b8 08 00 00 00                                  	mov    eax,0x8
  af279d:	74 6a                                           	je     0xaf2809
  af279f:	f6 c1 04                                        	test   cl,0x4
  af27a2:	74 0c                                           	je     0xaf27b0
  af27a4:	83 3d 29 54 20 03 01                            	cmp    DWORD PTR [rip+0x3205429],0x1        # 0x3cf7bd4
  af27ab:	74 5c                                           	je     0xaf2809
  af27ad:	83 c8 04                                        	or     eax,0x4
  af27b0:	f6 c1 20                                        	test   cl,0x20
  af27b3:	74 0c                                           	je     0xaf27c1
  af27b5:	83 3d 24 54 20 03 01                            	cmp    DWORD PTR [rip+0x3205424],0x1        # 0x3cf7be0
  af27bc:	74 4b                                           	je     0xaf2809
  af27be:	83 c8 20                                        	or     eax,0x20
  af27c1:	f6 c1 02                                        	test   cl,0x2
  af27c4:	74 0e                                           	je     0xaf27d4
  af27c6:	83 3d 17 54 20 03 01                            	cmp    DWORD PTR [rip+0x3205417],0x1        # 0x3cf7be4
  af27cd:	b8 01 00 00 00                                  	mov    eax,0x1
  af27d2:	74 35                                           	je     0xaf2809
  af27d4:	84 c9                                           	test   cl,cl
  af27d6:	78 0b                                           	js     0xaf27e3
  af27d8:	48 0f ba e1 32                                  	bt     rcx,0x32
  af27dd:	72 18                                           	jb     0xaf27f7
  af27df:	85 c0                                           	test   eax,eax
  af27e1:	eb 1b                                           	jmp    0xaf27fe
  af27e3:	83 3d fe 53 20 03 01                            	cmp    DWORD PTR [rip+0x32053fe],0x1        # 0x3cf7be8
  af27ea:	74 1d                                           	je     0xaf2809
  af27ec:	48 0f ba e1 32                                  	bt     rcx,0x32
  af27f1:	0f 83 44 ff ff ff                               	jae    0xaf273b
  af27f7:	83 3d ee 53 20 03 01                            	cmp    DWORD PTR [rip+0x32053ee],0x1        # 0x3cf7bec
  af27fe:	b8 01 00 00 00                                  	mov    eax,0x1
  af2803:	0f 85 37 ff ff ff                               	jne    0xaf2740
  af2809:	48 8b 55 c0                                     	mov    rdx,QWORD PTR [rbp-0x40]
  af280d:	b8 07 01 0d 80                                  	mov    eax,0x800d0107
  af2812:	89 d1                                           	mov    ecx,edx
  af2814:	44 29 f1                                        	sub    ecx,r14d
  af2817:	83 c1 fd                                        	add    ecx,0xfffffffd
  af281a:	85 c9                                           	test   ecx,ecx
  af281c:	0f 8e 1e ff ff ff                               	jle    0xaf2740
  af2822:	48 8b 4d a0                                     	mov    rcx,QWORD PTR [rbp-0x60]
  af2826:	4c 29 f2                                        	sub    rdx,r14
  af2829:	45 31 ff                                        	xor    r15d,r15d
  af282c:	4c 8d 6a fc                                     	lea    r13,[rdx-0x4]
  af2830:	48 83 c2 fd                                     	add    rdx,0xfffffffffffffffd
  af2834:	81 e2 ff ff ff 7f                               	and    edx,0x7fffffff
  af283a:	4a 8d 7c 31 03                                  	lea    rdi,[rcx+r14*1+0x3]
  af283f:	4a 8d 74 31 03                                  	lea    rsi,[rcx+r14*1+0x3]
  af2844:	44 0f b6 07                                     	movzx  r8d,BYTE PTR [rdi]
  af2848:	41 80 f8 3a                                     	cmp    r8b,0x3a
  af284c:	74 1c                                           	je     0xaf286a
  af284e:	45 84 c0                                        	test   r8b,r8b
  af2851:	0f 84 e9 fe ff ff                               	je     0xaf2740
  af2857:	49 ff c7                                        	inc    r15
  af285a:	41 ff cd                                        	dec    r13d
  af285d:	48 ff c7                                        	inc    rdi
  af2860:	49 39 d7                                        	cmp    r15,rdx
  af2863:	72 df                                           	jb     0xaf2844
  af2865:	e9 d6 fe ff ff                                  	jmp    0xaf2740
  af286a:	49 8d 57 ff                                     	lea    rdx,[r15-0x1]
  af286e:	48 81 fa fe 00 00 00                            	cmp    rdx,0xfe
  af2875:	0f 87 c5 fe ff ff                               	ja     0xaf2740
  af287b:	4c 01 f1                                        	add    rcx,r14
  af287e:	48 89 d8                                        	mov    rax,rbx
  af2881:	48 8d 3d e4 bd 21 03                            	lea    rdi,[rip+0x321bde4]        # 0x3d0e66c
  af2888:	49 8d 54 0f 07                                  	lea    rdx,[r15+rcx*1+0x7]
  af288d:	4c 29 f8                                        	sub    rax,r15
  af2890:	49 89 ce                                        	mov    r14,rcx
  af2893:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  af2897:	48 89 55 c0                                     	mov    QWORD PTR [rbp-0x40],rdx
  af289b:	4c 89 fa                                        	mov    rdx,r15
  af289e:	e8 0d 68 76 ff                                  	call   0x2590b0
  af28a3:	4c 29 fb                                        	sub    rbx,r15
  af28a6:	4b 8d 74 37 04                                  	lea    rsi,[r15+r14*1+0x4]
  af28ab:	43 c6 84 27 0c 1c 00 00 00                      	mov    BYTE PTR [r15+r12*1+0x1c0c],0x0
  af28b4:	31 d2                                           	xor    edx,edx
  af28b6:	31 c9                                           	xor    ecx,ecx
  af28b8:	48 ff c3                                        	inc    rbx
  af28bb:	42 0f b6 84 21 0c 1c 00 00                      	movzx  eax,BYTE PTR [rcx+r12*1+0x1c0c]
  af28c4:	83 f8 20                                        	cmp    eax,0x20
  af28c7:	75 16                                           	jne    0xaf28df
  af28c9:	48 ff c1                                        	inc    rcx
  af28cc:	48 81 f9 00 01 00 00                            	cmp    rcx,0x100
  af28d3:	75 e6                                           	jne    0xaf28bb
  af28d5:	b8 01 00 00 00                                  	mov    eax,0x1
  af28da:	e9 e2 00 00 00                                  	jmp    0xaf29c1
  af28df:	83 f8 30                                        	cmp    eax,0x30
  af28e2:	75 7e                                           	jne    0xaf2962
  af28e4:	42 0f b6 84 21 0d 1c 00 00                      	movzx  eax,BYTE PTR [rcx+r12*1+0x1c0d]
  af28ed:	83 c8 20                                        	or     eax,0x20
  af28f0:	83 f8 78                                        	cmp    eax,0x78
  af28f3:	75 7d                                           	jne    0xaf2972
  af28f5:	b8 01 00 00 00                                  	mov    eax,0x1
  af28fa:	31 d2                                           	xor    edx,edx
  af28fc:	48 81 f9 fd 00 00 00                            	cmp    rcx,0xfd
  af2903:	76 1f                                           	jbe    0xaf2924
  af2905:	e9 b7 00 00 00                                  	jmp    0xaf29c1
  af290a:	48 c1 e2 04                                     	shl    rdx,0x4
  af290e:	48 ff c1                                        	inc    rcx
  af2911:	4c 01 c2                                        	add    rdx,r8
  af2914:	48 01 fa                                        	add    rdx,rdi
  af2917:	48 81 f9 fe 00 00 00                            	cmp    rcx,0xfe
  af291e:	0f 84 9d 00 00 00                               	je     0xaf29c1
  af2924:	42 0f b6 bc 21 0e 1c 00 00                      	movzx  edi,BYTE PTR [rcx+r12*1+0x1c0e]
  af292d:	49 c7 c0 d0 ff ff ff                            	mov    r8,0xffffffffffffffd0
  af2934:	44 8d 4f d0                                     	lea    r9d,[rdi-0x30]
  af2938:	41 80 f9 0a                                     	cmp    r9b,0xa
  af293c:	72 cc                                           	jb     0xaf290a
  af293e:	44 8d 4f 9f                                     	lea    r9d,[rdi-0x61]
  af2942:	49 c7 c0 a9 ff ff ff                            	mov    r8,0xffffffffffffffa9
  af2949:	41 80 f9 06                                     	cmp    r9b,0x6
  af294d:	72 bb                                           	jb     0xaf290a
  af294f:	44 8d 4f bf                                     	lea    r9d,[rdi-0x41]
  af2953:	49 c7 c0 c9 ff ff ff                            	mov    r8,0xffffffffffffffc9
  af295a:	41 80 f9 05                                     	cmp    r9b,0x5
  af295e:	76 aa                                           	jbe    0xaf290a
  af2960:	eb 5f                                           	jmp    0xaf29c1
  af2962:	31 d2                                           	xor    edx,edx
  af2964:	3c 2d                                           	cmp    al,0x2d
  af2966:	0f 94 c2                                        	sete   dl
  af2969:	89 d0                                           	mov    eax,edx
  af296b:	f7 d8                                           	neg    eax
  af296d:	83 c8 01                                        	or     eax,0x1
  af2970:	eb 07                                           	jmp    0xaf2979
  af2972:	b8 01 00 00 00                                  	mov    eax,0x1
  af2977:	31 d2                                           	xor    edx,edx
  af2979:	0f b6 fa                                        	movzx  edi,dl
  af297c:	8d 14 0f                                        	lea    edx,[rdi+rcx*1]
  af297f:	81 fa ff 00 00 00                               	cmp    edx,0xff
  af2985:	77 38                                           	ja     0xaf29bf
  af2987:	48 81 cf 0c 1c 00 00                            	or     rdi,0x1c0c
  af298e:	31 d2                                           	xor    edx,edx
  af2990:	4c 8d 04 0f                                     	lea    r8,[rdi+rcx*1]
  af2994:	47 0f b6 04 04                                  	movzx  r8d,BYTE PTR [r12+r8*1]
  af2999:	45 8d 48 d0                                     	lea    r9d,[r8-0x30]
  af299d:	41 80 f9 09                                     	cmp    r9b,0x9
  af29a1:	77 1e                                           	ja     0xaf29c1
  af29a3:	48 8d 14 92                                     	lea    rdx,[rdx+rdx*4]
  af29a7:	4c 8d 4c 0f 01                                  	lea    r9,[rdi+rcx*1+0x1]
  af29ac:	48 ff c1                                        	inc    rcx
  af29af:	49 8d 54 50 d0                                  	lea    rdx,[r8+rdx*2-0x30]
  af29b4:	49 81 f9 0c 1d 00 00                            	cmp    r9,0x1d0c
  af29bb:	75 d3                                           	jne    0xaf2990
  af29bd:	eb 02                                           	jmp    0xaf29c1
  af29bf:	31 d2                                           	xor    edx,edx
  af29c1:	89 c0                                           	mov    eax,eax
  af29c3:	48 0f af c2                                     	imul   rax,rdx
  af29c7:	83 f8 02                                        	cmp    eax,0x2
  af29ca:	76 0a                                           	jbe    0xaf29d6
  af29cc:	b8 07 01 0d 80                                  	mov    eax,0x800d0107
  af29d1:	e9 6a fd ff ff                                  	jmp    0xaf2740
  af29d6:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af29da:	66 89 41 04                                     	mov    WORD PTR [rcx+0x4],ax
  af29de:	45 85 ed                                        	test   r13d,r13d
  af29e1:	7e 73                                           	jle    0xaf2a56
  af29e3:	4c 8b 6d c0                                     	mov    r13,QWORD PTR [rbp-0x40]
  af29e7:	48 8b 4d 88                                     	mov    rcx,QWORD PTR [rbp-0x78]
  af29eb:	81 e3 ff ff ff 7f                               	and    ebx,0x7fffffff
  af29f1:	45 31 f6                                        	xor    r14d,r14d
  af29f4:	41 0f b6 45 fd                                  	movzx  eax,BYTE PTR [r13-0x3]
  af29f9:	3c 3a                                           	cmp    al,0x3a
  af29fb:	74 14                                           	je     0xaf2a11
  af29fd:	84 c0                                           	test   al,al
  af29ff:	74 55                                           	je     0xaf2a56
  af2a01:	49 ff c6                                        	inc    r14
  af2a04:	49 ff c5                                        	inc    r13
  af2a07:	48 ff c9                                        	dec    rcx
  af2a0a:	49 39 de                                        	cmp    r14,rbx
  af2a0d:	72 e5                                           	jb     0xaf29f4
  af2a0f:	eb 45                                           	jmp    0xaf2a56
  af2a11:	49 8d 46 ff                                     	lea    rax,[r14-0x1]
  af2a15:	48 3d fe 00 00 00                               	cmp    rax,0xfe
  af2a1b:	77 39                                           	ja     0xaf2a56
  af2a1d:	4c 8d 3d 48 bc 21 03                            	lea    r15,[rip+0x321bc48]        # 0x3d0e66c
  af2a24:	4c 89 f2                                        	mov    rdx,r14
  af2a27:	48 89 cb                                        	mov    rbx,rcx
  af2a2a:	4c 89 ff                                        	mov    rdi,r15
  af2a2d:	e8 7e 66 76 ff                                  	call   0x2590b0
  af2a32:	be 00 01 00 00                                  	mov    esi,0x100
  af2a37:	4c 89 ff                                        	mov    rdi,r15
  af2a3a:	43 c6 84 26 0c 1c 00 00 00                      	mov    BYTE PTR [r14+r12*1+0x1c0c],0x0
  af2a43:	e8 48 f5 ff ff                                  	call   0xaf1f90
  af2a48:	8d 88 00 f8 ff ff                               	lea    ecx,[rax-0x800]
  af2a4e:	81 f9 01 f8 ff ff                               	cmp    ecx,0xfffff801
  af2a54:	73 0a                                           	jae    0xaf2a60
  af2a56:	b8 08 01 0d 80                                  	mov    eax,0x800d0108
  af2a5b:	e9 e0 fc ff ff                                  	jmp    0xaf2740
  af2a60:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2a64:	49 8d 7d fe                                     	lea    rdi,[r13-0x2]
  af2a68:	48 89 de                                        	mov    rsi,rbx
  af2a6b:	66 89 41 06                                     	mov    WORD PTR [rcx+0x6],ax
  af2a6f:	e8 4c f6 ff ff                                  	call   0xaf20c0
  af2a74:	85 c0                                           	test   eax,eax
  af2a76:	7e 37                                           	jle    0xaf2aaf
  af2a78:	48 8d 3d ed bb 21 03                            	lea    rdi,[rip+0x321bbed]        # 0x3d0e66c
  af2a7f:	be 00 01 00 00                                  	mov    esi,0x100
  af2a84:	41 89 c6                                        	mov    r14d,eax
  af2a87:	e8 04 f5 ff ff                                  	call   0xaf1f90
  af2a8c:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2a90:	80 79 0b 00                                     	cmp    BYTE PTR [rcx+0xb],0x0
  af2a94:	75 37                                           	jne    0xaf2acd
  af2a96:	a8 02                                           	test   al,0x2
  af2a98:	75 1f                                           	jne    0xaf2ab9
  af2a9a:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2a9e:	66 83 79 06 04                                  	cmp    WORD PTR [rcx+0x6],0x4
  af2aa3:	77 20                                           	ja     0xaf2ac5
  af2aa5:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2aa9:	c6 41 0a 01                                     	mov    BYTE PTR [rcx+0xa],0x1
  af2aad:	eb 1e                                           	jmp    0xaf2acd
  af2aaf:	b8 18 01 0d 80                                  	mov    eax,0x800d0118
  af2ab4:	e9 87 fc ff ff                                  	jmp    0xaf2740
  af2ab9:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2abd:	66 c7 41 0a 00 02                               	mov    WORD PTR [rcx+0xa],0x200
  af2ac3:	eb 08                                           	jmp    0xaf2acd
  af2ac5:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2ac9:	c6 41 0a 02                                     	mov    BYTE PTR [rcx+0xa],0x2
  af2acd:	83 e0 fd                                        	and    eax,0xfffffffd
  af2ad0:	74 16                                           	je     0xaf2ae8
  af2ad2:	83 f8 01                                        	cmp    eax,0x1
  af2ad5:	b8 18 01 0d 80                                  	mov    eax,0x800d0118
  af2ada:	0f 85 60 fc ff ff                               	jne    0xaf2740
  af2ae0:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2ae4:	80 48 12 04                                     	or     BYTE PTR [rax+0x12],0x4
  af2ae8:	44 89 f0                                        	mov    eax,r14d
  af2aeb:	48 89 de                                        	mov    rsi,rbx
  af2aee:	49 8d 7c 05 fe                                  	lea    rdi,[r13+rax*1-0x2]
  af2af3:	48 29 c6                                        	sub    rsi,rax
  af2af6:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  af2afa:	e8 c1 f5 ff ff                                  	call   0xaf20c0
  af2aff:	85 c0                                           	test   eax,eax
  af2b01:	0f 8e e8 00 00 00                               	jle    0xaf2bef
  af2b07:	48 8d 3d 5e bb 21 03                            	lea    rdi,[rip+0x321bb5e]        # 0x3d0e66c
  af2b0e:	be 00 01 00 00                                  	mov    esi,0x100
  af2b13:	41 89 c6                                        	mov    r14d,eax
  af2b16:	e8 75 f4 ff ff                                  	call   0xaf1f90
  af2b1b:	48 89 c1                                        	mov    rcx,rax
  af2b1e:	f7 c1 00 00 01 00                               	test   ecx,0x10000
  af2b24:	74 0e                                           	je     0xaf2b34
  af2b26:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2b2a:	81 e1 ff ff fe ff                               	and    ecx,0xfffeffff
  af2b30:	80 48 12 20                                     	or     BYTE PTR [rax+0x12],0x20
  af2b34:	f7 c1 00 00 02 00                               	test   ecx,0x20000
  af2b3a:	74 0e                                           	je     0xaf2b4a
  af2b3c:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2b40:	81 e1 ff ff fd ff                               	and    ecx,0xfffdffff
  af2b46:	80 48 12 80                                     	or     BYTE PTR [rax+0x12],0x80
  af2b4a:	89 ca                                           	mov    edx,ecx
  af2b4c:	81 e2 ff 19 ff ff                               	and    edx,0xffff19ff
  af2b52:	81 fa ff 00 00 00                               	cmp    edx,0xff
  af2b58:	0f 8f a5 00 00 00                               	jg     0xaf2c03
  af2b5e:	8d 72 f0                                        	lea    esi,[rdx-0x10]
  af2b61:	b8 0a 01 0d 80                                  	mov    eax,0x800d010a
  af2b66:	83 fe 30                                        	cmp    esi,0x30
  af2b69:	0f 87 b6 00 00 00                               	ja     0xaf2c25
  af2b6f:	48 bf 01 00 01 00 01 00 01 00                   	movabs rdi,0x1000100010001
  af2b79:	48 0f a3 f7                                     	bt     rdi,rsi
  af2b7d:	0f 83 a2 00 00 00                               	jae    0xaf2c25
  af2b83:	48 8b 45 c0                                     	mov    rax,QWORD PTR [rbp-0x40]
  af2b87:	44 89 f2                                        	mov    edx,r14d
  af2b8a:	48 89 de                                        	mov    rsi,rbx
  af2b8d:	48 89 55 a0                                     	mov    QWORD PTR [rbp-0x60],rdx
  af2b91:	48 01 d0                                        	add    rax,rdx
  af2b94:	48 29 c6                                        	sub    rsi,rax
  af2b97:	83 3d 22 50 20 03 01                            	cmp    DWORD PTR [rip+0x3205022],0x1        # 0x3cf7bc0
  af2b9e:	49 8d 7c 05 fe                                  	lea    rdi,[r13+rax*1-0x2]
  af2ba3:	49 89 c7                                        	mov    r15,rax
  af2ba6:	b8 00 10 00 00                                  	mov    eax,0x1000
  af2bab:	0f 44 c8                                        	cmove  ecx,eax
  af2bae:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2bb2:	66 89 48 08                                     	mov    WORD PTR [rax+0x8],cx
  af2bb6:	e8 05 f5 ff ff                                  	call   0xaf20c0
  af2bbb:	85 c0                                           	test   eax,eax
  af2bbd:	7e 3a                                           	jle    0xaf2bf9
  af2bbf:	48 8d 3d a6 ba 21 03                            	lea    rdi,[rip+0x321baa6]        # 0x3d0e66c
  af2bc6:	be 00 01 00 00                                  	mov    esi,0x100
  af2bcb:	41 89 c6                                        	mov    r14d,eax
  af2bce:	e8 bd f3 ff ff                                  	call   0xaf1f90
  af2bd3:	48 89 c1                                        	mov    rcx,rax
  af2bd6:	85 c9                                           	test   ecx,ecx
  af2bd8:	74 58                                           	je     0xaf2c32
  af2bda:	83 f9 01                                        	cmp    ecx,0x1
  af2bdd:	75 63                                           	jne    0xaf2c42
  af2bdf:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2be3:	66 c7 40 10 00 00                               	mov    WORD PTR [rax+0x10],0x0
  af2be9:	80 48 12 01                                     	or     BYTE PTR [rax+0x12],0x1
  af2bed:	eb 75                                           	jmp    0xaf2c64
  af2bef:	b8 0a 01 0d 80                                  	mov    eax,0x800d010a
  af2bf4:	e9 47 fb ff ff                                  	jmp    0xaf2740
  af2bf9:	b8 0b 01 0d 80                                  	mov    eax,0x800d010b
  af2bfe:	e9 3d fb ff ff                                  	jmp    0xaf2740
  af2c03:	b8 0a 01 0d 80                                  	mov    eax,0x800d010a
  af2c08:	81 fa 00 10 00 00                               	cmp    edx,0x1000
  af2c0e:	0f 84 6f ff ff ff                               	je     0xaf2b83
  af2c14:	81 fa 00 01 00 00                               	cmp    edx,0x100
  af2c1a:	0f 84 63 ff ff ff                               	je     0xaf2b83
  af2c20:	e9 1b fb ff ff                                  	jmp    0xaf2740
  af2c25:	85 d2                                           	test   edx,edx
  af2c27:	0f 84 56 ff ff ff                               	je     0xaf2b83
  af2c2d:	e9 0e fb ff ff                                  	jmp    0xaf2740
  af2c32:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2c36:	66 c7 40 10 00 00                               	mov    WORD PTR [rax+0x10],0x0
  af2c3c:	80 60 12 fe                                     	and    BYTE PTR [rax+0x12],0xfe
  af2c40:	eb 22                                           	jmp    0xaf2c64
  af2c42:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2c46:	0f b7 40 06                                     	movzx  eax,WORD PTR [rax+0x6]
  af2c4a:	01 c8                                           	add    eax,ecx
  af2c4c:	3d ff 0b 00 00                                  	cmp    eax,0xbff
  af2c51:	b8 0b 01 0d 80                                  	mov    eax,0x800d010b
  af2c56:	0f 87 e4 fa ff ff                               	ja     0xaf2740
  af2c5c:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2c60:	66 89 48 10                                     	mov    WORD PTR [rax+0x10],cx
  af2c64:	44 89 f1                                        	mov    ecx,r14d
  af2c67:	4c 89 f8                                        	mov    rax,r15
  af2c6a:	48 89 de                                        	mov    rsi,rbx
  af2c6d:	48 01 c8                                        	add    rax,rcx
  af2c70:	48 89 4d 88                                     	mov    QWORD PTR [rbp-0x78],rcx
  af2c74:	49 8d 7c 05 fe                                  	lea    rdi,[r13+rax*1-0x2]
  af2c79:	48 29 c6                                        	sub    rsi,rax
  af2c7c:	49 89 c7                                        	mov    r15,rax
  af2c7f:	e8 3c f4 ff ff                                  	call   0xaf20c0
  af2c84:	85 c0                                           	test   eax,eax
  af2c86:	0f 8e 82 00 00 00                               	jle    0xaf2d0e
  af2c8c:	48 8d 3d d9 b9 21 03                            	lea    rdi,[rip+0x321b9d9]        # 0x3d0e66c
  af2c93:	be 00 01 00 00                                  	mov    esi,0x100
  af2c98:	41 89 c6                                        	mov    r14d,eax
  af2c9b:	e8 f0 f2 ff ff                                  	call   0xaf1f90
  af2ca0:	85 c0                                           	test   eax,eax
  af2ca2:	74 74                                           	je     0xaf2d18
  af2ca4:	b9 00 00 00 00                                  	mov    ecx,0x0
  af2ca9:	c7 45 b8 00 00 00 00                            	mov    DWORD PTR [rbp-0x48],0x0
  af2cb0:	a8 01                                           	test   al,0x1
  af2cb2:	74 0d                                           	je     0xaf2cc1
  af2cb4:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2cb8:	80 49 12 02                                     	or     BYTE PTR [rcx+0x12],0x2
  af2cbc:	b9 01 00 00 00                                  	mov    ecx,0x1
  af2cc1:	a8 02                                           	test   al,0x2
  af2cc3:	74 11                                           	je     0xaf2cd6
  af2cc5:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  af2cc9:	ff c1                                           	inc    ecx
  af2ccb:	80 4a 1a 02                                     	or     BYTE PTR [rdx+0x1a],0x2
  af2ccf:	0f b7 52 06                                     	movzx  edx,WORD PTR [rdx+0x6]
  af2cd3:	89 55 b8                                        	mov    DWORD PTR [rbp-0x48],edx
  af2cd6:	c7 45 bc 00 00 00 00                            	mov    DWORD PTR [rbp-0x44],0x0
  af2cdd:	a8 04                                           	test   al,0x4
  af2cdf:	74 14                                           	je     0xaf2cf5
  af2ce1:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2ce5:	80 49 1a 04                                     	or     BYTE PTR [rcx+0x1a],0x4
  af2ce9:	0f b7 49 06                                     	movzx  ecx,WORD PTR [rcx+0x6]
  af2ced:	89 4d bc                                        	mov    DWORD PTR [rbp-0x44],ecx
  af2cf0:	b9 01 00 00 00                                  	mov    ecx,0x1
  af2cf5:	84 c0                                           	test   al,al
  af2cf7:	78 2f                                           	js     0xaf2d28
  af2cf9:	a9 00 01 00 00                                  	test   eax,0x100
  af2cfe:	75 43                                           	jne    0xaf2d43
  af2d00:	b8 0c 01 0d 80                                  	mov    eax,0x800d010c
  af2d05:	85 c9                                           	test   ecx,ecx
  af2d07:	75 50                                           	jne    0xaf2d59
  af2d09:	e9 32 fa ff ff                                  	jmp    0xaf2740
  af2d0e:	b8 0c 01 0d 80                                  	mov    eax,0x800d010c
  af2d13:	e9 28 fa ff ff                                  	jmp    0xaf2740
  af2d18:	c7 45 bc 00 00 00 00                            	mov    DWORD PTR [rbp-0x44],0x0
  af2d1f:	c7 45 b8 00 00 00 00                            	mov    DWORD PTR [rbp-0x48],0x0
  af2d26:	eb 31                                           	jmp    0xaf2d59
  af2d28:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  af2d2c:	0f b7 4a 12                                     	movzx  ecx,WORD PTR [rdx+0x12]
  af2d30:	81 c9 00 01 00 00                               	or     ecx,0x100
  af2d36:	66 89 4a 12                                     	mov    WORD PTR [rdx+0x12],cx
  af2d3a:	a9 00 01 00 00                                  	test   eax,0x100
  af2d3f:	75 0a                                           	jne    0xaf2d4b
  af2d41:	eb 16                                           	jmp    0xaf2d59
  af2d43:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2d47:	0f b7 48 12                                     	movzx  ecx,WORD PTR [rax+0x12]
  af2d4b:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2d4f:	81 c9 00 03 00 00                               	or     ecx,0x300
  af2d55:	66 89 48 12                                     	mov    WORD PTR [rax+0x12],cx
  af2d59:	44 89 f0                                        	mov    eax,r14d
  af2d5c:	48 89 de                                        	mov    rsi,rbx
  af2d5f:	49 01 c7                                        	add    r15,rax
  af2d62:	48 89 85 38 ff ff ff                            	mov    QWORD PTR [rbp-0xc8],rax
  af2d69:	4b 8d 7c 3d fe                                  	lea    rdi,[r13+r15*1-0x2]
  af2d6e:	4c 29 fe                                        	sub    rsi,r15
  af2d71:	4d 89 fe                                        	mov    r14,r15
  af2d74:	e8 47 f3 ff ff                                  	call   0xaf20c0
  af2d79:	85 c0                                           	test   eax,eax
  af2d7b:	0f 8e 27 01 00 00                               	jle    0xaf2ea8
  af2d81:	89 c0                                           	mov    eax,eax
  af2d83:	49 89 df                                        	mov    r15,rbx
  af2d86:	49 01 c6                                        	add    r14,rax
  af2d89:	48 89 85 40 ff ff ff                            	mov    QWORD PTR [rbp-0xc0],rax
  af2d90:	4d 29 f7                                        	sub    r15,r14
  af2d93:	83 3d 1e 4e 20 03 01                            	cmp    DWORD PTR [rip+0x3204e1e],0x1        # 0x3cf7bb8
  af2d9a:	4b 8d 44 35 fe                                  	lea    rax,[r13+r14*1-0x2]
  af2d9f:	4c 89 75 c8                                     	mov    QWORD PTR [rbp-0x38],r14
  af2da3:	41 be ff ff ff ff                               	mov    r14d,0xffffffff
  af2da9:	48 89 45 a8                                     	mov    QWORD PTR [rbp-0x58],rax
  af2dad:	75 37                                           	jne    0xaf2de6
  af2daf:	48 8d 3d b6 b8 21 03                            	lea    rdi,[rip+0x321b8b6]        # 0x3d0e66c
  af2db6:	be 00 01 00 00                                  	mov    esi,0x100
  af2dbb:	e8 d0 f1 ff ff                                  	call   0xaf1f90
  af2dc0:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2dc4:	49 89 c6                                        	mov    r14,rax
  af2dc7:	81 39 00 00 80 19                               	cmp    DWORD PTR [rcx],0x19800000
  af2dcd:	75 17                                           	jne    0xaf2de6
  af2dcf:	83 3d 0a 4e 20 03 01                            	cmp    DWORD PTR [rip+0x3204e0a],0x1        # 0x3cf7be0
  af2dd6:	75 0e                                           	jne    0xaf2de6
  af2dd8:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2ddc:	41 be 06 00 00 00                               	mov    r14d,0x6
  af2de2:	80 60 09 19                                     	and    BYTE PTR [rax+0x9],0x19
  af2de6:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  af2dea:	4c 89 fe                                        	mov    rsi,r15
  af2ded:	e8 ce f2 ff ff                                  	call   0xaf20c0
  af2df2:	85 c0                                           	test   eax,eax
  af2df4:	0f 8e ae 00 00 00                               	jle    0xaf2ea8
  af2dfa:	89 c1                                           	mov    ecx,eax
  af2dfc:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  af2e00:	49 89 df                                        	mov    r15,rbx
  af2e03:	48 89 8d 48 ff ff ff                            	mov    QWORD PTR [rbp-0xb8],rcx
  af2e0a:	48 01 c8                                        	add    rax,rcx
  af2e0d:	49 29 c7                                        	sub    r15,rax
  af2e10:	83 3d a1 4d 20 03 03                            	cmp    DWORD PTR [rip+0x3204da1],0x3        # 0x3cf7bb8
  af2e17:	49 8d 4c 05 fe                                  	lea    rcx,[r13+rax*1-0x2]
  af2e1c:	48 89 45 c8                                     	mov    QWORD PTR [rbp-0x38],rax
  af2e20:	48 89 4d a8                                     	mov    QWORD PTR [rbp-0x58],rcx
  af2e24:	75 14                                           	jne    0xaf2e3a
  af2e26:	48 8d 3d 3f b8 21 03                            	lea    rdi,[rip+0x321b83f]        # 0x3d0e66c
  af2e2d:	be 00 01 00 00                                  	mov    esi,0x100
  af2e32:	e8 59 f1 ff ff                                  	call   0xaf1f90
  af2e37:	49 89 c6                                        	mov    r14,rax
  af2e3a:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  af2e3e:	4c 89 fe                                        	mov    rsi,r15
  af2e41:	e8 7a f2 ff ff                                  	call   0xaf20c0
  af2e46:	85 c0                                           	test   eax,eax
  af2e48:	7e 5e                                           	jle    0xaf2ea8
  af2e4a:	83 3d 67 4d 20 03 02                            	cmp    DWORD PTR [rip+0x3204d67],0x2        # 0x3cf7bb8
  af2e51:	41 89 c7                                        	mov    r15d,eax
  af2e54:	75 5c                                           	jne    0xaf2eb2
  af2e56:	48 8d 3d 0f b8 21 03                            	lea    rdi,[rip+0x321b80f]        # 0x3d0e66c
  af2e5d:	be 00 01 00 00                                  	mov    esi,0x100
  af2e62:	e8 29 f1 ff ff                                  	call   0xaf1f90
  af2e67:	49 89 c6                                        	mov    r14,rax
  af2e6a:	41 f6 c6 20                                     	test   r14b,0x20
  af2e6e:	74 48                                           	je     0xaf2eb8
  af2e70:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2e74:	41 83 e6 df                                     	and    r14d,0xffffffdf
  af2e78:	80 48 12 08                                     	or     BYTE PTR [rax+0x12],0x8
  af2e7c:	41 f6 c6 40                                     	test   r14b,0x40
  af2e80:	74 3c                                           	je     0xaf2ebe
  af2e82:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2e86:	41 83 e6 bf                                     	and    r14d,0xffffffbf
  af2e8a:	80 48 12 10                                     	or     BYTE PTR [rax+0x12],0x10
  af2e8e:	45 84 f6                                        	test   r14b,r14b
  af2e91:	79 30                                           	jns    0xaf2ec3
  af2e93:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2e97:	41 81 e6 7f ff ff ff                            	and    r14d,0xffffff7f
  af2e9e:	80 48 12 40                                     	or     BYTE PTR [rax+0x12],0x40
  af2ea2:	41 83 fe 09                                     	cmp    r14d,0x9
  af2ea6:	76 21                                           	jbe    0xaf2ec9
  af2ea8:	b8 0d 01 0d 80                                  	mov    eax,0x800d010d
  af2ead:	e9 8e f8 ff ff                                  	jmp    0xaf2740
  af2eb2:	41 f6 c6 20                                     	test   r14b,0x20
  af2eb6:	75 b8                                           	jne    0xaf2e70
  af2eb8:	41 f6 c6 40                                     	test   r14b,0x40
  af2ebc:	75 c4                                           	jne    0xaf2e82
  af2ebe:	45 84 f6                                        	test   r14b,r14b
  af2ec1:	78 d0                                           	js     0xaf2e93
  af2ec3:	41 83 fe 09                                     	cmp    r14d,0x9
  af2ec7:	77 df                                           	ja     0xaf2ea8
  af2ec9:	b8 53 02 00 00                                  	mov    eax,0x253
  af2ece:	44 0f a3 f0                                     	bt     eax,r14d
  af2ed2:	b8 0d 01 0d 80                                  	mov    eax,0x800d010d
  af2ed7:	0f 83 63 f8 ff ff                               	jae    0xaf2740
  af2edd:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  af2ee1:	44 89 f9                                        	mov    ecx,r15d
  af2ee4:	48 89 de                                        	mov    rsi,rbx
  af2ee7:	48 89 4d a8                                     	mov    QWORD PTR [rbp-0x58],rcx
  af2eeb:	48 01 c8                                        	add    rax,rcx
  af2eee:	49 8d 7c 05 fe                                  	lea    rdi,[r13+rax*1-0x2]
  af2ef3:	48 29 c6                                        	sub    rsi,rax
  af2ef6:	49 89 c7                                        	mov    r15,rax
  af2ef9:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2efd:	44 88 70 14                                     	mov    BYTE PTR [rax+0x14],r14b
  af2f01:	e8 ba f1 ff ff                                  	call   0xaf20c0
  af2f06:	85 c0                                           	test   eax,eax
  af2f08:	7e 38                                           	jle    0xaf2f42
  af2f0a:	48 8d 3d 5b b7 21 03                            	lea    rdi,[rip+0x321b75b]        # 0x3d0e66c
  af2f11:	be 00 01 00 00                                  	mov    esi,0x100
  af2f16:	41 89 c6                                        	mov    r14d,eax
  af2f19:	e8 72 f0 ff ff                                  	call   0xaf1f90
  af2f1e:	85 c0                                           	test   eax,eax
  af2f20:	74 70                                           	je     0xaf2f92
  af2f22:	31 c9                                           	xor    ecx,ecx
  af2f24:	a8 01                                           	test   al,0x1
  af2f26:	75 24                                           	jne    0xaf2f4c
  af2f28:	a8 02                                           	test   al,0x2
  af2f2a:	75 31                                           	jne    0xaf2f5d
  af2f2c:	a8 04                                           	test   al,0x4
  af2f2e:	75 3e                                           	jne    0xaf2f6e
  af2f30:	a8 08                                           	test   al,0x8
  af2f32:	75 4d                                           	jne    0xaf2f81
  af2f34:	b8 0e 01 0d 80                                  	mov    eax,0x800d010e
  af2f39:	85 c9                                           	test   ecx,ecx
  af2f3b:	75 55                                           	jne    0xaf2f92
  af2f3d:	e9 fe f7 ff ff                                  	jmp    0xaf2740
  af2f42:	b8 0e 01 0d 80                                  	mov    eax,0x800d010e
  af2f47:	e9 f4 f7 ff ff                                  	jmp    0xaf2740
  af2f4c:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2f50:	80 49 1c 01                                     	or     BYTE PTR [rcx+0x1c],0x1
  af2f54:	b9 01 00 00 00                                  	mov    ecx,0x1
  af2f59:	a8 02                                           	test   al,0x2
  af2f5b:	74 cf                                           	je     0xaf2f2c
  af2f5d:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2f61:	80 49 1c 02                                     	or     BYTE PTR [rcx+0x1c],0x2
  af2f65:	b9 01 00 00 00                                  	mov    ecx,0x1
  af2f6a:	a8 04                                           	test   al,0x4
  af2f6c:	74 c2                                           	je     0xaf2f30
  af2f6e:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  af2f72:	8b 4a 1c                                        	mov    ecx,DWORD PTR [rdx+0x1c]
  af2f75:	83 c9 04                                        	or     ecx,0x4
  af2f78:	89 4a 1c                                        	mov    DWORD PTR [rdx+0x1c],ecx
  af2f7b:	a8 08                                           	test   al,0x8
  af2f7d:	75 09                                           	jne    0xaf2f88
  af2f7f:	eb 11                                           	jmp    0xaf2f92
  af2f81:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2f85:	8b 48 1c                                        	mov    ecx,DWORD PTR [rax+0x1c]
  af2f88:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af2f8c:	83 c9 08                                        	or     ecx,0x8
  af2f8f:	89 48 1c                                        	mov    DWORD PTR [rax+0x1c],ecx
  af2f92:	44 89 f1                                        	mov    ecx,r14d
  af2f95:	4c 89 f8                                        	mov    rax,r15
  af2f98:	48 89 de                                        	mov    rsi,rbx
  af2f9b:	48 01 c8                                        	add    rax,rcx
  af2f9e:	48 89 8d 50 ff ff ff                            	mov    QWORD PTR [rbp-0xb0],rcx
  af2fa5:	49 8d 7c 05 fe                                  	lea    rdi,[r13+rax*1-0x2]
  af2faa:	48 29 c6                                        	sub    rsi,rax
  af2fad:	49 89 c7                                        	mov    r15,rax
  af2fb0:	e8 0b f1 ff ff                                  	call   0xaf20c0
  af2fb5:	85 c0                                           	test   eax,eax
  af2fb7:	7e 38                                           	jle    0xaf2ff1
  af2fb9:	48 8d 3d ac b6 21 03                            	lea    rdi,[rip+0x321b6ac]        # 0x3d0e66c
  af2fc0:	be 00 01 00 00                                  	mov    esi,0x100
  af2fc5:	41 89 c6                                        	mov    r14d,eax
  af2fc8:	e8 c3 ef ff ff                                  	call   0xaf1f90
  af2fcd:	85 c0                                           	test   eax,eax
  af2fcf:	74 73                                           	je     0xaf3044
  af2fd1:	31 c9                                           	xor    ecx,ecx
  af2fd3:	a8 01                                           	test   al,0x1
  af2fd5:	75 24                                           	jne    0xaf2ffb
  af2fd7:	a8 02                                           	test   al,0x2
  af2fd9:	75 31                                           	jne    0xaf300c
  af2fdb:	a8 04                                           	test   al,0x4
  af2fdd:	75 3e                                           	jne    0xaf301d
  af2fdf:	a8 08                                           	test   al,0x8
  af2fe1:	75 4d                                           	jne    0xaf3030
  af2fe3:	b8 0f 01 0d 80                                  	mov    eax,0x800d010f
  af2fe8:	85 c9                                           	test   ecx,ecx
  af2fea:	75 58                                           	jne    0xaf3044
  af2fec:	e9 4f f7 ff ff                                  	jmp    0xaf2740
  af2ff1:	b8 0f 01 0d 80                                  	mov    eax,0x800d010f
  af2ff6:	e9 45 f7 ff ff                                  	jmp    0xaf2740
  af2ffb:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af2fff:	80 49 1c 10                                     	or     BYTE PTR [rcx+0x1c],0x10
  af3003:	b9 01 00 00 00                                  	mov    ecx,0x1
  af3008:	a8 02                                           	test   al,0x2
  af300a:	74 cf                                           	je     0xaf2fdb
  af300c:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af3010:	80 49 1c 20                                     	or     BYTE PTR [rcx+0x1c],0x20
  af3014:	b9 01 00 00 00                                  	mov    ecx,0x1
  af3019:	a8 04                                           	test   al,0x4
  af301b:	74 c2                                           	je     0xaf2fdf
  af301d:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  af3021:	8b 4a 1c                                        	mov    ecx,DWORD PTR [rdx+0x1c]
  af3024:	83 c9 40                                        	or     ecx,0x40
  af3027:	89 4a 1c                                        	mov    DWORD PTR [rdx+0x1c],ecx
  af302a:	a8 08                                           	test   al,0x8
  af302c:	75 09                                           	jne    0xaf3037
  af302e:	eb 14                                           	jmp    0xaf3044
  af3030:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af3034:	8b 48 1c                                        	mov    ecx,DWORD PTR [rax+0x1c]
  af3037:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af303b:	81 c9 80 00 00 00                               	or     ecx,0x80
  af3041:	89 48 1c                                        	mov    DWORD PTR [rax+0x1c],ecx
  af3044:	44 89 f1                                        	mov    ecx,r14d
  af3047:	4c 89 f8                                        	mov    rax,r15
  af304a:	48 89 de                                        	mov    rsi,rbx
  af304d:	48 01 c8                                        	add    rax,rcx
  af3050:	48 89 8d 58 ff ff ff                            	mov    QWORD PTR [rbp-0xa8],rcx
  af3057:	49 8d 7c 05 fe                                  	lea    rdi,[r13+rax*1-0x2]
  af305c:	48 29 c6                                        	sub    rsi,rax
  af305f:	49 89 c7                                        	mov    r15,rax
  af3062:	e8 59 f0 ff ff                                  	call   0xaf20c0
  af3067:	85 c0                                           	test   eax,eax
  af3069:	7e 44                                           	jle    0xaf30af
  af306b:	48 8d 3d fa b5 21 03                            	lea    rdi,[rip+0x321b5fa]        # 0x3d0e66c
  af3072:	be 00 01 00 00                                  	mov    esi,0x100
  af3077:	41 89 c6                                        	mov    r14d,eax
  af307a:	e8 11 ef ff ff                                  	call   0xaf1f90
  af307f:	85 c0                                           	test   eax,eax
  af3081:	0f 84 99 00 00 00                               	je     0xaf3120
  af3087:	31 c9                                           	xor    ecx,ecx
  af3089:	a8 01                                           	test   al,0x1
  af308b:	75 2c                                           	jne    0xaf30b9
  af308d:	a8 02                                           	test   al,0x2
  af308f:	75 39                                           	jne    0xaf30ca
  af3091:	a8 04                                           	test   al,0x4
  af3093:	75 43                                           	jne    0xaf30d8
  af3095:	a8 08                                           	test   al,0x8
  af3097:	75 4d                                           	jne    0xaf30e6
  af3099:	a8 10                                           	test   al,0x10
  af309b:	75 5a                                           	jne    0xaf30f7
  af309d:	a8 20                                           	test   al,0x20
  af309f:	75 6b                                           	jne    0xaf310c
  af30a1:	b8 15 01 0d 80                                  	mov    eax,0x800d0115
  af30a6:	85 c9                                           	test   ecx,ecx
  af30a8:	75 76                                           	jne    0xaf3120
  af30aa:	e9 91 f6 ff ff                                  	jmp    0xaf2740
  af30af:	b8 15 01 0d 80                                  	mov    eax,0x800d0115
  af30b4:	e9 87 f6 ff ff                                  	jmp    0xaf2740
  af30b9:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af30bd:	80 49 1d 04                                     	or     BYTE PTR [rcx+0x1d],0x4
  af30c1:	b9 01 00 00 00                                  	mov    ecx,0x1
  af30c6:	a8 02                                           	test   al,0x2
  af30c8:	74 c7                                           	je     0xaf3091
  af30ca:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  af30ce:	ff c1                                           	inc    ecx
  af30d0:	80 4a 1d 08                                     	or     BYTE PTR [rdx+0x1d],0x8
  af30d4:	a8 04                                           	test   al,0x4
  af30d6:	74 bd                                           	je     0xaf3095
  af30d8:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  af30dc:	ff c1                                           	inc    ecx
  af30de:	80 4a 1d 10                                     	or     BYTE PTR [rdx+0x1d],0x10
  af30e2:	a8 08                                           	test   al,0x8
  af30e4:	74 b3                                           	je     0xaf3099
  af30e6:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af30ea:	80 49 1d 20                                     	or     BYTE PTR [rcx+0x1d],0x20
  af30ee:	b9 01 00 00 00                                  	mov    ecx,0x1
  af30f3:	a8 10                                           	test   al,0x10
  af30f5:	74 a6                                           	je     0xaf309d
  af30f7:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  af30fb:	b9 00 40 00 00                                  	mov    ecx,0x4000
  af3100:	0b 4a 1c                                        	or     ecx,DWORD PTR [rdx+0x1c]
  af3103:	89 4a 1c                                        	mov    DWORD PTR [rdx+0x1c],ecx
  af3106:	a8 20                                           	test   al,0x20
  af3108:	75 09                                           	jne    0xaf3113
  af310a:	eb 14                                           	jmp    0xaf3120
  af310c:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af3110:	8b 48 1c                                        	mov    ecx,DWORD PTR [rax+0x1c]
  af3113:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af3117:	81 c9 00 80 00 00                               	or     ecx,0x8000
  af311d:	89 48 1c                                        	mov    DWORD PTR [rax+0x1c],ecx
  af3120:	44 89 f0                                        	mov    eax,r14d
  af3123:	48 89 de                                        	mov    rsi,rbx
  af3126:	49 01 c7                                        	add    r15,rax
  af3129:	48 89 85 60 ff ff ff                            	mov    QWORD PTR [rbp-0xa0],rax
  af3130:	4b 8d 7c 3d fe                                  	lea    rdi,[r13+r15*1-0x2]
  af3135:	4c 29 fe                                        	sub    rsi,r15
  af3138:	4d 89 fe                                        	mov    r14,r15
  af313b:	e8 80 ef ff ff                                  	call   0xaf20c0
  af3140:	85 c0                                           	test   eax,eax
  af3142:	0f 8e fa 00 00 00                               	jle    0xaf3242
  af3148:	89 c0                                           	mov    eax,eax
  af314a:	49 89 df                                        	mov    r15,rbx
  af314d:	49 01 c6                                        	add    r14,rax
  af3150:	48 89 85 68 ff ff ff                            	mov    QWORD PTR [rbp-0x98],rax
  af3157:	4d 29 f7                                        	sub    r15,r14
  af315a:	83 3d 63 4a 20 03 01                            	cmp    DWORD PTR [rip+0x3204a63],0x1        # 0x3cf7bc4
  af3161:	4b 8d 44 35 fe                                  	lea    rax,[r13+r14*1-0x2]
  af3166:	4c 89 75 c8                                     	mov    QWORD PTR [rbp-0x38],r14
  af316a:	41 be ff ff ff ff                               	mov    r14d,0xffffffff
  af3170:	48 89 45 90                                     	mov    QWORD PTR [rbp-0x70],rax
  af3174:	75 14                                           	jne    0xaf318a
  af3176:	48 8d 3d ef b4 21 03                            	lea    rdi,[rip+0x321b4ef]        # 0x3d0e66c
  af317d:	be 00 01 00 00                                  	mov    esi,0x100
  af3182:	e8 09 ee ff ff                                  	call   0xaf1f90
  af3187:	49 89 c6                                        	mov    r14,rax
  af318a:	48 8b 7d 90                                     	mov    rdi,QWORD PTR [rbp-0x70]
  af318e:	4c 89 fe                                        	mov    rsi,r15
  af3191:	e8 2a ef ff ff                                  	call   0xaf20c0
  af3196:	85 c0                                           	test   eax,eax
  af3198:	0f 8e a4 00 00 00                               	jle    0xaf3242
  af319e:	83 3d 1f 4a 20 03 01                            	cmp    DWORD PTR [rip+0x3204a1f],0x1        # 0x3cf7bc4
  af31a5:	41 89 c7                                        	mov    r15d,eax
  af31a8:	74 14                                           	je     0xaf31be
  af31aa:	48 8d 3d bb b4 21 03                            	lea    rdi,[rip+0x321b4bb]        # 0x3d0e66c
  af31b1:	be 00 01 00 00                                  	mov    esi,0x100
  af31b6:	e8 d5 ed ff ff                                  	call   0xaf1f90
  af31bb:	49 89 c6                                        	mov    r14,rax
  af31be:	b8 10 01 0d 80                                  	mov    eax,0x800d0110
  af31c3:	41 83 fe ff                                     	cmp    r14d,0xffffffff
  af31c7:	0f 84 73 f5 ff ff                               	je     0xaf2740
  af31cd:	44 89 f8                                        	mov    eax,r15d
  af31d0:	48 01 45 c8                                     	add    QWORD PTR [rbp-0x38],rax
  af31d4:	48 89 45 90                                     	mov    QWORD PTR [rbp-0x70],rax
  af31d8:	41 f6 c6 01                                     	test   r14b,0x1
  af31dc:	74 08                                           	je     0xaf31e6
  af31de:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af31e2:	80 48 1d 01                                     	or     BYTE PTR [rax+0x1d],0x1
  af31e6:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  af31ea:	48 89 de                                        	mov    rsi,rbx
  af31ed:	49 8d 7c 05 fe                                  	lea    rdi,[r13+rax*1-0x2]
  af31f2:	48 29 c6                                        	sub    rsi,rax
  af31f5:	41 f6 c6 02                                     	test   r14b,0x2
  af31f9:	74 08                                           	je     0xaf3203
  af31fb:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af31ff:	80 48 1d 02                                     	or     BYTE PTR [rax+0x1d],0x2
  af3203:	e8 b8 ee ff ff                                  	call   0xaf20c0
  af3208:	85 c0                                           	test   eax,eax
  af320a:	7e 40                                           	jle    0xaf324c
  af320c:	48 8d 3d 59 b4 21 03                            	lea    rdi,[rip+0x321b459]        # 0x3d0e66c
  af3213:	be 00 01 00 00                                  	mov    esi,0x100
  af3218:	41 89 c6                                        	mov    r14d,eax
  af321b:	e8 70 ed ff ff                                  	call   0xaf1f90
  af3220:	48 89 c1                                        	mov    rcx,rax
  af3223:	83 f9 22                                        	cmp    ecx,0x22
  af3226:	7f 2e                                           	jg     0xaf3256
  af3228:	8d 41 ff                                        	lea    eax,[rcx-0x1]
  af322b:	83 f8 03                                        	cmp    eax,0x3
  af322e:	b8 19 01 0d 80                                  	mov    eax,0x800d0119
  af3233:	72 55                                           	jb     0xaf328a
  af3235:	83 f9 13                                        	cmp    ecx,0x13
  af3238:	0f 85 02 f5 ff ff                               	jne    0xaf2740
  af323e:	b0 12                                           	mov    al,0x12
  af3240:	eb 4e                                           	jmp    0xaf3290
  af3242:	b8 10 01 0d 80                                  	mov    eax,0x800d0110
  af3247:	e9 f4 f4 ff ff                                  	jmp    0xaf2740
  af324c:	b8 19 01 0d 80                                  	mov    eax,0x800d0119
  af3251:	e9 ea f4 ff ff                                  	jmp    0xaf2740
  af3256:	83 f9 52                                        	cmp    ecx,0x52
  af3259:	7f 19                                           	jg     0xaf3274
  af325b:	b0 22                                           	mov    al,0x22
  af325d:	83 f9 23                                        	cmp    ecx,0x23
  af3260:	74 2e                                           	je     0xaf3290
  af3262:	b8 19 01 0d 80                                  	mov    eax,0x800d0119
  af3267:	83 f9 43                                        	cmp    ecx,0x43
  af326a:	0f 85 d0 f4 ff ff                               	jne    0xaf2740
  af3270:	b0 42                                           	mov    al,0x42
  af3272:	eb 1c                                           	jmp    0xaf3290
  af3274:	83 f9 53                                        	cmp    ecx,0x53
  af3277:	74 15                                           	je     0xaf328e
  af3279:	b8 19 01 0d 80                                  	mov    eax,0x800d0119
  af327e:	81 f9 83 00 00 00                               	cmp    ecx,0x83
  af3284:	0f 85 b6 f4 ff ff                               	jne    0xaf2740
  af328a:	89 c8                                           	mov    eax,ecx
  af328c:	eb 02                                           	jmp    0xaf3290
  af328e:	b0 52                                           	mov    al,0x52
  af3290:	48 8b 4d c8                                     	mov    rcx,QWORD PTR [rbp-0x38]
  af3294:	44 89 f2                                        	mov    edx,r14d
  af3297:	48 89 de                                        	mov    rsi,rbx
  af329a:	48 89 95 70 ff ff ff                            	mov    QWORD PTR [rbp-0x90],rdx
  af32a1:	48 01 d1                                        	add    rcx,rdx
  af32a4:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  af32a8:	49 8d 7c 0d fe                                  	lea    rdi,[r13+rcx*1-0x2]
  af32ad:	48 29 ce                                        	sub    rsi,rcx
  af32b0:	49 89 cf                                        	mov    r15,rcx
  af32b3:	88 42 18                                        	mov    BYTE PTR [rdx+0x18],al
  af32b6:	e8 05 ee ff ff                                  	call   0xaf20c0
  af32bb:	85 c0                                           	test   eax,eax
  af32bd:	7e 3b                                           	jle    0xaf32fa
  af32bf:	48 8d 3d a6 b3 21 03                            	lea    rdi,[rip+0x321b3a6]        # 0x3d0e66c
  af32c6:	be 00 01 00 00                                  	mov    esi,0x100
  af32cb:	41 89 c6                                        	mov    r14d,eax
  af32ce:	e8 bd ec ff ff                                  	call   0xaf1f90
  af32d3:	48 89 c1                                        	mov    rcx,rax
  af32d6:	b8 12 01 0d 80                                  	mov    eax,0x800d0112
  af32db:	89 ca                                           	mov    edx,ecx
  af32dd:	81 e2 7f ff ff ff                               	and    edx,0xffffff7f
  af32e3:	83 fa 63                                        	cmp    edx,0x63
  af32e6:	0f 8f 54 f4 ff ff                               	jg     0xaf2740
  af32ec:	84 c9                                           	test   cl,cl
  af32ee:	78 14                                           	js     0xaf3304
  af32f0:	85 c9                                           	test   ecx,ecx
  af32f2:	74 1c                                           	je     0xaf3310
  af32f4:	b0 08                                           	mov    al,0x8
  af32f6:	89 ca                                           	mov    edx,ecx
  af32f8:	eb 0c                                           	jmp    0xaf3306
  af32fa:	b8 12 01 0d 80                                  	mov    eax,0x800d0112
  af32ff:	e9 3c f4 ff ff                                  	jmp    0xaf2740
  af3304:	b0 10                                           	mov    al,0x10
  af3306:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af330a:	88 51 15                                        	mov    BYTE PTR [rcx+0x15],dl
  af330d:	88 41 16                                        	mov    BYTE PTR [rcx+0x16],al
  af3310:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af3314:	80 78 0b 00                                     	cmp    BYTE PTR [rax+0xb],0x0
  af3318:	75 64                                           	jne    0xaf337e
  af331a:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af331e:	0f b6 40 15                                     	movzx  eax,BYTE PTR [rax+0x15]
  af3322:	85 c0                                           	test   eax,eax
  af3324:	74 1c                                           	je     0xaf3342
  af3326:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af332a:	c6 41 0a 10                                     	mov    BYTE PTR [rcx+0xa],0x10
  af332e:	8b 15 10 4b 20 03                               	mov    edx,DWORD PTR [rip+0x3204b10]        # 0x3cf7e44
  af3334:	89 51 0c                                        	mov    DWORD PTR [rcx+0xc],edx
  af3337:	0f b7 49 06                                     	movzx  ecx,WORD PTR [rcx+0x6]
  af333b:	0f af c8                                        	imul   ecx,eax
  af333e:	01 d1                                           	add    ecx,edx
  af3340:	eb 1d                                           	jmp    0xaf335f
  af3342:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af3346:	8b 0d f8 4a 20 03                               	mov    ecx,DWORD PTR [rip+0x3204af8]        # 0x3cf7e44
  af334c:	80 78 0a 01                                     	cmp    BYTE PTR [rax+0xa],0x1
  af3350:	74 13                                           	je     0xaf3365
  af3352:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af3356:	89 48 0c                                        	mov    DWORD PTR [rax+0xc],ecx
  af3359:	0f b7 40 06                                     	movzx  eax,WORD PTR [rax+0x6]
  af335d:	01 c1                                           	add    ecx,eax
  af335f:	89 0d df 4a 20 03                               	mov    DWORD PTR [rip+0x3204adf],ecx        # 0x3cf7e44
  af3365:	b8 12 02 0d 80                                  	mov    eax,0x800d0212
  af336a:	81 f9 00 40 06 00                               	cmp    ecx,0x64000
  af3370:	0f 87 ca f3 ff ff                               	ja     0xaf2740
  af3376:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af337a:	c6 40 0b 01                                     	mov    BYTE PTR [rax+0xb],0x1
  af337e:	44 89 f1                                        	mov    ecx,r14d
  af3381:	4c 89 f8                                        	mov    rax,r15
  af3384:	48 89 de                                        	mov    rsi,rbx
  af3387:	48 01 c8                                        	add    rax,rcx
  af338a:	48 89 4d c8                                     	mov    QWORD PTR [rbp-0x38],rcx
  af338e:	49 8d 7c 05 fe                                  	lea    rdi,[r13+rax*1-0x2]
  af3393:	48 29 c6                                        	sub    rsi,rax
  af3396:	49 89 c7                                        	mov    r15,rax
  af3399:	e8 22 ed ff ff                                  	call   0xaf20c0
  af339e:	85 c0                                           	test   eax,eax
  af33a0:	0f 8e 34 01 00 00                               	jle    0xaf34da
  af33a6:	48 8d 3d bf b2 21 03                            	lea    rdi,[rip+0x321b2bf]        # 0x3d0e66c
  af33ad:	be 00 01 00 00                                  	mov    esi,0x100
  af33b2:	41 89 c6                                        	mov    r14d,eax
  af33b5:	e8 d6 eb ff ff                                  	call   0xaf1f90
  af33ba:	83 f8 02                                        	cmp    eax,0x2
  af33bd:	0f 93 c1                                        	setae  cl
  af33c0:	84 c0                                           	test   al,al
  af33c2:	0f 99 c2                                        	setns  dl
  af33c5:	84 d1                                           	test   cl,dl
  af33c7:	0f 85 0d 01 00 00                               	jne    0xaf34da
  af33cd:	44 89 f1                                        	mov    ecx,r14d
  af33d0:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  af33d4:	48 89 de                                        	mov    rsi,rbx
  af33d7:	49 01 cf                                        	add    r15,rcx
  af33da:	48 89 8d 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],rcx
  af33e1:	4b 8d 7c 3d fe                                  	lea    rdi,[r13+r15*1-0x2]
  af33e6:	4c 29 fe                                        	sub    rsi,r15
  af33e9:	4c 89 fb                                        	mov    rbx,r15
  af33ec:	66 89 42 20                                     	mov    WORD PTR [rdx+0x20],ax
  af33f0:	49 89 ff                                        	mov    r15,rdi
  af33f3:	e8 c8 ec ff ff                                  	call   0xaf20c0
  af33f8:	85 c0                                           	test   eax,eax
  af33fa:	0f 8e da 00 00 00                               	jle    0xaf34da
  af3400:	41 89 c6                                        	mov    r14d,eax
  af3403:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af3407:	0f b7 48 04                                     	movzx  ecx,WORD PTR [rax+0x4]
  af340b:	8d 41 ff                                        	lea    eax,[rcx-0x1]
  af340e:	83 f8 02                                        	cmp    eax,0x2
  af3411:	0f 83 cd 00 00 00                               	jae    0xaf34e4
  af3417:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af341b:	0f b7 48 06                                     	movzx  ecx,WORD PTR [rax+0x6]
  af341f:	b8 08 01 0d 80                                  	mov    eax,0x800d0108
  af3424:	8d 91 ff f7 ff ff                               	lea    edx,[rcx-0x801]
  af342a:	66 81 fa 00 f8                                  	cmp    dx,0xf800
  af342f:	0f 82 0b f3 ff ff                               	jb     0xaf2740
  af3435:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af3439:	0f b7 50 20                                     	movzx  edx,WORD PTR [rax+0x20]
  af343d:	66 85 d2                                        	test   dx,dx
  af3440:	0f 95 c0                                        	setne  al
  af3443:	84 d2                                           	test   dl,dl
  af3445:	40 0f 99 c6                                     	setns  sil
  af3449:	40 84 f0                                        	test   al,sil
  af344c:	0f 84 e6 00 00 00                               	je     0xaf3538
  af3452:	b8 11 01 0d 80                                  	mov    eax,0x800d0111
  af3457:	66 83 fa 01                                     	cmp    dx,0x1
  af345b:	0f 85 df f2 ff ff                               	jne    0xaf2740
  af3461:	48 8d 3d 04 b2 21 03                            	lea    rdi,[rip+0x321b204]        # 0x3d0e66c
  af3468:	be ff 00 00 00                                  	mov    esi,0xff
  af346d:	e8 3e 1a 95 ff                                  	call   0x444eb0
  af3472:	48 89 45 98                                     	mov    QWORD PTR [rbp-0x68],rax
  af3476:	ff c0                                           	inc    eax
  af3478:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  af347c:	44 89 f0                                        	mov    eax,r14d
  af347f:	48 01 d8                                        	add    rax,rbx
  af3482:	41 80 7c 05 fe 00                               	cmp    BYTE PTR [r13+rax*1-0x2],0x0
  af3488:	0f 84 7d 01 00 00                               	je     0xaf360b
  af348e:	be 00 01 00 00                                  	mov    esi,0x100
  af3493:	4c 89 ff                                        	mov    rdi,r15
  af3496:	e8 15 1a 95 ff                                  	call   0x444eb0
  af349b:	44 0f b7 f0                                     	movzx  r14d,ax
  af349f:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  af34a3:	4c 01 f3                                        	add    rbx,r14
  af34a6:	41 80 7c 1d fd 3a                               	cmp    BYTE PTR [r13+rbx*1-0x3],0x3a
  af34ac:	0f 85 96 02 00 00                               	jne    0xaf3748
  af34b2:	48 8d 3d b3 b1 21 03                            	lea    rdi,[rip+0x321b1b3]        # 0x3d0e66c
  af34b9:	4c 89 fe                                        	mov    rsi,r15
  af34bc:	4c 89 f2                                        	mov    rdx,r14
  af34bf:	e8 ec 5b 76 ff                                  	call   0x2590b0
  af34c4:	48 8b 45 c0                                     	mov    rax,QWORD PTR [rbp-0x40]
  af34c8:	43 c6 84 26 0b 1c 00 00 00                      	mov    BYTE PTR [r14+r12*1+0x1c0b],0x0
  af34d1:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  af34d5:	e9 6e 02 00 00                                  	jmp    0xaf3748
  af34da:	b8 11 01 0d 80                                  	mov    eax,0x800d0111
  af34df:	e9 5c f2 ff ff                                  	jmp    0xaf2740
  af34e4:	b8 07 01 0d 80                                  	mov    eax,0x800d0107
  af34e9:	85 c9                                           	test   ecx,ecx
  af34eb:	0f 85 4f f2 ff ff                               	jne    0xaf2740
  af34f1:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af34f5:	66 83 78 06 04                                  	cmp    WORD PTR [rax+0x6],0x4
  af34fa:	b8 08 01 0d 80                                  	mov    eax,0x800d0108
  af34ff:	0f 85 3b f2 ff ff                               	jne    0xaf2740
  af3505:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af3509:	0f b7 40 20                                     	movzx  eax,WORD PTR [rax+0x20]
  af350d:	66 83 f8 01                                     	cmp    ax,0x1
  af3511:	0f 95 c1                                        	setne  cl
  af3514:	84 c0                                           	test   al,al
  af3516:	b8 11 01 0d 80                                  	mov    eax,0x800d0111
  af351b:	0f 99 c2                                        	setns  dl
  af351e:	84 d1                                           	test   cl,dl
  af3520:	0f 85 1a f2 ff ff                               	jne    0xaf2740
  af3526:	48 8b 5d d0                                     	mov    rbx,QWORD PTR [rbp-0x30]
  af352a:	66 c7 43 06 04 00                               	mov    WORD PTR [rbx+0x6],0x4
  af3530:	66 c7 43 22 04 00                               	mov    WORD PTR [rbx+0x22],0x4
  af3536:	eb 08                                           	jmp    0xaf3540
  af3538:	48 8b 5d d0                                     	mov    rbx,QWORD PTR [rbp-0x30]
  af353c:	66 89 4b 22                                     	mov    WORD PTR [rbx+0x22],cx
  af3540:	48 8d 3d 25 b1 21 03                            	lea    rdi,[rip+0x321b125]        # 0x3d0e66c
  af3547:	be 00 01 00 00                                  	mov    esi,0x100
  af354c:	e8 3f ea ff ff                                  	call   0xaf1f90
  af3551:	89 43 24                                        	mov    DWORD PTR [rbx+0x24],eax
  af3554:	83 7d 84 00                                     	cmp    DWORD PTR [rbp-0x7c],0x0
  af3558:	0f 84 a6 00 00 00                               	je     0xaf3604
  af355e:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af3562:	0f b6 48 15                                     	movzx  ecx,BYTE PTR [rax+0x15]
  af3566:	85 c9                                           	test   ecx,ecx
  af3568:	74 35                                           	je     0xaf359f
  af356a:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af356e:	8b 00                                           	mov    eax,DWORD PTR [rax]
  af3570:	89 c2                                           	mov    edx,eax
  af3572:	81 e2 00 00 00 ff                               	and    edx,0xff000000
  af3578:	81 fa 00 00 00 07                               	cmp    edx,0x7000000
  af357e:	75 1b                                           	jne    0xaf359b
  af3580:	ba 12 06 00 00                                  	mov    edx,0x612
  af3585:	c4 e2 68 f7 c0                                  	bextr  eax,eax,edx
  af358a:	8d 14 85 80 ff ff ff                            	lea    edx,[rax*4-0x80]
  af3591:	b8 10 00 00 00                                  	mov    eax,0x10
  af3596:	83 fa 14                                        	cmp    edx,0x14
  af3599:	72 09                                           	jb     0xaf35a4
  af359b:	89 c8                                           	mov    eax,ecx
  af359d:	eb 05                                           	jmp    0xaf35a4
  af359f:	b8 01 00 00 00                                  	mov    eax,0x1
  af35a4:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  af35a8:	31 c9                                           	xor    ecx,ecx
  af35aa:	66 83 7a 10 00                                  	cmp    WORD PTR [rdx+0x10],0x0
  af35af:	0f 94 c1                                        	sete   cl
  af35b2:	83 7d b8 00                                     	cmp    DWORD PTR [rbp-0x48],0x0
  af35b6:	74 23                                           	je     0xaf35db
  af35b8:	8b 75 b8                                        	mov    esi,DWORD PTR [rbp-0x48]
  af35bb:	48 8d 15 ce 45 20 03                            	lea    rdx,[rip+0x32045ce]        # 0x3cf7b90
  af35c2:	01 84 8a a8 00 00 00                            	add    DWORD PTR [rdx+rcx*4+0xa8],eax
  af35c9:	ff ce                                           	dec    esi
  af35cb:	83 e6 fc                                        	and    esi,0xfffffffc
  af35ce:	83 c6 08                                        	add    esi,0x8
  af35d1:	0f af f0                                        	imul   esi,eax
  af35d4:	01 b4 8a b0 00 00 00                            	add    DWORD PTR [rdx+rcx*4+0xb0],esi
  af35db:	83 7d bc 00                                     	cmp    DWORD PTR [rbp-0x44],0x0
  af35df:	74 23                                           	je     0xaf3604
  af35e1:	8b 75 bc                                        	mov    esi,DWORD PTR [rbp-0x44]
  af35e4:	48 8d 15 a5 45 20 03                            	lea    rdx,[rip+0x32045a5]        # 0x3cf7b90
  af35eb:	01 84 8a bc 00 00 00                            	add    DWORD PTR [rdx+rcx*4+0xbc],eax
  af35f2:	ff ce                                           	dec    esi
  af35f4:	83 e6 fc                                        	and    esi,0xfffffffc
  af35f7:	83 c6 08                                        	add    esi,0x8
  af35fa:	0f af f0                                        	imul   esi,eax
  af35fd:	01 b4 8a c4 00 00 00                            	add    DWORD PTR [rdx+rcx*4+0xc4],esi
  af3604:	31 c0                                           	xor    eax,eax
  af3606:	e9 35 f1 ff ff                                  	jmp    0xaf2740
  af360b:	80 3d 5a b0 21 03 62                            	cmp    BYTE PTR [rip+0x321b05a],0x62        # 0x3d0e66c
  af3612:	0f 85 30 01 00 00                               	jne    0xaf3748
  af3618:	80 3d 4e b0 21 03 27                            	cmp    BYTE PTR [rip+0x321b04e],0x27        # 0x3d0e66d
  af361f:	0f 85 23 01 00 00                               	jne    0xaf3748
  af3625:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  af3629:	66 83 78 04 02                                  	cmp    WORD PTR [rax+0x4],0x2
  af362e:	b8 07 01 0d 80                                  	mov    eax,0x800d0107
  af3633:	0f 85 07 f1 ff ff                               	jne    0xaf2740
  af3639:	f6 45 98 01                                     	test   BYTE PTR [rbp-0x68],0x1
  af363d:	0f 85 fb 00 00 00                               	jne    0xaf373e
  af3643:	48 8b 45 98                                     	mov    rax,QWORD PTR [rbp-0x68]
  af3647:	48 8d 3d 1e b0 21 03                            	lea    rdi,[rip+0x321b01e]        # 0x3d0e66c
  af364e:	89 c3                                           	mov    ebx,eax
  af3650:	81 e3 fe ff 00 00                               	and    ebx,0xfffe
  af3656:	89 de                                           	mov    esi,ebx
  af3658:	d1 ee                                           	shr    esi,1
  af365a:	e8 91 59 76 ff                                  	call   0x258ff0
  af365f:	48 c7 45 b0 00 00 00 00                         	mov    QWORD PTR [rbp-0x50],0x0
  af3667:	83 fb 03                                        	cmp    ebx,0x3
  af366a:	0f 82 d8 00 00 00                               	jb     0xaf3748
  af3670:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  af3674:	48 03 95 70 ff ff ff                            	add    rdx,QWORD PTR [rbp-0x90]
  af367b:	4c 8b 4d a8                                     	mov    r9,QWORD PTR [rbp-0x58]
  af367f:	4c 03 8d 48 ff ff ff                            	add    r9,QWORD PTR [rbp-0xb8]
  af3686:	48 8b 45 c0                                     	mov    rax,QWORD PTR [rbp-0x40]
  af368a:	48 03 85 78 ff ff ff                            	add    rax,QWORD PTR [rbp-0x88]
  af3691:	0f b7 4d 98                                     	movzx  ecx,WORD PTR [rbp-0x68]
  af3695:	bf 10 00 00 00                                  	mov    edi,0x10
  af369a:	31 f6                                           	xor    esi,esi
  af369c:	48 03 55 90                                     	add    rdx,QWORD PTR [rbp-0x70]
  af36a0:	4c 03 8d 40 ff ff ff                            	add    r9,QWORD PTR [rbp-0xc0]
  af36a7:	48 03 95 68 ff ff ff                            	add    rdx,QWORD PTR [rbp-0x98]
  af36ae:	4c 03 8d 38 ff ff ff                            	add    r9,QWORD PTR [rbp-0xc8]
  af36b5:	48 03 95 60 ff ff ff                            	add    rdx,QWORD PTR [rbp-0xa0]
  af36bc:	4c 03 4d 88                                     	add    r9,QWORD PTR [rbp-0x78]
  af36c0:	48 03 95 58 ff ff ff                            	add    rdx,QWORD PTR [rbp-0xa8]
  af36c7:	4c 03 4d a0                                     	add    r9,QWORD PTR [rbp-0x60]
  af36cb:	48 83 c1 fe                                     	add    rcx,0xfffffffffffffffe
  af36cf:	48 03 95 50 ff ff ff                            	add    rdx,QWORD PTR [rbp-0xb0]
  af36d6:	48 01 c2                                        	add    rdx,rax
  af36d9:	49 01 d1                                        	add    r9,rdx
  af36dc:	ba 10 00 00 00                                  	mov    edx,0x10
  af36e1:	eb 33                                           	jmp    0xaf3716
  af36e3:	04 c9                                           	add    al,0xc9
  af36e5:	4c 8b 45 b0                                     	mov    r8,QWORD PTR [rbp-0x50]
  af36e9:	40 f6 e7                                        	mul    dil
  af36ec:	4d 63 c0                                        	movsxd r8,r8d
  af36ef:	43 00 84 20 0c 1c 00 00                         	add    BYTE PTR [r8+r12*1+0x1c0c],al
  af36f7:	31 c0                                           	xor    eax,eax
  af36f9:	83 ff 10                                        	cmp    edi,0x10
  af36fc:	bf 01 00 00 00                                  	mov    edi,0x1
  af3701:	0f 95 c0                                        	setne  al
  af3704:	0f 45 fa                                        	cmovne edi,edx
  af3707:	48 ff c6                                        	inc    rsi
  af370a:	41 01 c0                                        	add    r8d,eax
  af370d:	4c 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],r8
  af3711:	48 39 f1                                        	cmp    rcx,rsi
  af3714:	74 32                                           	je     0xaf3748
  af3716:	49 8d 04 31                                     	lea    rax,[r9+rsi*1]
  af371a:	41 0f b6 44 05 00                               	movzx  eax,BYTE PTR [r13+rax*1+0x0]
  af3720:	44 8d 40 bf                                     	lea    r8d,[rax-0x41]
  af3724:	41 80 f8 05                                     	cmp    r8b,0x5
  af3728:	76 b9                                           	jbe    0xaf36e3
  af372a:	44 8d 40 9f                                     	lea    r8d,[rax-0x61]
  af372e:	41 80 f8 05                                     	cmp    r8b,0x5
  af3732:	77 04                                           	ja     0xaf3738
  af3734:	04 a9                                           	add    al,0xa9
  af3736:	eb ad                                           	jmp    0xaf36e5
  af3738:	04 d0                                           	add    al,0xd0
  af373a:	3c 09                                           	cmp    al,0x9
  af373c:	76 a7                                           	jbe    0xaf36e5
  af373e:	b8 13 01 0d 80                                  	mov    eax,0x800d0113
  af3743:	e9 f8 ef ff ff                                  	jmp    0xaf2740
  af3748:	0f b7 3d f3 46 20 03                            	movzx  edi,WORD PTR [rip+0x32046f3]        # 0x3cf7e42
  af374f:	44 0f b7 75 b0                                  	movzx  r14d,WORD PTR [rbp-0x50]
  af3754:	b8 13 01 0d 80                                  	mov    eax,0x800d0113
  af3759:	42 8d 0c 37                                     	lea    ecx,[rdi+r14*1]
  af375d:	81 f9 00 0a 00 00                               	cmp    ecx,0xa00
  af3763:	0f 87 d7 ef ff ff                               	ja     0xaf2740
  af3769:	48 03 3d e0 86 21 03                            	add    rdi,QWORD PTR [rip+0x32186e0]        # 0x3d0be50
  af3770:	48 8d 35 f5 ae 21 03                            	lea    rsi,[rip+0x321aef5]        # 0x3d0e66c
  af3777:	4c 89 f2                                        	mov    rdx,r14
  af377a:	e8 31 59 76 ff                                  	call   0x2590b0
  af377f:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  af3783:	66 44 89 71 22                                  	mov    WORD PTR [rcx+0x22],r14w
  af3788:	0f b7 05 b3 46 20 03                            	movzx  eax,WORD PTR [rip+0x32046b3]        # 0x3cf7e42
  af378f:	89 41 24                                        	mov    DWORD PTR [rcx+0x24],eax
  af3792:	44 01 f0                                        	add    eax,r14d
  af3795:	66 89 05 a6 46 20 03                            	mov    WORD PTR [rip+0x32046a6],ax        # 0x3cf7e42
  af379c:	83 7d 84 00                                     	cmp    DWORD PTR [rbp-0x7c],0x0
  af37a0:	0f 85 b8 fd ff ff                               	jne    0xaf355e
  af37a6:	e9 59 fe ff ff                                  	jmp    0xaf3604
  af37ab:	90                                              	nop
  af37ac:	90                                              	nop
  af37ad:	90                                              	nop
  af37ae:	90                                              	nop
  af37af:	90                                              	nop
  af37b0:	55                                              	push   rbp
  af37b1:	48 89 e5                                        	mov    rbp,rsp
  af37b4:	41 56                                           	push   r14
  af37b6:	53                                              	push   rbx
  af37b7:	44 0f b7 05 81 46 20 03                         	movzx  r8d,WORD PTR [rip+0x3204681]        # 0x3cf7e40
  af37bf:	4d 85 c0                                        	test   r8,r8
  af37c2:	74 7f                                           	je     0xaf3843
  af37c4:	48 8d 0d 6d 46 20 03                            	lea    rcx,[rip+0x320466d]        # 0x3cf7e38
  af37cb:	31 c0                                           	xor    eax,eax
  af37cd:	eb 09                                           	jmp    0xaf37d8
  af37cf:	90                                              	nop
  af37d0:	48 ff c0                                        	inc    rax
  af37d3:	4c 39 c0                                        	cmp    rax,r8
  af37d6:	74 6b                                           	je     0xaf3843
  af37d8:	4c 8d 14 80                                     	lea    r10,[rax+rax*4]
  af37dc:	46 8b 4c d1 18                                  	mov    r9d,DWORD PTR [rcx+r10*8+0x18]
  af37e1:	44 39 cf                                        	cmp    edi,r9d
  af37e4:	74 40                                           	je     0xaf3826
  af37e6:	4e 8d 5c d1 18                                  	lea    r11,[rcx+r10*8+0x18]
  af37eb:	45 0f b6 53 15                                  	movzx  r10d,BYTE PTR [r11+0x15]
  af37f0:	45 85 d2                                        	test   r10d,r10d
  af37f3:	74 db                                           	je     0xaf37d0
  af37f5:	41 83 fa 01                                     	cmp    r10d,0x1
  af37f9:	74 d5                                           	je     0xaf37d0
  af37fb:	45 0f b6 5b 16                                  	movzx  r11d,BYTE PTR [r11+0x16]
  af3800:	bb 01 00 00 00                                  	mov    ebx,0x1
  af3805:	66 66 2e 0f 1f 84 00 00 00 00 00                	data16 cs nop WORD PTR [rax+rax*1+0x0]
  af3810:	c4 62 21 f7 f3                                  	shlx   r14d,ebx,r11d
  af3815:	45 01 ce                                        	add    r14d,r9d
  af3818:	44 39 f7                                        	cmp    edi,r14d
  af381b:	74 09                                           	je     0xaf3826
  af381d:	ff c3                                           	inc    ebx
  af381f:	41 39 da                                        	cmp    r10d,ebx
  af3822:	75 ec                                           	jne    0xaf3810
  af3824:	eb aa                                           	jmp    0xaf37d0
  af3826:	85 c0                                           	test   eax,eax
  af3828:	78 19                                           	js     0xaf3843
  af382a:	25 ff ff ff 7f                                  	and    eax,0x7fffffff
  af382f:	48 8d 04 80                                     	lea    rax,[rax+rax*4]
  af3833:	80 7c c1 22 00                                  	cmp    BYTE PTR [rcx+rax*8+0x22],0x0
  af3838:	74 13                                           	je     0xaf384d
  af383a:	5b                                              	pop    rbx
  af383b:	41 5e                                           	pop    r14
  af383d:	5d                                              	pop    rbp
  af383e:	e9 7d 0b 1c 00                                  	jmp    0xcb43c0
  af3843:	b8 03 02 0d 80                                  	mov    eax,0x800d0203
  af3848:	5b                                              	pop    rbx
  af3849:	41 5e                                           	pop    r14
  af384b:	5d                                              	pop    rbp
  af384c:	c3                                              	ret
  af384d:	5b                                              	pop    rbx
  af384e:	41 5e                                           	pop    r14
  af3850:	5d                                              	pop    rbp
  af3851:	e9 2a 7e c6 ff                                  	jmp    0x75b680
  af3856:	90                                              	nop
  af3857:	90                                              	nop
  af3858:	90                                              	nop
  af3859:	90                                              	nop
  af385a:	90                                              	nop
  af385b:	90                                              	nop
  af385c:	90                                              	nop
  af385d:	90                                              	nop
  af385e:	90                                              	nop
  af385f:	90                                              	nop
  af3860:	55                                              	push   rbp
  af3861:	48 89 e5                                        	mov    rbp,rsp
  af3864:	66 83 3d 0c 86 21 03 00                         	cmp    WORD PTR [rip+0x321860c],0x0        # 0x3d0be78
  af386c:	74 61                                           	je     0xaf38cf
  af386e:	0f b6 0d 09 86 21 03                            	movzx  ecx,BYTE PTR [rip+0x3218609]        # 0x3d0be7e
  af3875:	0f b6 15 03 86 21 03                            	movzx  edx,BYTE PTR [rip+0x3218603]        # 0x3d0be7f
  af387c:	44 0f b6 05 fc 85 21 03                         	movzx  r8d,BYTE PTR [rip+0x32185fc]        # 0x3d0be80
  af3884:	0f b6 35 ec 85 21 03                            	movzx  esi,BYTE PTR [rip+0x32185ec]        # 0x3d0be77
  af388b:	89 f8                                           	mov    eax,edi
  af388d:	c1 e1 18                                        	shl    ecx,0x18
  af3890:	c1 e2 10                                        	shl    edx,0x10
  af3893:	41 c1 e0 08                                     	shl    r8d,0x8
  af3897:	09 ca                                           	or     edx,ecx
  af3899:	41 09 d0                                        	or     r8d,edx
  af389c:	44 09 c6                                        	or     esi,r8d
  af389f:	39 f7                                           	cmp    edi,esi
  af38a1:	74 2c                                           	je     0xaf38cf
  af38a3:	89 c1                                           	mov    ecx,eax
  af38a5:	88 05 cc 85 21 03                               	mov    BYTE PTR [rip+0x32185cc],al        # 0x3d0be77
  af38ab:	c7 05 73 43 20 03 01 00 00 00                   	mov    DWORD PTR [rip+0x3204373],0x1        # 0x3cf7c28
  af38b5:	c1 e9 18                                        	shr    ecx,0x18
  af38b8:	88 0d c0 85 21 03                               	mov    BYTE PTR [rip+0x32185c0],cl        # 0x3d0be7e
  af38be:	89 c1                                           	mov    ecx,eax
  af38c0:	c1 e9 10                                        	shr    ecx,0x10
  af38c3:	88 0d b6 85 21 03                               	mov    BYTE PTR [rip+0x32185b6],cl        # 0x3d0be7f
  af38c9:	88 25 b1 85 21 03                               	mov    BYTE PTR [rip+0x32185b1],ah        # 0x3d0be80
  af38cf:	5d                                              	pop    rbp
  af38d0:	c3                                              	ret
  af38d1:	90                                              	nop
  af38d2:	90                                              	nop
  af38d3:	90                                              	nop
  af38d4:	90                                              	nop
  af38d5:	90                                              	nop
  af38d6:	90                                              	nop
  af38d7:	90                                              	nop
  af38d8:	90                                              	nop
  af38d9:	90                                              	nop
  af38da:	90                                              	nop
  af38db:	90                                              	nop
  af38dc:	90                                              	nop
  af38dd:	90                                              	nop
  af38de:	90                                              	nop
  af38df:	90                                              	nop
  af38e0:	55                                              	push   rbp
  af38e1:	48 89 e5                                        	mov    rbp,rsp
  af38e4:	41 57                                           	push   r15
  af38e6:	41 56                                           	push   r14
  af38e8:	41 54                                           	push   r12
  af38ea:	53                                              	push   rbx
  af38eb:	48 83 ec 20                                     	sub    rsp,0x20
  af38ef:	4c 8d 25 1a 8a e2 02                            	lea    r12,[rip+0x2e28a1a]        # 0x391c310
  af38f6:	89 f3                                           	mov    ebx,esi
  af38f8:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  af38fc:	48 89 45 d8                                     	mov    QWORD PTR [rbp-0x28],rax
  af3900:	83 fe 02                                        	cmp    esi,0x2
  af3903:	0f 84 f3 03 00 00                               	je     0xaf3cfc
  af3909:	83 fb 01                                        	cmp    ebx,0x1
  af390c:	0f 84 b1 03 00 00                               	je     0xaf3cc3
  af3912:	85 db                                           	test   ebx,ebx
  af3914:	0f 85 c0 04 00 00                               	jne    0xaf3dda
  af391a:	48 8d 35 3a c6 78 00                            	lea    rsi,[rip+0x78c63a]        # 0x127ff5b
  af3921:	48 8d 15 98 74 77 ff                            	lea    rdx,[rip+0xffffffffff777498]        # 0x26adc0
  af3928:	48 8d 0d 10 49 79 00                            	lea    rcx,[rip+0x794910]        # 0x128823f
  af392f:	4c 8d 05 ea a7 dd 01                            	lea    r8,[rip+0x1dda7ea]        # 0x28ce120
  af3936:	31 ff                                           	xor    edi,edi
  af3938:	45 31 c9                                        	xor    r9d,r9d
  af393b:	e8 00 a4 c4 ff                                  	call   0x73dd40
  af3940:	41 be 13 02 0d 80                               	mov    r14d,0x800d0213
  af3946:	48 89 05 23 ae 21 03                            	mov    QWORD PTR [rip+0x321ae23],rax        # 0x3d0e770
  af394d:	48 85 c0                                        	test   rax,rax
  af3950:	0f 84 2a 06 00 00                               	je     0xaf3f80
  af3956:	48 8d 35 57 d5 7f 00                            	lea    rsi,[rip+0x7fd557]        # 0x12f0eb4
  af395d:	48 8d 15 74 10 77 ff                            	lea    rdx,[rip+0xffffffffff771074]        # 0x2649d8
  af3964:	48 8d 0d e9 f0 84 00                            	lea    rcx,[rip+0x84f0e9]        # 0x1342a54
  af396b:	4c 8d 05 be a7 dd 01                            	lea    r8,[rip+0x1dda7be]        # 0x28ce130
  af3972:	41 b9 1f 4e 00 00                               	mov    r9d,0x4e1f
  af3978:	31 ff                                           	xor    edi,edi
  af397a:	e8 c1 a3 c4 ff                                  	call   0x73dd40
  af397f:	48 89 05 fa ad 21 03                            	mov    QWORD PTR [rip+0x321adfa],rax        # 0x3d0e780
  af3986:	48 85 c0                                        	test   rax,rax
  af3989:	0f 84 f1 05 00 00                               	je     0xaf3f80
  af398f:	48 8d 35 cf 0a 7a 00                            	lea    rsi,[rip+0x7a0acf]        # 0x1294465
  af3996:	48 8d 15 43 10 77 ff                            	lea    rdx,[rip+0xffffffffff771043]        # 0x2649e0
  af399d:	48 8d 0d 10 cb 7d 00                            	lea    rcx,[rip+0x7dcb10]        # 0x12d04b4
  af39a4:	41 b9 01 00 00 00                               	mov    r9d,0x1
  af39aa:	41 bf 01 00 00 00                               	mov    r15d,0x1
  af39b0:	31 ff                                           	xor    edi,edi
  af39b2:	45 31 c0                                        	xor    r8d,r8d
  af39b5:	e8 86 a3 c4 ff                                  	call   0x73dd40
  af39ba:	48 89 05 c7 ad 21 03                            	mov    QWORD PTR [rip+0x321adc7],rax        # 0x3d0e788
  af39c1:	48 85 c0                                        	test   rax,rax
  af39c4:	0f 84 b6 05 00 00                               	je     0xaf3f80
  af39ca:	48 8d 3d bf 41 20 03                            	lea    rdi,[rip+0x32041bf]        # 0x3cf7b90
  af39d1:	be a8 02 00 00                                  	mov    esi,0x2a8
  af39d6:	e8 15 56 76 ff                                  	call   0x258ff0
  af39db:	48 b8 00 00 00 00 02 00 00 00                   	movabs rax,0x200000000
  af39e5:	48 b9 00 00 00 00 01 00 00 00                   	movabs rcx,0x100000000
  af39ef:	48 8d 3d 42 44 20 03                            	lea    rdi,[rip+0x3204442]        # 0x3cf7e38
  af39f6:	be 28 40 01 00                                  	mov    esi,0x14028
  af39fb:	48 89 05 ae 41 20 03                            	mov    QWORD PTR [rip+0x32041ae],rax        # 0x3cf7bb0
  af3a02:	c7 05 ac 41 20 03 02 00 00 00                   	mov    DWORD PTR [rip+0x32041ac],0x2        # 0x3cf7bb8
  af3a0c:	48 c7 05 a9 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x32041a9],0x0        # 0x3cf7bc0
  af3a17:	48 c7 05 a6 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x32041a6],0x0        # 0x3cf7bc8
  af3a22:	48 c7 05 a3 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x32041a3],0x0        # 0x3cf7bd0
  af3a2d:	48 c7 05 a0 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x32041a0],0x0        # 0x3cf7bd8
  af3a38:	48 c7 05 9d 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x320419d],0x0        # 0x3cf7be0
  af3a43:	48 c7 05 9a 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x320419a],0x0        # 0x3cf7be8
  af3a4e:	48 c7 05 9f 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x320419f],0x0        # 0x3cf7bf8
  af3a59:	48 c7 05 8c 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x320418c],0x0        # 0x3cf7bf0
  af3a64:	48 c7 05 91 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x3204191],0x0        # 0x3cf7c00
  af3a6f:	48 c7 05 8e 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x320418e],0x0        # 0x3cf7c08
  af3a7a:	48 c7 05 8b 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x320418b],0x0        # 0x3cf7c10
  af3a85:	48 c7 05 88 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x3204188],0x0        # 0x3cf7c18
  af3a90:	48 c7 05 85 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x3204185],0x0        # 0x3cf7c20
  af3a9b:	48 c7 05 82 41 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x3204182],0x0        # 0x3cf7c28
  af3aa6:	48 89 0d b7 41 20 03                            	mov    QWORD PTR [rip+0x32041b7],rcx        # 0x3cf7c64
  af3aad:	48 c7 05 38 43 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x3204338],0x0        # 0x3cf7df0
  af3ab8:	48 c7 05 35 43 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x3204335],0x0        # 0x3cf7df8
  af3ac3:	c7 05 33 43 20 03 00 00 00 00                   	mov    DWORD PTR [rip+0x3204333],0x0        # 0x3cf7e00
  af3acd:	c7 05 31 43 20 03 00 00 00 00                   	mov    DWORD PTR [rip+0x3204331],0x0        # 0x3cf7e08
  af3ad7:	48 c7 05 4a 43 20 03 00 00 00 00                	mov    QWORD PTR [rip+0x320434a],0x0        # 0x3cf7e2c
  af3ae2:	c7 05 48 43 20 03 00 00 00 00                   	mov    DWORD PTR [rip+0x3204348],0x0        # 0x3cf7e34
  af3aec:	c7 05 6a 41 20 03 00 00 00 00                   	mov    DWORD PTR [rip+0x320416a],0x0        # 0x3cf7c60
  af3af6:	e8 f5 54 76 ff                                  	call   0x258ff0
  af3afb:	48 8d 3d 5e 8f 21 03                            	lea    rdi,[rip+0x3218f5e]        # 0x3d0ca60
  af3b02:	be 0c 1d 00 00                                  	mov    esi,0x1d0c
  af3b07:	e8 e4 54 76 ff                                  	call   0x258ff0
  af3b0c:	48 8d 3d 4d 83 21 03                            	lea    rdi,[rip+0x321834d]        # 0x3d0be60
  af3b13:	be 00 0c 00 00                                  	mov    esi,0xc00
  af3b18:	e8 d3 54 76 ff                                  	call   0x258ff0
  af3b1d:	c7 05 dd 42 20 03 00 00 00 00                   	mov    DWORD PTR [rip+0x32042dd],0x0        # 0x3cf7e04
  af3b27:	e8 64 11 ab ff                                  	call   0x5a4c90
  af3b2c:	31 c9                                           	xor    ecx,ecx
  af3b2e:	83 f8 01                                        	cmp    eax,0x1
  af3b31:	0f 94 c1                                        	sete   cl
  af3b34:	89 0d 8a 40 20 03                               	mov    DWORD PTR [rip+0x320408a],ecx        # 0x3cf7bc4
  af3b3a:	e8 a1 12 ab ff                                  	call   0x5a4de0
  af3b3f:	31 c9                                           	xor    ecx,ecx
  af3b41:	83 f8 01                                        	cmp    eax,0x1
  af3b44:	0f 94 c1                                        	sete   cl
  af3b47:	89 0d 7b 40 20 03                               	mov    DWORD PTR [rip+0x320407b],ecx        # 0x3cf7bc8
  af3b4d:	e8 ae 11 ab ff                                  	call   0x5a4d00
  af3b52:	31 c9                                           	xor    ecx,ecx
  af3b54:	83 f8 01                                        	cmp    eax,0x1
  af3b57:	0f 94 c1                                        	sete   cl
  af3b5a:	89 0d 80 40 20 03                               	mov    DWORD PTR [rip+0x3204080],ecx        # 0x3cf7be0
  af3b60:	e8 8b 18 ab ff                                  	call   0x5a53f0
  af3b65:	31 c9                                           	xor    ecx,ecx
  af3b67:	83 f8 01                                        	cmp    eax,0x1
  af3b6a:	0f 94 c1                                        	sete   cl
  af3b6d:	89 0d 71 40 20 03                               	mov    DWORD PTR [rip+0x3204071],ecx        # 0x3cf7be4
  af3b73:	e8 e8 18 ab ff                                  	call   0x5a5460
  af3b78:	31 c9                                           	xor    ecx,ecx
  af3b7a:	83 f8 01                                        	cmp    eax,0x1
  af3b7d:	0f 94 c1                                        	sete   cl
  af3b80:	89 0d 62 40 20 03                               	mov    DWORD PTR [rip+0x3204062],ecx        # 0x3cf7be8
  af3b86:	e8 e5 11 ab ff                                  	call   0x5a4d70
  af3b8b:	31 c9                                           	xor    ecx,ecx
  af3b8d:	83 f8 01                                        	cmp    eax,0x1
  af3b90:	0f 94 c1                                        	sete   cl
  af3b93:	89 0d 53 40 20 03                               	mov    DWORD PTR [rip+0x3204053],ecx        # 0x3cf7bec
  af3b99:	e8 d2 13 ab ff                                  	call   0x5a4f70
  af3b9e:	31 c9                                           	xor    ecx,ecx
  af3ba0:	83 f8 01                                        	cmp    eax,0x1
  af3ba3:	0f 94 c1                                        	sete   cl
  af3ba6:	89 0d 28 40 20 03                               	mov    DWORD PTR [rip+0x3204028],ecx        # 0x3cf7bd4
  af3bac:	e8 8f 3d 01 00                                  	call   0xb07940
  af3bb1:	85 c0                                           	test   eax,eax
  af3bb3:	75 23                                           	jne    0xaf3bd8
  af3bb5:	e8 a6 3d 01 00                                  	call   0xb07960
  af3bba:	85 c0                                           	test   eax,eax
  af3bbc:	75 1a                                           	jne    0xaf3bd8
  af3bbe:	e8 5d 3d 01 00                                  	call   0xb07920
  af3bc3:	85 c0                                           	test   eax,eax
  af3bc5:	74 0e                                           	je     0xaf3bd5
  af3bc7:	bf 6d 00 00 00                                  	mov    edi,0x6d
  af3bcc:	e8 cf 8d fd ff                                  	call   0xacc9a0
  af3bd1:	85 c0                                           	test   eax,eax
  af3bd3:	75 03                                           	jne    0xaf3bd8
  af3bd5:	45 31 ff                                        	xor    r15d,r15d
  af3bd8:	44 89 3d 11 40 20 03                            	mov    DWORD PTR [rip+0x3204011],r15d        # 0x3cf7bf0
  af3bdf:	c7 05 83 ab 21 03 00 00 00 00                   	mov    DWORD PTR [rip+0x321ab83],0x0        # 0x3d0e76c
  af3be9:	e8 a2 6c be ff                                  	call   0x6da890
  af3bee:	85 c0                                           	test   eax,eax
  af3bf0:	75 07                                           	jne    0xaf3bf9
  af3bf2:	80 0d 73 ab 21 03 02                            	or     BYTE PTR [rip+0x321ab73],0x2        # 0x3d0e76c
  af3bf9:	e8 52 20 9d ff                                  	call   0x4c5c50
  af3bfe:	48 8d 35 db a3 dd 01                            	lea    rsi,[rip+0x1dda3db]        # 0x28cdfe0
  af3c05:	bf 00 0a 00 00                                  	mov    edi,0xa00
  af3c0a:	ba 01 01 00 00                                  	mov    edx,0x101
  af3c0f:	e8 3c 4f 11 00                                  	call   0xc08b50
  af3c14:	48 89 05 35 82 21 03                            	mov    QWORD PTR [rip+0x3218235],rax        # 0x3d0be50
  af3c1b:	48 85 c0                                        	test   rax,rax
  af3c1e:	74 6e                                           	je     0xaf3c8e
  af3c20:	48 8d 35 b9 a3 dd 01                            	lea    rsi,[rip+0x1dda3b9]        # 0x28cdfe0
  af3c27:	bf 00 40 06 00                                  	mov    edi,0x64000
  af3c2c:	ba 01 01 00 00                                  	mov    edx,0x101
  af3c31:	e8 1a 4f 11 00                                  	call   0xc08b50
  af3c36:	48 89 05 1b 82 21 03                            	mov    QWORD PTR [rip+0x321821b],rax        # 0x3d0be58
  af3c3d:	48 85 c0                                        	test   rax,rax
  af3c40:	74 4c                                           	je     0xaf3c8e
  af3c42:	48 8d 3d 5f 3f 20 03                            	lea    rdi,[rip+0x3203f5f]        # 0x3cf7ba8
  af3c49:	48 8d 35 3b 5a 80 00                            	lea    rsi,[rip+0x805a3b]        # 0x12f968b
  af3c50:	b9 04 00 00 00                                  	mov    ecx,0x4
  af3c55:	31 d2                                           	xor    edx,edx
  af3c57:	e8 74 41 9d ff                                  	call   0x4c7dd0
  af3c5c:	80 0d 9d 3f 20 03 01                            	or     BYTE PTR [rip+0x3203f9d],0x1        # 0x3cf7c00
  af3c63:	e8 08 69 bb ff                                  	call   0x6aa570
  af3c68:	80 3d e9 84 f6 00 00                            	cmp    BYTE PTR [rip+0xf684e9],0x0        # 0x1a5c158
  af3c6f:	74 1d                                           	je     0xaf3c8e
  af3c71:	e8 7a 64 be ff                                  	call   0x6da0f0
  af3c76:	3c 01                                           	cmp    al,0x1
  af3c78:	74 14                                           	je     0xaf3c8e
  af3c7a:	c7 05 78 3f 20 03 01 00 00 00                   	mov    DWORD PTR [rip+0x3203f78],0x1        # 0x3cf7bfc
  af3c84:	c7 05 32 3f 20 03 01 00 00 00                   	mov    DWORD PTR [rip+0x3203f32],0x1        # 0x3cf7bc0
  af3c8e:	65 48 8b 04 25 00 00 00 00                      	mov    rax,QWORD PTR gs:0x0
  af3c97:	48 85 c0                                        	test   rax,rax
  af3c9a:	0f 84 0e 02 00 00                               	je     0xaf3eae
  af3ca0:	48 8b 40 08                                     	mov    rax,QWORD PTR [rax+0x8]
  af3ca4:	48 85 c0                                        	test   rax,rax
  af3ca7:	0f 84 0a 02 00 00                               	je     0xaf3eb7
  af3cad:	48 05 e4 05 00 00                               	add    rax,0x5e4
  af3cb3:	4c 8d 3d 50 a8 89 00                            	lea    r15,[rip+0x89a850]        # 0x138e50a
  af3cba:	4c 0f 45 f8                                     	cmovne r15,rax
  af3cbe:	e9 fb 01 00 00                                  	jmp    0xaf3ebe
  af3cc3:	bf 04 00 00 00                                  	mov    edi,0x4
  af3cc8:	e8 b3 65 a7 ff                                  	call   0x56a280
  af3ccd:	bf 03 00 00 00                                  	mov    edi,0x3
  af3cd2:	e8 a9 65 a7 ff                                  	call   0x56a280
  af3cd7:	bf 02 00 00 00                                  	mov    edi,0x2
  af3cdc:	e8 9f 65 a7 ff                                  	call   0x56a280
  af3ce1:	bf 01 00 00 00                                  	mov    edi,0x1
  af3ce6:	e8 95 65 a7 ff                                  	call   0x56a280
  af3ceb:	31 ff                                           	xor    edi,edi
  af3ced:	e8 8e 65 a7 ff                                  	call   0x56a280
  af3cf2:	e8 69 b7 fc ff                                  	call   0xabf460
  af3cf7:	e9 de 00 00 00                                  	jmp    0xaf3dda
  af3cfc:	e8 5f 28 9d ff                                  	call   0x4c6560
  af3d01:	e8 da 68 bb ff                                  	call   0x6aa5e0
  af3d06:	48 83 3d 6a aa 21 03 00                         	cmp    QWORD PTR [rip+0x321aa6a],0x0        # 0x3d0e778
  af3d0e:	74 2b                                           	je     0xaf3d3b
  af3d10:	48 8d 3d 13 44 78 00                            	lea    rdi,[rip+0x784413]        # 0x127812a
  af3d17:	e8 c4 a5 c4 ff                                  	call   0x73e2e0
  af3d1c:	48 85 c0                                        	test   rax,rax
  af3d1f:	74 0f                                           	je     0xaf3d30
  af3d21:	48 8b 35 50 aa 21 03                            	mov    rsi,QWORD PTR [rip+0x321aa50]        # 0x3d0e778
  af3d28:	48 89 c7                                        	mov    rdi,rax
  af3d2b:	e8 50 a3 c4 ff                                  	call   0x73e080
  af3d30:	48 c7 05 3d aa 21 03 00 00 00 00                	mov    QWORD PTR [rip+0x321aa3d],0x0        # 0x3d0e778
  af3d3b:	48 83 3d 45 aa 21 03 00                         	cmp    QWORD PTR [rip+0x321aa45],0x0        # 0x3d0e788
  af3d43:	74 2b                                           	je     0xaf3d70
  af3d45:	48 8d 3d 19 07 7a 00                            	lea    rdi,[rip+0x7a0719]        # 0x1294465
  af3d4c:	e8 8f a5 c4 ff                                  	call   0x73e2e0
  af3d51:	48 85 c0                                        	test   rax,rax
  af3d54:	74 0f                                           	je     0xaf3d65
  af3d56:	48 8b 35 2b aa 21 03                            	mov    rsi,QWORD PTR [rip+0x321aa2b]        # 0x3d0e788
  af3d5d:	48 89 c7                                        	mov    rdi,rax
  af3d60:	e8 1b a3 c4 ff                                  	call   0x73e080
  af3d65:	48 c7 05 18 aa 21 03 00 00 00 00                	mov    QWORD PTR [rip+0x321aa18],0x0        # 0x3d0e788
  af3d70:	48 83 3d 08 aa 21 03 00                         	cmp    QWORD PTR [rip+0x321aa08],0x0        # 0x3d0e780
  af3d78:	74 2b                                           	je     0xaf3da5
  af3d7a:	48 8d 3d 33 d1 7f 00                            	lea    rdi,[rip+0x7fd133]        # 0x12f0eb4
  af3d81:	e8 5a a5 c4 ff                                  	call   0x73e2e0
  af3d86:	48 85 c0                                        	test   rax,rax
  af3d89:	74 0f                                           	je     0xaf3d9a
  af3d8b:	48 8b 35 ee a9 21 03                            	mov    rsi,QWORD PTR [rip+0x321a9ee]        # 0x3d0e780
  af3d92:	48 89 c7                                        	mov    rdi,rax
  af3d95:	e8 e6 a2 c4 ff                                  	call   0x73e080
  af3d9a:	48 c7 05 db a9 21 03 00 00 00 00                	mov    QWORD PTR [rip+0x321a9db],0x0        # 0x3d0e780
  af3da5:	48 83 3d c3 a9 21 03 00                         	cmp    QWORD PTR [rip+0x321a9c3],0x0        # 0x3d0e770
  af3dad:	74 2b                                           	je     0xaf3dda
  af3daf:	48 8d 3d a5 c1 78 00                            	lea    rdi,[rip+0x78c1a5]        # 0x127ff5b
  af3db6:	e8 25 a5 c4 ff                                  	call   0x73e2e0
  af3dbb:	48 85 c0                                        	test   rax,rax
  af3dbe:	74 0f                                           	je     0xaf3dcf
  af3dc0:	48 8b 35 a9 a9 21 03                            	mov    rsi,QWORD PTR [rip+0x321a9a9]        # 0x3d0e770
  af3dc7:	48 89 c7                                        	mov    rdi,rax
  af3dca:	e8 b1 a2 c4 ff                                  	call   0x73e080
  af3dcf:	48 c7 05 96 a9 21 03 00 00 00 00                	mov    QWORD PTR [rip+0x321a996],0x0        # 0x3d0e770
  af3dda:	65 48 8b 04 25 00 00 00 00                      	mov    rax,QWORD PTR gs:0x0
  af3de3:	48 85 c0                                        	test   rax,rax
  af3de6:	74 1c                                           	je     0xaf3e04
  af3de8:	48 8b 40 08                                     	mov    rax,QWORD PTR [rax+0x8]
  af3dec:	48 85 c0                                        	test   rax,rax
  af3def:	74 1c                                           	je     0xaf3e0d
  af3df1:	48 05 e4 05 00 00                               	add    rax,0x5e4
  af3df7:	4c 8d 35 0c a7 89 00                            	lea    r14,[rip+0x89a70c]        # 0x138e50a
  af3dfe:	4c 0f 45 f0                                     	cmovne r14,rax
  af3e02:	eb 10                                           	jmp    0xaf3e14
  af3e04:	4c 8d 35 b5 95 7c 00                            	lea    r14,[rip+0x7c95b5]        # 0x12bd3c0
  af3e0b:	eb 07                                           	jmp    0xaf3e14
  af3e0d:	4c 8d 35 e4 fc 8a 00                            	lea    r14,[rip+0x8afce4]        # 0x13a3af8
  af3e14:	be 09 00 00 00                                  	mov    esi,0x9
  af3e19:	4c 89 f7                                        	mov    rdi,r14
  af3e1c:	e8 8f 10 95 ff                                  	call   0x444eb0
  af3e21:	48 8d 7d c8                                     	lea    rdi,[rbp-0x38]
  af3e25:	48 83 f8 08                                     	cmp    rax,0x8
  af3e29:	77 0f                                           	ja     0xaf3e3a
  af3e2b:	ba 09 00 00 00                                  	mov    edx,0x9
  af3e30:	4c 89 f6                                        	mov    rsi,r14
  af3e33:	e8 08 06 e9 ff                                  	call   0x984440
  af3e38:	eb 0d                                           	jmp    0xaf3e47
  af3e3a:	ba 08 00 00 00                                  	mov    edx,0x8
  af3e3f:	4c 89 f6                                        	mov    rsi,r14
  af3e42:	e8 69 52 76 ff                                  	call   0x2590b0
  af3e47:	c6 45 d0 00                                     	mov    BYTE PTR [rbp-0x30],0x0
  af3e4b:	31 c0                                           	xor    eax,eax
  af3e4d:	80 7d c8 00                                     	cmp    BYTE PTR [rbp-0x38],0x0
  af3e51:	74 3c                                           	je     0xaf3e8f
  af3e53:	bf 01 00 00 00                                  	mov    edi,0x1
  af3e58:	48 b9 16 08 99 19 24 11 04 20                   	movabs rcx,0x2004112419990816
  af3e62:	be ff 00 00 00                                  	mov    esi,0xff
  af3e67:	31 d2                                           	xor    edx,edx
  af3e69:	0f 1f 80 00 00 00 00                            	nop    DWORD PTR [rax+0x0]
  af3e70:	c4 62 f9 f7 c6                                  	shlx   r8,rsi,rax
  af3e75:	83 c0 08                                        	add    eax,0x8
  af3e78:	49 21 c8                                        	and    r8,rcx
  af3e7b:	4c 09 c2                                        	or     rdx,r8
  af3e7e:	4c 63 c7                                        	movsxd r8,edi
  af3e81:	42 80 7c 05 c8 00                               	cmp    BYTE PTR [rbp+r8*1-0x38],0x0
  af3e87:	41 8d 78 01                                     	lea    edi,[r8+0x1]
  af3e8b:	75 e3                                           	jne    0xaf3e70
  af3e8d:	eb 02                                           	jmp    0xaf3e91
  af3e8f:	31 d2                                           	xor    edx,edx
  af3e91:	48 33 55 c8                                     	xor    rdx,QWORD PTR [rbp-0x38]
  af3e95:	48 8d 3d 42 c1 85 00                            	lea    rdi,[rip+0x85c142]        # 0x134ffde
  af3e9c:	be 48 3f 00 00                                  	mov    esi,0x3f48
  af3ea1:	b9 d2 02 96 49                                  	mov    ecx,0x499602d2
  af3ea6:	41 89 d8                                        	mov    r8d,ebx
  af3ea9:	e9 cf 01 00 00                                  	jmp    0xaf407d
  af3eae:	4c 8d 3d 0b 95 7c 00                            	lea    r15,[rip+0x7c950b]        # 0x12bd3c0
  af3eb5:	eb 07                                           	jmp    0xaf3ebe
  af3eb7:	4c 8d 3d 3a fc 8a 00                            	lea    r15,[rip+0x8afc3a]        # 0x13a3af8
  af3ebe:	be 09 00 00 00                                  	mov    esi,0x9
  af3ec3:	4c 89 ff                                        	mov    rdi,r15
  af3ec6:	e8 e5 0f 95 ff                                  	call   0x444eb0
  af3ecb:	48 8d 7d c8                                     	lea    rdi,[rbp-0x38]
  af3ecf:	48 83 f8 08                                     	cmp    rax,0x8
  af3ed3:	77 0f                                           	ja     0xaf3ee4
  af3ed5:	ba 09 00 00 00                                  	mov    edx,0x9
  af3eda:	4c 89 fe                                        	mov    rsi,r15
  af3edd:	e8 5e 05 e9 ff                                  	call   0x984440
  af3ee2:	eb 0d                                           	jmp    0xaf3ef1
  af3ee4:	ba 08 00 00 00                                  	mov    edx,0x8
  af3ee9:	4c 89 fe                                        	mov    rsi,r15
  af3eec:	e8 bf 51 76 ff                                  	call   0x2590b0
  af3ef1:	c6 45 d0 00                                     	mov    BYTE PTR [rbp-0x30],0x0
  af3ef5:	31 c0                                           	xor    eax,eax
  af3ef7:	80 7d c8 00                                     	cmp    BYTE PTR [rbp-0x38],0x0
  af3efb:	74 42                                           	je     0xaf3f3f
  af3efd:	bf 01 00 00 00                                  	mov    edi,0x1
  af3f02:	48 b9 16 08 99 19 24 11 04 20                   	movabs rcx,0x2004112419990816
  af3f0c:	be ff 00 00 00                                  	mov    esi,0xff
  af3f11:	31 d2                                           	xor    edx,edx
  af3f13:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  af3f20:	c4 62 f9 f7 c6                                  	shlx   r8,rsi,rax
  af3f25:	83 c0 08                                        	add    eax,0x8
  af3f28:	49 21 c8                                        	and    r8,rcx
  af3f2b:	4c 09 c2                                        	or     rdx,r8
  af3f2e:	4c 63 c7                                        	movsxd r8,edi
  af3f31:	42 80 7c 05 c8 00                               	cmp    BYTE PTR [rbp+r8*1-0x38],0x0
  af3f37:	41 8d 78 01                                     	lea    edi,[r8+0x1]
  af3f3b:	75 e3                                           	jne    0xaf3f20
  af3f3d:	eb 02                                           	jmp    0xaf3f41
  af3f3f:	31 d2                                           	xor    edx,edx
  af3f41:	48 33 55 c8                                     	xor    rdx,QWORD PTR [rbp-0x38]
  af3f45:	48 8d 3d 92 c0 85 00                            	lea    rdi,[rip+0x85c092]        # 0x134ffde
  af3f4c:	be 98 3e 00 00                                  	mov    esi,0x3e98
  af3f51:	b9 e3 1a 1d 21                                  	mov    ecx,0x211d1ae3
  af3f56:	45 31 c0                                        	xor    r8d,r8d
  af3f59:	31 c0                                           	xor    eax,eax
  af3f5b:	e8 b0 94 76 ff                                  	call   0x25d410
  af3f60:	e8 bb b3 fc ff                                  	call   0xabf320
  af3f65:	85 c0                                           	test   eax,eax
  af3f67:	75 14                                           	jne    0xaf3f7d
  af3f69:	e8 d2 24 9d ff                                  	call   0x4c6440
  af3f6e:	31 ff                                           	xor    edi,edi
  af3f70:	e8 4b 62 a7 ff                                  	call   0x56a1c0
  af3f75:	85 c0                                           	test   eax,eax
  af3f77:	0f 84 24 01 00 00                               	je     0xaf40a1
  af3f7d:	41 89 c6                                        	mov    r14d,eax
  af3f80:	83 3d 7d 3c 20 03 00                            	cmp    DWORD PTR [rip+0x3203c7d],0x0        # 0x3cf7c04
  af3f87:	74 24                                           	je     0xaf3fad
  af3f89:	44 89 f0                                        	mov    eax,r14d
  af3f8c:	44 89 35 71 3c 20 03                            	mov    DWORD PTR [rip+0x3203c71],r14d        # 0x3cf7c04
  af3f93:	25 00 00 ff ff                                  	and    eax,0xffff0000
  af3f98:	3d 00 00 0d 80                                  	cmp    eax,0x800d0000
  af3f9d:	75 0e                                           	jne    0xaf3fad
  af3f9f:	41 81 ce 00 80 0d 80                            	or     r14d,0x800d8000
  af3fa6:	44 89 35 57 3c 20 03                            	mov    DWORD PTR [rip+0x3203c57],r14d        # 0x3cf7c04
  af3fad:	65 48 8b 04 25 00 00 00 00                      	mov    rax,QWORD PTR gs:0x0
  af3fb6:	48 85 c0                                        	test   rax,rax
  af3fb9:	74 1c                                           	je     0xaf3fd7
  af3fbb:	48 8b 40 08                                     	mov    rax,QWORD PTR [rax+0x8]
  af3fbf:	48 85 c0                                        	test   rax,rax
  af3fc2:	74 1c                                           	je     0xaf3fe0
  af3fc4:	48 05 e4 05 00 00                               	add    rax,0x5e4
  af3fca:	48 8d 1d 39 a5 89 00                            	lea    rbx,[rip+0x89a539]        # 0x138e50a
  af3fd1:	48 0f 45 d8                                     	cmovne rbx,rax
  af3fd5:	eb 10                                           	jmp    0xaf3fe7
  af3fd7:	48 8d 1d e2 93 7c 00                            	lea    rbx,[rip+0x7c93e2]        # 0x12bd3c0
  af3fde:	eb 07                                           	jmp    0xaf3fe7
  af3fe0:	48 8d 1d 11 fb 8a 00                            	lea    rbx,[rip+0x8afb11]        # 0x13a3af8
  af3fe7:	be 09 00 00 00                                  	mov    esi,0x9
  af3fec:	48 89 df                                        	mov    rdi,rbx
  af3fef:	e8 bc 0e 95 ff                                  	call   0x444eb0
  af3ff4:	48 8d 7d c8                                     	lea    rdi,[rbp-0x38]
  af3ff8:	48 83 f8 08                                     	cmp    rax,0x8
  af3ffc:	77 0f                                           	ja     0xaf400d
  af3ffe:	ba 09 00 00 00                                  	mov    edx,0x9
  af4003:	48 89 de                                        	mov    rsi,rbx
  af4006:	e8 35 04 e9 ff                                  	call   0x984440
  af400b:	eb 0d                                           	jmp    0xaf401a
  af400d:	ba 08 00 00 00                                  	mov    edx,0x8
  af4012:	48 89 de                                        	mov    rsi,rbx
  af4015:	e8 96 50 76 ff                                  	call   0x2590b0
  af401a:	c6 45 d0 00                                     	mov    BYTE PTR [rbp-0x30],0x0
  af401e:	31 c0                                           	xor    eax,eax
  af4020:	80 7d c8 00                                     	cmp    BYTE PTR [rbp-0x38],0x0
  af4024:	74 39                                           	je     0xaf405f
  af4026:	bf 01 00 00 00                                  	mov    edi,0x1
  af402b:	48 b9 16 08 99 19 24 11 04 20                   	movabs rcx,0x2004112419990816
  af4035:	be ff 00 00 00                                  	mov    esi,0xff
  af403a:	31 d2                                           	xor    edx,edx
  af403c:	0f 1f 40 00                                     	nop    DWORD PTR [rax+0x0]
