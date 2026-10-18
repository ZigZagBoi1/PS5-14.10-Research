
/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/deep_648.bin:     file format binary


Disassembly of section .data:

00000000009f81f0 <.data>:
  9f81f0:	55                                              	push   rbp
  9f81f1:	48 89 e5                                        	mov    rbp,rsp
  9f81f4:	41 56                                           	push   r14
  9f81f6:	53                                              	push   rbx
  9f81f7:	48 8b bf 40 01 00 00                            	mov    rdi,QWORD PTR [rdi+0x140]
  9f81fe:	49 89 f6                                        	mov    r14,rsi
  9f8201:	e8 0a 0f c1 ff                                  	call   0x609110
  9f8206:	85 c0                                           	test   eax,eax
  9f8208:	74 2f                                           	je     0x9f8239
  9f820a:	48 8d 3d af 5d 1b 03                            	lea    rdi,[rip+0x31b5daf]        # 0x3badfc0
  9f8211:	31 db                                           	xor    ebx,ebx
  9f8213:	31 f6                                           	xor    esi,esi
  9f8215:	31 d2                                           	xor    edx,edx
  9f8217:	31 c9                                           	xor    ecx,ecx
  9f8219:	e8 02 39 25 00                                  	call   0xc4bb20
  9f821e:	41 83 3e 07                                     	cmp    DWORD PTR [r14],0x7
  9f8222:	75 2a                                           	jne    0x9f824e
  9f8224:	48 8b 05 b5 5d 1b 03                            	mov    rax,QWORD PTR [rip+0x31b5db5]        # 0x3badfe0
  9f822b:	48 85 c0                                        	test   rax,rax
  9f822e:	74 10                                           	je     0x9f8240
  9f8230:	80 88 40 01 00 00 08                            	or     BYTE PTR [rax+0x140],0x8
  9f8237:	eb 15                                           	jmp    0x9f824e
  9f8239:	bb 01 00 00 00                                  	mov    ebx,0x1
  9f823e:	eb 1e                                           	jmp    0x9f825e
  9f8240:	48 8d 3d bb 47 93 00                            	lea    rdi,[rip+0x9347bb]        # 0x132ca02
  9f8247:	31 c0                                           	xor    eax,eax
  9f8249:	e8 c2 51 86 ff                                  	call   0x25d410
  9f824e:	48 8d 3d 6b 5d 1b 03                            	lea    rdi,[rip+0x31b5d6b]        # 0x3badfc0
  9f8255:	31 f6                                           	xor    esi,esi
  9f8257:	31 d2                                           	xor    edx,edx
  9f8259:	e8 52 42 25 00                                  	call   0xc4c4b0
  9f825e:	89 d8                                           	mov    eax,ebx
  9f8260:	5b                                              	pop    rbx
  9f8261:	41 5e                                           	pop    r14
  9f8263:	5d                                              	pop    rbp
  9f8264:	c3                                              	ret
  9f8265:	90                                              	nop
  9f8266:	90                                              	nop
  9f8267:	90                                              	nop
  9f8268:	90                                              	nop
  9f8269:	90                                              	nop
  9f826a:	90                                              	nop
  9f826b:	90                                              	nop
  9f826c:	90                                              	nop
  9f826d:	90                                              	nop
  9f826e:	90                                              	nop
  9f826f:	90                                              	nop
  9f8270:	55                                              	push   rbp
  9f8271:	48 89 e5                                        	mov    rbp,rsp
  9f8274:	48 85 ff                                        	test   rdi,rdi
  9f8277:	74 09                                           	je     0x9f8282
  9f8279:	48 8b 87 a0 05 00 00                            	mov    rax,QWORD PTR [rdi+0x5a0]
  9f8280:	5d                                              	pop    rbp
  9f8281:	c3                                              	ret
  9f8282:	31 c0                                           	xor    eax,eax
  9f8284:	5d                                              	pop    rbp
  9f8285:	c3                                              	ret
  9f8286:	90                                              	nop
  9f8287:	90                                              	nop
  9f8288:	90                                              	nop
  9f8289:	90                                              	nop
  9f828a:	90                                              	nop
  9f828b:	90                                              	nop
  9f828c:	90                                              	nop
  9f828d:	90                                              	nop
  9f828e:	90                                              	nop
  9f828f:	90                                              	nop
  9f8290:	55                                              	push   rbp
  9f8291:	48 89 e5                                        	mov    rbp,rsp
  9f8294:	41 57                                           	push   r15
  9f8296:	41 56                                           	push   r14
  9f8298:	41 55                                           	push   r13
  9f829a:	41 54                                           	push   r12
  9f829c:	53                                              	push   rbx
  9f829d:	48 81 ec c8 01 00 00                            	sub    rsp,0x1c8
  9f82a4:	4c 8d 25 65 40 f2 02                            	lea    r12,[rip+0x2f24065]        # 0x391c310
  9f82ab:	49 89 fe                                        	mov    r14,rdi
  9f82ae:	48 89 f3                                        	mov    rbx,rsi
  9f82b1:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  9f82b5:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9f82b9:	48 c7 85 50 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x1b0],0x0
  9f82c4:	c7 85 38 fe ff ff ff ff ff ff                   	mov    DWORD PTR [rbp-0x1c8],0xffffffff
  9f82ce:	48 8b bf 40 01 00 00                            	mov    rdi,QWORD PTR [rdi+0x140]
  9f82d5:	e8 c6 4d 87 ff                                  	call   0x26d0a0
  9f82da:	85 c0                                           	test   eax,eax
  9f82dc:	75 34                                           	jne    0x9f8312
  9f82de:	49 8b be 40 01 00 00                            	mov    rdi,QWORD PTR [r14+0x140]
  9f82e5:	e8 26 0e c1 ff                                  	call   0x609110
  9f82ea:	85 c0                                           	test   eax,eax
  9f82ec:	75 24                                           	jne    0x9f8312
  9f82ee:	49 8b be 40 01 00 00                            	mov    rdi,QWORD PTR [r14+0x140]
  9f82f5:	e8 d6 0d c1 ff                                  	call   0x6090d0
  9f82fa:	85 c0                                           	test   eax,eax
  9f82fc:	75 14                                           	jne    0x9f8312
  9f82fe:	49 8b be 40 01 00 00                            	mov    rdi,QWORD PTR [r14+0x140]
  9f8305:	e8 96 0d c1 ff                                  	call   0x6090a0
  9f830a:	85 c0                                           	test   eax,eax
  9f830c:	0f 84 5f 03 00 00                               	je     0x9f8671
  9f8312:	48 8b 1b                                        	mov    rbx,QWORD PTR [rbx]
  9f8315:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  9f831e:	48 8d 35 18 fc 99 00                            	lea    rsi,[rip+0x99fc18]        # 0x1397f3d
  9f8325:	31 d2                                           	xor    edx,edx
  9f8327:	e8 b4 20 22 00                                  	call   0xc1a3e0
  9f832c:	48 8d b5 58 fe ff ff                            	lea    rsi,[rbp-0x1a8]
  9f8333:	ba 78 01 00 00                                  	mov    edx,0x178
  9f8338:	48 89 df                                        	mov    rdi,rbx
  9f833b:	e8 40 0f 86 ff                                  	call   0x259280
  9f8340:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f8346:	85 c0                                           	test   eax,eax
  9f8348:	74 38                                           	je     0x9f8382
  9f834a:	48 8d 3d 5f a2 92 00                            	lea    rdi,[rip+0x92a25f]        # 0x13225b0
  9f8351:	31 c0                                           	xor    eax,eax
  9f8353:	e8 b8 50 86 ff                                  	call   0x25d410
  9f8358:	44 8b bd 3c fe ff ff                            	mov    r15d,DWORD PTR [rbp-0x1c4]
  9f835f:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  9f8363:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  9f8367:	0f 85 44 09 00 00                               	jne    0x9f8cb1
  9f836d:	44 89 f8                                        	mov    eax,r15d
  9f8370:	48 81 c4 c8 01 00 00                            	add    rsp,0x1c8
  9f8377:	5b                                              	pop    rbx
  9f8378:	41 5c                                           	pop    r12
  9f837a:	41 5d                                           	pop    r13
  9f837c:	41 5e                                           	pop    r14
  9f837e:	41 5f                                           	pop    r15
  9f8380:	5d                                              	pop    rbp
  9f8381:	c3                                              	ret
  9f8382:	48 83 bd 08 ff ff ff 00                         	cmp    QWORD PTR [rbp-0xf8],0x0
  9f838a:	74 6d                                           	je     0x9f83f9
  9f838c:	8b b5 a8 fe ff ff                               	mov    esi,DWORD PTR [rbp-0x158]
  9f8392:	48 8d 3d 2d 31 8a 00                            	lea    rdi,[rip+0x8a312d]        # 0x129b4c6
  9f8399:	31 c0                                           	xor    eax,eax
  9f839b:	e8 70 50 86 ff                                  	call   0x25d410
  9f83a0:	48 83 bd 08 ff ff ff 00                         	cmp    QWORD PTR [rbp-0xf8],0x0
  9f83a8:	8b 85 a8 fe ff ff                               	mov    eax,DWORD PTR [rbp-0x158]
  9f83ae:	0f 95 c1                                        	setne  cl
  9f83b1:	3d 00 0f 02 00                                  	cmp    eax,0x20f00
  9f83b6:	0f 94 c2                                        	sete   dl
  9f83b9:	08 ca                                           	or     dl,cl
  9f83bb:	80 fa 01                                        	cmp    dl,0x1
  9f83be:	75 4a                                           	jne    0x9f840a
  9f83c0:	48 8d bd 58 fe ff ff                            	lea    rdi,[rbp-0x1a8]
  9f83c7:	48 8d b5 38 fe ff ff                            	lea    rsi,[rbp-0x1c8]
  9f83ce:	48 8d 95 50 fe ff ff                            	lea    rdx,[rbp-0x1b0]
  9f83d5:	e8 06 09 00 00                                  	call   0x9f8ce0
  9f83da:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f83e0:	85 c0                                           	test   eax,eax
  9f83e2:	74 20                                           	je     0x9f8404
  9f83e4:	89 c6                                           	mov    esi,eax
  9f83e6:	48 8d 3d e6 fd 8f 00                            	lea    rdi,[rip+0x8ffde6]        # 0x12f81d3
  9f83ed:	31 c0                                           	xor    eax,eax
  9f83ef:	e8 1c 50 86 ff                                  	call   0x25d410
  9f83f4:	e9 5f ff ff ff                                  	jmp    0x9f8358
  9f83f9:	41 bf 16 00 00 00                               	mov    r15d,0x16
  9f83ff:	e9 5b ff ff ff                                  	jmp    0x9f835f
  9f8404:	8b 85 a8 fe ff ff                               	mov    eax,DWORD PTR [rbp-0x158]
  9f840a:	48 c7 85 48 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x1b8],0x0
  9f8415:	3d 00 00 00 01                                  	cmp    eax,0x1000000
  9f841a:	0f 82 b8 00 00 00                               	jb     0x9f84d8
  9f8420:	e8 fb f4 10 00                                  	call   0xb07920
  9f8425:	85 c0                                           	test   eax,eax
  9f8427:	74 37                                           	je     0x9f8460
  9f8429:	48 8b bd f8 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x108]
  9f8430:	48 8b b5 00 ff ff ff                            	mov    rsi,QWORD PTR [rbp-0x100]
  9f8437:	48 8d 95 48 fe ff ff                            	lea    rdx,[rbp-0x1b8]
  9f843e:	e8 4d 0e 00 00                                  	call   0x9f9290
  9f8443:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f8449:	85 c0                                           	test   eax,eax
  9f844b:	75 13                                           	jne    0x9f8460
  9f844d:	48 8b bd 50 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x1b0]
  9f8454:	48 8b b5 48 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x1b8]
  9f845b:	e8 a0 10 00 00                                  	call   0x9f9500
  9f8460:	48 8b 9d 08 ff ff ff                            	mov    rbx,QWORD PTR [rbp-0xf8]
  9f8467:	48 85 db                                        	test   rbx,rbx
  9f846a:	0f 84 a6 00 00 00                               	je     0x9f8516
  9f8470:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  9f8479:	48 8d 35 17 6e 95 00                            	lea    rsi,[rip+0x956e17]        # 0x134f297
  9f8480:	31 d2                                           	xor    edx,edx
  9f8482:	e8 59 1f 22 00                                  	call   0xc1a3e0
  9f8487:	48 8d bd 38 fe ff ff                            	lea    rdi,[rbp-0x1c8]
  9f848e:	ba 04 00 00 00                                  	mov    edx,0x4
  9f8493:	48 89 de                                        	mov    rsi,rbx
  9f8496:	e8 35 0d 86 ff                                  	call   0x2591d0
  9f849b:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f84a1:	85 c0                                           	test   eax,eax
  9f84a3:	74 71                                           	je     0x9f8516
  9f84a5:	48 8d 3d ae e8 95 00                            	lea    rdi,[rip+0x95e8ae]        # 0x1356d5a
  9f84ac:	31 c0                                           	xor    eax,eax
  9f84ae:	e8 5d 4f 86 ff                                  	call   0x25d410
  9f84b3:	8b bd 38 fe ff ff                               	mov    edi,DWORD PTR [rbp-0x1c8]
  9f84b9:	e8 a2 14 00 00                                  	call   0x9f9960
  9f84be:	48 8b bd 48 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x1b8]
  9f84c5:	48 85 ff                                        	test   rdi,rdi
  9f84c8:	0f 84 8a fe ff ff                               	je     0x9f8358
  9f84ce:	e8 ed 1c 16 00                                  	call   0xb5a1c0
  9f84d3:	e9 80 fe ff ff                                  	jmp    0x9f8358
  9f84d8:	48 8b bd f8 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x108]
  9f84df:	48 8b b5 00 ff ff ff                            	mov    rsi,QWORD PTR [rbp-0x100]
  9f84e6:	48 8d 95 48 fe ff ff                            	lea    rdx,[rbp-0x1b8]
  9f84ed:	e8 9e 0d 00 00                                  	call   0x9f9290
  9f84f2:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f84f8:	85 c0                                           	test   eax,eax
  9f84fa:	0f 84 e8 00 00 00                               	je     0x9f85e8
  9f8500:	48 83 bd 08 ff ff ff 00                         	cmp    QWORD PTR [rbp-0xf8],0x0
  9f8508:	0f 85 61 02 00 00                               	jne    0x9f876f
  9f850e:	41 89 c7                                        	mov    r15d,eax
  9f8511:	e9 49 fe ff ff                                  	jmp    0x9f835f
  9f8516:	48 8b bd 48 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x1b8]
  9f851d:	48 85 ff                                        	test   rdi,rdi
  9f8520:	74 05                                           	je     0x9f8527
  9f8522:	e8 99 1c 16 00                                  	call   0xb5a1c0
  9f8527:	48 8d 3d ba 5a 1b 03                            	lea    rdi,[rip+0x31b5aba]        # 0x3badfe8
  9f852e:	31 f6                                           	xor    esi,esi
  9f8530:	31 d2                                           	xor    edx,edx
  9f8532:	31 c9                                           	xor    ecx,ecx
  9f8534:	e8 e7 35 25 00                                  	call   0xc4bb20
  9f8539:	48 8d 3d b2 ef 87 00                            	lea    rdi,[rip+0x87efb2]        # 0x12774f2
  9f8540:	e8 9b 5d d4 ff                                  	call   0x73e2e0
  9f8545:	48 85 c0                                        	test   rax,rax
  9f8548:	0f 84 73 01 00 00                               	je     0x9f86c1
  9f854e:	48 89 c3                                        	mov    rbx,rax
  9f8551:	8b 40 0c                                        	mov    eax,DWORD PTR [rax+0xc]
  9f8554:	8d 48 01                                        	lea    ecx,[rax+0x1]
  9f8557:	89 4b 0c                                        	mov    DWORD PTR [rbx+0xc],ecx
  9f855a:	4c 8b 63 40                                     	mov    r12,QWORD PTR [rbx+0x40]
  9f855e:	4d 85 e4                                        	test   r12,r12
  9f8561:	0f 84 32 01 00 00                               	je     0x9f8699
  9f8567:	4c 8b bd 50 fe ff ff                            	mov    r15,QWORD PTR [rbp-0x1b0]
  9f856e:	4c 8d 73 28                                     	lea    r14,[rbx+0x28]
  9f8572:	eb 32                                           	jmp    0x9f85a6
  9f8574:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9f8580:	49 8b 7c 24 18                                  	mov    rdi,QWORD PTR [r12+0x18]
  9f8585:	4c 89 fe                                        	mov    rsi,r15
  9f8588:	41 ff d5                                        	call   r13
  9f858b:	4c 89 f7                                        	mov    rdi,r14
  9f858e:	31 f6                                           	xor    esi,esi
  9f8590:	31 d2                                           	xor    edx,edx
  9f8592:	31 c9                                           	xor    ecx,ecx
  9f8594:	e8 67 e4 ac ff                                  	call   0x4c6a00
  9f8599:	4d 8b 24 24                                     	mov    r12,QWORD PTR [r12]
  9f859d:	4d 85 e4                                        	test   r12,r12
  9f85a0:	0f 84 ee 00 00 00                               	je     0x9f8694
  9f85a6:	41 83 7c 24 10 ff                               	cmp    DWORD PTR [r12+0x10],0xffffffff
  9f85ac:	74 eb                                           	je     0x9f8599
  9f85ae:	4c 89 f7                                        	mov    rdi,r14
  9f85b1:	31 f6                                           	xor    esi,esi
  9f85b3:	31 d2                                           	xor    edx,edx
  9f85b5:	31 c9                                           	xor    ecx,ecx
  9f85b7:	e8 e4 e9 ac ff                                  	call   0x4c6fa0
  9f85bc:	4d 8b 6c 24 28                                  	mov    r13,QWORD PTR [r12+0x28]
  9f85c1:	48 8d 05 c0 f8 86 ff                            	lea    rax,[rip+0xffffffffff86f8c0]        # 0x267e88
  9f85c8:	4c 29 e8                                        	sub    rax,r13
  9f85cb:	48 c1 c8 03                                     	ror    rax,0x3
  9f85cf:	48 3d 97 01 00 00                               	cmp    rax,0x197
  9f85d5:	76 a9                                           	jbe    0x9f8580
  9f85d7:	48 8d 3d 32 b9 b6 01                            	lea    rdi,[rip+0x1b6b932]        # 0x2563f10
  9f85de:	4c 89 ee                                        	mov    rsi,r13
  9f85e1:	e8 da 72 a5 ff                                  	call   0x44f8c0
  9f85e6:	eb 98                                           	jmp    0x9f8580
  9f85e8:	e8 33 f3 10 00                                  	call   0xb07920
  9f85ed:	85 c0                                           	test   eax,eax
  9f85ef:	74 13                                           	je     0x9f8604
  9f85f1:	48 8b bd 50 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x1b0]
  9f85f8:	48 8b b5 48 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x1b8]
  9f85ff:	e8 fc 0e 00 00                                  	call   0x9f9500
  9f8604:	81 bd a8 fe ff ff 00 f0 00 00                   	cmp    DWORD PTR [rbp-0x158],0xf000
  9f860e:	75 28                                           	jne    0x9f8638
  9f8610:	80 bd a0 fe ff ff 00                            	cmp    BYTE PTR [rbp-0x160],0x0
  9f8617:	75 1f                                           	jne    0x9f8638
  9f8619:	48 8d 3d 71 e7 95 00                            	lea    rdi,[rip+0x95e771]        # 0x1356d91
  9f8620:	be 00 f0 00 00                                  	mov    esi,0xf000
  9f8625:	31 d2                                           	xor    edx,edx
  9f8627:	31 c0                                           	xor    eax,eax
  9f8629:	e8 e2 4d 86 ff                                  	call   0x25d410
  9f862e:	c7 85 a8 fe ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x158],0x0
  9f8638:	48 8b bd 20 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe0]
  9f863f:	48 83 ff ff                                     	cmp    rdi,0xffffffffffffffff
  9f8643:	0f 84 b3 00 00 00                               	je     0x9f86fc
  9f8649:	48 85 ff                                        	test   rdi,rdi
  9f864c:	0f 85 c0 00 00 00                               	jne    0x9f8712
  9f8652:	48 8b bd 48 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x1b8]
  9f8659:	48 8d b5 37 fe ff ff                            	lea    rsi,[rbp-0x1c9]
  9f8660:	48 8d 95 40 fe ff ff                            	lea    rdx,[rbp-0x1c0]
  9f8667:	e8 84 15 00 00                                  	call   0x9f9bf0
  9f866c:	e9 bb 00 00 00                                  	jmp    0x9f872c
  9f8671:	49 8b 46 08                                     	mov    rax,QWORD PTR [r14+0x8]
  9f8675:	48 8d 3d 09 c0 8c 00                            	lea    rdi,[rip+0x8cc009]        # 0x12c4685
  9f867c:	8b b0 bc 00 00 00                               	mov    esi,DWORD PTR [rax+0xbc]
  9f8682:	31 c0                                           	xor    eax,eax
  9f8684:	e8 87 4d 86 ff                                  	call   0x25d410
  9f8689:	41 bf 01 00 00 00                               	mov    r15d,0x1
  9f868f:	e9 cb fc ff ff                                  	jmp    0x9f835f
  9f8694:	8b 43 0c                                        	mov    eax,DWORD PTR [rbx+0xc]
  9f8697:	ff c8                                           	dec    eax
  9f8699:	89 43 0c                                        	mov    DWORD PTR [rbx+0xc],eax
  9f869c:	85 c0                                           	test   eax,eax
  9f869e:	75 08                                           	jne    0x9f86a8
  9f86a0:	48 89 df                                        	mov    rdi,rbx
  9f86a3:	e8 c8 5c d4 ff                                  	call   0x73e370
  9f86a8:	48 83 c3 28                                     	add    rbx,0x28
  9f86ac:	31 f6                                           	xor    esi,esi
  9f86ae:	31 d2                                           	xor    edx,edx
  9f86b0:	31 c9                                           	xor    ecx,ecx
  9f86b2:	48 89 df                                        	mov    rdi,rbx
  9f86b5:	e8 e6 e8 ac ff                                  	call   0x4c6fa0
  9f86ba:	4c 8d 25 4f 3c f2 02                            	lea    r12,[rip+0x2f23c4f]        # 0x391c310
  9f86c1:	48 8b 05 38 59 1b 03                            	mov    rax,QWORD PTR [rip+0x31b5938]        # 0x3bae000
  9f86c8:	48 8d 3d 19 59 1b 03                            	lea    rdi,[rip+0x31b5919]        # 0x3badfe8
  9f86cf:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9f86d8:	45 31 ff                                        	xor    r15d,r15d
  9f86db:	31 f6                                           	xor    esi,esi
  9f86dd:	31 d2                                           	xor    edx,edx
  9f86df:	48 83 e0 f1                                     	and    rax,0xfffffffffffffff1
  9f86e3:	48 39 c8                                        	cmp    rax,rcx
  9f86e6:	75 0a                                           	jne    0x9f86f2
  9f86e8:	e8 c3 3d 25 00                                  	call   0xc4c4b0
  9f86ed:	e9 6d fc ff ff                                  	jmp    0x9f835f
  9f86f2:	e8 09 3c 25 00                                  	call   0xc4c300
  9f86f7:	e9 63 fc ff ff                                  	jmp    0x9f835f
  9f86fc:	c6 85 37 fe ff ff 01                            	mov    BYTE PTR [rbp-0x1c9],0x1
  9f8703:	48 c7 85 40 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x1c0],0x0
  9f870e:	31 ff                                           	xor    edi,edi
  9f8710:	eb 15                                           	jmp    0x9f8727
  9f8712:	48 89 f8                                        	mov    rax,rdi
  9f8715:	c6 85 37 fe ff ff 01                            	mov    BYTE PTR [rbp-0x1c9],0x1
  9f871c:	48 c1 e0 14                                     	shl    rax,0x14
  9f8720:	48 89 85 40 fe ff ff                            	mov    QWORD PTR [rbp-0x1c0],rax
  9f8727:	e8 94 15 00 00                                  	call   0x9f9cc0
  9f872c:	4c 8b bd 48 fe ff ff                            	mov    r15,QWORD PTR [rbp-0x1b8]
  9f8733:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f8739:	85 c0                                           	test   eax,eax
  9f873b:	75 1c                                           	jne    0x9f8759
  9f873d:	48 8b 9d 50 fe ff ff                            	mov    rbx,QWORD PTR [rbp-0x1b0]
  9f8744:	4c 89 fe                                        	mov    rsi,r15
  9f8747:	48 89 df                                        	mov    rdi,rbx
  9f874a:	e8 01 16 00 00                                  	call   0x9f9d50
  9f874f:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f8755:	85 c0                                           	test   eax,eax
  9f8757:	74 26                                           	je     0x9f877f
  9f8759:	4c 89 ff                                        	mov    rdi,r15
  9f875c:	e8 5f 1a 16 00                                  	call   0xb5a1c0
  9f8761:	48 83 bd 08 ff ff ff 00                         	cmp    QWORD PTR [rbp-0xf8],0x0
  9f8769:	0f 84 e9 fb ff ff                               	je     0x9f8358
  9f876f:	8b bd 38 fe ff ff                               	mov    edi,DWORD PTR [rbp-0x1c8]
  9f8775:	e8 e6 11 00 00                                  	call   0x9f9960
  9f877a:	e9 d9 fb ff ff                                  	jmp    0x9f8358
  9f877f:	48 8d 3d 3a 58 1b 03                            	lea    rdi,[rip+0x31b583a]        # 0x3badfc0
  9f8786:	48 89 9d 28 fe ff ff                            	mov    QWORD PTR [rbp-0x1d8],rbx
  9f878d:	31 f6                                           	xor    esi,esi
  9f878f:	31 d2                                           	xor    edx,edx
  9f8791:	31 c9                                           	xor    ecx,ecx
  9f8793:	e8 88 33 25 00                                  	call   0xc4bb20
  9f8798:	65 48 8b 04 25 00 00 00 00                      	mov    rax,QWORD PTR gs:0x0
  9f87a1:	48 83 3d 37 58 1b 03 00                         	cmp    QWORD PTR [rip+0x31b5837],0x0        # 0x3badfe0
  9f87a9:	48 89 85 20 fe ff ff                            	mov    QWORD PTR [rbp-0x1e0],rax
  9f87b0:	48 89 05 51 58 1b 03                            	mov    QWORD PTR [rip+0x31b5851],rax        # 0x3bae008
  9f87b7:	0f 85 fb 04 00 00                               	jne    0x9f8cb8
  9f87bd:	48 8d 9d 68 fe ff ff                            	lea    rbx,[rbp-0x198]
  9f87c4:	48 8d 35 a6 88 89 00                            	lea    rsi,[rip+0x8988a6]        # 0x1291071
  9f87cb:	ba 0a 00 00 00                                  	mov    edx,0xa
  9f87d0:	48 89 df                                        	mov    rdi,rbx
  9f87d3:	e8 58 92 ed ff                                  	call   0x8d1a30
  9f87d8:	45 31 ed                                        	xor    r13d,r13d
  9f87db:	85 c0                                           	test   eax,eax
  9f87dd:	48 8d 35 f6 ab 87 00                            	lea    rsi,[rip+0x87abf6]        # 0x12733da
  9f87e4:	ba 0a 00 00 00                                  	mov    edx,0xa
  9f87e9:	48 89 df                                        	mov    rdi,rbx
  9f87ec:	41 0f 94 c5                                     	sete   r13b
  9f87f0:	e8 3b 92 ed ff                                  	call   0x8d1a30
  9f87f5:	49 8b be 40 01 00 00                            	mov    rdi,QWORD PTR [r14+0x140]
  9f87fc:	31 db                                           	xor    ebx,ebx
  9f87fe:	85 c0                                           	test   eax,eax
  9f8800:	89 85 30 fe ff ff                               	mov    DWORD PTR [rbp-0x1d0],eax
  9f8806:	0f 94 c3                                        	sete   bl
  9f8809:	e8 c2 08 c1 ff                                  	call   0x6090d0
  9f880e:	31 ff                                           	xor    edi,edi
  9f8810:	85 c0                                           	test   eax,eax
  9f8812:	48 8b 85 40 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x1c0]
  9f8819:	0f b6 95 a0 fe ff ff                            	movzx  edx,BYTE PTR [rbp-0x160]
  9f8820:	44 0f b6 8d 37 fe ff ff                         	movzx  r9d,BYTE PTR [rbp-0x1c9]
  9f8828:	89 de                                           	mov    esi,ebx
  9f882a:	44 89 e9                                        	mov    ecx,r13d
  9f882d:	40 0f 94 c7                                     	sete   dil
  9f8831:	45 31 c0                                        	xor    r8d,r8d
  9f8834:	81 bd a8 fe ff ff 00 0f 02 00                   	cmp    DWORD PTR [rbp-0x158],0x20f00
  9f883e:	48 89 04 24                                     	mov    QWORD PTR [rsp],rax
  9f8842:	41 0f 94 c0                                     	sete   r8b
  9f8846:	e8 c5 15 00 00                                  	call   0x9f9e10
  9f884b:	8b bd a8 fe ff ff                               	mov    edi,DWORD PTR [rbp-0x158]
  9f8851:	8b b5 38 fe ff ff                               	mov    esi,DWORD PTR [rbp-0x1c8]
  9f8857:	48 8b 95 28 fe ff ff                            	mov    rdx,QWORD PTR [rbp-0x1d8]
  9f885e:	4c 89 f9                                        	mov    rcx,r15
  9f8861:	e8 aa 19 00 00                                  	call   0x9fa210
  9f8866:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f886c:	85 c0                                           	test   eax,eax
  9f886e:	0f 85 50 01 00 00                               	jne    0x9f89c4
  9f8874:	83 bd 30 fe ff ff 00                            	cmp    DWORD PTR [rbp-0x1d0],0x0
  9f887b:	75 10                                           	jne    0x9f888d
  9f887d:	48 8b 05 5c 57 1b 03                            	mov    rax,QWORD PTR [rip+0x31b575c]        # 0x3badfe0
  9f8884:	66 81 88 40 01 00 00 80 00                      	or     WORD PTR [rax+0x140],0x80
  9f888d:	8b 8d 28 ff ff ff                               	mov    ecx,DWORD PTR [rbp-0xd8]
  9f8893:	b8 16 00 00 00                                  	mov    eax,0x16
  9f8898:	83 f9 10                                        	cmp    ecx,0x10
  9f889b:	76 0b                                           	jbe    0x9f88a8
  9f889d:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f88a3:	e9 1c 01 00 00                                  	jmp    0x9f89c4
  9f88a8:	48 8b 3d 31 57 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b5731]        # 0x3badfe0
  9f88af:	48 8d b5 50 ff ff ff                            	lea    rsi,[rbp-0xb0]
  9f88b6:	48 8d 95 2c ff ff ff                            	lea    rdx,[rbp-0xd4]
  9f88bd:	e8 0e b2 c5 ff                                  	call   0x653ad0
  9f88c2:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f88c8:	85 c0                                           	test   eax,eax
  9f88ca:	0f 85 f4 00 00 00                               	jne    0x9f89c4
  9f88d0:	48 8d 3d 62 d8 8d 00                            	lea    rdi,[rip+0x8dd862]        # 0x12d6139
  9f88d7:	e8 04 5a d4 ff                                  	call   0x73e2e0
  9f88dc:	48 85 c0                                        	test   rax,rax
  9f88df:	0f 84 b7 00 00 00                               	je     0x9f899c
  9f88e5:	49 89 c6                                        	mov    r14,rax
  9f88e8:	8b 40 0c                                        	mov    eax,DWORD PTR [rax+0xc]
  9f88eb:	8d 48 01                                        	lea    ecx,[rax+0x1]
  9f88ee:	41 89 4e 0c                                     	mov    DWORD PTR [r14+0xc],ecx
  9f88f2:	4d 8b 6e 40                                     	mov    r13,QWORD PTR [r14+0x40]
  9f88f6:	4d 85 ed                                        	test   r13,r13
  9f88f9:	74 7f                                           	je     0x9f897a
  9f88fb:	4d 8d 7e 28                                     	lea    r15,[r14+0x28]
  9f88ff:	4c 8d 25 3a fb 86 ff                            	lea    r12,[rip+0xffffffffff86fb3a]        # 0x268440
  9f8906:	eb 2b                                           	jmp    0x9f8933
  9f8908:	49 8b 7d 18                                     	mov    rdi,QWORD PTR [r13+0x18]
  9f890c:	48 8b 35 cd 56 1b 03                            	mov    rsi,QWORD PTR [rip+0x31b56cd]        # 0x3badfe0
  9f8913:	48 8d 95 3c fe ff ff                            	lea    rdx,[rbp-0x1c4]
  9f891a:	ff d3                                           	call   rbx
  9f891c:	4c 89 ff                                        	mov    rdi,r15
  9f891f:	31 f6                                           	xor    esi,esi
  9f8921:	31 d2                                           	xor    edx,edx
  9f8923:	31 c9                                           	xor    ecx,ecx
  9f8925:	e8 d6 e0 ac ff                                  	call   0x4c6a00
  9f892a:	4d 8b 6d 00                                     	mov    r13,QWORD PTR [r13+0x0]
  9f892e:	4d 85 ed                                        	test   r13,r13
  9f8931:	74 3a                                           	je     0x9f896d
  9f8933:	41 83 7d 10 ff                                  	cmp    DWORD PTR [r13+0x10],0xffffffff
  9f8938:	74 f0                                           	je     0x9f892a
  9f893a:	4c 89 ff                                        	mov    rdi,r15
  9f893d:	31 f6                                           	xor    esi,esi
  9f893f:	31 d2                                           	xor    edx,edx
  9f8941:	31 c9                                           	xor    ecx,ecx
  9f8943:	e8 58 e6 ac ff                                  	call   0x4c6fa0
  9f8948:	49 8b 5d 28                                     	mov    rbx,QWORD PTR [r13+0x28]
  9f894c:	4c 89 e0                                        	mov    rax,r12
  9f894f:	48 29 d8                                        	sub    rax,rbx
  9f8952:	48 c1 c8 03                                     	ror    rax,0x3
  9f8956:	48 83 f8 42                                     	cmp    rax,0x42
  9f895a:	76 ac                                           	jbe    0x9f8908
  9f895c:	48 8d 3d cd b5 b6 01                            	lea    rdi,[rip+0x1b6b5cd]        # 0x2563f30
  9f8963:	48 89 de                                        	mov    rsi,rbx
  9f8966:	e8 55 6f a5 ff                                  	call   0x44f8c0
  9f896b:	eb 9b                                           	jmp    0x9f8908
  9f896d:	41 8b 46 0c                                     	mov    eax,DWORD PTR [r14+0xc]
  9f8971:	4c 8d 25 98 39 f2 02                            	lea    r12,[rip+0x2f23998]        # 0x391c310
  9f8978:	ff c8                                           	dec    eax
  9f897a:	41 89 46 0c                                     	mov    DWORD PTR [r14+0xc],eax
  9f897e:	85 c0                                           	test   eax,eax
  9f8980:	75 08                                           	jne    0x9f898a
  9f8982:	4c 89 f7                                        	mov    rdi,r14
  9f8985:	e8 e6 59 d4 ff                                  	call   0x73e370
  9f898a:	49 83 c6 28                                     	add    r14,0x28
  9f898e:	31 f6                                           	xor    esi,esi
  9f8990:	31 d2                                           	xor    edx,edx
  9f8992:	31 c9                                           	xor    ecx,ecx
  9f8994:	4c 89 f7                                        	mov    rdi,r14
  9f8997:	e8 04 e6 ac ff                                  	call   0x4c6fa0
  9f899c:	83 bd 3c fe ff ff 00                            	cmp    DWORD PTR [rbp-0x1c4],0x0
  9f89a3:	75 1f                                           	jne    0x9f89c4
  9f89a5:	e8 e6 1c 00 00                                  	call   0x9fa690
  9f89aa:	48 8b bd 18 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe8]
  9f89b1:	e8 fa 1d 00 00                                  	call   0x9fa7b0
  9f89b6:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f89bc:	85 c0                                           	test   eax,eax
  9f89be:	0f 84 b5 01 00 00                               	je     0x9f8b79
  9f89c4:	48 8b 3d 15 56 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b5615]        # 0x3badfe0
  9f89cb:	48 85 ff                                        	test   rdi,rdi
  9f89ce:	74 21                                           	je     0x9f89f1
  9f89d0:	e8 0b 2b 00 00                                  	call   0x9fb4e0
  9f89d5:	83 bd 3c fe ff ff 00                            	cmp    DWORD PTR [rbp-0x1c4],0x0
  9f89dc:	0f 94 c1                                        	sete   cl
  9f89df:	85 c0                                           	test   eax,eax
  9f89e1:	0f 95 c2                                        	setne  dl
  9f89e4:	20 ca                                           	and    dl,cl
  9f89e6:	80 fa 01                                        	cmp    dl,0x1
  9f89e9:	75 06                                           	jne    0x9f89f1
  9f89eb:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f89f1:	e8 3a 30 00 00                                  	call   0x9fba30
  9f89f6:	48 8d 3d c3 55 1b 03                            	lea    rdi,[rip+0x31b55c3]        # 0x3badfc0
  9f89fd:	31 f6                                           	xor    esi,esi
  9f89ff:	31 d2                                           	xor    edx,edx
  9f8a01:	e8 aa 3a 25 00                                  	call   0xc4c4b0
  9f8a06:	44 8b bd 3c fe ff ff                            	mov    r15d,DWORD PTR [rbp-0x1c4]
  9f8a0d:	45 85 ff                                        	test   r15d,r15d
  9f8a10:	0f 85 19 01 00 00                               	jne    0x9f8b2f
  9f8a16:	48 8d 3d cb 55 1b 03                            	lea    rdi,[rip+0x31b55cb]        # 0x3badfe8
  9f8a1d:	31 f6                                           	xor    esi,esi
  9f8a1f:	31 d2                                           	xor    edx,edx
  9f8a21:	31 c9                                           	xor    ecx,ecx
  9f8a23:	e8 f8 30 25 00                                  	call   0xc4bb20
  9f8a28:	48 8d 3d c3 ea 87 00                            	lea    rdi,[rip+0x87eac3]        # 0x12774f2
  9f8a2f:	e8 ac 58 d4 ff                                  	call   0x73e2e0
  9f8a34:	48 85 c0                                        	test   rax,rax
  9f8a37:	0f 84 b5 00 00 00                               	je     0x9f8af2
  9f8a3d:	49 89 c6                                        	mov    r14,rax
  9f8a40:	8b 40 0c                                        	mov    eax,DWORD PTR [rax+0xc]
  9f8a43:	8d 48 01                                        	lea    ecx,[rax+0x1]
  9f8a46:	41 89 4e 0c                                     	mov    DWORD PTR [r14+0xc],ecx
  9f8a4a:	4d 8b 66 40                                     	mov    r12,QWORD PTR [r14+0x40]
  9f8a4e:	4d 85 e4                                        	test   r12,r12
  9f8a51:	74 76                                           	je     0x9f8ac9
  9f8a53:	4d 8d 7e 28                                     	lea    r15,[r14+0x28]
  9f8a57:	4c 8d 2d 2a f4 86 ff                            	lea    r13,[rip+0xffffffffff86f42a]        # 0x267e88
  9f8a5e:	eb 25                                           	jmp    0x9f8a85
  9f8a60:	49 8b 7c 24 18                                  	mov    rdi,QWORD PTR [r12+0x18]
  9f8a65:	48 8b b5 28 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x1d8]
  9f8a6c:	ff d3                                           	call   rbx
  9f8a6e:	4c 89 ff                                        	mov    rdi,r15
  9f8a71:	31 f6                                           	xor    esi,esi
  9f8a73:	31 d2                                           	xor    edx,edx
  9f8a75:	31 c9                                           	xor    ecx,ecx
  9f8a77:	e8 84 df ac ff                                  	call   0x4c6a00
  9f8a7c:	4d 8b 24 24                                     	mov    r12,QWORD PTR [r12]
  9f8a80:	4d 85 e4                                        	test   r12,r12
  9f8a83:	74 3e                                           	je     0x9f8ac3
  9f8a85:	41 83 7c 24 10 ff                               	cmp    DWORD PTR [r12+0x10],0xffffffff
  9f8a8b:	74 ef                                           	je     0x9f8a7c
  9f8a8d:	4c 89 ff                                        	mov    rdi,r15
  9f8a90:	31 f6                                           	xor    esi,esi
  9f8a92:	31 d2                                           	xor    edx,edx
  9f8a94:	31 c9                                           	xor    ecx,ecx
  9f8a96:	e8 05 e5 ac ff                                  	call   0x4c6fa0
  9f8a9b:	49 8b 5c 24 28                                  	mov    rbx,QWORD PTR [r12+0x28]
  9f8aa0:	4c 89 e8                                        	mov    rax,r13
  9f8aa3:	48 29 d8                                        	sub    rax,rbx
  9f8aa6:	48 c1 c8 03                                     	ror    rax,0x3
  9f8aaa:	48 3d 97 01 00 00                               	cmp    rax,0x197
  9f8ab0:	76 ae                                           	jbe    0x9f8a60
  9f8ab2:	48 8d 3d b7 b4 b6 01                            	lea    rdi,[rip+0x1b6b4b7]        # 0x2563f70
  9f8ab9:	48 89 de                                        	mov    rsi,rbx
  9f8abc:	e8 ff 6d a5 ff                                  	call   0x44f8c0
  9f8ac1:	eb 9d                                           	jmp    0x9f8a60
  9f8ac3:	41 8b 46 0c                                     	mov    eax,DWORD PTR [r14+0xc]
  9f8ac7:	ff c8                                           	dec    eax
  9f8ac9:	41 89 46 0c                                     	mov    DWORD PTR [r14+0xc],eax
  9f8acd:	85 c0                                           	test   eax,eax
  9f8acf:	75 08                                           	jne    0x9f8ad9
  9f8ad1:	4c 89 f7                                        	mov    rdi,r14
  9f8ad4:	e8 97 58 d4 ff                                  	call   0x73e370
  9f8ad9:	49 83 c6 28                                     	add    r14,0x28
  9f8add:	31 f6                                           	xor    esi,esi
  9f8adf:	31 d2                                           	xor    edx,edx
  9f8ae1:	31 c9                                           	xor    ecx,ecx
  9f8ae3:	4c 89 f7                                        	mov    rdi,r14
  9f8ae6:	e8 b5 e4 ac ff                                  	call   0x4c6fa0
  9f8aeb:	4c 8d 25 1e 38 f2 02                            	lea    r12,[rip+0x2f2381e]        # 0x391c310
  9f8af2:	48 8b 05 07 55 1b 03                            	mov    rax,QWORD PTR [rip+0x31b5507]        # 0x3bae000
  9f8af9:	48 83 e0 f1                                     	and    rax,0xfffffffffffffff1
  9f8afd:	48 3b 85 20 fe ff ff                            	cmp    rax,QWORD PTR [rbp-0x1e0]
  9f8b04:	75 12                                           	jne    0x9f8b18
  9f8b06:	48 8d 3d db 54 1b 03                            	lea    rdi,[rip+0x31b54db]        # 0x3badfe8
  9f8b0d:	31 f6                                           	xor    esi,esi
  9f8b0f:	31 d2                                           	xor    edx,edx
  9f8b11:	e8 9a 39 25 00                                  	call   0xc4c4b0
  9f8b16:	eb 10                                           	jmp    0x9f8b28
  9f8b18:	48 8d 3d c9 54 1b 03                            	lea    rdi,[rip+0x31b54c9]        # 0x3badfe8
  9f8b1f:	31 f6                                           	xor    esi,esi
  9f8b21:	31 d2                                           	xor    edx,edx
  9f8b23:	e8 d8 37 25 00                                  	call   0xc4c300
  9f8b28:	44 8b bd 3c fe ff ff                            	mov    r15d,DWORD PTR [rbp-0x1c4]
  9f8b2f:	48 8b b5 08 ff ff ff                            	mov    rsi,QWORD PTR [rbp-0xf8]
  9f8b36:	48 85 f6                                        	test   rsi,rsi
  9f8b39:	0f 84 20 f8 ff ff                               	je     0x9f835f
  9f8b3f:	45 85 ff                                        	test   r15d,r15d
  9f8b42:	0f 85 27 fc ff ff                               	jne    0x9f876f
  9f8b48:	48 8d bd 38 fe ff ff                            	lea    rdi,[rbp-0x1c8]
  9f8b4f:	e8 cc 0d 00 00                                  	call   0x9f9920
  9f8b54:	89 85 3c fe ff ff                               	mov    DWORD PTR [rbp-0x1c4],eax
  9f8b5a:	85 c0                                           	test   eax,eax
  9f8b5c:	74 13                                           	je     0x9f8b71
  9f8b5e:	48 8d 3d f5 e1 95 00                            	lea    rdi,[rip+0x95e1f5]        # 0x1356d5a
  9f8b65:	31 c0                                           	xor    eax,eax
  9f8b67:	e8 a4 48 86 ff                                  	call   0x25d410
  9f8b6c:	e9 fe fb ff ff                                  	jmp    0x9f876f
  9f8b71:	45 31 ff                                        	xor    r15d,r15d
  9f8b74:	e9 e6 f7 ff ff                                  	jmp    0x9f835f
  9f8b79:	48 8b 05 60 54 1b 03                            	mov    rax,QWORD PTR [rip+0x31b5460]        # 0x3badfe0
  9f8b80:	8b b8 24 01 00 00                               	mov    edi,DWORD PTR [rax+0x124]
  9f8b86:	e8 b5 e1 c1 ff                                  	call   0x616d40
  9f8b8b:	84 c0                                           	test   al,al
  9f8b8d:	0f 84 a1 00 00 00                               	je     0x9f8c34
  9f8b93:	48 8d 3d 22 29 94 00                            	lea    rdi,[rip+0x942922]        # 0x133b4bc
  9f8b9a:	e8 41 57 d4 ff                                  	call   0x73e2e0
  9f8b9f:	48 85 c0                                        	test   rax,rax
  9f8ba2:	0f 84 e0 00 00 00                               	je     0x9f8c88
  9f8ba8:	49 89 c6                                        	mov    r14,rax
  9f8bab:	8b 40 0c                                        	mov    eax,DWORD PTR [rax+0xc]
  9f8bae:	8d 48 01                                        	lea    ecx,[rax+0x1]
  9f8bb1:	41 89 4e 0c                                     	mov    DWORD PTR [r14+0xc],ecx
  9f8bb5:	4d 8b 6e 40                                     	mov    r13,QWORD PTR [r14+0x40]
  9f8bb9:	4d 85 ed                                        	test   r13,r13
  9f8bbc:	0f 84 a4 00 00 00                               	je     0x9f8c66
  9f8bc2:	4d 8d 7e 28                                     	lea    r15,[r14+0x28]
  9f8bc6:	4c 8d 25 73 f8 86 ff                            	lea    r12,[rip+0xffffffffff86f873]        # 0x268440
  9f8bcd:	eb 2b                                           	jmp    0x9f8bfa
  9f8bcf:	49 8b 7d 18                                     	mov    rdi,QWORD PTR [r13+0x18]
  9f8bd3:	48 8b 35 06 54 1b 03                            	mov    rsi,QWORD PTR [rip+0x31b5406]        # 0x3badfe0
  9f8bda:	48 8d 95 3c fe ff ff                            	lea    rdx,[rbp-0x1c4]
  9f8be1:	ff d3                                           	call   rbx
  9f8be3:	4c 89 ff                                        	mov    rdi,r15
  9f8be6:	31 f6                                           	xor    esi,esi
  9f8be8:	31 d2                                           	xor    edx,edx
  9f8bea:	31 c9                                           	xor    ecx,ecx
  9f8bec:	e8 0f de ac ff                                  	call   0x4c6a00
  9f8bf1:	4d 8b 6d 00                                     	mov    r13,QWORD PTR [r13+0x0]
  9f8bf5:	4d 85 ed                                        	test   r13,r13
  9f8bf8:	74 66                                           	je     0x9f8c60
  9f8bfa:	41 83 7d 10 ff                                  	cmp    DWORD PTR [r13+0x10],0xffffffff
  9f8bff:	74 f0                                           	je     0x9f8bf1
  9f8c01:	4c 89 ff                                        	mov    rdi,r15
  9f8c04:	31 f6                                           	xor    esi,esi
  9f8c06:	31 d2                                           	xor    edx,edx
  9f8c08:	31 c9                                           	xor    ecx,ecx
  9f8c0a:	e8 91 e3 ac ff                                  	call   0x4c6fa0
  9f8c0f:	49 8b 5d 28                                     	mov    rbx,QWORD PTR [r13+0x28]
  9f8c13:	4c 89 e0                                        	mov    rax,r12
  9f8c16:	48 29 d8                                        	sub    rax,rbx
  9f8c19:	48 c1 c8 03                                     	ror    rax,0x3
  9f8c1d:	48 83 f8 42                                     	cmp    rax,0x42
  9f8c21:	76 ac                                           	jbe    0x9f8bcf
  9f8c23:	48 8d 3d 26 b3 b6 01                            	lea    rdi,[rip+0x1b6b326]        # 0x2563f50
  9f8c2a:	48 89 de                                        	mov    rsi,rbx
  9f8c2d:	e8 8e 6c a5 ff                                  	call   0x44f8c0
  9f8c32:	eb 9b                                           	jmp    0x9f8bcf
  9f8c34:	48 8b 05 a5 53 1b 03                            	mov    rax,QWORD PTR [rip+0x31b53a5]        # 0x3badfe0
  9f8c3b:	48 8d 3d e4 9e 90 00                            	lea    rdi,[rip+0x909ee4]        # 0x1302b26
  9f8c42:	8b b0 24 01 00 00                               	mov    esi,DWORD PTR [rax+0x124]
  9f8c48:	31 c0                                           	xor    eax,eax
  9f8c4a:	e8 c1 47 86 ff                                  	call   0x25d410
  9f8c4f:	4c 8d 25 ba 36 f2 02                            	lea    r12,[rip+0x2f236ba]        # 0x391c310
  9f8c56:	b8 58 00 00 00                                  	mov    eax,0x58
  9f8c5b:	e9 3d fc ff ff                                  	jmp    0x9f889d
  9f8c60:	41 8b 46 0c                                     	mov    eax,DWORD PTR [r14+0xc]
  9f8c64:	ff c8                                           	dec    eax
  9f8c66:	41 89 46 0c                                     	mov    DWORD PTR [r14+0xc],eax
  9f8c6a:	85 c0                                           	test   eax,eax
  9f8c6c:	75 08                                           	jne    0x9f8c76
  9f8c6e:	4c 89 f7                                        	mov    rdi,r14
  9f8c71:	e8 fa 56 d4 ff                                  	call   0x73e370
  9f8c76:	49 83 c6 28                                     	add    r14,0x28
  9f8c7a:	31 f6                                           	xor    esi,esi
  9f8c7c:	31 d2                                           	xor    edx,edx
  9f8c7e:	31 c9                                           	xor    ecx,ecx
  9f8c80:	4c 89 f7                                        	mov    rdi,r14
  9f8c83:	e8 18 e3 ac ff                                  	call   0x4c6fa0
  9f8c88:	48 8b 05 51 53 1b 03                            	mov    rax,QWORD PTR [rip+0x31b5351]        # 0x3badfe0
  9f8c8f:	4c 8d 25 7a 36 f2 02                            	lea    r12,[rip+0x2f2367a]        # 0x391c310
  9f8c96:	66 81 88 40 01 00 00 00 02                      	or     WORD PTR [rax+0x140],0x200
  9f8c9f:	83 bd 3c fe ff ff 00                            	cmp    DWORD PTR [rbp-0x1c4],0x0
  9f8ca6:	0f 85 18 fd ff ff                               	jne    0x9f89c4
  9f8cac:	e9 45 fd ff ff                                  	jmp    0x9f89f6
  9f8cb1:	e8 fa 49 d0 ff                                  	call   0x6fd6b0
  9f8cb6:	0f 0b                                           	ud2
  9f8cb8:	e8 93 8c df ff                                  	call   0x7f1950
  9f8cbd:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x9f8cb8
  9f8cc4:	e8 47 8b df ff                                  	call   0x7f1810
  9f8cc9:	48 8d 35 2e 22 99 00                            	lea    rsi,[rip+0x99222e]        # 0x138aefe
  9f8cd0:	bf aa 00 00 00                                  	mov    edi,0xaa
  9f8cd5:	31 c0                                           	xor    eax,eax
  9f8cd7:	e8 34 1d 2a 00                                  	call   0xc9aa10
  9f8cdc:	0f 0b                                           	ud2
  9f8cde:	90                                              	nop
  9f8cdf:	90                                              	nop
  9f8ce0:	55                                              	push   rbp
  9f8ce1:	48 89 e5                                        	mov    rbp,rsp
  9f8ce4:	41 57                                           	push   r15
  9f8ce6:	41 56                                           	push   r14
  9f8ce8:	41 55                                           	push   r13
  9f8cea:	41 54                                           	push   r12
  9f8cec:	53                                              	push   rbx
  9f8ced:	48 83 ec 28                                     	sub    rsp,0x28
  9f8cf1:	48 8d 05 18 36 f2 02                            	lea    rax,[rip+0x2f23618]        # 0x391c310
  9f8cf8:	48 89 55 b8                                     	mov    QWORD PTR [rbp-0x48],rdx
  9f8cfc:	48 89 75 b0                                     	mov    QWORD PTR [rbp-0x50],rsi
  9f8d00:	49 89 fd                                        	mov    r13,rdi
  9f8d03:	48 8d 35 46 b0 b6 01                            	lea    rsi,[rip+0x1b6b046]        # 0x2563d50
  9f8d0a:	bf c0 05 00 00                                  	mov    edi,0x5c0
  9f8d0f:	ba 02 01 00 00                                  	mov    edx,0x102
  9f8d14:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  9f8d17:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9f8d1b:	e8 30 fe 20 00                                  	call   0xc08b50
  9f8d20:	48 8d 78 10                                     	lea    rdi,[rax+0x10]
  9f8d24:	ba 98 00 00 00                                  	mov    edx,0x98
  9f8d29:	4c 89 ee                                        	mov    rsi,r13
  9f8d2c:	48 89 c3                                        	mov    rbx,rax
  9f8d2f:	e8 7c 03 86 ff                                  	call   0x2590b0
  9f8d34:	41 81 7d 50 ff ff ff 00                         	cmp    DWORD PTR [r13+0x50],0xffffff
  9f8d3c:	76 08                                           	jbe    0x9f8d46
  9f8d3e:	45 31 ff                                        	xor    r15d,r15d
  9f8d41:	45 31 f6                                        	xor    r14d,r14d
  9f8d44:	eb 3e                                           	jmp    0x9f8d84
  9f8d46:	48 8d 35 03 b0 b6 01                            	lea    rsi,[rip+0x1b6b003]        # 0x2563d50
  9f8d4d:	bf 00 32 00 00                                  	mov    edi,0x3200
  9f8d52:	ba 02 01 00 00                                  	mov    edx,0x102
  9f8d57:	e8 f4 fd 20 00                                  	call   0xc08b50
  9f8d5c:	41 83 7d 50 00                                  	cmp    DWORD PTR [r13+0x50],0x0
  9f8d61:	49 89 c7                                        	mov    r15,rax
  9f8d64:	74 05                                           	je     0x9f8d6b
  9f8d66:	45 31 f6                                        	xor    r14d,r14d
  9f8d69:	eb 19                                           	jmp    0x9f8d84
  9f8d6b:	48 8d 35 de af b6 01                            	lea    rsi,[rip+0x1b6afde]        # 0x2563d50
  9f8d72:	bf 90 01 00 00                                  	mov    edi,0x190
  9f8d77:	ba 02 01 00 00                                  	mov    edx,0x102
  9f8d7c:	e8 cf fd 20 00                                  	call   0xc08b50
  9f8d81:	49 89 c6                                        	mov    r14,rax
  9f8d84:	48 8b 3d 35 b0 b6 01                            	mov    rdi,QWORD PTR [rip+0x1b6b035]        # 0x2563dc0
  9f8d8b:	48 8d 75 c8                                     	lea    rsi,[rbp-0x38]
  9f8d8f:	e8 4c 0b 9a ff                                  	call   0x3998e0
  9f8d94:	83 f8 ff                                        	cmp    eax,0xffffffff
  9f8d97:	74 50                                           	je     0x9f8de9
  9f8d99:	48 8d 3d 48 52 1b 03                            	lea    rdi,[rip+0x31b5248]        # 0x3badfe8
  9f8da0:	41 89 c4                                        	mov    r12d,eax
  9f8da3:	31 f6                                           	xor    esi,esi
  9f8da5:	31 d2                                           	xor    edx,edx
  9f8da7:	31 c9                                           	xor    ecx,ecx
  9f8da9:	e8 72 2d 25 00                                  	call   0xc4bb20
  9f8dae:	83 3d 6b 52 1b 03 20                            	cmp    DWORD PTR [rip+0x31b526b],0x20        # 0x3bae020
  9f8db5:	72 74                                           	jb     0x9f8e2b
  9f8db7:	48 8b 05 42 52 1b 03                            	mov    rax,QWORD PTR [rip+0x31b5242]        # 0x3bae000
  9f8dbe:	48 8d 3d 23 52 1b 03                            	lea    rdi,[rip+0x31b5223]        # 0x3badfe8
  9f8dc5:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9f8dce:	31 f6                                           	xor    esi,esi
  9f8dd0:	31 d2                                           	xor    edx,edx
  9f8dd2:	48 83 e0 f1                                     	and    rax,0xfffffffffffffff1
  9f8dd6:	48 39 c8                                        	cmp    rax,rcx
  9f8dd9:	0f 85 af 00 00 00                               	jne    0x9f8e8e
  9f8ddf:	e8 cc 36 25 00                                  	call   0xc4c4b0
  9f8de4:	e9 aa 00 00 00                                  	jmp    0x9f8e93
  9f8de9:	4d 85 ff                                        	test   r15,r15
  9f8dec:	74 0f                                           	je     0x9f8dfd
  9f8dee:	48 8d 35 5b af b6 01                            	lea    rsi,[rip+0x1b6af5b]        # 0x2563d50
  9f8df5:	4c 89 ff                                        	mov    rdi,r15
  9f8df8:	e8 f3 ff 20 00                                  	call   0xc08df0
  9f8dfd:	4d 85 f6                                        	test   r14,r14
  9f8e00:	74 0f                                           	je     0x9f8e11
  9f8e02:	48 8d 35 47 af b6 01                            	lea    rsi,[rip+0x1b6af47]        # 0x2563d50
  9f8e09:	4c 89 f7                                        	mov    rdi,r14
  9f8e0c:	e8 df ff 20 00                                  	call   0xc08df0
  9f8e11:	48 8d 35 38 af b6 01                            	lea    rsi,[rip+0x1b6af38]        # 0x2563d50
  9f8e18:	48 89 df                                        	mov    rdi,rbx
  9f8e1b:	e8 d0 ff 20 00                                  	call   0xc08df0
  9f8e20:	41 be 23 00 00 00                               	mov    r14d,0x23
  9f8e26:	e9 0f 04 00 00                                  	jmp    0x9f923a
  9f8e2b:	41 8b 45 50                                     	mov    eax,DWORD PTR [r13+0x50]
  9f8e2f:	3d ff ff ff 00                                  	cmp    eax,0xffffff
  9f8e34:	0f 86 cb 00 00 00                               	jbe    0x9f8f05
  9f8e3a:	3d 00 01 00 02                                  	cmp    eax,0x2000100
  9f8e3f:	0f 85 6f 02 00 00                               	jne    0x9f90b4
  9f8e45:	44 89 e7                                        	mov    edi,r12d
  9f8e48:	4c 89 75 c0                                     	mov    QWORD PTR [rbp-0x40],r14
  9f8e4c:	e8 ef cc ba ff                                  	call   0x5a5b40
  9f8e51:	85 c0                                           	test   eax,eax
  9f8e53:	0f 84 53 02 00 00                               	je     0x9f90ac
  9f8e59:	4c 8b 05 a0 51 1b 03                            	mov    r8,QWORD PTR [rip+0x31b51a0]        # 0x3bae000
  9f8e60:	41 89 c6                                        	mov    r14d,eax
  9f8e63:	48 8d 3d 7e 51 1b 03                            	lea    rdi,[rip+0x31b517e]        # 0x3badfe8
  9f8e6a:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9f8e73:	31 f6                                           	xor    esi,esi
  9f8e75:	31 d2                                           	xor    edx,edx
  9f8e77:	49 83 e0 f1                                     	and    r8,0xfffffffffffffff1
  9f8e7b:	49 39 c8                                        	cmp    r8,rcx
  9f8e7e:	0f 85 af 01 00 00                               	jne    0x9f9033
  9f8e84:	e8 27 36 25 00                                  	call   0xc4c4b0
  9f8e89:	e9 aa 01 00 00                                  	jmp    0x9f9038
  9f8e8e:	e8 6d 34 25 00                                  	call   0xc4c300
  9f8e93:	48 8b 3d 26 af b6 01                            	mov    rdi,QWORD PTR [rip+0x1b6af26]        # 0x2563dc0
  9f8e9a:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  9f8e9e:	44 89 e6                                        	mov    esi,r12d
  9f8ea1:	e8 8a 0f 9a ff                                  	call   0x399e30
  9f8ea6:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  9f8eaa:	e8 01 10 9a ff                                  	call   0x399eb0
  9f8eaf:	4d 85 ff                                        	test   r15,r15
  9f8eb2:	74 0f                                           	je     0x9f8ec3
  9f8eb4:	48 8d 35 95 ae b6 01                            	lea    rsi,[rip+0x1b6ae95]        # 0x2563d50
  9f8ebb:	4c 89 ff                                        	mov    rdi,r15
  9f8ebe:	e8 2d ff 20 00                                  	call   0xc08df0
  9f8ec3:	4d 85 f6                                        	test   r14,r14
  9f8ec6:	74 0f                                           	je     0x9f8ed7
  9f8ec8:	48 8d 35 81 ae b6 01                            	lea    rsi,[rip+0x1b6ae81]        # 0x2563d50
  9f8ecf:	4c 89 f7                                        	mov    rdi,r14
  9f8ed2:	e8 19 ff 20 00                                  	call   0xc08df0
  9f8ed7:	48 8d 35 72 ae b6 01                            	lea    rsi,[rip+0x1b6ae72]        # 0x2563d50
  9f8ede:	48 89 df                                        	mov    rdi,rbx
  9f8ee1:	e8 0a ff 20 00                                  	call   0xc08df0
  9f8ee6:	8b 35 34 51 1b 03                               	mov    esi,DWORD PTR [rip+0x31b5134]        # 0x3bae020
  9f8eec:	48 8d 3d 6c dc 93 00                            	lea    rdi,[rip+0x93dc6c]        # 0x1336b5f
  9f8ef3:	31 c0                                           	xor    eax,eax
  9f8ef5:	e8 16 45 86 ff                                  	call   0x25d410
  9f8efa:	41 be 23 00 00 00                               	mov    r14d,0x23
  9f8f00:	e9 35 03 00 00                                  	jmp    0x9f923a
  9f8f05:	8b 15 31 b2 1b 03                               	mov    edx,DWORD PTR [rip+0x31bb231]        # 0x3bb413c
  9f8f0b:	0f b6 35 26 b2 1b 03                            	movzx  esi,BYTE PTR [rip+0x31bb226]        # 0x3bb4138
  9f8f12:	85 d2                                           	test   edx,edx
  9f8f14:	0f 95 c0                                        	setne  al
  9f8f17:	40 08 f0                                        	or     al,sil
  9f8f1a:	74 27                                           	je     0x9f8f43
  9f8f1c:	48 8d 3d f2 20 99 00                            	lea    rdi,[rip+0x9920f2]        # 0x138b015
  9f8f23:	31 c0                                           	xor    eax,eax
  9f8f25:	e8 e6 44 86 ff                                  	call   0x25d410
  9f8f2a:	48 8b 05 cf 50 1b 03                            	mov    rax,QWORD PTR [rip+0x31b50cf]        # 0x3bae000
  9f8f31:	48 8d 3d b0 50 1b 03                            	lea    rdi,[rip+0x31b50b0]        # 0x3badfe8
  9f8f38:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9f8f41:	eb 56                                           	jmp    0x9f8f99
  9f8f43:	48 8b 05 c6 50 1b 03                            	mov    rax,QWORD PTR [rip+0x31b50c6]        # 0x3bae010
  9f8f4a:	eb 0c                                           	jmp    0x9f8f58
  9f8f4c:	83 b8 b4 00 00 00 01                            	cmp    DWORD PTR [rax+0xb4],0x1
  9f8f53:	74 2d                                           	je     0x9f8f82
  9f8f55:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  9f8f58:	48 85 c0                                        	test   rax,rax
  9f8f5b:	0f 84 af 00 00 00                               	je     0x9f9010
  9f8f61:	81 78 60 ff ff ff 00                            	cmp    DWORD PTR [rax+0x60],0xffffff
  9f8f68:	77 eb                                           	ja     0x9f8f55
  9f8f6a:	8b 88 b0 00 00 00                               	mov    ecx,DWORD PTR [rax+0xb0]
  9f8f70:	83 f9 02                                        	cmp    ecx,0x2
  9f8f73:	74 d7                                           	je     0x9f8f4c
  9f8f75:	8d 51 fd                                        	lea    edx,[rcx-0x3]
  9f8f78:	83 fa 03                                        	cmp    edx,0x3
  9f8f7b:	72 05                                           	jb     0x9f8f82
  9f8f7d:	83 f9 01                                        	cmp    ecx,0x1
  9f8f80:	75 d3                                           	jne    0x9f8f55
  9f8f82:	48 8b 05 77 50 1b 03                            	mov    rax,QWORD PTR [rip+0x31b5077]        # 0x3bae000
  9f8f89:	48 8d 3d 58 50 1b 03                            	lea    rdi,[rip+0x31b5058]        # 0x3badfe8
  9f8f90:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9f8f99:	31 f6                                           	xor    esi,esi
  9f8f9b:	31 d2                                           	xor    edx,edx
  9f8f9d:	48 83 e0 f1                                     	and    rax,0xfffffffffffffff1
  9f8fa1:	48 39 c8                                        	cmp    rax,rcx
  9f8fa4:	75 07                                           	jne    0x9f8fad
  9f8fa6:	e8 05 35 25 00                                  	call   0xc4c4b0
  9f8fab:	eb 05                                           	jmp    0x9f8fb2
  9f8fad:	e8 4e 33 25 00                                  	call   0xc4c300
  9f8fb2:	48 8b 3d 07 ae b6 01                            	mov    rdi,QWORD PTR [rip+0x1b6ae07]        # 0x2563dc0
  9f8fb9:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  9f8fbd:	44 89 e6                                        	mov    esi,r12d
  9f8fc0:	e8 6b 0e 9a ff                                  	call   0x399e30
  9f8fc5:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  9f8fc9:	e8 e2 0e 9a ff                                  	call   0x399eb0
  9f8fce:	4d 85 ff                                        	test   r15,r15
  9f8fd1:	74 0f                                           	je     0x9f8fe2
  9f8fd3:	48 8d 35 76 ad b6 01                            	lea    rsi,[rip+0x1b6ad76]        # 0x2563d50
  9f8fda:	4c 89 ff                                        	mov    rdi,r15
  9f8fdd:	e8 0e fe 20 00                                  	call   0xc08df0
  9f8fe2:	4d 85 f6                                        	test   r14,r14
  9f8fe5:	74 0f                                           	je     0x9f8ff6
  9f8fe7:	48 8d 35 62 ad b6 01                            	lea    rsi,[rip+0x1b6ad62]        # 0x2563d50
  9f8fee:	4c 89 f7                                        	mov    rdi,r14
  9f8ff1:	e8 fa fd 20 00                                  	call   0xc08df0
  9f8ff6:	48 8d 35 53 ad b6 01                            	lea    rsi,[rip+0x1b6ad53]        # 0x2563d50
  9f8ffd:	48 89 df                                        	mov    rdi,rbx
  9f9000:	e8 eb fd 20 00                                  	call   0xc08df0
  9f9005:	41 be 10 00 00 00                               	mov    r14d,0x10
  9f900b:	e9 2a 02 00 00                                  	jmp    0x9f923a
  9f9010:	83 3d 1d 50 1b 03 ff                            	cmp    DWORD PTR [rip+0x31b501d],0xffffffff        # 0x3bae034
  9f9017:	4c 89 75 c0                                     	mov    QWORD PTR [rbp-0x40],r14
  9f901b:	74 74                                           	je     0x9f9091
  9f901d:	83 3d 18 50 1b 03 ff                            	cmp    DWORD PTR [rip+0x31b5018],0xffffffff        # 0x3bae03c
  9f9024:	0f 85 82 00 00 00                               	jne    0x9f90ac
  9f902a:	48 8d 05 07 50 1b 03                            	lea    rax,[rip+0x31b5007]        # 0x3bae038
  9f9031:	eb 65                                           	jmp    0x9f9098
  9f9033:	e8 c8 32 25 00                                  	call   0xc4c300
  9f9038:	48 8b 3d 81 ad b6 01                            	mov    rdi,QWORD PTR [rip+0x1b6ad81]        # 0x2563dc0
  9f903f:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  9f9043:	44 89 e6                                        	mov    esi,r12d
  9f9046:	e8 e5 0d 9a ff                                  	call   0x399e30
  9f904b:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  9f904f:	e8 5c 0e 9a ff                                  	call   0x399eb0
  9f9054:	4d 85 ff                                        	test   r15,r15
  9f9057:	74 0f                                           	je     0x9f9068
  9f9059:	48 8d 35 f0 ac b6 01                            	lea    rsi,[rip+0x1b6acf0]        # 0x2563d50
  9f9060:	4c 89 ff                                        	mov    rdi,r15
  9f9063:	e8 88 fd 20 00                                  	call   0xc08df0
  9f9068:	48 8b 7d c0                                     	mov    rdi,QWORD PTR [rbp-0x40]
  9f906c:	48 85 ff                                        	test   rdi,rdi
  9f906f:	74 0c                                           	je     0x9f907d
  9f9071:	48 8d 35 d8 ac b6 01                            	lea    rsi,[rip+0x1b6acd8]        # 0x2563d50
  9f9078:	e8 73 fd 20 00                                  	call   0xc08df0
  9f907d:	48 8d 35 cc ac b6 01                            	lea    rsi,[rip+0x1b6accc]        # 0x2563d50
  9f9084:	48 89 df                                        	mov    rdi,rbx
  9f9087:	e8 64 fd 20 00                                  	call   0xc08df0
  9f908c:	e9 a9 01 00 00                                  	jmp    0x9f923a
  9f9091:	48 8d 05 98 4f 1b 03                            	lea    rax,[rip+0x31b4f98]        # 0x3bae030
  9f9098:	44 89 60 04                                     	mov    DWORD PTR [rax+0x4],r12d
  9f909c:	0f b7 38                                        	movzx  edi,WORD PTR [rax]
  9f909f:	e8 dc 16 e6 ff                                  	call   0x85a780
  9f90a4:	85 c0                                           	test   eax,eax
  9f90a6:	0f 85 b7 01 00 00                               	jne    0x9f9263
  9f90ac:	41 8b 45 50                                     	mov    eax,DWORD PTR [r13+0x50]
  9f90b0:	4c 8b 75 c0                                     	mov    r14,QWORD PTR [rbp-0x40]
  9f90b4:	b9 00 00 60 00                                  	mov    ecx,0x600000
  9f90b9:	3d 00 03 01 00                                  	cmp    eax,0x10300
  9f90be:	74 28                                           	je     0x9f90e8
  9f90c0:	3d 00 00 01 00                                  	cmp    eax,0x10000
  9f90c5:	74 21                                           	je     0x9f90e8
  9f90c7:	85 c0                                           	test   eax,eax
  9f90c9:	75 18                                           	jne    0x9f90e3
  9f90cb:	48 c7 83 a8 05 00 00 00 00 f0 00                	mov    QWORD PTR [rbx+0x5a8],0xf00000
  9f90d6:	48 c7 83 b0 05 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x5b0],0x0
  9f90e1:	eb 38                                           	jmp    0x9f911b
  9f90e3:	b9 00 00 00 40                                  	mov    ecx,0x40000000
  9f90e8:	0d 00 01 00 00                                  	or     eax,0x100
  9f90ed:	48 89 8b a8 05 00 00                            	mov    QWORD PTR [rbx+0x5a8],rcx
  9f90f4:	48 c7 83 b0 05 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x5b0],0x0
  9f90ff:	3d 00 f1 00 00                                  	cmp    eax,0xf100
  9f9104:	75 15                                           	jne    0x9f911b
  9f9106:	41 80 7d 4a 01                                  	cmp    BYTE PTR [r13+0x4a],0x1
  9f910b:	75 0e                                           	jne    0x9f911b
  9f910d:	48 8d 3d 6d de 88 00                            	lea    rdi,[rip+0x88de6d]        # 0x1286f81
  9f9114:	31 c0                                           	xor    eax,eax
  9f9116:	e8 f5 42 86 ff                                  	call   0x25d410
  9f911b:	48 8b 05 f6 4e 1b 03                            	mov    rax,QWORD PTR [rip+0x31b4ef6]        # 0x3bae018
  9f9122:	48 c7 03 00 00 00 00                            	mov    QWORD PTR [rbx],0x0
  9f9129:	ff 05 f1 4e 1b 03                               	inc    DWORD PTR [rip+0x31b4ef1]        # 0x3bae020
  9f912f:	48 8d 3d b2 4e 1b 03                            	lea    rdi,[rip+0x31b4eb2]        # 0x3badfe8
  9f9136:	31 f6                                           	xor    esi,esi
  9f9138:	31 d2                                           	xor    edx,edx
  9f913a:	48 89 43 08                                     	mov    QWORD PTR [rbx+0x8],rax
  9f913e:	48 89 18                                        	mov    QWORD PTR [rax],rbx
  9f9141:	48 89 1d d0 4e 1b 03                            	mov    QWORD PTR [rip+0x31b4ed0],rbx        # 0x3bae018
  9f9148:	c7 83 b0 00 00 00 05 00 00 00                   	mov    DWORD PTR [rbx+0xb0],0x5
  9f9152:	48 8b 05 a7 4e 1b 03                            	mov    rax,QWORD PTR [rip+0x31b4ea7]        # 0x3bae000
  9f9159:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9f9162:	48 83 e0 f1                                     	and    rax,0xfffffffffffffff1
  9f9166:	48 39 c8                                        	cmp    rax,rcx
  9f9169:	75 07                                           	jne    0x9f9172
  9f916b:	e8 40 33 25 00                                  	call   0xc4c4b0
  9f9170:	eb 05                                           	jmp    0x9f9177
  9f9172:	e8 89 31 25 00                                  	call   0xc4c300
  9f9177:	48 8d bb cc 00 00 00                            	lea    rdi,[rbx+0xcc]
  9f917e:	be 00 04 00 00                                  	mov    esi,0x400
  9f9183:	44 89 63 10                                     	mov    DWORD PTR [rbx+0x10],r12d
  9f9187:	48 c7 83 a8 00 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0xa8],0x0
  9f9192:	c7 83 b4 00 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0xb4],0x0
  9f919c:	c7 83 bc 00 00 00 ff ff ff ff                   	mov    DWORD PTR [rbx+0xbc],0xffffffff
  9f91a6:	4c 89 bb c0 00 00 00                            	mov    QWORD PTR [rbx+0xc0],r15
  9f91ad:	c7 83 c8 00 00 00 04 00 00 00                   	mov    DWORD PTR [rbx+0xc8],0x4
  9f91b7:	e8 34 fe 85 ff                                  	call   0x258ff0
  9f91bc:	48 8d bb cc 04 00 00                            	lea    rdi,[rbx+0x4cc]
  9f91c3:	be 08 00 00 00                                  	mov    esi,0x8
  9f91c8:	e8 23 fe 85 ff                                  	call   0x258ff0
  9f91cd:	41 0f b6 45 53                                  	movzx  eax,BYTE PTR [r13+0x53]
  9f91d2:	c1 e0 18                                        	shl    eax,0x18
  9f91d5:	3d 00 00 00 03                                  	cmp    eax,0x3000000
  9f91da:	75 0d                                           	jne    0x9f91e9
  9f91dc:	41 8b 85 b8 00 00 00                            	mov    eax,DWORD PTR [r13+0xb8]
  9f91e3:	89 83 bc 00 00 00                               	mov    DWORD PTR [rbx+0xbc],eax
  9f91e9:	4c 89 b3 b8 05 00 00                            	mov    QWORD PTR [rbx+0x5b8],r14
  9f91f0:	4c 8b 75 b0                                     	mov    r14,QWORD PTR [rbp-0x50]
  9f91f4:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  9f91f8:	be 10 80 00 00                                  	mov    esi,0x8010
  9f91fd:	48 89 da                                        	mov    rdx,rbx
  9f9200:	8b 43 10                                        	mov    eax,DWORD PTR [rbx+0x10]
  9f9203:	41 89 06                                        	mov    DWORD PTR [r14],eax
  9f9206:	48 89 19                                        	mov    QWORD PTR [rcx],rbx
  9f9209:	48 89 d9                                        	mov    rcx,rbx
  9f920c:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  9f9210:	48 83 c1 20                                     	add    rcx,0x20
  9f9214:	e8 c7 0b 9a ff                                  	call   0x399de0
  9f9219:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  9f921d:	e8 8e 0c 9a ff                                  	call   0x399eb0
  9f9222:	41 8b 36                                        	mov    esi,DWORD PTR [r14]
  9f9225:	41 8b 55 50                                     	mov    edx,DWORD PTR [r13+0x50]
  9f9229:	48 8d 3d c1 5c 8d 00                            	lea    rdi,[rip+0x8d5cc1]        # 0x12ceef1
  9f9230:	31 c0                                           	xor    eax,eax
  9f9232:	45 31 f6                                        	xor    r14d,r14d
  9f9235:	e8 d6 41 86 ff                                  	call   0x25d410
  9f923a:	48 8d 05 cf 30 f2 02                            	lea    rax,[rip+0x2f230cf]        # 0x391c310
  9f9241:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  9f9244:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  9f9248:	75 12                                           	jne    0x9f925c
  9f924a:	44 89 f0                                        	mov    eax,r14d
  9f924d:	48 83 c4 28                                     	add    rsp,0x28
  9f9251:	5b                                              	pop    rbx
  9f9252:	41 5c                                           	pop    r12
  9f9254:	41 5d                                           	pop    r13
  9f9256:	41 5e                                           	pop    r14
  9f9258:	41 5f                                           	pop    r15
  9f925a:	5d                                              	pop    rbp
  9f925b:	c3                                              	ret
  9f925c:	e8 4f 44 d0 ff                                  	call   0x6fd6b0
  9f9261:	0f 0b                                           	ud2
  9f9263:	89 c3                                           	mov    ebx,eax
  9f9265:	e8 e6 86 df ff                                  	call   0x7f1950
  9f926a:	48 63 f3                                        	movsxd rsi,ebx
  9f926d:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x9f9263
  9f9274:	e8 27 86 df ff                                  	call   0x7f18a0
  9f9279:	48 8d 35 50 5c 8d 00                            	lea    rsi,[rip+0x8d5c50]        # 0x12ceed0
  9f9280:	bf d1 00 00 00                                  	mov    edi,0xd1
  9f9285:	89 da                                           	mov    edx,ebx
  9f9287:	31 c0                                           	xor    eax,eax
  9f9289:	e8 82 17 2a 00                                  	call   0xc9aa10
  9f928e:	0f 0b                                           	ud2
  9f9290:	55                                              	push   rbp
  9f9291:	48 89 e5                                        	mov    rbp,rsp
  9f9294:	41 57                                           	push   r15
  9f9296:	41 56                                           	push   r14
  9f9298:	41 55                                           	push   r13
  9f929a:	41 54                                           	push   r12
  9f929c:	53                                              	push   rbx
  9f929d:	48 83 ec 48                                     	sub    rsp,0x48
  9f92a1:	4c 8d 35 68 30 f2 02                            	lea    r14,[rip+0x2f23068]        # 0x391c310
  9f92a8:	49 89 f7                                        	mov    r15,rsi
  9f92ab:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  9f92ae:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9f92b2:	48 81 fe 01 00 10 00                            	cmp    rsi,0x100001
  9f92b9:	72 20                                           	jb     0x9f92db
  9f92bb:	48 8d 3d bf d0 97 00                            	lea    rdi,[rip+0x97d0bf]        # 0x1376381
  9f92c2:	ba 00 00 10 00                                  	mov    edx,0x100000
  9f92c7:	4c 89 fe                                        	mov    rsi,r15
  9f92ca:	31 c0                                           	xor    eax,eax
  9f92cc:	e8 3f 41 86 ff                                  	call   0x25d410
  9f92d1:	bb 0c 00 00 00                                  	mov    ebx,0xc
  9f92d6:	e9 01 02 00 00                                  	jmp    0x9f94dc
  9f92db:	4d 85 ff                                        	test   r15,r15
  9f92de:	0f 84 87 01 00 00                               	je     0x9f946b
  9f92e4:	48 89 55 98                                     	mov    QWORD PTR [rbp-0x68],rdx
  9f92e8:	44 89 fe                                        	mov    esi,r15d
  9f92eb:	ba 02 00 00 00                                  	mov    edx,0x2
  9f92f0:	b9 01 00 00 00                                  	mov    ecx,0x1
  9f92f5:	49 89 fc                                        	mov    r12,rdi
  9f92f8:	31 ff                                           	xor    edi,edi
  9f92fa:	45 31 c0                                        	xor    r8d,r8d
  9f92fd:	e8 de 11 a3 ff                                  	call   0x42a4e0
  9f9302:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  9f9306:	48 85 c0                                        	test   rax,rax
  9f9309:	0f 84 97 00 00 00                               	je     0x9f93a6
  9f930f:	4c 8b 6d a0                                     	mov    r13,QWORD PTR [rbp-0x60]
  9f9313:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9f9320:	41 8b 45 1c                                     	mov    eax,DWORD PTR [r13+0x1c]
  9f9324:	a9 00 01 00 00                                  	test   eax,0x100
  9f9329:	75 25                                           	jne    0x9f9350
  9f932b:	a9 00 02 00 00                                  	test   eax,0x200
  9f9330:	41 be 88 00 00 00                               	mov    r14d,0x88
  9f9336:	b8 e0 00 00 00                                  	mov    eax,0xe0
  9f933b:	4c 0f 44 f0                                     	cmove  r14,rax
  9f933f:	eb 16                                           	jmp    0x9f9357
  9f9341:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9f9350:	45 8b b5 88 00 00 00                            	mov    r14d,DWORD PTR [r13+0x88]
  9f9357:	4d 39 f7                                        	cmp    r15,r14
  9f935a:	49 8b 5d 10                                     	mov    rbx,QWORD PTR [r13+0x10]
  9f935e:	48 8d 35 d8 eb 99 00                            	lea    rsi,[rip+0x99ebd8]        # 0x1397f3d
  9f9365:	4d 0f 42 f7                                     	cmovb  r14,r15
  9f9369:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  9f9372:	31 d2                                           	xor    edx,edx
  9f9374:	e8 67 10 22 00                                  	call   0xc1a3e0
  9f9379:	4c 89 e7                                        	mov    rdi,r12
  9f937c:	48 89 de                                        	mov    rsi,rbx
  9f937f:	4c 89 f2                                        	mov    rdx,r14
  9f9382:	e8 f9 fe 85 ff                                  	call   0x259280
  9f9387:	85 c0                                           	test   eax,eax
  9f9389:	0f 85 ed 00 00 00                               	jne    0x9f947c
  9f938f:	45 89 75 18                                     	mov    DWORD PTR [r13+0x18],r14d
  9f9393:	4d 01 f4                                        	add    r12,r14
  9f9396:	4d 29 f7                                        	sub    r15,r14
  9f9399:	4d 8b 6d 00                                     	mov    r13,QWORD PTR [r13+0x0]
  9f939d:	4d 85 ed                                        	test   r13,r13
  9f93a0:	0f 85 7a ff ff ff                               	jne    0x9f9320
  9f93a6:	48 8d 5d a8                                     	lea    rbx,[rbp-0x58]
  9f93aa:	be 20 00 00 00                                  	mov    esi,0x20
  9f93af:	48 89 df                                        	mov    rdi,rbx
  9f93b2:	e8 39 fc 85 ff                                  	call   0x258ff0
  9f93b7:	48 89 de                                        	mov    rsi,rbx
  9f93ba:	48 8b 5d a0                                     	mov    rbx,QWORD PTR [rbp-0x60]
  9f93be:	48 8d 7d c8                                     	lea    rdi,[rbp-0x38]
  9f93c2:	b9 10 00 00 00                                  	mov    ecx,0x10
  9f93c7:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  9f93cf:	48 89 da                                        	mov    rdx,rbx
  9f93d2:	e8 79 17 16 00                                  	call   0xb5ab50
  9f93d7:	4c 8d 35 32 2f f2 02                            	lea    r14,[rip+0x2f22f32]        # 0x391c310
  9f93de:	4c 8b 7d 98                                     	mov    r15,QWORD PTR [rbp-0x68]
  9f93e2:	84 c0                                           	test   al,al
  9f93e4:	0f 85 b1 00 00 00                               	jne    0x9f949b
  9f93ea:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  9f93ee:	48 8d 35 6c 21 8a 00                            	lea    rsi,[rip+0x8a216c]        # 0x129b561
  9f93f5:	e8 b6 25 87 ff                                  	call   0x26b9b0
  9f93fa:	85 c0                                           	test   eax,eax
  9f93fc:	0f 84 8e 00 00 00                               	je     0x9f9490
  9f9402:	48 8b 4d a8                                     	mov    rcx,QWORD PTR [rbp-0x58]
  9f9406:	4c 8b 45 b0                                     	mov    r8,QWORD PTR [rbp-0x50]
  9f940a:	48 8d 15 3f 7a ed 00                            	lea    rdx,[rip+0xed7a3f]        # 0x18d0e50
  9f9411:	31 ff                                           	xor    edi,edi
  9f9413:	31 f6                                           	xor    esi,esi
  9f9415:	31 c0                                           	xor    eax,eax
  9f9417:	e8 b4 b0 10 00                                  	call   0xb044d0
  9f941c:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  9f9420:	48 85 ff                                        	test   rdi,rdi
  9f9423:	74 23                                           	je     0x9f9448
  9f9425:	e8 96 57 ec ff                                  	call   0x8bebc0
  9f942a:	48 89 c1                                        	mov    rcx,rax
  9f942d:	48 8d 15 6c 7a ed 00                            	lea    rdx,[rip+0xed7a6c]        # 0x18d0ea0
  9f9434:	31 ff                                           	xor    edi,edi
  9f9436:	31 f6                                           	xor    esi,esi
  9f9438:	31 c0                                           	xor    eax,eax
  9f943a:	e8 91 b0 10 00                                  	call   0xb044d0
  9f943f:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  9f9443:	e8 68 51 ec ff                                  	call   0x8be5b0
  9f9448:	8b 4d c0                                        	mov    ecx,DWORD PTR [rbp-0x40]
  9f944b:	44 8b 45 c4                                     	mov    r8d,DWORD PTR [rbp-0x3c]
  9f944f:	48 8d 15 5a 7a ed 00                            	lea    rdx,[rip+0xed7a5a]        # 0x18d0eb0
  9f9456:	31 ff                                           	xor    edi,edi
  9f9458:	31 f6                                           	xor    esi,esi
  9f945a:	31 c0                                           	xor    eax,eax
  9f945c:	e8 6f b0 10 00                                  	call   0xb044d0
  9f9461:	48 89 df                                        	mov    rdi,rbx
  9f9464:	e8 e7 13 a3 ff                                  	call   0x42a850
  9f9469:	eb 6c                                           	jmp    0x9f94d7
  9f946b:	31 ff                                           	xor    edi,edi
  9f946d:	31 db                                           	xor    ebx,ebx
  9f946f:	49 89 d7                                        	mov    r15,rdx
  9f9472:	e8 d9 0c 16 00                                  	call   0xb5a150
  9f9477:	49 89 07                                        	mov    QWORD PTR [r15],rax
  9f947a:	eb 60                                           	jmp    0x9f94dc
  9f947c:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  9f9480:	89 c3                                           	mov    ebx,eax
  9f9482:	e8 c9 13 a3 ff                                  	call   0x42a850
  9f9487:	4c 8d 35 82 2e f2 02                            	lea    r14,[rip+0x2f22e82]        # 0x391c310
  9f948e:	eb 4c                                           	jmp    0x9f94dc
  9f9490:	31 ff                                           	xor    edi,edi
  9f9492:	e8 b9 0c 16 00                                  	call   0xb5a150
  9f9497:	48 89 45 c8                                     	mov    QWORD PTR [rbp-0x38],rax
  9f949b:	48 89 df                                        	mov    rdi,rbx
  9f949e:	e8 ad 13 a3 ff                                  	call   0x42a850
  9f94a3:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  9f94a7:	e8 84 0e 16 00                                  	call   0xb5a330
  9f94ac:	83 f8 02                                        	cmp    eax,0x2
  9f94af:	75 0b                                           	jne    0x9f94bc
  9f94b1:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  9f94b5:	31 db                                           	xor    ebx,ebx
  9f94b7:	49 89 07                                        	mov    QWORD PTR [r15],rax
  9f94ba:	eb 20                                           	jmp    0x9f94dc
  9f94bc:	48 8d 15 0d 7a ed 00                            	lea    rdx,[rip+0xed7a0d]        # 0x18d0ed0
  9f94c3:	31 ff                                           	xor    edi,edi
  9f94c5:	31 f6                                           	xor    esi,esi
  9f94c7:	31 c0                                           	xor    eax,eax
  9f94c9:	e8 02 b0 10 00                                  	call   0xb044d0
  9f94ce:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  9f94d2:	e8 e9 0c 16 00                                  	call   0xb5a1c0
  9f94d7:	bb 16 00 00 00                                  	mov    ebx,0x16
  9f94dc:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  9f94df:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  9f94e3:	75 11                                           	jne    0x9f94f6
  9f94e5:	89 d8                                           	mov    eax,ebx
  9f94e7:	48 83 c4 48                                     	add    rsp,0x48
  9f94eb:	5b                                              	pop    rbx
  9f94ec:	41 5c                                           	pop    r12
  9f94ee:	41 5d                                           	pop    r13
  9f94f0:	41 5e                                           	pop    r14
  9f94f2:	41 5f                                           	pop    r15
  9f94f4:	5d                                              	pop    rbp
  9f94f5:	c3                                              	ret
  9f94f6:	e8 b5 41 d0 ff                                  	call   0x6fd6b0
  9f94fb:	0f 0b                                           	ud2
  9f94fd:	90                                              	nop
  9f94fe:	90                                              	nop
  9f94ff:	90                                              	nop
  9f9500:	55                                              	push   rbp
  9f9501:	48 89 e5                                        	mov    rbp,rsp
  9f9504:	41 57                                           	push   r15
  9f9506:	41 56                                           	push   r14
  9f9508:	53                                              	push   rbx
  9f9509:	50                                              	push   rax
  9f950a:	48 89 f0                                        	mov    rax,rsi
  9f950d:	49 89 ff                                        	mov    r15,rdi
  9f9510:	48 8d 35 c1 d2 8e 00                            	lea    rsi,[rip+0x8ed2c1]        # 0x12e67d8
  9f9517:	48 89 c7                                        	mov    rdi,rax
  9f951a:	e8 a1 15 16 00                                  	call   0xb5aac0
  9f951f:	48 85 c0                                        	test   rax,rax
  9f9522:	0f 84 e0 03 00 00                               	je     0x9f9908
  9f9528:	48 89 c7                                        	mov    rdi,rax
  9f952b:	48 89 c3                                        	mov    rbx,rax
  9f952e:	e8 fd 0d 16 00                                  	call   0xb5a330
  9f9533:	83 f8 02                                        	cmp    eax,0x2
  9f9536:	0f 85 11 01 00 00                               	jne    0x9f964d
  9f953c:	48 8d 35 2e 20 8a 00                            	lea    rsi,[rip+0x8a202e]        # 0x129b571
  9f9543:	48 89 df                                        	mov    rdi,rbx
  9f9546:	e8 75 15 16 00                                  	call   0xb5aac0
  9f954b:	48 85 c0                                        	test   rax,rax
  9f954e:	0f 84 b4 03 00 00                               	je     0x9f9908
  9f9554:	48 89 c7                                        	mov    rdi,rax
  9f9557:	48 89 c3                                        	mov    rbx,rax
  9f955a:	e8 d1 0d 16 00                                  	call   0xb5a330
  9f955f:	83 f8 02                                        	cmp    eax,0x2
  9f9562:	0f 85 f1 00 00 00                               	jne    0x9f9659
  9f9568:	48 8d 35 db 90 92 00                            	lea    rsi,[rip+0x9290db]        # 0x132264a
  9f956f:	48 89 df                                        	mov    rdi,rbx
  9f9572:	e8 49 15 16 00                                  	call   0xb5aac0
  9f9577:	48 85 c0                                        	test   rax,rax
  9f957a:	0f 84 88 03 00 00                               	je     0x9f9908
  9f9580:	48 89 c7                                        	mov    rdi,rax
  9f9583:	49 89 c6                                        	mov    r14,rax
  9f9586:	e8 a5 0d 16 00                                  	call   0xb5a330
  9f958b:	83 f8 02                                        	cmp    eax,0x2
  9f958e:	0f 85 d1 00 00 00                               	jne    0x9f9665
  9f9594:	48 8d 35 b5 a7 b6 01                            	lea    rsi,[rip+0x1b6a7b5]        # 0x2563d50
  9f959b:	bf 04 00 00 00                                  	mov    edi,0x4
  9f95a0:	ba 02 01 00 00                                  	mov    edx,0x102
  9f95a5:	e8 a6 f5 20 00                                  	call   0xc08b50
  9f95aa:	48 8d 35 0b 2d 94 00                            	lea    rsi,[rip+0x942d0b]        # 0x133c2bc
  9f95b1:	4c 89 f7                                        	mov    rdi,r14
  9f95b4:	49 89 87 a0 05 00 00                            	mov    QWORD PTR [r15+0x5a0],rax
  9f95bb:	48 89 c3                                        	mov    rbx,rax
  9f95be:	c6 00 01                                        	mov    BYTE PTR [rax],0x1
  9f95c1:	e8 fa 14 16 00                                  	call   0xb5aac0
  9f95c6:	48 85 c0                                        	test   rax,rax
  9f95c9:	0f 84 d9 00 00 00                               	je     0x9f96a8
  9f95cf:	48 89 c7                                        	mov    rdi,rax
  9f95d2:	49 89 c7                                        	mov    r15,rax
  9f95d5:	e8 56 0d 16 00                                  	call   0xb5a330
  9f95da:	83 f8 05                                        	cmp    eax,0x5
  9f95dd:	0f 85 8e 00 00 00                               	jne    0x9f9671
  9f95e3:	4c 89 ff                                        	mov    rdi,r15
  9f95e6:	e8 75 0d 16 00                                  	call   0xb5a360
  9f95eb:	48 8d 35 75 27 92 00                            	lea    rsi,[rip+0x922775]        # 0x131bd67
  9f95f2:	ba 02 00 00 00                                  	mov    edx,0x2
  9f95f7:	48 89 c7                                        	mov    rdi,rax
  9f95fa:	49 89 c7                                        	mov    r15,rax
  9f95fd:	e8 2e 84 ed ff                                  	call   0x8d1a30
  9f9602:	85 c0                                           	test   eax,eax
  9f9604:	74 7f                                           	je     0x9f9685
  9f9606:	48 8d 35 4e d3 87 00                            	lea    rsi,[rip+0x87d34e]        # 0x127695b
  9f960d:	ba 02 00 00 00                                  	mov    edx,0x2
  9f9612:	4c 89 ff                                        	mov    rdi,r15
  9f9615:	e8 16 84 ed ff                                  	call   0x8d1a30
  9f961a:	85 c0                                           	test   eax,eax
  9f961c:	74 76                                           	je     0x9f9694
  9f961e:	48 8d 35 c7 9b 98 00                            	lea    rsi,[rip+0x989bc7]        # 0x13831ec
  9f9625:	ba 02 00 00 00                                  	mov    edx,0x2
  9f962a:	4c 89 ff                                        	mov    rdi,r15
  9f962d:	e8 fe 83 ed ff                                  	call   0x8d1a30
  9f9632:	85 c0                                           	test   eax,eax
  9f9634:	74 6e                                           	je     0x9f96a4
  9f9636:	48 8d 15 f3 79 ed 00                            	lea    rdx,[rip+0xed79f3]        # 0x18d1030
  9f963d:	4c 89 f9                                        	mov    rcx,r15
  9f9640:	31 ff                                           	xor    edi,edi
  9f9642:	31 f6                                           	xor    esi,esi
  9f9644:	31 c0                                           	xor    eax,eax
  9f9646:	e8 85 ae 10 00                                  	call   0xb044d0
  9f964b:	eb 5b                                           	jmp    0x9f96a8
  9f964d:	48 8d 15 ac 78 ed 00                            	lea    rdx,[rip+0xed78ac]        # 0x18d0f00
  9f9654:	e9 5a 02 00 00                                  	jmp    0x9f98b3
  9f9659:	48 8d 15 e0 78 ed 00                            	lea    rdx,[rip+0xed78e0]        # 0x18d0f40
  9f9660:	e9 4e 02 00 00                                  	jmp    0x9f98b3
  9f9665:	48 8d 15 24 79 ed 00                            	lea    rdx,[rip+0xed7924]        # 0x18d0f90
  9f966c:	e9 42 02 00 00                                  	jmp    0x9f98b3
  9f9671:	48 8d 15 68 79 ed 00                            	lea    rdx,[rip+0xed7968]        # 0x18d0fe0
  9f9678:	31 ff                                           	xor    edi,edi
  9f967a:	31 f6                                           	xor    esi,esi
  9f967c:	31 c0                                           	xor    eax,eax
  9f967e:	e8 4d ae 10 00                                  	call   0xb044d0
  9f9683:	eb 23                                           	jmp    0x9f96a8
  9f9685:	0f b7 43 02                                     	movzx  eax,WORD PTR [rbx+0x2]
  9f9689:	83 e0 f0                                        	and    eax,0xfffffff0
  9f968c:	ff c0                                           	inc    eax
  9f968e:	66 89 43 02                                     	mov    WORD PTR [rbx+0x2],ax
  9f9692:	eb 14                                           	jmp    0x9f96a8
  9f9694:	0f b7 43 02                                     	movzx  eax,WORD PTR [rbx+0x2]
  9f9698:	83 e0 f0                                        	and    eax,0xfffffff0
  9f969b:	83 c8 02                                        	or     eax,0x2
  9f969e:	66 89 43 02                                     	mov    WORD PTR [rbx+0x2],ax
  9f96a2:	eb 04                                           	jmp    0x9f96a8
  9f96a4:	80 63 02 f0                                     	and    BYTE PTR [rbx+0x2],0xf0
  9f96a8:	48 8d 35 11 37 94 00                            	lea    rsi,[rip+0x943711]        # 0x133cdc0
  9f96af:	4c 89 f7                                        	mov    rdi,r14
  9f96b2:	e8 09 14 16 00                                  	call   0xb5aac0
  9f96b7:	48 85 c0                                        	test   rax,rax
  9f96ba:	0f 84 8c 00 00 00                               	je     0x9f974c
  9f96c0:	48 89 c7                                        	mov    rdi,rax
  9f96c3:	49 89 c7                                        	mov    r15,rax
  9f96c6:	e8 65 0c 16 00                                  	call   0xb5a330
  9f96cb:	83 f8 05                                        	cmp    eax,0x5
  9f96ce:	75 52                                           	jne    0x9f9722
  9f96d0:	4c 89 ff                                        	mov    rdi,r15
  9f96d3:	e8 88 0c 16 00                                  	call   0xb5a360
  9f96d8:	48 8d 35 88 26 92 00                            	lea    rsi,[rip+0x922688]        # 0x131bd67
  9f96df:	ba 02 00 00 00                                  	mov    edx,0x2
  9f96e4:	48 89 c7                                        	mov    rdi,rax
  9f96e7:	49 89 c7                                        	mov    r15,rax
  9f96ea:	e8 41 83 ed ff                                  	call   0x8d1a30
  9f96ef:	85 c0                                           	test   eax,eax
  9f96f1:	74 43                                           	je     0x9f9736
  9f96f3:	48 8d 35 f2 9a 98 00                            	lea    rsi,[rip+0x989af2]        # 0x13831ec
  9f96fa:	ba 02 00 00 00                                  	mov    edx,0x2
  9f96ff:	4c 89 ff                                        	mov    rdi,r15
  9f9702:	e8 29 83 ed ff                                  	call   0x8d1a30
  9f9707:	85 c0                                           	test   eax,eax
  9f9709:	74 3d                                           	je     0x9f9748
  9f970b:	48 8d 15 de 79 ed 00                            	lea    rdx,[rip+0xed79de]        # 0x18d10f0
  9f9712:	4c 89 f9                                        	mov    rcx,r15
  9f9715:	31 ff                                           	xor    edi,edi
  9f9717:	31 f6                                           	xor    esi,esi
  9f9719:	31 c0                                           	xor    eax,eax
  9f971b:	e8 b0 ad 10 00                                  	call   0xb044d0
  9f9720:	eb 2a                                           	jmp    0x9f974c
  9f9722:	48 8d 15 67 79 ed 00                            	lea    rdx,[rip+0xed7967]        # 0x18d1090
  9f9729:	31 ff                                           	xor    edi,edi
  9f972b:	31 f6                                           	xor    esi,esi
  9f972d:	31 c0                                           	xor    eax,eax
  9f972f:	e8 9c ad 10 00                                  	call   0xb044d0
  9f9734:	eb 16                                           	jmp    0x9f974c
  9f9736:	0f b7 43 02                                     	movzx  eax,WORD PTR [rbx+0x2]
  9f973a:	25 0f ff ff ff                                  	and    eax,0xffffff0f
  9f973f:	83 c8 10                                        	or     eax,0x10
  9f9742:	66 89 43 02                                     	mov    WORD PTR [rbx+0x2],ax
  9f9746:	eb 04                                           	jmp    0x9f974c
  9f9748:	80 63 02 0f                                     	and    BYTE PTR [rbx+0x2],0xf
  9f974c:	48 8d 35 4f 3e 91 00                            	lea    rsi,[rip+0x913e4f]        # 0x130d5a2
  9f9753:	4c 89 f7                                        	mov    rdi,r14
  9f9756:	e8 65 13 16 00                                  	call   0xb5aac0
  9f975b:	48 85 c0                                        	test   rax,rax
  9f975e:	0f 84 8e 00 00 00                               	je     0x9f97f2
  9f9764:	48 89 c7                                        	mov    rdi,rax
  9f9767:	49 89 c7                                        	mov    r15,rax
  9f976a:	e8 c1 0b 16 00                                  	call   0xb5a330
  9f976f:	83 f8 05                                        	cmp    eax,0x5
  9f9772:	75 52                                           	jne    0x9f97c6
  9f9774:	4c 89 ff                                        	mov    rdi,r15
  9f9777:	e8 e4 0b 16 00                                  	call   0xb5a360
  9f977c:	48 8d 35 e4 25 92 00                            	lea    rsi,[rip+0x9225e4]        # 0x131bd67
  9f9783:	ba 02 00 00 00                                  	mov    edx,0x2
  9f9788:	48 89 c7                                        	mov    rdi,rax
  9f978b:	49 89 c7                                        	mov    r15,rax
  9f978e:	e8 9d 82 ed ff                                  	call   0x8d1a30
  9f9793:	85 c0                                           	test   eax,eax
  9f9795:	74 43                                           	je     0x9f97da
  9f9797:	48 8d 35 4e 9a 98 00                            	lea    rsi,[rip+0x989a4e]        # 0x13831ec
  9f979e:	ba 02 00 00 00                                  	mov    edx,0x2
  9f97a3:	4c 89 ff                                        	mov    rdi,r15
  9f97a6:	e8 85 82 ed ff                                  	call   0x8d1a30
  9f97ab:	85 c0                                           	test   eax,eax
  9f97ad:	74 3f                                           	je     0x9f97ee
  9f97af:	48 8d 15 fa 79 ed 00                            	lea    rdx,[rip+0xed79fa]        # 0x18d11b0
  9f97b6:	4c 89 f9                                        	mov    rcx,r15
  9f97b9:	31 ff                                           	xor    edi,edi
  9f97bb:	31 f6                                           	xor    esi,esi
  9f97bd:	31 c0                                           	xor    eax,eax
  9f97bf:	e8 0c ad 10 00                                  	call   0xb044d0
  9f97c4:	eb 2c                                           	jmp    0x9f97f2
  9f97c6:	48 8d 15 83 79 ed 00                            	lea    rdx,[rip+0xed7983]        # 0x18d1150
  9f97cd:	31 ff                                           	xor    edi,edi
  9f97cf:	31 f6                                           	xor    esi,esi
  9f97d1:	31 c0                                           	xor    eax,eax
  9f97d3:	e8 f8 ac 10 00                                  	call   0xb044d0
  9f97d8:	eb 18                                           	jmp    0x9f97f2
  9f97da:	0f b7 43 02                                     	movzx  eax,WORD PTR [rbx+0x2]
  9f97de:	25 ff f0 ff ff                                  	and    eax,0xfffff0ff
  9f97e3:	0d 00 01 00 00                                  	or     eax,0x100
  9f97e8:	66 89 43 02                                     	mov    WORD PTR [rbx+0x2],ax
  9f97ec:	eb 04                                           	jmp    0x9f97f2
  9f97ee:	80 63 03 f0                                     	and    BYTE PTR [rbx+0x3],0xf0
  9f97f2:	48 8d 35 5b bf 8a 00                            	lea    rsi,[rip+0x8abf5b]        # 0x12a5754
  9f97f9:	4c 89 f7                                        	mov    rdi,r14
  9f97fc:	e8 bf 12 16 00                                  	call   0xb5aac0
  9f9801:	48 85 c0                                        	test   rax,rax
  9f9804:	0f 84 fe 00 00 00                               	je     0x9f9908
  9f980a:	48 89 c7                                        	mov    rdi,rax
  9f980d:	49 89 c6                                        	mov    r14,rax
  9f9810:	e8 1b 0b 16 00                                  	call   0xb5a330
  9f9815:	83 f8 05                                        	cmp    eax,0x5
  9f9818:	0f 85 8e 00 00 00                               	jne    0x9f98ac
  9f981e:	4c 89 f7                                        	mov    rdi,r14
  9f9821:	e8 3a 0b 16 00                                  	call   0xb5a360
  9f9826:	48 8d 35 3a 25 92 00                            	lea    rsi,[rip+0x92253a]        # 0x131bd67
  9f982d:	ba 02 00 00 00                                  	mov    edx,0x2
  9f9832:	48 89 c7                                        	mov    rdi,rax
  9f9835:	49 89 c6                                        	mov    r14,rax
  9f9838:	e8 f3 81 ed ff                                  	call   0x8d1a30
  9f983d:	85 c0                                           	test   eax,eax
  9f983f:	0f 84 83 00 00 00                               	je     0x9f98c8
  9f9845:	48 8d 35 f3 e3 91 00                            	lea    rsi,[rip+0x91e3f3]        # 0x1317c3f
  9f984c:	ba 03 00 00 00                                  	mov    edx,0x3
  9f9851:	4c 89 f7                                        	mov    rdi,r14
  9f9854:	e8 d7 81 ed ff                                  	call   0x8d1a30
  9f9859:	85 c0                                           	test   eax,eax
  9f985b:	74 7f                                           	je     0x9f98dc
  9f985d:	48 8d 35 ee 8d 92 00                            	lea    rsi,[rip+0x928dee]        # 0x1322652
  9f9864:	ba 03 00 00 00                                  	mov    edx,0x3
  9f9869:	4c 89 f7                                        	mov    rdi,r14
  9f986c:	e8 bf 81 ed ff                                  	call   0x8d1a30
  9f9871:	85 c0                                           	test   eax,eax
  9f9873:	74 7b                                           	je     0x9f98f0
  9f9875:	48 8d 35 70 99 98 00                            	lea    rsi,[rip+0x989970]        # 0x13831ec
  9f987c:	ba 02 00 00 00                                  	mov    edx,0x2
  9f9881:	4c 89 f7                                        	mov    rdi,r14
  9f9884:	e8 a7 81 ed ff                                  	call   0x8d1a30
  9f9889:	85 c0                                           	test   eax,eax
  9f988b:	74 77                                           	je     0x9f9904
  9f988d:	48 8d 15 dc 79 ed 00                            	lea    rdx,[rip+0xed79dc]        # 0x18d1270
  9f9894:	31 ff                                           	xor    edi,edi
  9f9896:	31 f6                                           	xor    esi,esi
  9f9898:	4c 89 f1                                        	mov    rcx,r14
  9f989b:	31 c0                                           	xor    eax,eax
  9f989d:	48 83 c4 08                                     	add    rsp,0x8
  9f98a1:	5b                                              	pop    rbx
  9f98a2:	41 5e                                           	pop    r14
  9f98a4:	41 5f                                           	pop    r15
  9f98a6:	5d                                              	pop    rbp
  9f98a7:	e9 24 ac 10 00                                  	jmp    0xb044d0
  9f98ac:	48 8d 15 5d 79 ed 00                            	lea    rdx,[rip+0xed795d]        # 0x18d1210
  9f98b3:	31 ff                                           	xor    edi,edi
  9f98b5:	31 f6                                           	xor    esi,esi
  9f98b7:	31 c0                                           	xor    eax,eax
  9f98b9:	48 83 c4 08                                     	add    rsp,0x8
  9f98bd:	5b                                              	pop    rbx
  9f98be:	41 5e                                           	pop    r14
  9f98c0:	41 5f                                           	pop    r15
  9f98c2:	5d                                              	pop    rbp
  9f98c3:	e9 08 ac 10 00                                  	jmp    0xb044d0
  9f98c8:	0f b7 43 02                                     	movzx  eax,WORD PTR [rbx+0x2]
  9f98cc:	25 ff 0f 00 00                                  	and    eax,0xfff
  9f98d1:	0d 00 10 00 00                                  	or     eax,0x1000
  9f98d6:	66 89 43 02                                     	mov    WORD PTR [rbx+0x2],ax
  9f98da:	eb 2c                                           	jmp    0x9f9908
  9f98dc:	0f b7 43 02                                     	movzx  eax,WORD PTR [rbx+0x2]
  9f98e0:	25 ff 0f 00 00                                  	and    eax,0xfff
  9f98e5:	0d 00 30 00 00                                  	or     eax,0x3000
  9f98ea:	66 89 43 02                                     	mov    WORD PTR [rbx+0x2],ax
  9f98ee:	eb 18                                           	jmp    0x9f9908
  9f98f0:	0f b7 43 02                                     	movzx  eax,WORD PTR [rbx+0x2]
  9f98f4:	25 ff 0f 00 00                                  	and    eax,0xfff
  9f98f9:	0d 00 40 00 00                                  	or     eax,0x4000
  9f98fe:	66 89 43 02                                     	mov    WORD PTR [rbx+0x2],ax
  9f9902:	eb 04                                           	jmp    0x9f9908
  9f9904:	80 63 03 0f                                     	and    BYTE PTR [rbx+0x3],0xf
  9f9908:	48 83 c4 08                                     	add    rsp,0x8
  9f990c:	5b                                              	pop    rbx
  9f990d:	41 5e                                           	pop    r14
  9f990f:	41 5f                                           	pop    r15
  9f9911:	5d                                              	pop    rbp
  9f9912:	c3                                              	ret
  9f9913:	90                                              	nop
  9f9914:	90                                              	nop
  9f9915:	90                                              	nop
  9f9916:	90                                              	nop
  9f9917:	90                                              	nop
  9f9918:	90                                              	nop
  9f9919:	90                                              	nop
  9f991a:	90                                              	nop
  9f991b:	90                                              	nop
  9f991c:	90                                              	nop
  9f991d:	90                                              	nop
  9f991e:	90                                              	nop
  9f991f:	90                                              	nop
  9f9920:	55                                              	push   rbp
  9f9921:	48 89 e5                                        	mov    rbp,rsp
  9f9924:	41 56                                           	push   r14
  9f9926:	53                                              	push   rbx
  9f9927:	49 89 fe                                        	mov    r14,rdi
  9f992a:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  9f9933:	48 89 f3                                        	mov    rbx,rsi
  9f9936:	48 8d 35 5a 59 95 00                            	lea    rsi,[rip+0x95595a]        # 0x134f297
  9f993d:	31 d2                                           	xor    edx,edx
  9f993f:	e8 9c 0a 22 00                                  	call   0xc1a3e0
  9f9944:	ba 04 00 00 00                                  	mov    edx,0x4
  9f9949:	4c 89 f7                                        	mov    rdi,r14
  9f994c:	48 89 de                                        	mov    rsi,rbx
  9f994f:	5b                                              	pop    rbx
  9f9950:	41 5e                                           	pop    r14
  9f9952:	5d                                              	pop    rbp
  9f9953:	e9 78 f8 85 ff                                  	jmp    0x2591d0
  9f9958:	90                                              	nop
  9f9959:	90                                              	nop
  9f995a:	90                                              	nop
  9f995b:	90                                              	nop
  9f995c:	90                                              	nop
  9f995d:	90                                              	nop
  9f995e:	90                                              	nop
  9f995f:	90                                              	nop
  9f9960:	55                                              	push   rbp
  9f9961:	48 89 e5                                        	mov    rbp,rsp
  9f9964:	41 57                                           	push   r15
  9f9966:	41 56                                           	push   r14
  9f9968:	53                                              	push   rbx
  9f9969:	48 83 ec 18                                     	sub    rsp,0x18
  9f996d:	4c 8d 3d 9c 29 f2 02                            	lea    r15,[rip+0x2f2299c]        # 0x391c310
  9f9974:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  9f9977:	48 89 45 e0                                     	mov    QWORD PTR [rbp-0x20],rax
  9f997b:	85 ff                                           	test   edi,edi
  9f997d:	0f 84 a9 01 00 00                               	je     0x9f9b2c
  9f9983:	89 fb                                           	mov    ebx,edi
  9f9985:	48 8b 3d 34 a4 b6 01                            	mov    rdi,QWORD PTR [rip+0x1b6a434]        # 0x2563dc0
  9f998c:	48 8d 4d d8                                     	lea    rcx,[rbp-0x28]
  9f9990:	ba 10 80 00 00                                  	mov    edx,0x8010
  9f9995:	89 de                                           	mov    esi,ebx
  9f9997:	e8 44 05 9a ff                                  	call   0x399ee0
  9f999c:	48 85 c0                                        	test   rax,rax
  9f999f:	0f 84 87 01 00 00                               	je     0x9f9b2c
  9f99a5:	48 8d 3d 3c 46 1b 03                            	lea    rdi,[rip+0x31b463c]        # 0x3badfe8
  9f99ac:	49 89 c6                                        	mov    r14,rax
  9f99af:	31 f6                                           	xor    esi,esi
  9f99b1:	31 d2                                           	xor    edx,edx
  9f99b3:	31 c9                                           	xor    ecx,ecx
  9f99b5:	e8 66 21 25 00                                  	call   0xc4bb20
  9f99ba:	41 8b 86 b0 00 00 00                            	mov    eax,DWORD PTR [r14+0xb0]
  9f99c1:	83 e0 fe                                        	and    eax,0xfffffffe
  9f99c4:	83 f8 04                                        	cmp    eax,0x4
  9f99c7:	75 25                                           	jne    0x9f99ee
  9f99c9:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  9f99cc:	48 85 c0                                        	test   rax,rax
  9f99cf:	74 72                                           	je     0x9f9a43
  9f99d1:	4c 39 70 08                                     	cmp    QWORD PTR [rax+0x8],r14
  9f99d5:	0f 85 d3 01 00 00                               	jne    0x9f9bae
  9f99db:	49 8b 4e 08                                     	mov    rcx,QWORD PTR [r14+0x8]
  9f99df:	4c 39 31                                        	cmp    QWORD PTR [rcx],r14
  9f99e2:	0f 85 5f 01 00 00                               	jne    0x9f9b47
  9f99e8:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  9f99ec:	eb 69                                           	jmp    0x9f9a57
  9f99ee:	48 8b 05 0b 46 1b 03                            	mov    rax,QWORD PTR [rip+0x31b460b]        # 0x3bae000
  9f99f5:	48 8d 3d ec 45 1b 03                            	lea    rdi,[rip+0x31b45ec]        # 0x3badfe8
  9f99fc:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9f9a05:	31 f6                                           	xor    esi,esi
  9f9a07:	31 d2                                           	xor    edx,edx
  9f9a09:	48 83 e0 f1                                     	and    rax,0xfffffffffffffff1
  9f9a0d:	48 39 c8                                        	cmp    rax,rcx
  9f9a10:	75 07                                           	jne    0x9f9a19
  9f9a12:	e8 99 2a 25 00                                  	call   0xc4c4b0
  9f9a17:	eb 05                                           	jmp    0x9f9a1e
  9f9a19:	e8 e2 28 25 00                                  	call   0xc4c300
  9f9a1e:	41 8b 96 b0 00 00 00                            	mov    edx,DWORD PTR [r14+0xb0]
  9f9a25:	48 8d 3d 89 01 8e 00                            	lea    rdi,[rip+0x8e0189]        # 0x12d9bb5
  9f9a2c:	89 de                                           	mov    esi,ebx
  9f9a2e:	31 c0                                           	xor    eax,eax
  9f9a30:	e8 db 39 86 ff                                  	call   0x25d410
  9f9a35:	48 8b 7d d8                                     	mov    rdi,QWORD PTR [rbp-0x28]
  9f9a39:	e8 72 04 9a ff                                  	call   0x399eb0
  9f9a3e:	e9 e9 00 00 00                                  	jmp    0x9f9b2c
  9f9a43:	49 8b 46 08                                     	mov    rax,QWORD PTR [r14+0x8]
  9f9a47:	4c 39 30                                        	cmp    QWORD PTR [rax],r14
  9f9a4a:	0f 85 f7 00 00 00                               	jne    0x9f9b47
  9f9a50:	48 89 05 c1 45 1b 03                            	mov    QWORD PTR [rip+0x31b45c1],rax        # 0x3bae018
  9f9a57:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  9f9a5a:	49 8b 4e 08                                     	mov    rcx,QWORD PTR [r14+0x8]
  9f9a5e:	48 8d 3d 83 45 1b 03                            	lea    rdi,[rip+0x31b4583]        # 0x3badfe8
  9f9a65:	31 f6                                           	xor    esi,esi
  9f9a67:	31 d2                                           	xor    edx,edx
  9f9a69:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  9f9a6c:	ff 0d ae 45 1b 03                               	dec    DWORD PTR [rip+0x31b45ae]        # 0x3bae020
  9f9a72:	48 8b 05 87 45 1b 03                            	mov    rax,QWORD PTR [rip+0x31b4587]        # 0x3bae000
  9f9a79:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9f9a82:	48 83 e0 f1                                     	and    rax,0xfffffffffffffff1
  9f9a86:	48 39 c8                                        	cmp    rax,rcx
  9f9a89:	75 07                                           	jne    0x9f9a92
  9f9a8b:	e8 20 2a 25 00                                  	call   0xc4c4b0
  9f9a90:	eb 05                                           	jmp    0x9f9a97
  9f9a92:	e8 69 28 25 00                                  	call   0xc4c300
  9f9a97:	89 df                                           	mov    edi,ebx
  9f9a99:	e8 62 da ce ff                                  	call   0x6e7500
  9f9a9e:	85 c0                                           	test   eax,eax
  9f9aa0:	74 1b                                           	je     0x9f9abd
  9f9aa2:	89 df                                           	mov    edi,ebx
  9f9aa4:	e8 87 d6 ce ff                                  	call   0x6e7130
  9f9aa9:	85 c0                                           	test   eax,eax
  9f9aab:	74 10                                           	je     0x9f9abd
  9f9aad:	89 c6                                           	mov    esi,eax
  9f9aaf:	48 8d 3d 91 66 98 00                            	lea    rdi,[rip+0x986691]        # 0x1380147
  9f9ab6:	31 c0                                           	xor    eax,eax
  9f9ab8:	e8 53 39 86 ff                                  	call   0x25d410
  9f9abd:	41 8b 76 60                                     	mov    esi,DWORD PTR [r14+0x60]
  9f9ac1:	89 df                                           	mov    edi,ebx
  9f9ac3:	e8 c8 c0 ba ff                                  	call   0x5a5b90
  9f9ac8:	41 81 7e 60 00 01 00 02                         	cmp    DWORD PTR [r14+0x60],0x2000100
  9f9ad0:	75 05                                           	jne    0x9f9ad7
  9f9ad2:	e8 99 c0 ba ff                                  	call   0x5a5b70
  9f9ad7:	39 1d 57 45 1b 03                               	cmp    DWORD PTR [rip+0x31b4557],ebx        # 0x3bae034
  9f9add:	75 09                                           	jne    0x9f9ae8
  9f9adf:	4c 8d 35 4a 45 1b 03                            	lea    r14,[rip+0x31b454a]        # 0x3bae030
  9f9ae6:	eb 0f                                           	jmp    0x9f9af7
  9f9ae8:	39 1d 4e 45 1b 03                               	cmp    DWORD PTR [rip+0x31b454e],ebx        # 0x3bae03c
  9f9aee:	75 1c                                           	jne    0x9f9b0c
  9f9af0:	4c 8d 35 41 45 1b 03                            	lea    r14,[rip+0x31b4541]        # 0x3bae038
  9f9af7:	41 0f b7 3e                                     	movzx  edi,WORD PTR [r14]
  9f9afb:	e8 80 0d e6 ff                                  	call   0x85a880
  9f9b00:	85 c0                                           	test   eax,eax
  9f9b02:	75 7d                                           	jne    0x9f9b81
  9f9b04:	41 c7 46 04 ff ff ff ff                         	mov    DWORD PTR [r14+0x4],0xffffffff
  9f9b0c:	48 8b 7d d8                                     	mov    rdi,QWORD PTR [rbp-0x28]
  9f9b10:	e8 9b 03 9a ff                                  	call   0x399eb0
  9f9b15:	89 df                                           	mov    edi,ebx
  9f9b17:	e8 34 25 00 00                                  	call   0x9fc050
  9f9b1c:	48 8d 3d d9 7c 96 00                            	lea    rdi,[rip+0x967cd9]        # 0x13617fc
  9f9b23:	89 de                                           	mov    esi,ebx
  9f9b25:	31 c0                                           	xor    eax,eax
  9f9b27:	e8 e4 38 86 ff                                  	call   0x25d410
  9f9b2c:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  9f9b2f:	48 3b 45 e0                                     	cmp    rax,QWORD PTR [rbp-0x20]
  9f9b33:	75 0b                                           	jne    0x9f9b40
  9f9b35:	48 83 c4 18                                     	add    rsp,0x18
  9f9b39:	5b                                              	pop    rbx
  9f9b3a:	41 5e                                           	pop    r14
  9f9b3c:	41 5f                                           	pop    r15
  9f9b3e:	5d                                              	pop    rbp
  9f9b3f:	c3                                              	ret
  9f9b40:	e8 6b 3b d0 ff                                  	call   0x6fd6b0
  9f9b45:	0f 0b                                           	ud2
  9f9b47:	e8 04 7e df ff                                  	call   0x7f1950
  9f9b4c:	49 8b 56 08                                     	mov    rdx,QWORD PTR [r14+0x8]
  9f9b50:	48 8d 3d f0 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff0]        # 0x9f9b47
  9f9b57:	4c 89 f6                                        	mov    rsi,r14
  9f9b5a:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  9f9b5d:	e8 5e 85 df ff                                  	call   0x7f20c0
  9f9b62:	49 8b 4e 08                                     	mov    rcx,QWORD PTR [r14+0x8]
  9f9b66:	48 8d 35 fe 29 90 00                            	lea    rsi,[rip+0x9029fe]        # 0x12fc56b
  9f9b6d:	bf d9 00 00 00                                  	mov    edi,0xd9
  9f9b72:	4c 89 f2                                        	mov    rdx,r14
  9f9b75:	31 c0                                           	xor    eax,eax
  9f9b77:	4c 8b 01                                        	mov    r8,QWORD PTR [rcx]
  9f9b7a:	e8 91 0e 2a 00                                  	call   0xc9aa10
  9f9b7f:	0f 0b                                           	ud2
  9f9b81:	89 c3                                           	mov    ebx,eax
  9f9b83:	e8 c8 7d df ff                                  	call   0x7f1950
  9f9b88:	48 63 f3                                        	movsxd rsi,ebx
  9f9b8b:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x9f9b81
  9f9b92:	e8 09 7d df ff                                  	call   0x7f18a0
  9f9b97:	48 8d 35 34 9f 8e 00                            	lea    rsi,[rip+0x8e9f34]        # 0x12e3ad2
  9f9b9e:	bf dd 00 00 00                                  	mov    edi,0xdd
  9f9ba3:	89 da                                           	mov    edx,ebx
  9f9ba5:	31 c0                                           	xor    eax,eax
  9f9ba7:	e8 64 0e 2a 00                                  	call   0xc9aa10
  9f9bac:	0f 0b                                           	ud2
  9f9bae:	e8 9d 7d df ff                                  	call   0x7f1950
  9f9bb3:	49 8b 16                                        	mov    rdx,QWORD PTR [r14]
  9f9bb6:	48 8d 3d f1 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff1]        # 0x9f9bae
  9f9bbd:	4c 89 f6                                        	mov    rsi,r14
  9f9bc0:	4d 89 f0                                        	mov    r8,r14
  9f9bc3:	48 8b 4a 08                                     	mov    rcx,QWORD PTR [rdx+0x8]
  9f9bc7:	e8 b4 85 df ff                                  	call   0x7f2180
  9f9bcc:	49 8b 0e                                        	mov    rcx,QWORD PTR [r14]
  9f9bcf:	48 8d 35 e0 00 94 00                            	lea    rsi,[rip+0x9400e0]        # 0x1339cb6
  9f9bd6:	bf d5 00 00 00                                  	mov    edi,0xd5
  9f9bdb:	4c 89 f2                                        	mov    rdx,r14
  9f9bde:	4d 89 f1                                        	mov    r9,r14
  9f9be1:	31 c0                                           	xor    eax,eax
  9f9be3:	4c 8b 41 08                                     	mov    r8,QWORD PTR [rcx+0x8]
  9f9be7:	e8 24 0e 2a 00                                  	call   0xc9aa10
  9f9bec:	0f 0b                                           	ud2
  9f9bee:	90                                              	nop
  9f9bef:	90                                              	nop
  9f9bf0:	c6 06 00                                        	mov    BYTE PTR [rsi],0x0
  9f9bf3:	48 85 ff                                        	test   rdi,rdi
  9f9bf6:	0f 84 93 00 00 00                               	je     0x9f9c8f
  9f9bfc:	55                                              	push   rbp
  9f9bfd:	48 89 e5                                        	mov    rbp,rsp
  9f9c00:	41 57                                           	push   r15
  9f9c02:	41 56                                           	push   r14
  9f9c04:	53                                              	push   rbx
  9f9c05:	50                                              	push   rax
  9f9c06:	48 89 fb                                        	mov    rbx,rdi
  9f9c09:	49 89 d7                                        	mov    r15,rdx
  9f9c0c:	49 89 f6                                        	mov    r14,rsi
  9f9c0f:	e8 fc 31 0d 00                                  	call   0xacce10
  9f9c14:	85 c0                                           	test   eax,eax
  9f9c16:	74 73                                           	je     0x9f9c8b
  9f9c18:	48 8d 35 b9 cb 8e 00                            	lea    rsi,[rip+0x8ecbb9]        # 0x12e67d8
  9f9c1f:	48 89 df                                        	mov    rdi,rbx
  9f9c22:	e8 99 0e 16 00                                  	call   0xb5aac0
  9f9c27:	48 85 c0                                        	test   rax,rax
  9f9c2a:	74 5f                                           	je     0x9f9c8b
  9f9c2c:	48 89 c7                                        	mov    rdi,rax
  9f9c2f:	48 89 c3                                        	mov    rbx,rax
  9f9c32:	e8 f9 06 16 00                                  	call   0xb5a330
  9f9c37:	83 f8 02                                        	cmp    eax,0x2
  9f9c3a:	75 56                                           	jne    0x9f9c92
  9f9c3c:	48 8d 35 15 e6 8f 00                            	lea    rsi,[rip+0x8fe615]        # 0x12f8258
  9f9c43:	48 89 df                                        	mov    rdi,rbx
  9f9c46:	e8 75 0e 16 00                                  	call   0xb5aac0
  9f9c4b:	48 85 c0                                        	test   rax,rax
  9f9c4e:	74 3b                                           	je     0x9f9c8b
  9f9c50:	48 89 c7                                        	mov    rdi,rax
  9f9c53:	48 89 c3                                        	mov    rbx,rax
  9f9c56:	e8 d5 06 16 00                                  	call   0xb5a330
  9f9c5b:	83 f8 03                                        	cmp    eax,0x3
  9f9c5e:	75 3b                                           	jne    0x9f9c9b
  9f9c60:	48 89 df                                        	mov    rdi,rbx
  9f9c63:	e8 d8 06 16 00                                  	call   0xb5a340
  9f9c68:	48 89 c7                                        	mov    rdi,rax
  9f9c6b:	48 89 c3                                        	mov    rbx,rax
  9f9c6e:	e8 4d 00 00 00                                  	call   0x9f9cc0
  9f9c73:	85 c0                                           	test   eax,eax
  9f9c75:	75 3b                                           	jne    0x9f9cb2
  9f9c77:	83 3d 92 a4 1b 03 00                            	cmp    DWORD PTR [rip+0x31ba492],0x0        # 0x3bb4110
  9f9c7e:	75 0b                                           	jne    0x9f9c8b
  9f9c80:	48 c1 e3 14                                     	shl    rbx,0x14
  9f9c84:	49 89 1f                                        	mov    QWORD PTR [r15],rbx
  9f9c87:	41 c6 06 01                                     	mov    BYTE PTR [r14],0x1
  9f9c8b:	31 c0                                           	xor    eax,eax
  9f9c8d:	eb 23                                           	jmp    0x9f9cb2
  9f9c8f:	31 c0                                           	xor    eax,eax
  9f9c91:	c3                                              	ret
  9f9c92:	48 8d 15 37 76 ed 00                            	lea    rdx,[rip+0xed7637]        # 0x18d12d0
  9f9c99:	eb 07                                           	jmp    0x9f9ca2
  9f9c9b:	48 8d 15 7e 76 ed 00                            	lea    rdx,[rip+0xed767e]        # 0x18d1320
  9f9ca2:	31 ff                                           	xor    edi,edi
  9f9ca4:	31 f6                                           	xor    esi,esi
  9f9ca6:	31 c0                                           	xor    eax,eax
  9f9ca8:	e8 23 a8 10 00                                  	call   0xb044d0
  9f9cad:	b8 16 00 00 00                                  	mov    eax,0x16
  9f9cb2:	48 83 c4 08                                     	add    rsp,0x8
  9f9cb6:	5b                                              	pop    rbx
  9f9cb7:	41 5e                                           	pop    r14
  9f9cb9:	41 5f                                           	pop    r15
  9f9cbb:	5d                                              	pop    rbp
  9f9cbc:	c3                                              	ret
  9f9cbd:	90                                              	nop
  9f9cbe:	90                                              	nop
  9f9cbf:	90                                              	nop
  9f9cc0:	55                                              	push   rbp
  9f9cc1:	48 89 e5                                        	mov    rbp,rsp
  9f9cc4:	53                                              	push   rbx
  9f9cc5:	50                                              	push   rax
  9f9cc6:	48 89 fb                                        	mov    rbx,rdi
  9f9cc9:	48 85 ff                                        	test   rdi,rdi
  9f9ccc:	78 0e                                           	js     0x9f9cdc
  9f9cce:	e8 6d e9 00 00                                  	call   0xa08640
  9f9cd3:	48 c1 e8 14                                     	shr    rax,0x14
  9f9cd7:	48 39 d8                                        	cmp    rax,rbx
  9f9cda:	73 25                                           	jae    0x9f9d01
  9f9cdc:	48 c1 e3 14                                     	shl    rbx,0x14
  9f9ce0:	48 8d 15 99 76 ed 00                            	lea    rdx,[rip+0xed7699]        # 0x18d1380
  9f9ce7:	48 89 d9                                        	mov    rcx,rbx
  9f9cea:	31 ff                                           	xor    edi,edi
  9f9cec:	31 f6                                           	xor    esi,esi
  9f9cee:	31 c0                                           	xor    eax,eax
  9f9cf0:	e8 db a7 10 00                                  	call   0xb044d0
  9f9cf5:	b8 16 00 00 00                                  	mov    eax,0x16
  9f9cfa:	48 83 c4 08                                     	add    rsp,0x8
  9f9cfe:	5b                                              	pop    rbx
  9f9cff:	5d                                              	pop    rbp
  9f9d00:	c3                                              	ret
  9f9d01:	f6 c3 01                                        	test   bl,0x1
  9f9d04:	75 37                                           	jne    0x9f9d3d
  9f9d06:	31 c0                                           	xor    eax,eax
  9f9d08:	83 3d 01 a4 1b 03 00                            	cmp    DWORD PTR [rip+0x31ba401],0x0        # 0x3bb4110
  9f9d0f:	74 e9                                           	je     0x9f9cfa
  9f9d11:	4c 8b 05 a0 a3 1b 03                            	mov    r8,QWORD PTR [rip+0x31ba3a0]        # 0x3bb40b8
  9f9d18:	48 c1 e3 14                                     	shl    rbx,0x14
  9f9d1c:	4c 39 c3                                        	cmp    rbx,r8
  9f9d1f:	74 d9                                           	je     0x9f9cfa
  9f9d21:	48 8d 15 e8 76 ed 00                            	lea    rdx,[rip+0xed76e8]        # 0x18d1410
  9f9d28:	48 89 d9                                        	mov    rcx,rbx
  9f9d2b:	31 ff                                           	xor    edi,edi
  9f9d2d:	31 f6                                           	xor    esi,esi
  9f9d2f:	31 c0                                           	xor    eax,eax
  9f9d31:	e8 9a a7 10 00                                  	call   0xb044d0
  9f9d36:	b8 73 00 00 00                                  	mov    eax,0x73
  9f9d3b:	eb bd                                           	jmp    0x9f9cfa
  9f9d3d:	48 c1 e3 14                                     	shl    rbx,0x14
  9f9d41:	48 8d 15 78 76 ed 00                            	lea    rdx,[rip+0xed7678]        # 0x18d13c0
  9f9d48:	eb 9d                                           	jmp    0x9f9ce7
  9f9d4a:	90                                              	nop
  9f9d4b:	90                                              	nop
  9f9d4c:	90                                              	nop
  9f9d4d:	90                                              	nop
  9f9d4e:	90                                              	nop
  9f9d4f:	90                                              	nop
  9f9d50:	55                                              	push   rbp
  9f9d51:	48 89 e5                                        	mov    rbp,rsp
  9f9d54:	41 56                                           	push   r14
  9f9d56:	53                                              	push   rbx
  9f9d57:	48 83 ec 10                                     	sub    rsp,0x10
  9f9d5b:	48 8d 1d ae 25 f2 02                            	lea    rbx,[rip+0x2f225ae]        # 0x391c310
  9f9d62:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  9f9d65:	48 89 45 e8                                     	mov    QWORD PTR [rbp-0x18],rax
  9f9d69:	48 85 ff                                        	test   rdi,rdi
  9f9d6c:	0f 84 81 00 00 00                               	je     0x9f9df3
  9f9d72:	48 8d 05 0e 51 8d 00                            	lea    rax,[rip+0x8d510e]        # 0x12cee87
  9f9d79:	49 89 fe                                        	mov    r14,rdi
  9f9d7c:	48 89 f7                                        	mov    rdi,rsi
  9f9d7f:	48 8d 55 e0                                     	lea    rdx,[rbp-0x20]
  9f9d83:	48 c7 45 e0 00 00 00 00                         	mov    QWORD PTR [rbp-0x20],0x0
  9f9d8b:	48 89 c6                                        	mov    rsi,rax
  9f9d8e:	e8 5d 89 00 00                                  	call   0xa026f0
  9f9d93:	85 c0                                           	test   eax,eax
  9f9d95:	75 5e                                           	jne    0x9f9df5
  9f9d97:	4c 8b 45 e0                                     	mov    r8,QWORD PTR [rbp-0x20]
  9f9d9b:	4d 85 c0                                        	test   r8,r8
  9f9d9e:	74 53                                           	je     0x9f9df3
  9f9da0:	49 81 f8 01 00 a0 00                            	cmp    r8,0xa00001
  9f9da7:	72 1e                                           	jb     0x9f9dc7
  9f9da9:	48 8d 15 b0 76 ed 00                            	lea    rdx,[rip+0xed76b0]        # 0x18d1460
  9f9db0:	b9 00 00 a0 00                                  	mov    ecx,0xa00000
  9f9db5:	31 ff                                           	xor    edi,edi
  9f9db7:	31 f6                                           	xor    esi,esi
  9f9db9:	31 c0                                           	xor    eax,eax
  9f9dbb:	e8 10 a7 10 00                                  	call   0xb044d0
  9f9dc0:	b8 16 00 00 00                                  	mov    eax,0x16
  9f9dc5:	eb 2e                                           	jmp    0x9f9df5
  9f9dc7:	4c 89 c0                                        	mov    rax,r8
  9f9dca:	48 c1 e0 32                                     	shl    rax,0x32
  9f9dce:	74 1c                                           	je     0x9f9dec
  9f9dd0:	48 8d 15 09 77 ed 00                            	lea    rdx,[rip+0xed7709]        # 0x18d14e0
  9f9dd7:	4c 89 c1                                        	mov    rcx,r8
  9f9dda:	31 ff                                           	xor    edi,edi
  9f9ddc:	31 f6                                           	xor    esi,esi
  9f9dde:	31 c0                                           	xor    eax,eax
  9f9de0:	e8 eb a6 10 00                                  	call   0xb044d0
  9f9de5:	b8 16 00 00 00                                  	mov    eax,0x16
  9f9dea:	eb 09                                           	jmp    0x9f9df5
  9f9dec:	4d 01 86 a8 05 00 00                            	add    QWORD PTR [r14+0x5a8],r8
  9f9df3:	31 c0                                           	xor    eax,eax
  9f9df5:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  9f9df8:	48 3b 4d e8                                     	cmp    rcx,QWORD PTR [rbp-0x18]
  9f9dfc:	75 09                                           	jne    0x9f9e07
  9f9dfe:	48 83 c4 10                                     	add    rsp,0x10
  9f9e02:	5b                                              	pop    rbx
  9f9e03:	41 5e                                           	pop    r14
  9f9e05:	5d                                              	pop    rbp
  9f9e06:	c3                                              	ret
  9f9e07:	e8 a4 38 d0 ff                                  	call   0x6fd6b0
  9f9e0c:	0f 0b                                           	ud2
  9f9e0e:	90                                              	nop
  9f9e0f:	90                                              	nop
  9f9e10:	55                                              	push   rbp
  9f9e11:	48 89 e5                                        	mov    rbp,rsp
  9f9e14:	41 57                                           	push   r15
  9f9e16:	41 56                                           	push   r14
  9f9e18:	41 55                                           	push   r13
  9f9e1a:	41 54                                           	push   r12
  9f9e1c:	53                                              	push   rbx
  9f9e1d:	48 83 ec 58                                     	sub    rsp,0x58
  9f9e21:	4c 8d 3d e8 24 f2 02                            	lea    r15,[rip+0x2f224e8]        # 0x391c310
  9f9e28:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  9f9e2b:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9f9e2f:	8b 05 db a2 1b 03                               	mov    eax,DWORD PTR [rip+0x31ba2db]        # 0x3bb4110
  9f9e35:	44 8d 50 01                                     	lea    r10d,[rax+0x1]
  9f9e39:	44 89 15 d0 a2 1b 03                            	mov    DWORD PTR [rip+0x31ba2d0],r10d        # 0x3bb4110
  9f9e40:	85 c0                                           	test   eax,eax
  9f9e42:	0f 8f 38 03 00 00                               	jg     0x9fa180
  9f9e48:	48 8b 05 39 42 1b 03                            	mov    rax,QWORD PTR [rip+0x31b4239]        # 0x3bae088
  9f9e4f:	83 b8 84 00 00 00 00                            	cmp    DWORD PTR [rax+0x84],0x0
  9f9e56:	0f 8f 24 03 00 00                               	jg     0x9fa180
  9f9e5c:	45 89 c7                                        	mov    r15d,r8d
  9f9e5f:	45 89 cd                                        	mov    r13d,r9d
  9f9e62:	89 75 88                                        	mov    DWORD PTR [rbp-0x78],esi
  9f9e65:	89 55 84                                        	mov    DWORD PTR [rbp-0x7c],edx
  9f9e68:	41 89 fc                                        	mov    r12d,edi
  9f9e6b:	89 4d 90                                        	mov    DWORD PTR [rbp-0x70],ecx
  9f9e6e:	e8 cd e7 00 00                                  	call   0xa08640
  9f9e73:	49 89 c6                                        	mov    r14,rax
  9f9e76:	48 85 c0                                        	test   rax,rax
  9f9e79:	74 2d                                           	je     0x9f9ea8
  9f9e7b:	48 8b 1d 96 a2 1b 03                            	mov    rbx,QWORD PTR [rip+0x31ba296]        # 0x3bb4118
  9f9e82:	e8 b9 e7 00 00                                  	call   0xa08640
  9f9e87:	48 29 c3                                        	sub    rbx,rax
  9f9e8a:	e8 b1 e7 00 00                                  	call   0xa08640
  9f9e8f:	48 8d 3d 7a b4 1b 03                            	lea    rdi,[rip+0x31bb47a]        # 0x3bb5310
  9f9e96:	48 8d 35 63 b4 1b 03                            	lea    rsi,[rip+0x31bb463]        # 0x3bb5300
  9f9e9d:	48 89 da                                        	mov    rdx,rbx
  9f9ea0:	48 89 c1                                        	mov    rcx,rax
  9f9ea3:	e8 e8 e4 00 00                                  	call   0xa08390
  9f9ea8:	45 84 ff                                        	test   r15b,r15b
  9f9eab:	74 0f                                           	je     0x9f9ebc
  9f9ead:	4c 8d 3d 5c 24 f2 02                            	lea    r15,[rip+0x2f2245c]        # 0x391c310
  9f9eb4:	4c 89 f3                                        	mov    rbx,r14
  9f9eb7:	44 89 e2                                        	mov    edx,r12d
  9f9eba:	eb 17                                           	jmp    0x9f9ed3
  9f9ebc:	4c 8d 3d 4d 24 f2 02                            	lea    r15,[rip+0x2f2244d]        # 0x391c310
  9f9ec3:	44 89 e2                                        	mov    edx,r12d
  9f9ec6:	45 84 ed                                        	test   r13b,r13b
  9f9ec9:	0f 84 4d 02 00 00                               	je     0x9fa11c
  9f9ecf:	48 8b 5d 10                                     	mov    rbx,QWORD PTR [rbp+0x10]
  9f9ed3:	48 c1 eb 14                                     	shr    rbx,0x14
  9f9ed7:	89 5d 9c                                        	mov    DWORD PTR [rbp-0x64],ebx
  9f9eda:	48 63 c3                                        	movsxd rax,ebx
  9f9edd:	48 8b 35 34 a2 1b 03                            	mov    rsi,QWORD PTR [rip+0x31ba234]        # 0x3bb4118
  9f9ee4:	4c 89 f1                                        	mov    rcx,r14
  9f9ee7:	45 31 e4                                        	xor    r12d,r12d
  9f9eea:	48 c1 e0 14                                     	shl    rax,0x14
  9f9eee:	48 29 c1                                        	sub    rcx,rax
  9f9ef1:	48 89 05 c0 a1 1b 03                            	mov    QWORD PTR [rip+0x31ba1c0],rax        # 0x3bb40b8
  9f9ef8:	4c 0f 43 e1                                     	cmovae r12,rcx
  9f9efc:	4c 29 e6                                        	sub    rsi,r12
  9f9eff:	48 89 35 1a a2 1b 03                            	mov    QWORD PTR [rip+0x31ba21a],rsi        # 0x3bb4120
  9f9f06:	49 39 c6                                        	cmp    r14,rax
  9f9f09:	0f 86 71 02 00 00                               	jbe    0x9fa180
  9f9f0f:	89 d3                                           	mov    ebx,edx
  9f9f11:	e8 8a f6 9c ff                                  	call   0x3c95a0
  9f9f16:	8b 45 90                                        	mov    eax,DWORD PTR [rbp-0x70]
  9f9f19:	84 db                                           	test   bl,bl
  9f9f1b:	0f 84 5f 02 00 00                               	je     0x9fa180
  9f9f21:	48 8b 3d 60 41 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b4160]        # 0x3bae088
  9f9f28:	0f b6 c0                                        	movzx  eax,al
  9f9f2b:	48 89 45 90                                     	mov    QWORD PTR [rbp-0x70],rax
  9f9f2f:	e8 5c 95 9c ff                                  	call   0x3c3490
  9f9f34:	48 8b 3d 4d 41 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b414d]        # 0x3bae088
  9f9f3b:	e8 d0 96 9c ff                                  	call   0x3c3610
  9f9f40:	48 8b 3d 41 41 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b4141]        # 0x3bae088
  9f9f47:	e8 34 96 9c ff                                  	call   0x3c3580
  9f9f4c:	48 8b 3d 35 41 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b4135]        # 0x3bae088
  9f9f53:	48 8b 15 c6 a1 1b 03                            	mov    rdx,QWORD PTR [rip+0x31ba1c6]        # 0x3bb4120
  9f9f5a:	4c 89 e1                                        	mov    rcx,r12
  9f9f5d:	31 f6                                           	xor    esi,esi
  9f9f5f:	e8 ec e1 9c ff                                  	call   0x3c8150
  9f9f64:	48 8b 3d 1d 41 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b411d]        # 0x3bae088
  9f9f6b:	e8 c0 94 9c ff                                  	call   0x3c3430
  9f9f70:	48 8b 3d 11 41 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b4111]        # 0x3bae088
  9f9f77:	e8 c4 95 9c ff                                  	call   0x3c3540
  9f9f7c:	48 8b 3d 05 41 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b4105]        # 0x3bae088
  9f9f83:	e8 f8 95 9c ff                                  	call   0x3c3580
  9f9f88:	48 8b 35 91 a1 1b 03                            	mov    rsi,QWORD PTR [rip+0x31ba191]        # 0x3bb4120
  9f9f8f:	bf 04 00 00 00                                  	mov    edi,0x4
  9f9f94:	4c 89 e2                                        	mov    rdx,r12
  9f9f97:	e8 44 c7 2b 00                                  	call   0xcb66e0
  9f9f9c:	85 c0                                           	test   eax,eax
  9f9f9e:	74 14                                           	je     0x9f9fb4
  9f9fa0:	89 c1                                           	mov    ecx,eax
  9f9fa2:	48 8d 15 b7 6d ed 00                            	lea    rdx,[rip+0xed6db7]        # 0x18d0d60
  9f9fa9:	31 ff                                           	xor    edi,edi
  9f9fab:	31 f6                                           	xor    esi,esi
  9f9fad:	31 c0                                           	xor    eax,eax
  9f9faf:	e8 1c a5 10 00                                  	call   0xb044d0
  9f9fb4:	48 ff 4d 90                                     	dec    QWORD PTR [rbp-0x70]
  9f9fb8:	4c 89 65 88                                     	mov    QWORD PTR [rbp-0x78],r12
  9f9fbc:	e8 ff e5 00 00                                  	call   0xa085c0
  9f9fc1:	84 c0                                           	test   al,al
  9f9fc3:	74 12                                           	je     0x9f9fd7
  9f9fc5:	48 8d 15 84 76 ed 00                            	lea    rdx,[rip+0xed7684]        # 0x18d1650
  9f9fcc:	31 ff                                           	xor    edi,edi
  9f9fce:	31 f6                                           	xor    esi,esi
  9f9fd0:	31 c0                                           	xor    eax,eax
  9f9fd2:	e8 f9 a4 10 00                                  	call   0xb044d0
  9f9fd7:	48 81 4d 90 11 80 00 00                         	or     QWORD PTR [rbp-0x70],0x8011
  9f9fdf:	48 8d 1d 42 ab b6 01                            	lea    rbx,[rip+0x1b6ab42]        # 0x2564b28
  9f9fe6:	41 bf 01 80 28 78                               	mov    r15d,0x78288001
  9f9fec:	45 31 ed                                        	xor    r13d,r13d
  9f9fef:	45 31 f6                                        	xor    r14d,r14d
  9f9ff2:	eb 34                                           	jmp    0x9fa028
  9f9ff4:	41 8d 7d 01                                     	lea    edi,[r13+0x1]
  9f9ff8:	4c 89 f6                                        	mov    rsi,r14
  9f9ffb:	4c 89 e2                                        	mov    rdx,r12
  9f9ffe:	e8 6d f5 9c ff                                  	call   0x3c9570
  9fa003:	4d 89 e6                                        	mov    r14,r12
  9fa006:	66 2e 0f 1f 84 00 00 00 00 00                   	cs nop WORD PTR [rax+rax*1+0x0]
  9fa010:	49 ff c5                                        	inc    r13
  9fa013:	48 83 c3 20                                     	add    rbx,0x20
  9fa017:	41 81 c7 00 01 00 00                            	add    r15d,0x100
  9fa01e:	49 83 fd 30                                     	cmp    r13,0x30
  9fa022:	0f 84 22 01 00 00                               	je     0x9fa14a
  9fa028:	44 89 ff                                        	mov    edi,r15d
  9fa02b:	48 8d 75 98                                     	lea    rsi,[rbp-0x68]
  9fa02f:	e8 8c d0 0e 00                                  	call   0xae70c0
  9fa034:	85 c0                                           	test   eax,eax
  9fa036:	74 28                                           	je     0x9fa060
  9fa038:	41 89 c4                                        	mov    r12d,eax
  9fa03b:	e8 d0 2d 0d 00                                  	call   0xacce10
  9fa040:	85 c0                                           	test   eax,eax
  9fa042:	74 15                                           	je     0x9fa059
  9fa044:	48 8d 15 85 76 ed 00                            	lea    rdx,[rip+0xed7685]        # 0x18d16d0
  9fa04b:	44 89 e1                                        	mov    ecx,r12d
  9fa04e:	31 ff                                           	xor    edi,edi
  9fa050:	31 f6                                           	xor    esi,esi
  9fa052:	31 c0                                           	xor    eax,eax
  9fa054:	e8 77 a4 10 00                                  	call   0xb044d0
  9fa059:	c7 45 98 00 00 00 00                            	mov    DWORD PTR [rbp-0x68],0x0
  9fa060:	e8 5b e5 00 00                                  	call   0xa085c0
  9fa065:	84 c0                                           	test   al,al
  9fa067:	74 37                                           	je     0x9fa0a0
  9fa069:	41 8d 45 fa                                     	lea    eax,[r13-0x6]
  9fa06d:	83 f8 07                                        	cmp    eax,0x7
  9fa070:	77 0e                                           	ja     0x9fa080
  9fa072:	c7 45 98 05 00 00 00                            	mov    DWORD PTR [rbp-0x68],0x5
  9fa079:	eb 45                                           	jmp    0x9fa0c0
  9fa07b:	0f 1f 44 00 00                                  	nop    DWORD PTR [rax+rax*1+0x0]
  9fa080:	49 83 fd 0e                                     	cmp    r13,0xe
  9fa084:	75 10                                           	jne    0x9fa096
  9fa086:	c7 45 98 02 00 00 00                            	mov    DWORD PTR [rbp-0x68],0x2
  9fa08d:	48 c7 03 00 00 00 01                            	mov    QWORD PTR [rbx],0x1000000
  9fa094:	eb 2a                                           	jmp    0x9fa0c0
  9fa096:	c7 45 98 00 00 00 00                            	mov    DWORD PTR [rbp-0x68],0x0
  9fa09d:	0f 1f 00                                        	nop    DWORD PTR [rax]
  9fa0a0:	49 83 fd 13                                     	cmp    r13,0x13
  9fa0a4:	75 1a                                           	jne    0x9fa0c0
  9fa0a6:	e8 95 e6 00 00                                  	call   0xa08740
  9fa0ab:	85 c0                                           	test   eax,eax
  9fa0ad:	74 11                                           	je     0x9fa0c0
  9fa0af:	c7 45 98 02 00 00 00                            	mov    DWORD PTR [rbp-0x68],0x2
  9fa0b6:	48 c7 03 00 00 00 20                            	mov    QWORD PTR [rbx],0x20000000
  9fa0bd:	0f 1f 00                                        	nop    DWORD PTR [rax]
  9fa0c0:	8b 45 98                                        	mov    eax,DWORD PTR [rbp-0x68]
  9fa0c3:	83 f8 05                                        	cmp    eax,0x5
  9fa0c6:	42 0f 94 44 2d a0                               	sete   BYTE PTR [rbp+r13*1-0x60]
  9fa0cc:	ff c8                                           	dec    eax
  9fa0ce:	83 f8 03                                        	cmp    eax,0x3
  9fa0d1:	0f 87 39 ff ff ff                               	ja     0x9fa010
  9fa0d7:	b9 01 00 00 00                                  	mov    ecx,0x1
  9fa0dc:	c4 e2 11 f7 c9                                  	shlx   ecx,ecx,r13d
  9fa0e1:	48 63 c9                                        	movsxd rcx,ecx
  9fa0e4:	48 85 4d 90                                     	test   QWORD PTR [rbp-0x70],rcx
  9fa0e8:	0f 84 22 ff ff ff                               	je     0x9fa010
  9fa0ee:	89 c0                                           	mov    eax,eax
  9fa0f0:	4c 8b 64 c3 f8                                  	mov    r12,QWORD PTR [rbx+rax*8-0x8]
  9fa0f5:	4d 01 f4                                        	add    r12,r14
  9fa0f8:	4c 39 65 88                                     	cmp    QWORD PTR [rbp-0x78],r12
  9fa0fc:	0f 83 f2 fe ff ff                               	jae    0x9f9ff4
  9fa102:	48 8d 15 17 76 ed 00                            	lea    rdx,[rip+0xed7617]        # 0x18d1720
  9fa109:	44 89 e9                                        	mov    ecx,r13d
  9fa10c:	31 ff                                           	xor    edi,edi
  9fa10e:	31 f6                                           	xor    esi,esi
  9fa110:	31 c0                                           	xor    eax,eax
  9fa112:	e8 b9 a3 10 00                                  	call   0xb044d0
  9fa117:	e9 f4 fe ff ff                                  	jmp    0x9fa010
  9fa11c:	80 7d 88 00                                     	cmp    BYTE PTR [rbp-0x78],0x0
  9fa120:	74 76                                           	je     0x9fa198
  9fa122:	8b 45 84                                        	mov    eax,DWORD PTR [rbp-0x7c]
  9fa125:	3c 02                                           	cmp    al,0x2
  9fa127:	0f 84 9e 00 00 00                               	je     0x9fa1cb
  9fa12d:	0f b6 c8                                        	movzx  ecx,al
  9fa130:	83 f9 01                                        	cmp    ecx,0x1
  9fa133:	0f 85 a3 00 00 00                               	jne    0x9fa1dc
  9fa139:	c7 45 9c 80 12 00 00                            	mov    DWORD PTR [rbp-0x64],0x1280
  9fa140:	bb 80 12 00 00                                  	mov    ebx,0x1280
  9fa145:	e9 90 fd ff ff                                  	jmp    0x9f9eda
  9fa14a:	4c 8d 3d bf 21 f2 02                            	lea    r15,[rip+0x2f221bf]        # 0x391c310
  9fa151:	4c 8b 65 88                                     	mov    r12,QWORD PTR [rbp-0x78]
  9fa155:	31 db                                           	xor    ebx,ebx
  9fa157:	eb 10                                           	jmp    0x9fa169
  9fa159:	0f 1f 80 00 00 00 00                            	nop    DWORD PTR [rax+0x0]
  9fa160:	48 ff c3                                        	inc    rbx
  9fa163:	48 83 fb 30                                     	cmp    rbx,0x30
  9fa167:	74 17                                           	je     0x9fa180
  9fa169:	80 7c 1d a0 01                                  	cmp    BYTE PTR [rbp+rbx*1-0x60],0x1
  9fa16e:	75 f0                                           	jne    0x9fa160
  9fa170:	8d 7b 01                                        	lea    edi,[rbx+0x1]
  9fa173:	4c 89 f6                                        	mov    rsi,r14
  9fa176:	4c 89 e2                                        	mov    rdx,r12
  9fa179:	e8 f2 f3 9c ff                                  	call   0x3c9570
  9fa17e:	eb e0                                           	jmp    0x9fa160
  9fa180:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  9fa183:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  9fa187:	75 7e                                           	jne    0x9fa207
  9fa189:	48 83 c4 58                                     	add    rsp,0x58
  9fa18d:	5b                                              	pop    rbx
  9fa18e:	41 5c                                           	pop    r12
  9fa190:	41 5d                                           	pop    r13
  9fa192:	41 5e                                           	pop    r14
  9fa194:	41 5f                                           	pop    r15
  9fa196:	5d                                              	pop    rbp
  9fa197:	c3                                              	ret
  9fa198:	84 d2                                           	test   dl,dl
  9fa19a:	74 21                                           	je     0x9fa1bd
  9fa19c:	e8 6f 2c 0d 00                                  	call   0xacce10
  9fa1a1:	44 89 e2                                        	mov    edx,r12d
  9fa1a4:	85 c0                                           	test   eax,eax
  9fa1a6:	74 15                                           	je     0x9fa1bd
  9fa1a8:	48 8d 75 9c                                     	lea    rsi,[rbp-0x64]
  9fa1ac:	bf 00 01 28 78                                  	mov    edi,0x78280100
  9fa1b1:	e8 0a cf 0e 00                                  	call   0xae70c0
  9fa1b6:	44 89 e2                                        	mov    edx,r12d
  9fa1b9:	85 c0                                           	test   eax,eax
  9fa1bb:	74 42                                           	je     0x9fa1ff
  9fa1bd:	31 db                                           	xor    ebx,ebx
  9fa1bf:	c7 45 9c 00 00 00 00                            	mov    DWORD PTR [rbp-0x64],0x0
  9fa1c6:	e9 0f fd ff ff                                  	jmp    0x9f9eda
  9fa1cb:	c7 45 9c 00 15 00 00                            	mov    DWORD PTR [rbp-0x64],0x1500
  9fa1d2:	bb 00 15 00 00                                  	mov    ebx,0x1500
  9fa1d7:	e9 fe fc ff ff                                  	jmp    0x9f9eda
  9fa1dc:	48 8d 15 0d 74 ed 00                            	lea    rdx,[rip+0xed740d]        # 0x18d15f0
  9fa1e3:	31 db                                           	xor    ebx,ebx
  9fa1e5:	31 ff                                           	xor    edi,edi
  9fa1e7:	31 f6                                           	xor    esi,esi
  9fa1e9:	31 c0                                           	xor    eax,eax
  9fa1eb:	e8 e0 a2 10 00                                  	call   0xb044d0
  9fa1f0:	44 89 e2                                        	mov    edx,r12d
  9fa1f3:	c7 45 9c 00 00 00 00                            	mov    DWORD PTR [rbp-0x64],0x0
  9fa1fa:	e9 db fc ff ff                                  	jmp    0x9f9eda
  9fa1ff:	8b 5d 9c                                        	mov    ebx,DWORD PTR [rbp-0x64]
  9fa202:	e9 d3 fc ff ff                                  	jmp    0x9f9eda
  9fa207:	e8 a4 34 d0 ff                                  	call   0x6fd6b0
  9fa20c:	0f 0b                                           	ud2
  9fa20e:	90                                              	nop
  9fa20f:	90                                              	nop
  9fa210:	55                                              	push   rbp
  9fa211:	48 89 e5                                        	mov    rbp,rsp
  9fa214:	41 57                                           	push   r15
  9fa216:	41 56                                           	push   r14
  9fa218:	41 55                                           	push   r13
  9fa21a:	41 54                                           	push   r12
  9fa21c:	53                                              	push   rbx
  9fa21d:	48 83 ec 18                                     	sub    rsp,0x18
  9fa221:	8b 05 05 9f 1b 03                               	mov    eax,DWORD PTR [rip+0x31b9f05]        # 0x3bb412c
  9fa227:	49 89 cd                                        	mov    r13,rcx
  9fa22a:	85 c0                                           	test   eax,eax
  9fa22c:	0f 84 33 02 00 00                               	je     0x9fa465
  9fa232:	f3 44 0f bc f8                                  	tzcnt  r15d,eax
  9fa237:	44 0f b3 f8                                     	btr    eax,r15d
  9fa23b:	89 05 eb 9e 1b 03                               	mov    DWORD PTR [rip+0x31b9eeb],eax        # 0x3bb412c
  9fa241:	45 85 ff                                        	test   r15d,r15d
  9fa244:	0f 84 1b 02 00 00                               	je     0x9fa465
  9fa24a:	41 89 fe                                        	mov    r14d,edi
  9fa24d:	89 75 d4                                        	mov    DWORD PTR [rbp-0x2c],esi
  9fa250:	48 89 55 c8                                     	mov    QWORD PTR [rbp-0x38],rdx
  9fa254:	48 8d 3d 4c 33 91 00                            	lea    rdi,[rip+0x91334c]        # 0x130d5a7
  9fa25b:	44 89 fa                                        	mov    edx,r15d
  9fa25e:	31 c0                                           	xor    eax,eax
  9fa260:	44 89 f6                                        	mov    esi,r14d
  9fa263:	e8 a8 31 86 ff                                  	call   0x25d410
  9fa268:	48 8d 3d 89 27 07 01                            	lea    rdi,[rip+0x1072789]        # 0x1a6c9f8
  9fa26f:	48 2b 3d 82 2f 06 01                            	sub    rdi,QWORD PTR [rip+0x1062f82]        # 0x1a5d1f8
  9fa276:	4c 8d 25 13 9a b6 01                            	lea    r12,[rip+0x1b69a13]        # 0x2563c90
  9fa27d:	ba 02 01 00 00                                  	mov    edx,0x102
  9fa282:	4c 89 e6                                        	mov    rsi,r12
  9fa285:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  9fa28c:	e8 bf e8 20 00                                  	call   0xc08b50
  9fa291:	48 8b 3d 80 9e 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b9e80]        # 0x3bb4118
  9fa298:	48 2b 3d 19 3d 1b 03                            	sub    rdi,QWORD PTR [rip+0x31b3d19]        # 0x3badfb8
  9fa29f:	4c 89 e6                                        	mov    rsi,r12
  9fa2a2:	ba 02 01 00 00                                  	mov    edx,0x102
  9fa2a7:	48 89 c3                                        	mov    rbx,rax
  9fa2aa:	48 81 c7 ff ff 1f 00                            	add    rdi,0x1fffff
  9fa2b1:	48 c1 ef 15                                     	shr    rdi,0x15
  9fa2b5:	48 83 c7 3f                                     	add    rdi,0x3f
  9fa2b9:	48 83 e7 c0                                     	and    rdi,0xffffffffffffffc0
  9fa2bd:	e8 8e e8 20 00                                  	call   0xc08b50
  9fa2c2:	44 89 ff                                        	mov    edi,r15d
  9fa2c5:	48 89 43 28                                     	mov    QWORD PTR [rbx+0x28],rax
  9fa2c9:	48 c7 03 00 00 00 00                            	mov    QWORD PTR [rbx],0x0
  9fa2d0:	4c 89 6b 10                                     	mov    QWORD PTR [rbx+0x10],r13
  9fa2d4:	31 f6                                           	xor    esi,esi
  9fa2d6:	44 89 bb 20 01 00 00                            	mov    DWORD PTR [rbx+0x120],r15d
  9fa2dd:	e8 3e 96 9c ff                                  	call   0x3c3920
  9fa2e2:	44 89 f6                                        	mov    esi,r14d
  9fa2e5:	45 31 d2                                        	xor    r10d,r10d
  9fa2e8:	48 89 43 18                                     	mov    QWORD PTR [rbx+0x18],rax
  9fa2ec:	48 8d 3d 20 c8 93 00                            	lea    rdi,[rip+0x93c820]        # 0x1336b13
  9fa2f3:	f7 d6                                           	not    esi
  9fa2f5:	f7 c6 00 f0 00 00                               	test   esi,0xf000
  9fa2fb:	be 70 01 00 00                                  	mov    esi,0x170
  9fa300:	41 0f 95 c2                                     	setne  r10b
  9fa304:	31 d2                                           	xor    edx,edx
  9fa306:	31 c9                                           	xor    ecx,ecx
  9fa308:	45 31 c0                                        	xor    r8d,r8d
  9fa30b:	45 31 c9                                        	xor    r9d,r9d
  9fa30e:	41 c1 e2 10                                     	shl    r10d,0x10
  9fa312:	41 81 ca 00 04 00 00                            	or     r10d,0x400
  9fa319:	41 52                                           	push   r10
  9fa31b:	6a 07                                           	push   0x7
  9fa31d:	e8 be 0d a4 ff                                  	call   0x43b0e0
  9fa322:	48 83 c4 10                                     	add    rsp,0x10
  9fa326:	48 89 43 30                                     	mov    QWORD PTR [rbx+0x30],rax
  9fa32a:	44 89 b3 18 01 00 00                            	mov    DWORD PTR [rbx+0x118],r14d
  9fa331:	41 81 fe 00 00 01 00                            	cmp    r14d,0x10000
  9fa338:	0f 83 39 01 00 00                               	jae    0x9fa477
  9fa33e:	4c 8b 2d db 9d 1b 03                            	mov    r13,QWORD PTR [rip+0x31b9ddb]        # 0x3bb4120
  9fa345:	bf 00 00 00 40                                  	mov    edi,0x40000000
  9fa34a:	4c 89 6b 78                                     	mov    QWORD PTR [rbx+0x78],r13
  9fa34e:	4c 89 ab 80 00 00 00                            	mov    QWORD PTR [rbx+0x80],r13
  9fa355:	e8 56 90 b0 ff                                  	call   0x5033b0
  9fa35a:	48 89 83 98 00 00 00                            	mov    QWORD PTR [rbx+0x98],rax
  9fa361:	48 8b 15 50 3c 1b 03                            	mov    rdx,QWORD PTR [rip+0x31b3c50]        # 0x3badfb8
  9fa368:	8b 4d d4                                        	mov    ecx,DWORD PTR [rbp-0x2c]
  9fa36b:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  9fa36f:	48 89 93 88 00 00 00                            	mov    QWORD PTR [rbx+0x88],rdx
  9fa376:	89 8b 1c 01 00 00                               	mov    DWORD PTR [rbx+0x11c],ecx
  9fa37c:	48 89 43 08                                     	mov    QWORD PTR [rbx+0x8],rax
  9fa380:	48 89 98 a8 00 00 00                            	mov    QWORD PTR [rax+0xa8],rbx
  9fa387:	e8 b4 f5 c0 ff                                  	call   0x609940
  9fa38c:	85 c0                                           	test   eax,eax
  9fa38e:	74 5b                                           	je     0x9fa3eb
  9fa390:	48 8d 93 10 01 00 00                            	lea    rdx,[rbx+0x110]
  9fa397:	48 8d 35 34 cb 95 00                            	lea    rsi,[rip+0x95cb34]        # 0x1356ed2
  9fa39e:	48 89 df                                        	mov    rdi,rbx
  9fa3a1:	e8 fa 83 00 00                                  	call   0xa027a0
  9fa3a6:	8b 8b 40 01 00 00                               	mov    ecx,DWORD PTR [rbx+0x140]
  9fa3ac:	0f b6 c0                                        	movzx  eax,al
  9fa3af:	48 89 da                                        	mov    rdx,rbx
  9fa3b2:	48 8d 35 f9 6c 89 00                            	lea    rsi,[rip+0x896cf9]        # 0x12910b2
  9fa3b9:	48 89 df                                        	mov    rdi,rbx
  9fa3bc:	48 81 c2 14 01 00 00                            	add    rdx,0x114
  9fa3c3:	83 e1 fd                                        	and    ecx,0xfffffffd
  9fa3c6:	8d 04 41                                        	lea    eax,[rcx+rax*2]
  9fa3c9:	66 89 83 40 01 00 00                            	mov    WORD PTR [rbx+0x140],ax
  9fa3d0:	e8 cb 83 00 00                                  	call   0xa027a0
  9fa3d5:	8b 8b 40 01 00 00                               	mov    ecx,DWORD PTR [rbx+0x140]
  9fa3db:	0f b6 c0                                        	movzx  eax,al
  9fa3de:	83 e1 fb                                        	and    ecx,0xfffffffb
  9fa3e1:	8d 04 81                                        	lea    eax,[rcx+rax*4]
  9fa3e4:	66 89 83 40 01 00 00                            	mov    WORD PTR [rbx+0x140],ax
  9fa3eb:	8b 83 20 01 00 00                               	mov    eax,DWORD PTR [rbx+0x120]
  9fa3f1:	8b 3d 31 9d 1b 03                               	mov    edi,DWORD PTR [rip+0x31b9d31]        # 0x3bb4128
  9fa3f7:	48 89 1d e2 3b 1b 03                            	mov    QWORD PTR [rip+0x31b3be2],rbx        # 0x3badfe0
  9fa3fe:	89 05 bc e1 35 02                               	mov    DWORD PTR [rip+0x235e1bc],eax        # 0x2d585c0
  9fa404:	85 ff                                           	test   edi,edi
  9fa406:	74 29                                           	je     0x9fa431
  9fa408:	48 8b 05 f1 9c 1b 03                            	mov    rax,QWORD PTR [rip+0x31b9cf1]        # 0x3bb4100
  9fa40f:	48 85 c0                                        	test   rax,rax
  9fa412:	74 0e                                           	je     0x9fa422
  9fa414:	48 8b 80 90 00 00 00                            	mov    rax,QWORD PTR [rax+0x90]
  9fa41b:	4c 39 e8                                        	cmp    rax,r13
  9fa41e:	4c 0f 42 e8                                     	cmovb  r13,rax
  9fa422:	48 8b 35 8f 3b 1b 03                            	mov    rsi,QWORD PTR [rip+0x31b3b8f]        # 0x3badfb8
  9fa429:	4c 89 ea                                        	mov    rdx,r13
  9fa42c:	e8 bf 4f ef ff                                  	call   0x8ef3f0
  9fa431:	44 89 3d f0 9c 1b 03                            	mov    DWORD PTR [rip+0x31b9cf0],r15d        # 0x3bb4128
  9fa438:	41 81 fe ff f2 01 00                            	cmp    r14d,0x1f2ff
  9fa43f:	7f 70                                           	jg     0x9fa4b1
  9fa441:	41 81 fe 00 f0 00 00                            	cmp    r14d,0xf000
  9fa448:	0f 84 82 00 00 00                               	je     0x9fa4d0
  9fa44e:	41 81 fe 00 f1 00 00                            	cmp    r14d,0xf100
  9fa455:	74 79                                           	je     0x9fa4d0
  9fa457:	41 81 fe 00 f0 01 00                            	cmp    r14d,0x1f000
  9fa45e:	74 70                                           	je     0x9fa4d0
  9fa460:	e9 ed 00 00 00                                  	jmp    0x9fa552
  9fa465:	4c 89 ef                                        	mov    rdi,r13
  9fa468:	e8 53 fd 15 00                                  	call   0xb5a1c0
  9fa46d:	b8 0c 00 00 00                                  	mov    eax,0xc
  9fa472:	e9 0a 02 00 00                                  	jmp    0x9fa681
  9fa477:	41 81 fe 00 03 01 00                            	cmp    r14d,0x10300
  9fa47e:	0f 84 ba fe ff ff                               	je     0x9fa33e
  9fa484:	41 81 fe 00 0f 02 00                            	cmp    r14d,0x20f00
  9fa48b:	0f 84 ad fe ff ff                               	je     0x9fa33e
  9fa491:	41 81 fe 00 f0 01 00                            	cmp    r14d,0x1f000
  9fa498:	0f 84 a0 fe ff ff                               	je     0x9fa33e
  9fa49e:	49 c7 c5 00 00 c0 9c                            	mov    r13,0xffffffff9cc00000
  9fa4a5:	4c 03 2d 74 9c 1b 03                            	add    r13,QWORD PTR [rip+0x31b9c74]        # 0x3bb4120
  9fa4ac:	e9 94 fe ff ff                                  	jmp    0x9fa345
  9fa4b1:	41 81 fe 00 f3 01 00                            	cmp    r14d,0x1f300
  9fa4b8:	74 16                                           	je     0x9fa4d0
  9fa4ba:	41 81 fe 00 f1 00 02                            	cmp    r14d,0x200f100
  9fa4c1:	74 0d                                           	je     0x9fa4d0
  9fa4c3:	41 81 fe 00 f0 02 00                            	cmp    r14d,0x2f000
  9fa4ca:	0f 85 82 00 00 00                               	jne    0x9fa552
  9fa4d0:	48 8b 05 01 3b 1b 03                            	mov    rax,QWORD PTR [rip+0x31b3b01]        # 0x3badfd8
  9fa4d7:	a8 01                                           	test   al,0x1
  9fa4d9:	75 0d                                           	jne    0x9fa4e8
  9fa4db:	48 8b 05 f6 3a 1b 03                            	mov    rax,QWORD PTR [rip+0x31b3af6]        # 0x3badfd8
  9fa4e2:	48 83 e0 f0                                     	and    rax,0xfffffffffffffff0
  9fa4e6:	eb 02                                           	jmp    0x9fa4ea
  9fa4e8:	31 c0                                           	xor    eax,eax
  9fa4ea:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9fa4f3:	48 39 c8                                        	cmp    rax,rcx
  9fa4f6:	74 39                                           	je     0x9fa531
  9fa4f8:	4c 8d 3d c1 3a 1b 03                            	lea    r15,[rip+0x31b3ac1]        # 0x3badfc0
  9fa4ff:	31 f6                                           	xor    esi,esi
  9fa501:	31 d2                                           	xor    edx,edx
  9fa503:	31 c9                                           	xor    ecx,ecx
  9fa505:	4c 89 ff                                        	mov    rdi,r15
  9fa508:	e8 13 16 25 00                                  	call   0xc4bb20
  9fa50d:	bf 00 00 40 0b                                  	mov    edi,0xb400000
  9fa512:	be 00 00 20 00                                  	mov    esi,0x200000
  9fa517:	31 d2                                           	xor    edx,edx
  9fa519:	31 c9                                           	xor    ecx,ecx
  9fa51b:	e8 a0 d6 ff ff                                  	call   0x9f7bc0
  9fa520:	4c 89 ff                                        	mov    rdi,r15
  9fa523:	49 89 c6                                        	mov    r14,rax
  9fa526:	31 f6                                           	xor    esi,esi
  9fa528:	31 d2                                           	xor    edx,edx
  9fa52a:	e8 81 1f 25 00                                  	call   0xc4c4b0
  9fa52f:	eb 16                                           	jmp    0x9fa547
  9fa531:	bf 00 00 40 0b                                  	mov    edi,0xb400000
  9fa536:	be 00 00 20 00                                  	mov    esi,0x200000
  9fa53b:	31 d2                                           	xor    edx,edx
  9fa53d:	31 c9                                           	xor    ecx,ecx
  9fa53f:	e8 7c d6 ff ff                                  	call   0x9f7bc0
  9fa544:	49 89 c6                                        	mov    r14,rax
  9fa547:	4c 89 73 70                                     	mov    QWORD PTR [rbx+0x70],r14
  9fa54b:	48 89 1d 5e 3a 1b 03                            	mov    QWORD PTR [rip+0x31b3a5e],rbx        # 0x3badfb0
  9fa552:	31 c0                                           	xor    eax,eax
  9fa554:	83 bb 18 01 00 00 00                            	cmp    DWORD PTR [rbx+0x118],0x0
  9fa55b:	0f 85 20 01 00 00                               	jne    0x9fa681
  9fa561:	41 be 92 00 00 00                               	mov    r14d,0x92
  9fa567:	4c 03 73 08                                     	add    r14,QWORD PTR [rbx+0x8]
  9fa56b:	48 8b 7b 10                                     	mov    rdi,QWORD PTR [rbx+0x10]
  9fa56f:	48 8d 35 01 ac 99 00                            	lea    rsi,[rip+0x99ac01]        # 0x1395177
  9fa576:	e8 45 05 16 00                                  	call   0xb5aac0
  9fa57b:	48 85 c0                                        	test   rax,rax
  9fa57e:	0f 84 fb 00 00 00                               	je     0x9fa67f
  9fa584:	48 89 c7                                        	mov    rdi,rax
  9fa587:	48 89 c3                                        	mov    rbx,rax
  9fa58a:	e8 a1 fd 15 00                                  	call   0xb5a330
  9fa58f:	83 f8 02                                        	cmp    eax,0x2
  9fa592:	0f 85 ba 00 00 00                               	jne    0x9fa652
  9fa598:	48 8d 35 5b 59 9a 00                            	lea    rsi,[rip+0x9a595b]        # 0x139fefa
  9fa59f:	48 89 df                                        	mov    rdi,rbx
  9fa5a2:	e8 19 05 16 00                                  	call   0xb5aac0
  9fa5a7:	48 89 c3                                        	mov    rbx,rax
  9fa5aa:	48 85 c0                                        	test   rax,rax
  9fa5ad:	b8 00 00 00 00                                  	mov    eax,0x0
  9fa5b2:	0f 84 c9 00 00 00                               	je     0x9fa681
  9fa5b8:	48 89 df                                        	mov    rdi,rbx
  9fa5bb:	e8 70 fd 15 00                                  	call   0xb5a330
  9fa5c0:	83 f8 05                                        	cmp    eax,0x5
  9fa5c3:	0f 85 9d 00 00 00                               	jne    0x9fa666
  9fa5c9:	48 89 df                                        	mov    rdi,rbx
  9fa5cc:	e8 7f fd 15 00                                  	call   0xb5a350
  9fa5d1:	41 89 c7                                        	mov    r15d,eax
  9fa5d4:	41 8d 47 f9                                     	lea    eax,[r15-0x7]
  9fa5d8:	83 f8 fe                                        	cmp    eax,0xfffffffe
  9fa5db:	0f 82 85 00 00 00                               	jb     0x9fa666
  9fa5e1:	48 89 df                                        	mov    rdi,rbx
  9fa5e4:	e8 77 fd 15 00                                  	call   0xb5a360
  9fa5e9:	0f b6 08                                        	movzx  ecx,BYTE PTR [rax]
  9fa5ec:	80 c1 d0                                        	add    cl,0xd0
  9fa5ef:	80 f9 09                                        	cmp    cl,0x9
  9fa5f2:	77 72                                           	ja     0x9fa666
  9fa5f4:	0f b6 48 01                                     	movzx  ecx,BYTE PTR [rax+0x1]
  9fa5f8:	80 c1 d0                                        	add    cl,0xd0
  9fa5fb:	80 f9 09                                        	cmp    cl,0x9
  9fa5fe:	77 66                                           	ja     0x9fa666
  9fa600:	80 78 02 2e                                     	cmp    BYTE PTR [rax+0x2],0x2e
  9fa604:	75 60                                           	jne    0x9fa666
  9fa606:	0f b6 48 03                                     	movzx  ecx,BYTE PTR [rax+0x3]
  9fa60a:	80 c1 d0                                        	add    cl,0xd0
  9fa60d:	80 f9 09                                        	cmp    cl,0x9
  9fa610:	77 54                                           	ja     0x9fa666
  9fa612:	0f b6 48 04                                     	movzx  ecx,BYTE PTR [rax+0x4]
  9fa616:	80 c1 d0                                        	add    cl,0xd0
  9fa619:	80 f9 09                                        	cmp    cl,0x9
  9fa61c:	77 48                                           	ja     0x9fa666
  9fa61e:	41 83 ff 05                                     	cmp    r15d,0x5
  9fa622:	74 10                                           	je     0x9fa634
  9fa624:	44 89 f9                                        	mov    ecx,r15d
  9fa627:	0f b6 44 08 ff                                  	movzx  eax,BYTE PTR [rax+rcx*1-0x1]
  9fa62c:	24 df                                           	and    al,0xdf
  9fa62e:	04 bf                                           	add    al,0xbf
  9fa630:	3c 1a                                           	cmp    al,0x1a
  9fa632:	73 32                                           	jae    0x9fa666
  9fa634:	48 89 df                                        	mov    rdi,rbx
  9fa637:	e8 24 fd 15 00                                  	call   0xb5a360
  9fa63c:	48 89 c7                                        	mov    rdi,rax
  9fa63f:	48 8d 35 e5 66 8f 00                            	lea    rsi,[rip+0x8f66e5]        # 0x12f0d2b
  9fa646:	4c 89 f2                                        	mov    rdx,r14
  9fa649:	31 c0                                           	xor    eax,eax
  9fa64b:	e8 b0 b3 c7 ff                                  	call   0x675a00
  9fa650:	eb 2d                                           	jmp    0x9fa67f
  9fa652:	48 8d 15 97 71 ed 00                            	lea    rdx,[rip+0xed7197]        # 0x18d17f0
  9fa659:	31 ff                                           	xor    edi,edi
  9fa65b:	31 f6                                           	xor    esi,esi
  9fa65d:	31 c0                                           	xor    eax,eax
  9fa65f:	e8 6c 9e 10 00                                  	call   0xb044d0
  9fa664:	eb 19                                           	jmp    0x9fa67f
  9fa666:	48 8d 15 c3 71 ed 00                            	lea    rdx,[rip+0xed71c3]        # 0x18d1830
  9fa66d:	48 8d 0d 86 58 9a 00                            	lea    rcx,[rip+0x9a5886]        # 0x139fefa
  9fa674:	31 ff                                           	xor    edi,edi
  9fa676:	31 f6                                           	xor    esi,esi
  9fa678:	31 c0                                           	xor    eax,eax
  9fa67a:	e8 51 9e 10 00                                  	call   0xb044d0
  9fa67f:	31 c0                                           	xor    eax,eax
  9fa681:	48 83 c4 18                                     	add    rsp,0x18
  9fa685:	5b                                              	pop    rbx
  9fa686:	41 5c                                           	pop    r12
  9fa688:	41 5d                                           	pop    r13
  9fa68a:	41 5e                                           	pop    r14
  9fa68c:	41 5f                                           	pop    r15
  9fa68e:	5d                                              	pop    rbp
  9fa68f:	c3                                              	ret
  9fa690:	55                                              	push   rbp
  9fa691:	48 89 e5                                        	mov    rbp,rsp
  9fa694:	41 57                                           	push   r15
  9fa696:	41 56                                           	push   r14
  9fa698:	41 54                                           	push   r12
  9fa69a:	53                                              	push   rbx
  9fa69b:	4c 8b 35 3e 39 1b 03                            	mov    r14,QWORD PTR [rip+0x31b393e]        # 0x3badfe0
  9fa6a2:	4c 89 f7                                        	mov    rdi,r14
  9fa6a5:	e8 06 94 c5 ff                                  	call   0x653ab0
  9fa6aa:	48 89 c3                                        	mov    rbx,rax
  9fa6ad:	48 81 c3 ff ff 1f 00                            	add    rbx,0x1fffff
  9fa6b4:	48 81 e3 00 00 e0 ff                            	and    rbx,0xffffffffffe00000
  9fa6bb:	48 81 fb 00 00 00 05                            	cmp    rbx,0x5000000
  9fa6c2:	0f 87 b9 00 00 00                               	ja     0x9fa781
  9fa6c8:	49 8b 86 80 00 00 00                            	mov    rax,QWORD PTR [r14+0x80]
  9fa6cf:	48 2b 05 4a 9a 1b 03                            	sub    rax,QWORD PTR [rip+0x31b9a4a]        # 0x3bb4120
  9fa6d6:	48 05 00 00 40 63                               	add    rax,0x63400000
  9fa6dc:	48 39 d8                                        	cmp    rax,rbx
  9fa6df:	0f 82 9c 00 00 00                               	jb     0x9fa781
  9fa6e5:	48 85 db                                        	test   rbx,rbx
  9fa6e8:	0f 84 8a 00 00 00                               	je     0x9fa778
  9fa6ee:	48 8b 05 e3 38 1b 03                            	mov    rax,QWORD PTR [rip+0x31b38e3]        # 0x3badfd8
  9fa6f5:	a8 01                                           	test   al,0x1
  9fa6f7:	75 0d                                           	jne    0x9fa706
  9fa6f9:	48 8b 05 d8 38 1b 03                            	mov    rax,QWORD PTR [rip+0x31b38d8]        # 0x3badfd8
  9fa700:	48 83 e0 f0                                     	and    rax,0xfffffffffffffff0
  9fa704:	eb 02                                           	jmp    0x9fa708
  9fa706:	31 c0                                           	xor    eax,eax
  9fa708:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9fa711:	48 39 c8                                        	cmp    rax,rcx
  9fa714:	74 38                                           	je     0x9fa74e
  9fa716:	4c 8d 25 a3 38 1b 03                            	lea    r12,[rip+0x31b38a3]        # 0x3badfc0
  9fa71d:	31 f6                                           	xor    esi,esi
  9fa71f:	31 d2                                           	xor    edx,edx
  9fa721:	31 c9                                           	xor    ecx,ecx
  9fa723:	4c 89 e7                                        	mov    rdi,r12
  9fa726:	e8 f5 13 25 00                                  	call   0xc4bb20
  9fa72b:	be 00 00 20 00                                  	mov    esi,0x200000
  9fa730:	48 89 df                                        	mov    rdi,rbx
  9fa733:	48 89 da                                        	mov    rdx,rbx
  9fa736:	31 c9                                           	xor    ecx,ecx
  9fa738:	e8 83 d4 ff ff                                  	call   0x9f7bc0
  9fa73d:	4c 89 e7                                        	mov    rdi,r12
  9fa740:	49 89 c7                                        	mov    r15,rax
  9fa743:	31 f6                                           	xor    esi,esi
  9fa745:	31 d2                                           	xor    edx,edx
  9fa747:	e8 64 1d 25 00                                  	call   0xc4c4b0
  9fa74c:	eb 15                                           	jmp    0x9fa763
  9fa74e:	be 00 00 20 00                                  	mov    esi,0x200000
  9fa753:	48 89 df                                        	mov    rdi,rbx
  9fa756:	48 89 da                                        	mov    rdx,rbx
  9fa759:	31 c9                                           	xor    ecx,ecx
  9fa75b:	e8 60 d4 ff ff                                  	call   0x9f7bc0
  9fa760:	49 89 c7                                        	mov    r15,rax
  9fa763:	4d 89 be 90 00 00 00                            	mov    QWORD PTR [r14+0x90],r15
  9fa76a:	49 89 9e c8 00 00 00                            	mov    QWORD PTR [r14+0xc8],rbx
  9fa771:	4c 89 35 88 99 1b 03                            	mov    QWORD PTR [rip+0x31b9988],r14        # 0x3bb4100
  9fa778:	5b                                              	pop    rbx
  9fa779:	41 5c                                           	pop    r12
  9fa77b:	41 5e                                           	pop    r14
  9fa77d:	41 5f                                           	pop    r15
  9fa77f:	5d                                              	pop    rbp
  9fa780:	c3                                              	ret
  9fa781:	e8 ca 71 df ff                                  	call   0x7f1950
  9fa786:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x9fa781
  9fa78d:	48 89 de                                        	mov    rsi,rbx
  9fa790:	e8 0b 71 df ff                                  	call   0x7f18a0
  9fa795:	48 8d 35 b9 7e 92 00                            	lea    rsi,[rip+0x927eb9]        # 0x1322655
  9fa79c:	bf 42 00 00 00                                  	mov    edi,0x42
  9fa7a1:	48 89 da                                        	mov    rdx,rbx
  9fa7a4:	31 c0                                           	xor    eax,eax
  9fa7a6:	e8 65 02 2a 00                                  	call   0xc9aa10
  9fa7ab:	0f 0b                                           	ud2
  9fa7ad:	90                                              	nop
  9fa7ae:	90                                              	nop
  9fa7af:	90                                              	nop
  9fa7b0:	55                                              	push   rbp
  9fa7b1:	48 89 e5                                        	mov    rbp,rsp
  9fa7b4:	41 57                                           	push   r15
  9fa7b6:	41 56                                           	push   r14
  9fa7b8:	41 55                                           	push   r13
  9fa7ba:	41 54                                           	push   r12
  9fa7bc:	53                                              	push   rbx
  9fa7bd:	48 81 ec 88 00 00 00                            	sub    rsp,0x88
  9fa7c4:	48 8d 05 45 1b f2 02                            	lea    rax,[rip+0x2f21b45]        # 0x391c310
  9fa7cb:	49 89 ff                                        	mov    r15,rdi
  9fa7ce:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  9fa7d1:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9fa7d5:	48 8b 1d 04 38 1b 03                            	mov    rbx,QWORD PTR [rip+0x31b3804]        # 0x3badfe0
  9fa7dc:	4c 63 ab 20 01 00 00                            	movsxd r13,DWORD PTR [rbx+0x120]
  9fa7e3:	44 8b b3 18 01 00 00                            	mov    r14d,DWORD PTR [rbx+0x118]
  9fa7ea:	41 81 fe ff f4 01 00                            	cmp    r14d,0x1f4ff
  9fa7f1:	7f 20                                           	jg     0x9fa813
  9fa7f3:	41 81 fe 00 f1 01 00                            	cmp    r14d,0x1f100
  9fa7fa:	74 35                                           	je     0x9fa831
  9fa7fc:	41 81 fe 00 f2 01 00                            	cmp    r14d,0x1f200
  9fa803:	74 2c                                           	je     0x9fa831
  9fa805:	44 89 f1                                        	mov    ecx,r14d
  9fa808:	41 81 fe 00 f4 01 00                            	cmp    r14d,0x1f400
  9fa80f:	74 20                                           	je     0x9fa831
  9fa811:	eb 43                                           	jmp    0x9fa856
  9fa813:	41 81 fe 00 f5 01 00                            	cmp    r14d,0x1f500
  9fa81a:	74 15                                           	je     0x9fa831
  9fa81c:	41 81 fe 00 f2 00 02                            	cmp    r14d,0x200f200
  9fa823:	74 0c                                           	je     0x9fa831
  9fa825:	44 89 f1                                        	mov    ecx,r14d
  9fa828:	41 81 fe 00 f1 02 00                            	cmp    r14d,0x2f100
  9fa82f:	75 25                                           	jne    0x9fa856
  9fa831:	48 8b 3d 58 98 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b9858]        # 0x3bb4090
  9fa838:	44 89 f1                                        	mov    ecx,r14d
  9fa83b:	48 85 ff                                        	test   rdi,rdi
  9fa83e:	74 16                                           	je     0x9fa856
  9fa840:	e8 5b 73 a6 ff                                  	call   0x461ba0
  9fa845:	48 c7 05 40 98 1b 03 00 00 00 00                	mov    QWORD PTR [rip+0x31b9840],0x0        # 0x3bb4090
  9fa850:	8b 8b 18 01 00 00                               	mov    ecx,DWORD PTR [rbx+0x118]
  9fa856:	41 b9 00 00 00 70                               	mov    r9d,0x70000000
  9fa85c:	41 bc 00 00 80 01                               	mov    r12d,0x1800000
  9fa862:	ba 00 00 20 00                                  	mov    edx,0x200000
  9fa867:	41 b8 00 00 00 08                               	mov    r8d,0x8000000
  9fa86d:	be 00 00 80 02                                  	mov    esi,0x2800000
  9fa872:	b0 01                                           	mov    al,0x1
  9fa874:	31 ff                                           	xor    edi,edi
  9fa876:	4c 89 ad 70 ff ff ff                            	mov    QWORD PTR [rbp-0x90],r13
  9fa87d:	81 f9 ff f1 01 00                               	cmp    ecx,0x1f1ff
  9fa883:	7e 41                                           	jle    0x9fa8c6
  9fa885:	81 f9 ff 00 02 00                               	cmp    ecx,0x200ff
  9fa88b:	7f 7a                                           	jg     0x9fa907
  9fa88d:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  9fa891:	81 f9 ff f3 01 00                               	cmp    ecx,0x1f3ff
  9fa897:	0f 8e 55 01 00 00                               	jle    0x9fa9f2
  9fa89d:	81 f9 00 f4 01 00                               	cmp    ecx,0x1f400
  9fa8a3:	0f 84 5d 01 00 00                               	je     0x9faa06
  9fa8a9:	81 f9 00 f5 01 00                               	cmp    ecx,0x1f500
  9fa8af:	0f 84 51 01 00 00                               	je     0x9faa06
  9fa8b5:	81 f9 00 00 02 00                               	cmp    ecx,0x20000
  9fa8bb:	0f 84 a2 01 00 00                               	je     0x9faa63
  9fa8c1:	e9 99 02 00 00                                  	jmp    0x9fab5f
  9fa8c6:	81 f9 ff 00 01 00                               	cmp    ecx,0x100ff
  9fa8cc:	7e 72                                           	jle    0x9fa940
  9fa8ce:	81 f9 ff 02 01 00                               	cmp    ecx,0x102ff
  9fa8d4:	0f 8e b1 00 00 00                               	jle    0x9fa98b
  9fa8da:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  9fa8de:	81 f9 00 03 01 00                               	cmp    ecx,0x10300
  9fa8e4:	0f 84 87 02 00 00                               	je     0x9fab71
  9fa8ea:	81 f9 00 f0 01 00                               	cmp    ecx,0x1f000
  9fa8f0:	0f 84 c8 01 00 00                               	je     0x9faabe
  9fa8f6:	81 f9 00 f1 01 00                               	cmp    ecx,0x1f100
  9fa8fc:	0f 84 04 01 00 00                               	je     0x9faa06
  9fa902:	e9 58 02 00 00                                  	jmp    0x9fab5f
  9fa907:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  9fa90b:	81 f9 ff 0e 02 00                               	cmp    ecx,0x20eff
  9fa911:	0f 8e 38 01 00 00                               	jle    0x9faa4f
  9fa917:	81 f9 00 0f 02 00                               	cmp    ecx,0x20f00
  9fa91d:	0f 84 f7 01 00 00                               	je     0x9fab1a
  9fa923:	81 f9 00 f0 02 00                               	cmp    ecx,0x2f000
  9fa929:	0f 84 8f 01 00 00                               	je     0x9faabe
  9fa92f:	81 f9 00 f1 02 00                               	cmp    ecx,0x2f100
  9fa935:	0f 84 cb 00 00 00                               	je     0x9faa06
  9fa93b:	e9 1f 02 00 00                                  	jmp    0x9fab5f
  9fa940:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  9fa944:	81 f9 ff f0 00 00                               	cmp    ecx,0xf0ff
  9fa94a:	7f 19                                           	jg     0x9fa965
  9fa94c:	85 c9                                           	test   ecx,ecx
  9fa94e:	0f 84 1d 02 00 00                               	je     0x9fab71
  9fa954:	81 f9 00 f0 00 00                               	cmp    ecx,0xf000
  9fa95a:	0f 84 44 01 00 00                               	je     0x9faaa4
  9fa960:	e9 fa 01 00 00                                  	jmp    0x9fab5f
  9fa965:	81 f9 00 f1 00 00                               	cmp    ecx,0xf100
  9fa96b:	0f 84 33 01 00 00                               	je     0x9faaa4
  9fa971:	81 f9 00 00 01 00                               	cmp    ecx,0x10000
  9fa977:	0f 85 e2 01 00 00                               	jne    0x9fab5f
  9fa97d:	80 8b 41 01 00 00 01                            	or     BYTE PTR [rbx+0x141],0x1
  9fa984:	31 ff                                           	xor    edi,edi
  9fa986:	e9 d8 00 00 00                                  	jmp    0x9faa63
  9fa98b:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  9fa98f:	81 f9 00 01 01 00                               	cmp    ecx,0x10100
  9fa995:	0f 84 c8 00 00 00                               	je     0x9faa63
  9fa99b:	81 f9 00 02 01 00                               	cmp    ecx,0x10200
  9fa9a1:	0f 85 b8 01 00 00                               	jne    0x9fab5f
  9fa9a7:	b8 00 00 00 70                                  	mov    eax,0x70000000
  9fa9ac:	41 b9 00 00 00 60                               	mov    r9d,0x60000000
  9fa9b2:	31 ff                                           	xor    edi,edi
  9fa9b4:	41 b8 00 00 80 02                               	mov    r8d,0x2800000
  9fa9ba:	ba 00 00 80 02                                  	mov    edx,0x2800000
  9fa9bf:	48 c7 45 98 00 00 00 00                         	mov    QWORD PTR [rbp-0x68],0x0
  9fa9c7:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  9fa9cf:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  9fa9d7:	48 89 45 b8                                     	mov    QWORD PTR [rbp-0x48],rax
  9fa9db:	b8 00 00 80 01                                  	mov    eax,0x1800000
  9fa9e0:	48 89 45 a8                                     	mov    QWORD PTR [rbp-0x58],rax
  9fa9e4:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  9fa9e8:	b8 00 00 00 60                                  	mov    eax,0x60000000
  9fa9ed:	e9 1b 01 00 00                                  	jmp    0x9fab0d
  9fa9f2:	81 f9 00 f2 01 00                               	cmp    ecx,0x1f200
  9fa9f8:	74 0c                                           	je     0x9faa06
  9fa9fa:	81 f9 00 f3 01 00                               	cmp    ecx,0x1f300
  9faa00:	0f 85 59 01 00 00                               	jne    0x9fab5f
  9faa06:	b8 00 00 80 01                                  	mov    eax,0x1800000
  9faa0b:	be 00 00 80 01                                  	mov    esi,0x1800000
  9faa10:	41 b8 00 00 80 01                               	mov    r8d,0x1800000
  9faa16:	ba 00 00 80 01                                  	mov    edx,0x1800000
  9faa1b:	31 ff                                           	xor    edi,edi
  9faa1d:	48 c7 45 98 00 00 00 00                         	mov    QWORD PTR [rbp-0x68],0x0
  9faa25:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  9faa2d:	48 89 45 a8                                     	mov    QWORD PTR [rbp-0x58],rax
  9faa31:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  9faa35:	b8 00 00 00 70                                  	mov    eax,0x70000000
  9faa3a:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  9faa3e:	48 c7 45 b8 00 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x0
  9faa46:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  9faa4a:	e9 b8 01 00 00                                  	jmp    0x9fac07
  9faa4f:	81 f9 00 01 02 00                               	cmp    ecx,0x20100
  9faa55:	74 0c                                           	je     0x9faa63
  9faa57:	81 f9 00 02 02 00                               	cmp    ecx,0x20200
  9faa5d:	0f 85 fc 00 00 00                               	jne    0x9fab5f
  9faa63:	b8 00 00 20 00                                  	mov    eax,0x200000
  9faa68:	48 c7 45 98 00 00 00 00                         	mov    QWORD PTR [rbp-0x68],0x0
  9faa70:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  9faa78:	48 c7 45 b8 00 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x0
  9faa80:	48 89 45 a8                                     	mov    QWORD PTR [rbp-0x58],rax
  9faa84:	b8 00 00 00 08                                  	mov    eax,0x8000000
  9faa89:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  9faa8d:	b8 00 00 20 00                                  	mov    eax,0x200000
  9faa92:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  9faa96:	b8 00 00 00 70                                  	mov    eax,0x70000000
  9faa9b:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  9faa9f:	e9 63 01 00 00                                  	jmp    0x9fac07
  9faaa4:	48 8d 3d 0a 6d 96 00                            	lea    rdi,[rip+0x966d0a]        # 0x13617b5
  9faaab:	31 c0                                           	xor    eax,eax
  9faaad:	e8 5e 29 86 ff                                  	call   0x25d410
  9faab2:	80 8b 41 01 00 00 20                            	or     BYTE PTR [rbx+0x141],0x20
  9faab9:	bf 00 00 00 08                                  	mov    edi,0x8000000
  9faabe:	80 8b 41 01 00 00 01                            	or     BYTE PTR [rbx+0x141],0x1
  9faac5:	b8 00 00 00 20                                  	mov    eax,0x20000000
  9faaca:	48 89 7d 90                                     	mov    QWORD PTR [rbp-0x70],rdi
  9faace:	41 b9 00 00 00 1c                               	mov    r9d,0x1c000000
  9faad4:	bf 00 00 00 10                                  	mov    edi,0x10000000
  9faad9:	be 00 00 80 0a                                  	mov    esi,0xa800000
  9faade:	48 c7 45 b8 00 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x0
  9faae6:	41 b8 00 00 80 0a                               	mov    r8d,0xa800000
  9faaec:	ba 00 00 80 0a                                  	mov    edx,0xa800000
  9faaf1:	41 bc 00 00 80 09                               	mov    r12d,0x9800000
  9faaf7:	48 89 45 98                                     	mov    QWORD PTR [rbp-0x68],rax
  9faafb:	b8 00 00 80 09                                  	mov    eax,0x9800000
  9fab00:	48 89 45 a8                                     	mov    QWORD PTR [rbp-0x58],rax
  9fab04:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  9fab08:	b8 00 00 00 1c                                  	mov    eax,0x1c000000
  9fab0d:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  9fab11:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  9fab15:	e9 ed 00 00 00                                  	jmp    0x9fac07
  9fab1a:	b8 00 00 00 07                                  	mov    eax,0x7000000
  9fab1f:	41 b9 00 00 00 1c                               	mov    r9d,0x1c000000
  9fab25:	be 00 00 00 07                                  	mov    esi,0x7000000
  9fab2a:	31 ff                                           	xor    edi,edi
  9fab2c:	41 b8 00 00 00 07                               	mov    r8d,0x7000000
  9fab32:	ba 00 00 00 07                                  	mov    edx,0x7000000
  9fab37:	41 bc 00 00 00 07                               	mov    r12d,0x7000000
  9fab3d:	48 c7 45 98 00 00 00 00                         	mov    QWORD PTR [rbp-0x68],0x0
  9fab45:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  9fab4d:	48 89 45 a8                                     	mov    QWORD PTR [rbp-0x58],rax
  9fab51:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  9fab55:	b8 00 00 00 1c                                  	mov    eax,0x1c000000
  9fab5a:	e9 db fe ff ff                                  	jmp    0x9faa3a
  9fab5f:	48 8d 15 0a 6d ed 00                            	lea    rdx,[rip+0xed6d0a]        # 0x18d1870
  9fab66:	31 ff                                           	xor    edi,edi
  9fab68:	31 f6                                           	xor    esi,esi
  9fab6a:	31 c0                                           	xor    eax,eax
  9fab6c:	e8 5f 99 10 00                                  	call   0xb044d0
  9fab71:	80 8b 41 01 00 00 01                            	or     BYTE PTR [rbx+0x141],0x1
  9fab78:	bf 07 00 00 00                                  	mov    edi,0x7
  9fab7d:	e8 ee da 00 00                                  	call   0xa08670
  9fab82:	b9 00 00 00 1c                                  	mov    ecx,0x1c000000
  9fab87:	41 b8 00 00 00 10                               	mov    r8d,0x10000000
  9fab8d:	be 00 00 00 04                                  	mov    esi,0x4000000
  9fab92:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  9fab96:	48 85 c0                                        	test   rax,rax
  9fab99:	74 26                                           	je     0x9fabc1
  9fab9b:	e8 70 22 0d 00                                  	call   0xacce10
  9faba0:	45 31 c9                                        	xor    r9d,r9d
  9faba3:	85 c0                                           	test   eax,eax
  9faba5:	41 b8 00 00 00 10                               	mov    r8d,0x10000000
  9fabab:	be 00 00 00 04                                  	mov    esi,0x4000000
  9fabb0:	41 0f 95 c1                                     	setne  r9b
  9fabb4:	41 c1 e1 1e                                     	shl    r9d,0x1e
  9fabb8:	49 81 c1 00 00 00 40                            	add    r9,0x40000000
  9fabbf:	eb 06                                           	jmp    0x9fabc7
  9fabc1:	41 b9 00 00 00 40                               	mov    r9d,0x40000000
  9fabc7:	b8 00 00 20 00                                  	mov    eax,0x200000
  9fabcc:	41 bc 00 00 00 04                               	mov    r12d,0x4000000
  9fabd2:	ba 00 00 20 00                                  	mov    edx,0x200000
  9fabd7:	31 ff                                           	xor    edi,edi
  9fabd9:	48 c7 45 98 00 00 00 00                         	mov    QWORD PTR [rbp-0x68],0x0
  9fabe1:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  9fabe9:	48 c7 45 b8 00 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x0
  9fabf1:	48 89 45 a8                                     	mov    QWORD PTR [rbp-0x58],rax
  9fabf5:	b8 00 00 00 10                                  	mov    eax,0x10000000
  9fabfa:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  9fabfe:	b8 00 00 20 00                                  	mov    eax,0x200000
  9fac03:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  9fac07:	8b 83 18 01 00 00                               	mov    eax,DWORD PTR [rbx+0x118]
  9fac0d:	48 89 95 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],rdx
  9fac14:	48 89 b5 58 ff ff ff                            	mov    QWORD PTR [rbp-0xa8],rsi
  9fac1b:	48 89 bd 68 ff ff ff                            	mov    QWORD PTR [rbp-0x98],rdi
  9fac22:	4c 89 85 60 ff ff ff                            	mov    QWORD PTR [rbp-0xa0],r8
  9fac29:	3d ff f0 01 00                                  	cmp    eax,0x1f0ff
  9fac2e:	7f 2b                                           	jg     0x9fac5b
  9fac30:	b9 08 00 00 00                                  	mov    ecx,0x8
  9fac35:	3d ff 00 01 00                                  	cmp    eax,0x100ff
  9fac3a:	7f 48                                           	jg     0x9fac84
  9fac3c:	3d ff f0 00 00                                  	cmp    eax,0xf0ff
  9fac41:	7f 75                                           	jg     0x9facb8
  9fac43:	85 c0                                           	test   eax,eax
  9fac45:	0f 84 d3 00 00 00                               	je     0x9fad1e
  9fac4b:	3d 00 f0 00 00                                  	cmp    eax,0xf000
  9fac50:	0f 84 9a 00 00 00                               	je     0x9facf0
  9fac56:	e9 2c 03 00 00                                  	jmp    0x9faf87
  9fac5b:	3d ff f4 01 00                                  	cmp    eax,0x1f4ff
  9fac60:	7f 3c                                           	jg     0x9fac9e
  9fac62:	3d ff f2 01 00                                  	cmp    eax,0x1f2ff
  9fac67:	7f 62                                           	jg     0x9faccb
  9fac69:	3d 00 f1 01 00                                  	cmp    eax,0x1f100
  9fac6e:	0f 84 9b 00 00 00                               	je     0x9fad0f
  9fac74:	3d 00 f2 01 00                                  	cmp    eax,0x1f200
  9fac79:	0f 84 90 00 00 00                               	je     0x9fad0f
  9fac7f:	e9 03 03 00 00                                  	jmp    0x9faf87
  9fac84:	3d ff 02 01 00                                  	cmp    eax,0x102ff
  9fac89:	7f 53                                           	jg     0x9facde
  9fac8b:	3d 00 01 01 00                                  	cmp    eax,0x10100
  9fac90:	74 7d                                           	je     0x9fad0f
  9fac92:	3d 00 02 01 00                                  	cmp    eax,0x10200
  9fac97:	74 76                                           	je     0x9fad0f
  9fac99:	e9 e9 02 00 00                                  	jmp    0x9faf87
  9fac9e:	3d ff 00 02 00                                  	cmp    eax,0x200ff
  9faca3:	7f 58                                           	jg     0x9facfd
  9faca5:	3d 00 f5 01 00                                  	cmp    eax,0x1f500
  9facaa:	74 63                                           	je     0x9fad0f
  9facac:	3d 00 00 02 00                                  	cmp    eax,0x20000
  9facb1:	74 5c                                           	je     0x9fad0f
  9facb3:	e9 cf 02 00 00                                  	jmp    0x9faf87
  9facb8:	3d 00 f1 00 00                                  	cmp    eax,0xf100
  9facbd:	74 31                                           	je     0x9facf0
  9facbf:	3d 00 00 01 00                                  	cmp    eax,0x10000
  9facc4:	74 49                                           	je     0x9fad0f
  9facc6:	e9 bc 02 00 00                                  	jmp    0x9faf87
  9faccb:	3d 00 f3 01 00                                  	cmp    eax,0x1f300
  9facd0:	74 3d                                           	je     0x9fad0f
  9facd2:	3d 00 f4 01 00                                  	cmp    eax,0x1f400
  9facd7:	74 36                                           	je     0x9fad0f
  9facd9:	e9 a9 02 00 00                                  	jmp    0x9faf87
  9facde:	3d 00 03 01 00                                  	cmp    eax,0x10300
  9face3:	74 39                                           	je     0x9fad1e
  9face5:	3d 00 f0 01 00                                  	cmp    eax,0x1f000
  9facea:	0f 85 97 02 00 00                               	jne    0x9faf87
  9facf0:	8b 8b 20 01 00 00                               	mov    ecx,DWORD PTR [rbx+0x120]
  9facf6:	b8 00 00 00 04                                  	mov    eax,0x4000000
  9facfb:	eb 26                                           	jmp    0x9fad23
  9facfd:	3d 00 01 02 00                                  	cmp    eax,0x20100
  9fad02:	74 0b                                           	je     0x9fad0f
  9fad04:	3d 00 02 02 00                                  	cmp    eax,0x20200
  9fad09:	0f 85 78 02 00 00                               	jne    0x9faf87
  9fad0f:	b8 00 00 20 00                                  	mov    eax,0x200000
  9fad14:	4d 89 cd                                        	mov    r13,r9
  9fad17:	b9 09 00 00 00                                  	mov    ecx,0x9
  9fad1c:	eb 08                                           	jmp    0x9fad26
  9fad1e:	b8 00 00 20 00                                  	mov    eax,0x200000
  9fad23:	4d 89 cd                                        	mov    r13,r9
  9fad26:	48 89 45 80                                     	mov    QWORD PTR [rbp-0x80],rax
  9fad2a:	89 8b 24 01 00 00                               	mov    DWORD PTR [rbx+0x124],ecx
  9fad30:	89 0d 56 ba cc 02                               	mov    DWORD PTR [rip+0x2ccba56],ecx        # 0x36c678c
  9fad36:	44 8b 8b 10 01 00 00                            	mov    r9d,DWORD PTR [rbx+0x110]
  9fad3d:	45 85 c9                                        	test   r9d,r9d
  9fad40:	74 29                                           	je     0x9fad6b
  9fad42:	44 89 c9                                        	mov    ecx,r9d
  9fad45:	b8 0c 0c 00 00                                  	mov    eax,0xc0c
  9fad4a:	48 8d 15 4f 6b ed 00                            	lea    rdx,[rip+0xed6b4f]        # 0x18d18a0
  9fad51:	31 ff                                           	xor    edi,edi
  9fad53:	31 f6                                           	xor    esi,esi
  9fad55:	c4 42 78 f7 c1                                  	bextr  r8d,r9d,eax
  9fad5a:	c1 e9 18                                        	shr    ecx,0x18
  9fad5d:	41 81 e1 ff 0f 00 00                            	and    r9d,0xfff
  9fad64:	31 c0                                           	xor    eax,eax
  9fad66:	e8 65 97 10 00                                  	call   0xb044d0
  9fad6b:	44 8b 8b 14 01 00 00                            	mov    r9d,DWORD PTR [rbx+0x114]
  9fad72:	45 85 c9                                        	test   r9d,r9d
  9fad75:	74 29                                           	je     0x9fada0
  9fad77:	44 89 c9                                        	mov    ecx,r9d
  9fad7a:	b8 0c 0c 00 00                                  	mov    eax,0xc0c
  9fad7f:	48 8d 15 5a 6b ed 00                            	lea    rdx,[rip+0xed6b5a]        # 0x18d18e0
  9fad86:	31 ff                                           	xor    edi,edi
  9fad88:	31 f6                                           	xor    esi,esi
  9fad8a:	c4 42 78 f7 c1                                  	bextr  r8d,r9d,eax
  9fad8f:	c1 e9 18                                        	shr    ecx,0x18
  9fad92:	41 81 e1 ff 0f 00 00                            	and    r9d,0xfff
  9fad99:	31 c0                                           	xor    eax,eax
  9fad9b:	e8 30 97 10 00                                  	call   0xb044d0
  9fada0:	4d 85 ff                                        	test   r15,r15
  9fada3:	74 31                                           	je     0x9fadd6
  9fada5:	4c 89 f8                                        	mov    rax,r15
  9fada8:	48 c1 e0 2b                                     	shl    rax,0x2b
  9fadac:	0f 85 95 01 00 00                               	jne    0x9faf47
  9fadb2:	4c 3b 7d c0                                     	cmp    r15,QWORD PTR [rbp-0x40]
  9fadb6:	0f 82 8b 01 00 00                               	jb     0x9faf47
  9fadbc:	4d 39 fd                                        	cmp    r13,r15
  9fadbf:	0f 82 82 01 00 00                               	jb     0x9faf47
  9fadc5:	4c 89 bb b0 00 00 00                            	mov    QWORD PTR [rbx+0xb0],r15
  9fadcc:	4c 2b 7d a0                                     	sub    r15,QWORD PTR [rbp-0x60]
  9fadd0:	4c 01 7b 40                                     	add    QWORD PTR [rbx+0x40],r15
  9fadd4:	eb 38                                           	jmp    0x9fae0e
  9fadd6:	48 8b 75 c0                                     	mov    rsi,QWORD PTR [rbp-0x40]
  9fadda:	48 8b 4d a0                                     	mov    rcx,QWORD PTR [rbp-0x60]
  9fadde:	41 81 fe 00 03 01 00                            	cmp    r14d,0x10300
  9fade5:	48 8d 05 90 a3 99 00                            	lea    rax,[rip+0x99a390]        # 0x139517c
  9fadec:	48 8d 3d 83 d4 8f 00                            	lea    rdi,[rip+0x8fd483]        # 0x12f8276
  9fadf3:	4c 8d 83 b0 00 00 00                            	lea    r8,[rbx+0xb0]
  9fadfa:	4c 89 ea                                        	mov    rdx,r13
  9fadfd:	48 0f 44 f8                                     	cmove  rdi,rax
  9fae01:	e8 ea 7b 00 00                                  	call   0xa029f0
  9fae06:	85 c0                                           	test   eax,eax
  9fae08:	0f 85 53 01 00 00                               	jne    0x9faf61
  9fae0e:	4c 8d ab a0 00 00 00                            	lea    r13,[rbx+0xa0]
  9fae15:	48 8d 3d c8 27 91 00                            	lea    rdi,[rip+0x9127c8]        # 0x130d5e4
  9fae1c:	31 f6                                           	xor    esi,esi
  9fae1e:	31 d2                                           	xor    edx,edx
  9fae20:	31 c9                                           	xor    ecx,ecx
  9fae22:	4d 89 e8                                        	mov    r8,r13
  9fae25:	e8 c6 7b 00 00                                  	call   0xa029f0
  9fae2a:	85 c0                                           	test   eax,eax
  9fae2c:	0f 85 2f 01 00 00                               	jne    0x9faf61
  9fae32:	48 8b 75 a8                                     	mov    rsi,QWORD PTR [rbp-0x58]
  9fae36:	48 8b 55 b0                                     	mov    rdx,QWORD PTR [rbp-0x50]
  9fae3a:	4c 8d bb d8 00 00 00                            	lea    r15,[rbx+0xd8]
  9fae41:	41 81 fe 00 03 01 00                            	cmp    r14d,0x10300
  9fae48:	48 8d 05 c5 ef 8b 00                            	lea    rax,[rip+0x8befc5]        # 0x12b9e14
  9fae4f:	48 8d 3d 10 c1 88 00                            	lea    rdi,[rip+0x88c110]        # 0x1286f66
  9fae56:	4c 89 e1                                        	mov    rcx,r12
  9fae59:	48 0f 44 f8                                     	cmove  rdi,rax
  9fae5d:	4d 89 f8                                        	mov    r8,r15
  9fae60:	e8 8b 7b 00 00                                  	call   0xa029f0
  9fae65:	85 c0                                           	test   eax,eax
  9fae67:	0f 85 f4 00 00 00                               	jne    0x9faf61
  9fae6d:	48 8b b5 78 ff ff ff                            	mov    rsi,QWORD PTR [rbp-0x88]
  9fae74:	48 8b 95 60 ff ff ff                            	mov    rdx,QWORD PTR [rbp-0xa0]
  9fae7b:	48 8b 8d 58 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xa8]
  9fae82:	41 81 fe 00 03 01 00                            	cmp    r14d,0x10300
  9fae89:	4c 8d b3 f8 00 00 00                            	lea    r14,[rbx+0xf8]
  9fae90:	48 8d 05 41 69 96 00                            	lea    rax,[rip+0x966941]        # 0x13617d8
  9fae97:	48 8d 3d 4d 69 96 00                            	lea    rdi,[rip+0x96694d]        # 0x13617eb
  9fae9e:	48 0f 44 f8                                     	cmove  rdi,rax
  9faea2:	4d 89 f0                                        	mov    r8,r14
  9faea5:	e8 46 7b 00 00                                  	call   0xa029f0
  9faeaa:	89 45 cc                                        	mov    DWORD PTR [rbp-0x34],eax
  9faead:	85 c0                                           	test   eax,eax
  9faeaf:	0f 85 ac 00 00 00                               	jne    0x9faf61
  9faeb5:	48 8b 55 98                                     	mov    rdx,QWORD PTR [rbp-0x68]
  9faeb9:	48 8b 8d 68 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0x98]
  9faec0:	4c 89 7d c0                                     	mov    QWORD PTR [rbp-0x40],r15
  9faec4:	4c 8b 7d 90                                     	mov    r15,QWORD PTR [rbp-0x70]
  9faec8:	48 89 93 b8 00 00 00                            	mov    QWORD PTR [rbx+0xb8],rdx
  9faecf:	48 89 8b c0 00 00 00                            	mov    QWORD PTR [rbx+0xc0],rcx
  9faed6:	48 09 ca                                        	or     rdx,rcx
  9faed9:	48 8b 4d 80                                     	mov    rcx,QWORD PTR [rbp-0x80]
  9faedd:	48 8b 83 b0 00 00 00                            	mov    rax,QWORD PTR [rbx+0xb0]
  9faee4:	49 01 cf                                        	add    r15,rcx
  9faee7:	c1 e9 0e                                        	shr    ecx,0xe
  9faeea:	49 01 d7                                        	add    r15,rdx
  9faeed:	49 01 c7                                        	add    r15,rax
  9faef0:	4c 89 bb a8 00 00 00                            	mov    QWORD PTR [rbx+0xa8],r15
  9faef7:	89 8b 34 01 00 00                               	mov    DWORD PTR [rbx+0x134],ecx
  9faefd:	8b 0d 89 b8 cc 02                               	mov    ecx,DWORD PTR [rip+0x2ccb889]        # 0x36c678c
  9faf03:	3b 8b 20 01 00 00                               	cmp    ecx,DWORD PTR [rbx+0x120]
  9faf09:	0f 94 c1                                        	sete   cl
  9faf0c:	48 3b 45 b8                                     	cmp    rax,QWORD PTR [rbp-0x48]
  9faf10:	0f 92 c0                                        	setb   al
  9faf13:	08 c8                                           	or     al,cl
  9faf15:	b9 ff ef ff ff                                  	mov    ecx,0xffffefff
  9faf1a:	23 8b 40 01 00 00                               	and    ecx,DWORD PTR [rbx+0x140]
  9faf20:	0f b6 c0                                        	movzx  eax,al
  9faf23:	c1 e0 0c                                        	shl    eax,0xc
  9faf26:	09 c1                                           	or     ecx,eax
  9faf28:	66 89 8b 40 01 00 00                            	mov    WORD PTR [rbx+0x140],cx
  9faf2f:	48 8b 05 a2 30 1b 03                            	mov    rax,QWORD PTR [rip+0x31b30a2]        # 0x3badfd8
  9faf36:	a8 01                                           	test   al,0x1
  9faf38:	75 5c                                           	jne    0x9faf96
  9faf3a:	48 8b 05 97 30 1b 03                            	mov    rax,QWORD PTR [rip+0x31b3097]        # 0x3badfd8
  9faf41:	48 83 e0 f0                                     	and    rax,0xfffffffffffffff0
  9faf45:	eb 51                                           	jmp    0x9faf98
  9faf47:	48 8d 15 d2 69 ed 00                            	lea    rdx,[rip+0xed69d2]        # 0x18d1920
  9faf4e:	4c 89 f9                                        	mov    rcx,r15
  9faf51:	31 ff                                           	xor    edi,edi
  9faf53:	31 f6                                           	xor    esi,esi
  9faf55:	31 c0                                           	xor    eax,eax
  9faf57:	e8 74 95 10 00                                  	call   0xb044d0
  9faf5c:	b8 16 00 00 00                                  	mov    eax,0x16
  9faf61:	48 8d 0d a8 13 f2 02                            	lea    rcx,[rip+0x2f213a8]        # 0x391c310
  9faf68:	48 8b 09                                        	mov    rcx,QWORD PTR [rcx]
  9faf6b:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  9faf6f:	0f 85 20 05 00 00                               	jne    0x9fb495
  9faf75:	48 81 c4 88 00 00 00                            	add    rsp,0x88
  9faf7c:	5b                                              	pop    rbx
  9faf7d:	41 5c                                           	pop    r12
  9faf7f:	41 5d                                           	pop    r13
  9faf81:	41 5e                                           	pop    r14
  9faf83:	41 5f                                           	pop    r15
  9faf85:	5d                                              	pop    rbp
  9faf86:	c3                                              	ret
  9faf87:	b8 00 00 20 00                                  	mov    eax,0x200000
  9faf8c:	4d 89 cd                                        	mov    r13,r9
  9faf8f:	31 c9                                           	xor    ecx,ecx
  9faf91:	e9 90 fd ff ff                                  	jmp    0x9fad26
  9faf96:	31 c0                                           	xor    eax,eax
  9faf98:	4c 89 75 b0                                     	mov    QWORD PTR [rbp-0x50],r14
  9faf9c:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9fafa5:	48 39 c8                                        	cmp    rax,rcx
  9fafa8:	74 37                                           	je     0x9fafe1
  9fafaa:	4c 8d 35 0f 30 1b 03                            	lea    r14,[rip+0x31b300f]        # 0x3badfc0
  9fafb1:	31 f6                                           	xor    esi,esi
  9fafb3:	31 d2                                           	xor    edx,edx
  9fafb5:	31 c9                                           	xor    ecx,ecx
  9fafb7:	4c 89 f7                                        	mov    rdi,r14
  9fafba:	e8 61 0b 25 00                                  	call   0xc4bb20
  9fafbf:	be 00 00 20 00                                  	mov    esi,0x200000
  9fafc4:	4c 89 ff                                        	mov    rdi,r15
  9fafc7:	31 d2                                           	xor    edx,edx
  9fafc9:	31 c9                                           	xor    ecx,ecx
  9fafcb:	e8 f0 cb ff ff                                  	call   0x9f7bc0
  9fafd0:	4c 89 f7                                        	mov    rdi,r14
  9fafd3:	49 89 c7                                        	mov    r15,rax
  9fafd6:	31 f6                                           	xor    esi,esi
  9fafd8:	31 d2                                           	xor    edx,edx
  9fafda:	e8 d1 14 25 00                                  	call   0xc4c4b0
  9fafdf:	eb 14                                           	jmp    0x9faff5
  9fafe1:	be 00 00 20 00                                  	mov    esi,0x200000
  9fafe6:	4c 89 ff                                        	mov    rdi,r15
  9fafe9:	31 d2                                           	xor    edx,edx
  9fafeb:	31 c9                                           	xor    ecx,ecx
  9fafed:	e8 ce cb ff ff                                  	call   0x9f7bc0
  9faff2:	49 89 c7                                        	mov    r15,rax
  9faff5:	4c 89 7b 68                                     	mov    QWORD PTR [rbx+0x68],r15
  9faff9:	8b 8b 20 01 00 00                               	mov    ecx,DWORD PTR [rbx+0x120]
  9fafff:	39 8b 24 01 00 00                               	cmp    DWORD PTR [rbx+0x124],ecx
  9fb005:	75 1a                                           	jne    0x9fb021
  9fb007:	48 8b 05 12 91 1b 03                            	mov    rax,QWORD PTR [rip+0x31b9112]        # 0x3bb4120
  9fb00e:	49 c7 c6 00 00 c0 9c                            	mov    r14,0xffffffff9cc00000
  9fb015:	4c 01 f0                                        	add    rax,r14
  9fb018:	49 39 c7                                        	cmp    r15,rax
  9fb01b:	0f 82 7b 04 00 00                               	jb     0x9fb49c
  9fb021:	49 8b 7d 00                                     	mov    rdi,QWORD PTR [r13+0x0]
  9fb025:	48 85 ff                                        	test   rdi,rdi
  9fb028:	74 23                                           	je     0x9fb04d
  9fb02a:	83 c1 04                                        	add    ecx,0x4
  9fb02d:	be 00 00 20 00                                  	mov    esi,0x200000
  9fb032:	31 d2                                           	xor    edx,edx
  9fb034:	89 8d 78 ff ff ff                               	mov    DWORD PTR [rbp-0x88],ecx
  9fb03a:	89 8b 28 01 00 00                               	mov    DWORD PTR [rbx+0x128],ecx
  9fb040:	31 c9                                           	xor    ecx,ecx
  9fb042:	e8 e9 ca ff ff                                  	call   0x9f7b30
  9fb047:	48 89 43 60                                     	mov    QWORD PTR [rbx+0x60],rax
  9fb04b:	eb 06                                           	jmp    0x9fb053
  9fb04d:	89 8b 28 01 00 00                               	mov    DWORD PTR [rbx+0x128],ecx
  9fb053:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  9fb057:	f6 40 5f 20                                     	test   BYTE PTR [rax+0x5f],0x20
  9fb05b:	74 07                                           	je     0x9fb064
  9fb05d:	80 8b 41 01 00 00 40                            	or     BYTE PTR [rbx+0x141],0x40
  9fb064:	4c 8b ab d8 00 00 00                            	mov    r13,QWORD PTR [rbx+0xd8]
  9fb06b:	48 8b 05 66 2f 1b 03                            	mov    rax,QWORD PTR [rip+0x31b2f66]        # 0x3badfd8
  9fb072:	41 bf 00 00 00 04                               	mov    r15d,0x4000000
  9fb078:	49 81 fd 00 00 00 04                            	cmp    r13,0x4000000
  9fb07f:	4d 0f 42 fd                                     	cmovb  r15,r13
  9fb083:	a8 01                                           	test   al,0x1
  9fb085:	75 0d                                           	jne    0x9fb094
  9fb087:	48 8b 05 4a 2f 1b 03                            	mov    rax,QWORD PTR [rip+0x31b2f4a]        # 0x3badfd8
  9fb08e:	48 83 e0 f0                                     	and    rax,0xfffffffffffffff0
  9fb092:	eb 02                                           	jmp    0x9fb096
  9fb094:	31 c0                                           	xor    eax,eax
  9fb096:	4c 8d 9b d0 00 00 00                            	lea    r11,[rbx+0xd0]
  9fb09d:	4c 8d a3 e0 00 00 00                            	lea    r12,[rbx+0xe0]
  9fb0a4:	4c 8d b3 e8 00 00 00                            	lea    r14,[rbx+0xe8]
  9fb0ab:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9fb0b4:	4c 89 65 a8                                     	mov    QWORD PTR [rbp-0x58],r12
  9fb0b8:	48 39 c8                                        	cmp    rax,rcx
  9fb0bb:	74 52                                           	je     0x9fb10f
  9fb0bd:	48 8d 3d fc 2e 1b 03                            	lea    rdi,[rip+0x31b2efc]        # 0x3badfc0
  9fb0c4:	31 f6                                           	xor    esi,esi
  9fb0c6:	31 d2                                           	xor    edx,edx
  9fb0c8:	31 c9                                           	xor    ecx,ecx
  9fb0ca:	4c 89 5d a0                                     	mov    QWORD PTR [rbp-0x60],r11
  9fb0ce:	e8 4d 0a 25 00                                  	call   0xc4bb20
  9fb0d3:	48 83 ec 08                                     	sub    rsp,0x8
  9fb0d7:	b9 00 00 20 00                                  	mov    ecx,0x200000
  9fb0dc:	31 ff                                           	xor    edi,edi
  9fb0de:	4c 89 ee                                        	mov    rsi,r13
  9fb0e1:	4c 89 fa                                        	mov    rdx,r15
  9fb0e4:	45 31 c0                                        	xor    r8d,r8d
  9fb0e7:	41 b9 01 00 00 00                               	mov    r9d,0x1
  9fb0ed:	41 56                                           	push   r14
  9fb0ef:	41 54                                           	push   r12
  9fb0f1:	ff 75 a0                                        	push   QWORD PTR [rbp-0x60]
  9fb0f4:	e8 a7 cd ff ff                                  	call   0x9f7ea0
  9fb0f9:	48 83 c4 20                                     	add    rsp,0x20
  9fb0fd:	48 8d 3d bc 2e 1b 03                            	lea    rdi,[rip+0x31b2ebc]        # 0x3badfc0
  9fb104:	31 f6                                           	xor    esi,esi
  9fb106:	31 d2                                           	xor    edx,edx
  9fb108:	e8 a3 13 25 00                                  	call   0xc4c4b0
  9fb10d:	eb 29                                           	jmp    0x9fb138
  9fb10f:	48 83 ec 08                                     	sub    rsp,0x8
  9fb113:	b9 00 00 20 00                                  	mov    ecx,0x200000
  9fb118:	31 ff                                           	xor    edi,edi
  9fb11a:	4c 89 ee                                        	mov    rsi,r13
  9fb11d:	4c 89 fa                                        	mov    rdx,r15
  9fb120:	45 31 c0                                        	xor    r8d,r8d
  9fb123:	41 b9 01 00 00 00                               	mov    r9d,0x1
  9fb129:	41 56                                           	push   r14
  9fb12b:	41 54                                           	push   r12
  9fb12d:	41 53                                           	push   r11
  9fb12f:	e8 6c cd ff ff                                  	call   0x9f7ea0
  9fb134:	48 83 c4 20                                     	add    rsp,0x20
  9fb138:	48 8d 55 cc                                     	lea    rdx,[rbp-0x34]
  9fb13c:	48 89 de                                        	mov    rsi,rbx
  9fb13f:	31 ff                                           	xor    edi,edi
  9fb141:	45 31 ff                                        	xor    r15d,r15d
  9fb144:	e8 b7 7d 0b 00                                  	call   0xab2f00
  9fb149:	8b 45 cc                                        	mov    eax,DWORD PTR [rbp-0x34]
  9fb14c:	85 c0                                           	test   eax,eax
  9fb14e:	0f 85 0d fe ff ff                               	jne    0x9faf61
  9fb154:	4c 8b 6b 68                                     	mov    r13,QWORD PTR [rbx+0x68]
  9fb158:	4c 8b b3 a8 00 00 00                            	mov    r14,QWORD PTR [rbx+0xa8]
  9fb15f:	44 8b a3 20 01 00 00                            	mov    r12d,DWORD PTR [rbx+0x120]
  9fb166:	8b 83 18 01 00 00                               	mov    eax,DWORD PTR [rbx+0x118]
  9fb16c:	4d 01 ee                                        	add    r14,r13
  9fb16f:	3d 00 03 01 00                                  	cmp    eax,0x10300
  9fb174:	74 04                                           	je     0x9fb17a
  9fb176:	85 c0                                           	test   eax,eax
  9fb178:	75 1d                                           	jne    0x9fb197
  9fb17a:	bf 07 00 00 00                                  	mov    edi,0x7
  9fb17f:	e8 ec d4 00 00                                  	call   0xa08670
  9fb184:	48 85 c0                                        	test   rax,rax
  9fb187:	74 0e                                           	je     0x9fb197
  9fb189:	e8 82 1c 0d 00                                  	call   0xacce10
  9fb18e:	45 31 ff                                        	xor    r15d,r15d
  9fb191:	85 c0                                           	test   eax,eax
  9fb193:	41 0f 95 c7                                     	setne  r15b
  9fb197:	44 89 e7                                        	mov    edi,r12d
  9fb19a:	4c 89 ee                                        	mov    rsi,r13
  9fb19d:	4c 89 f2                                        	mov    rdx,r14
  9fb1a0:	44 89 f9                                        	mov    ecx,r15d
  9fb1a3:	e8 18 b5 c1 ff                                  	call   0x6166c0
  9fb1a8:	8b bb 20 01 00 00                               	mov    edi,DWORD PTR [rbx+0x120]
  9fb1ae:	e8 fd ba c1 ff                                  	call   0x616cb0
  9fb1b3:	48 8b 93 a0 00 00 00                            	mov    rdx,QWORD PTR [rbx+0xa0]
  9fb1ba:	48 85 d2                                        	test   rdx,rdx
  9fb1bd:	74 35                                           	je     0x9fb1f4
  9fb1bf:	48 8b 73 60                                     	mov    rsi,QWORD PTR [rbx+0x60]
  9fb1c3:	44 8b b5 78 ff ff ff                            	mov    r14d,DWORD PTR [rbp-0x88]
  9fb1ca:	31 c9                                           	xor    ecx,ecx
  9fb1cc:	48 01 f2                                        	add    rdx,rsi
  9fb1cf:	44 89 f7                                        	mov    edi,r14d
  9fb1d2:	e8 e9 b4 c1 ff                                  	call   0x6166c0
  9fb1d7:	48 63 83 20 01 00 00                            	movsxd rax,DWORD PTR [rbx+0x120]
  9fb1de:	48 8d 0d bb 27 cf 02                            	lea    rcx,[rip+0x2cf27bb]        # 0x36ed9a0
  9fb1e5:	48 69 c0 c0 08 00 00                            	imul   rax,rax,0x8c0
  9fb1ec:	44                                              	rex.R
  9fb1ed:	89                                              	.byte 0x89
  9fb1ee:	b4 08                                           	mov    ah,0x8
