
/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/deep_558.bin:     file format binary


Disassembly of section .data:

0000000000ac73c0 <.data>:
  ac73c0:	55                                              	push   rbp
  ac73c1:	48 89 e5                                        	mov    rbp,rsp
  ac73c4:	41 57                                           	push   r15
  ac73c6:	41 56                                           	push   r14
  ac73c8:	41 54                                           	push   r12
  ac73ca:	53                                              	push   rbx
  ac73cb:	48 83 ec 10                                     	sub    rsp,0x10
  ac73cf:	4c 8d 25 3a 4f e5 02                            	lea    r12,[rip+0x2e54f3a]        # 0x391c310
  ac73d6:	49 89 f6                                        	mov    r14,rsi
  ac73d9:	48 8d 4d d0                                     	lea    rcx,[rbp-0x30]
  ac73dd:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  ac73e1:	48 89 45 d8                                     	mov    QWORD PTR [rbp-0x28],rax
  ac73e5:	48 8b 47 08                                     	mov    rax,QWORD PTR [rdi+0x8]
  ac73e9:	0f b7 56 08                                     	movzx  edx,WORD PTR [rsi+0x8]
  ac73ed:	8b 36                                           	mov    esi,DWORD PTR [rsi]
  ac73ef:	4c 8b b8 48 0c 00 00                            	mov    r15,QWORD PTR [rax+0xc48]
  ac73f6:	81 ca 00 10 00 00                               	or     edx,0x1000
  ac73fc:	4c 89 ff                                        	mov    rdi,r15
  ac73ff:	e8 9c 2e 8d ff                                  	call   0x39a2a0
  ac7404:	48 85 c0                                        	test   rax,rax
  ac7407:	74 3c                                           	je     0xac7445
  ac7409:	41 8b 36                                        	mov    esi,DWORD PTR [r14]
  ac740c:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  ac7410:	4c 89 ff                                        	mov    rdi,r15
  ac7413:	48 89 c3                                        	mov    rbx,rax
  ac7416:	e8 15 2a 8d ff                                  	call   0x399e30
  ac741b:	48 8b 7d d0                                     	mov    rdi,QWORD PTR [rbp-0x30]
  ac741f:	e8 8c 2a 8d ff                                  	call   0x399eb0
  ac7424:	48 8b 3b                                        	mov    rdi,QWORD PTR [rbx]
  ac7427:	4c 8d 35 a2 29 dc 01                            	lea    r14,[rip+0x1dc29a2]        # 0x2889dd0
  ac742e:	4c 89 f6                                        	mov    rsi,r14
  ac7431:	e8 ba 19 14 00                                  	call   0xc08df0
  ac7436:	48 89 df                                        	mov    rdi,rbx
  ac7439:	4c 89 f6                                        	mov    rsi,r14
  ac743c:	e8 af 19 14 00                                  	call   0xc08df0
  ac7441:	31 c0                                           	xor    eax,eax
  ac7443:	eb 05                                           	jmp    0xac744a
  ac7445:	b8 03 00 00 00                                  	mov    eax,0x3
  ac744a:	49 8b 0c 24                                     	mov    rcx,QWORD PTR [r12]
  ac744e:	48 3b 4d d8                                     	cmp    rcx,QWORD PTR [rbp-0x28]
  ac7452:	75 0d                                           	jne    0xac7461
  ac7454:	48 83 c4 10                                     	add    rsp,0x10
  ac7458:	5b                                              	pop    rbx
  ac7459:	41 5c                                           	pop    r12
  ac745b:	41 5e                                           	pop    r14
  ac745d:	41 5f                                           	pop    r15
  ac745f:	5d                                              	pop    rbp
  ac7460:	c3                                              	ret
  ac7461:	e8 4a 62 c3 ff                                  	call   0x6fd6b0
  ac7466:	0f 0b                                           	ud2
  ac7468:	90                                              	nop
  ac7469:	90                                              	nop
  ac746a:	90                                              	nop
  ac746b:	90                                              	nop
  ac746c:	90                                              	nop
  ac746d:	90                                              	nop
  ac746e:	90                                              	nop
  ac746f:	90                                              	nop
  ac7470:	55                                              	push   rbp
  ac7471:	48 89 e5                                        	mov    rbp,rsp
  ac7474:	41 57                                           	push   r15
  ac7476:	41 56                                           	push   r14
  ac7478:	41 55                                           	push   r13
  ac747a:	41 54                                           	push   r12
  ac747c:	53                                              	push   rbx
  ac747d:	48 83 ec 18                                     	sub    rsp,0x18
  ac7481:	4c 8d 2d 88 4e e5 02                            	lea    r13,[rip+0x2e54e88]        # 0x391c310
  ac7488:	bb 16 00 00 00                                  	mov    ebx,0x16
  ac748d:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  ac7491:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ac7495:	8b 47 40                                        	mov    eax,DWORD PTR [rdi+0x40]
  ac7498:	ff c8                                           	dec    eax
  ac749a:	83 f8 01                                        	cmp    eax,0x1
  ac749d:	0f 87 90 00 00 00                               	ja     0xac7533
  ac74a3:	49 89 ff                                        	mov    r15,rdi
  ac74a6:	48 8d 3d 63 9d 1f 03                            	lea    rdi,[rip+0x31f9d63]        # 0x3cc1210
  ac74ad:	49 89 f6                                        	mov    r14,rsi
  ac74b0:	31 db                                           	xor    ebx,ebx
  ac74b2:	31 f6                                           	xor    esi,esi
  ac74b4:	31 d2                                           	xor    edx,edx
  ac74b6:	31 c9                                           	xor    ecx,ecx
  ac74b8:	e8 d3 fc 9f ff                                  	call   0x4c7190
  ac74bd:	4c 8d 65 c0                                     	lea    r12,[rbp-0x40]
  ac74c1:	4c 89 e7                                        	mov    rdi,r12
  ac74c4:	e8 37 7d 00 00                                  	call   0xacf200
  ac74c9:	49 8b 46 08                                     	mov    rax,QWORD PTR [r14+0x8]
  ac74cd:	4c 89 ff                                        	mov    rdi,r15
  ac74d0:	4c 89 e6                                        	mov    rsi,r12
  ac74d3:	48 01 45 c8                                     	add    QWORD PTR [rbp-0x38],rax
  ac74d7:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  ac74da:	48 11 45 c0                                     	adc    QWORD PTR [rbp-0x40],rax
  ac74de:	41 c7 47 44 00 00 00 00                         	mov    DWORD PTR [r15+0x44],0x0
  ac74e6:	e8 75 00 00 00                                  	call   0xac7560
  ac74eb:	41 80 4f 40 04                                  	or     BYTE PTR [r15+0x40],0x4
  ac74f0:	4c 39 3d 21 9d 1f 03                            	cmp    QWORD PTR [rip+0x31f9d21],r15        # 0x3cc1218
  ac74f7:	75 28                                           	jne    0xac7521
  ac74f9:	48 8b 3d 28 9d 1f 03                            	mov    rdi,QWORD PTR [rip+0x31f9d28]        # 0x3cc1228
  ac7500:	e8 eb 62 17 00                                  	call   0xc3d7f0
  ac7505:	49 8b 36                                        	mov    rsi,QWORD PTR [r14]
  ac7508:	41 8b 46 0c                                     	mov    eax,DWORD PTR [r14+0xc]
  ac750c:	48 8b 3d 15 9d 1f 03                            	mov    rdi,QWORD PTR [rip+0x31f9d15]        # 0x3cc1228
  ac7513:	31 d2                                           	xor    edx,edx
  ac7515:	48 c1 e6 20                                     	shl    rsi,0x20
  ac7519:	48 09 c6                                        	or     rsi,rax
  ac751c:	e8 1f 62 17 00                                  	call   0xc3d740
  ac7521:	48 8d 3d e8 9c 1f 03                            	lea    rdi,[rip+0x31f9ce8]        # 0x3cc1210
  ac7528:	31 f6                                           	xor    esi,esi
  ac752a:	31 d2                                           	xor    edx,edx
  ac752c:	31 c9                                           	xor    ecx,ecx
  ac752e:	e8 ed ff 9f ff                                  	call   0x4c7520
  ac7533:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  ac7537:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ac753b:	75 11                                           	jne    0xac754e
  ac753d:	89 d8                                           	mov    eax,ebx
  ac753f:	48 83 c4 18                                     	add    rsp,0x18
  ac7543:	5b                                              	pop    rbx
  ac7544:	41 5c                                           	pop    r12
  ac7546:	41 5d                                           	pop    r13
  ac7548:	41 5e                                           	pop    r14
  ac754a:	41 5f                                           	pop    r15
  ac754c:	5d                                              	pop    rbp
  ac754d:	c3                                              	ret
  ac754e:	e8 5d 61 c3 ff                                  	call   0x6fd6b0
  ac7553:	0f 0b                                           	ud2
  ac7555:	90                                              	nop
  ac7556:	90                                              	nop
  ac7557:	90                                              	nop
  ac7558:	90                                              	nop
  ac7559:	90                                              	nop
  ac755a:	90                                              	nop
  ac755b:	90                                              	nop
  ac755c:	90                                              	nop
  ac755d:	90                                              	nop
  ac755e:	90                                              	nop
  ac755f:	90                                              	nop
  ac7560:	55                                              	push   rbp
  ac7561:	48 89 e5                                        	mov    rbp,rsp
  ac7564:	53                                              	push   rbx
  ac7565:	50                                              	push   rax
  ac7566:	48 8b 1d ab 9c 1f 03                            	mov    rbx,QWORD PTR [rip+0x31f9cab]        # 0x3cc1218
  ac756d:	48 85 db                                        	test   rbx,rbx
  ac7570:	74 45                                           	je     0xac75b7
  ac7572:	48 8b 06                                        	mov    rax,QWORD PTR [rsi]
  ac7575:	eb 13                                           	jmp    0xac758a
  ac7577:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  ac7580:	7f 18                                           	jg     0xac759a
  ac7582:	48 8b 1b                                        	mov    rbx,QWORD PTR [rbx]
  ac7585:	48 85 db                                        	test   rbx,rbx
  ac7588:	74 2d                                           	je     0xac75b7
  ac758a:	48 39 43 10                                     	cmp    QWORD PTR [rbx+0x10],rax
  ac758e:	75 f0                                           	jne    0xac7580
  ac7590:	48 8b 4b 18                                     	mov    rcx,QWORD PTR [rbx+0x18]
  ac7594:	48 3b 4e 08                                     	cmp    rcx,QWORD PTR [rsi+0x8]
  ac7598:	76 e8                                           	jbe    0xac7582
  ac759a:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  ac759e:	48 39 18                                        	cmp    QWORD PTR [rax],rbx
  ac75a1:	75 46                                           	jne    0xac75e9
  ac75a3:	48 89 47 08                                     	mov    QWORD PTR [rdi+0x8],rax
  ac75a7:	48 89 1f                                        	mov    QWORD PTR [rdi],rbx
  ac75aa:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  ac75ae:	48 89 38                                        	mov    QWORD PTR [rax],rdi
  ac75b1:	48 89 7b 08                                     	mov    QWORD PTR [rbx+0x8],rdi
  ac75b5:	eb 1c                                           	jmp    0xac75d3
  ac75b7:	48 c7 07 00 00 00 00                            	mov    QWORD PTR [rdi],0x0
  ac75be:	48 8b 05 5b 9c 1f 03                            	mov    rax,QWORD PTR [rip+0x31f9c5b]        # 0x3cc1220
  ac75c5:	48 89 47 08                                     	mov    QWORD PTR [rdi+0x8],rax
  ac75c9:	48 89 38                                        	mov    QWORD PTR [rax],rdi
  ac75cc:	48 89 3d 4d 9c 1f 03                            	mov    QWORD PTR [rip+0x31f9c4d],rdi        # 0x3cc1220
  ac75d3:	48 8b 06                                        	mov    rax,QWORD PTR [rsi]
  ac75d6:	48 8b 4e 08                                     	mov    rcx,QWORD PTR [rsi+0x8]
  ac75da:	48 89 4f 18                                     	mov    QWORD PTR [rdi+0x18],rcx
  ac75de:	48 89 47 10                                     	mov    QWORD PTR [rdi+0x10],rax
  ac75e2:	48 83 c4 08                                     	add    rsp,0x8
  ac75e6:	5b                                              	pop    rbx
  ac75e7:	5d                                              	pop    rbp
  ac75e8:	c3                                              	ret
  ac75e9:	e8 62 a3 d2 ff                                  	call   0x7f1950
  ac75ee:	48 8b 53 08                                     	mov    rdx,QWORD PTR [rbx+0x8]
  ac75f2:	48 8d 3d f0 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff0]        # 0xac75e9
  ac75f9:	48 89 de                                        	mov    rsi,rbx
  ac75fc:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  ac75ff:	e8 bc aa d2 ff                                  	call   0x7f20c0
  ac7604:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac7608:	48 8d 35 a9 17 8b 00                            	lea    rsi,[rip+0x8b17a9]        # 0x1378db8
  ac760f:	bf 07 00 00 00                                  	mov    edi,0x7
  ac7614:	48 89 da                                        	mov    rdx,rbx
  ac7617:	31 c0                                           	xor    eax,eax
  ac7619:	4c 8b 01                                        	mov    r8,QWORD PTR [rcx]
  ac761c:	e8 ef 33 1d 00                                  	call   0xc9aa10
  ac7621:	0f 0b                                           	ud2
  ac7623:	90                                              	nop
  ac7624:	90                                              	nop
  ac7625:	90                                              	nop
  ac7626:	90                                              	nop
  ac7627:	90                                              	nop
  ac7628:	90                                              	nop
  ac7629:	90                                              	nop
  ac762a:	90                                              	nop
  ac762b:	90                                              	nop
  ac762c:	90                                              	nop
  ac762d:	90                                              	nop
  ac762e:	90                                              	nop
  ac762f:	90                                              	nop
  ac7630:	55                                              	push   rbp
  ac7631:	48 89 e5                                        	mov    rbp,rsp
  ac7634:	41 57                                           	push   r15
  ac7636:	41 56                                           	push   r14
  ac7638:	41 54                                           	push   r12
  ac763a:	53                                              	push   rbx
  ac763b:	48 83 ec 20                                     	sub    rsp,0x20
  ac763f:	4c 8d 3d ca 4c e5 02                            	lea    r15,[rip+0x2e54cca]        # 0x391c310
  ac7646:	48 89 fb                                        	mov    rbx,rdi
  ac7649:	48 8d 3d c0 9b 1f 03                            	lea    rdi,[rip+0x31f9bc0]        # 0x3cc1210
  ac7650:	31 f6                                           	xor    esi,esi
  ac7652:	31 d2                                           	xor    edx,edx
  ac7654:	31 c9                                           	xor    ecx,ecx
  ac7656:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  ac7659:	48 89 45 d8                                     	mov    QWORD PTR [rbp-0x28],rax
  ac765d:	e8 2e fb 9f ff                                  	call   0x4c7190
  ac7662:	44 8b 73 40                                     	mov    r14d,DWORD PTR [rbx+0x40]
  ac7666:	41 f6 c6 04                                     	test   r14b,0x4
  ac766a:	0f 84 f6 00 00 00                               	je     0xac7766
  ac7670:	48 39 1d a1 9b 1f 03                            	cmp    QWORD PTR [rip+0x31f9ba1],rbx        # 0x3cc1218
  ac7677:	74 25                                           	je     0xac769e
  ac7679:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ac767c:	48 85 c0                                        	test   rax,rax
  ac767f:	74 4e                                           	je     0xac76cf
  ac7681:	48 39 58 08                                     	cmp    QWORD PTR [rax+0x8],rbx
  ac7685:	0f 85 4b 01 00 00                               	jne    0xac77d6
  ac768b:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac768f:	48 39 19                                        	cmp    QWORD PTR [rcx],rbx
  ac7692:	0f 85 11 01 00 00                               	jne    0xac77a9
  ac7698:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  ac769c:	eb 45                                           	jmp    0xac76e3
  ac769e:	48 8b 3d 83 9b 1f 03                            	mov    rdi,QWORD PTR [rip+0x31f9b83]        # 0x3cc1228
  ac76a5:	e8 46 61 17 00                                  	call   0xc3d7f0
  ac76aa:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ac76ad:	48 85 c0                                        	test   rax,rax
  ac76b0:	74 45                                           	je     0xac76f7
  ac76b2:	48 39 58 08                                     	cmp    QWORD PTR [rax+0x8],rbx
  ac76b6:	0f 85 83 01 00 00                               	jne    0xac783f
  ac76bc:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac76c0:	48 39 19                                        	cmp    QWORD PTR [rcx],rbx
  ac76c3:	0f 85 3c 01 00 00                               	jne    0xac7805
  ac76c9:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  ac76cd:	eb 3c                                           	jmp    0xac770b
  ac76cf:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  ac76d3:	48 39 18                                        	cmp    QWORD PTR [rax],rbx
  ac76d6:	0f 85 cd 00 00 00                               	jne    0xac77a9
  ac76dc:	48 89 05 3d 9b 1f 03                            	mov    QWORD PTR [rip+0x31f9b3d],rax        # 0x3cc1220
  ac76e3:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ac76e6:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac76ea:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  ac76ed:	44 8b 73 40                                     	mov    r14d,DWORD PTR [rbx+0x40]
  ac76f1:	41 83 e6 fb                                     	and    r14d,0xfffffffb
  ac76f5:	eb 6f                                           	jmp    0xac7766
  ac76f7:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  ac76fb:	48 39 18                                        	cmp    QWORD PTR [rax],rbx
  ac76fe:	0f 85 01 01 00 00                               	jne    0xac7805
  ac7704:	48 89 05 15 9b 1f 03                            	mov    QWORD PTR [rip+0x31f9b15],rax        # 0x3cc1220
  ac770b:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ac770e:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac7712:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  ac7715:	44 8b 73 40                                     	mov    r14d,DWORD PTR [rbx+0x40]
  ac7719:	41 83 e6 fb                                     	and    r14d,0xfffffffb
  ac771d:	44 89 73 40                                     	mov    DWORD PTR [rbx+0x40],r14d
  ac7721:	48 8b 05 f0 9a 1f 03                            	mov    rax,QWORD PTR [rip+0x31f9af0]        # 0x3cc1218
  ac7728:	48 85 c0                                        	test   rax,rax
  ac772b:	74 39                                           	je     0xac7766
  ac772d:	44 8b 60 10                                     	mov    r12d,DWORD PTR [rax+0x10]
  ac7731:	4c 8b 70 18                                     	mov    r14,QWORD PTR [rax+0x18]
  ac7735:	48 8d 7d c8                                     	lea    rdi,[rbp-0x38]
  ac7739:	e8 c2 7a 00 00                                  	call   0xacf200
  ac773e:	4c 2b 75 d0                                     	sub    r14,QWORD PTR [rbp-0x30]
  ac7742:	48 8b 3d df 9a 1f 03                            	mov    rdi,QWORD PTR [rip+0x31f9adf]        # 0x3cc1228
  ac7749:	44 1b 65 c8                                     	sbb    r12d,DWORD PTR [rbp-0x38]
  ac774d:	31 d2                                           	xor    edx,edx
  ac774f:	49 c1 ee 20                                     	shr    r14,0x20
  ac7753:	49 c1 e4 20                                     	shl    r12,0x20
  ac7757:	4d 09 e6                                        	or     r14,r12
  ac775a:	4c 89 f6                                        	mov    rsi,r14
  ac775d:	e8 de 5f 17 00                                  	call   0xc3d740
  ac7762:	44 8b 73 40                                     	mov    r14d,DWORD PTR [rbx+0x40]
  ac7766:	44 89 f0                                        	mov    eax,r14d
  ac7769:	48 8d 3d a0 9a 1f 03                            	lea    rdi,[rip+0x31f9aa0]        # 0x3cc1210
  ac7770:	31 f6                                           	xor    esi,esi
  ac7772:	31 d2                                           	xor    edx,edx
  ac7774:	31 c9                                           	xor    ecx,ecx
  ac7776:	83 c8 10                                        	or     eax,0x10
  ac7779:	89 43 40                                        	mov    DWORD PTR [rbx+0x40],eax
  ac777c:	e8 9f fd 9f ff                                  	call   0x4c7520
  ac7781:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  ac7784:	48 3b 45 d8                                     	cmp    rax,QWORD PTR [rbp-0x28]
  ac7788:	75 18                                           	jne    0xac77a2
  ac778a:	41 c1 e6 1c                                     	shl    r14d,0x1c
  ac778e:	41 c1 fe 1f                                     	sar    r14d,0x1f
  ac7792:	44 89 f0                                        	mov    eax,r14d
  ac7795:	48 83 c4 20                                     	add    rsp,0x20
  ac7799:	5b                                              	pop    rbx
  ac779a:	41 5c                                           	pop    r12
  ac779c:	41 5e                                           	pop    r14
  ac779e:	41 5f                                           	pop    r15
  ac77a0:	5d                                              	pop    rbp
  ac77a1:	c3                                              	ret
  ac77a2:	e8 09 5f c3 ff                                  	call   0x6fd6b0
  ac77a7:	0f 0b                                           	ud2
  ac77a9:	e8 a2 a1 d2 ff                                  	call   0x7f1950
  ac77ae:	48 8b 53 08                                     	mov    rdx,QWORD PTR [rbx+0x8]
  ac77b2:	48 8d 3d f0 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff0]        # 0xac77a9
  ac77b9:	48 89 de                                        	mov    rsi,rbx
  ac77bc:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  ac77bf:	e8 fc a8 d2 ff                                  	call   0x7f20c0
  ac77c4:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac77c8:	48 8d 35 e9 15 8b 00                            	lea    rsi,[rip+0x8b15e9]        # 0x1378db8
  ac77cf:	bf 27 00 00 00                                  	mov    edi,0x27
  ac77d4:	eb 5a                                           	jmp    0xac7830
  ac77d6:	e8 75 a1 d2 ff                                  	call   0x7f1950
  ac77db:	48 8b 13                                        	mov    rdx,QWORD PTR [rbx]
  ac77de:	48 8d 3d f1 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff1]        # 0xac77d6
  ac77e5:	48 89 de                                        	mov    rsi,rbx
  ac77e8:	49 89 d8                                        	mov    r8,rbx
  ac77eb:	48 8b 4a 08                                     	mov    rcx,QWORD PTR [rdx+0x8]
  ac77ef:	e8 8c a9 d2 ff                                  	call   0x7f2180
  ac77f4:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  ac77f7:	48 8d 35 e8 21 7c 00                            	lea    rsi,[rip+0x7c21e8]        # 0x12899e6
  ac77fe:	bf 23 00 00 00                                  	mov    edi,0x23
  ac7803:	eb 67                                           	jmp    0xac786c
  ac7805:	e8 46 a1 d2 ff                                  	call   0x7f1950
  ac780a:	48 8b 53 08                                     	mov    rdx,QWORD PTR [rbx+0x8]
  ac780e:	48 8d 3d f0 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff0]        # 0xac7805
  ac7815:	48 89 de                                        	mov    rsi,rbx
  ac7818:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  ac781b:	e8 a0 a8 d2 ff                                  	call   0x7f20c0
  ac7820:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac7824:	48 8d 35 8d 15 8b 00                            	lea    rsi,[rip+0x8b158d]        # 0x1378db8
  ac782b:	bf 1f 00 00 00                                  	mov    edi,0x1f
  ac7830:	4c 8b 01                                        	mov    r8,QWORD PTR [rcx]
  ac7833:	48 89 da                                        	mov    rdx,rbx
  ac7836:	31 c0                                           	xor    eax,eax
  ac7838:	e8 d3 31 1d 00                                  	call   0xc9aa10
  ac783d:	0f 0b                                           	ud2
  ac783f:	e8 0c a1 d2 ff                                  	call   0x7f1950
  ac7844:	48 8b 13                                        	mov    rdx,QWORD PTR [rbx]
  ac7847:	48 8d 3d f1 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff1]        # 0xac783f
  ac784e:	48 89 de                                        	mov    rsi,rbx
  ac7851:	49 89 d8                                        	mov    r8,rbx
  ac7854:	48 8b 4a 08                                     	mov    rcx,QWORD PTR [rdx+0x8]
  ac7858:	e8 23 a9 d2 ff                                  	call   0x7f2180
  ac785d:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  ac7860:	48 8d 35 7f 21 7c 00                            	lea    rsi,[rip+0x7c217f]        # 0x12899e6
  ac7867:	bf 1b 00 00 00                                  	mov    edi,0x1b
  ac786c:	4c 8b 41 08                                     	mov    r8,QWORD PTR [rcx+0x8]
  ac7870:	48 89 da                                        	mov    rdx,rbx
  ac7873:	49 89 d9                                        	mov    r9,rbx
  ac7876:	31 c0                                           	xor    eax,eax
  ac7878:	e8 93 31 1d 00                                  	call   0xc9aa10
  ac787d:	0f 0b                                           	ud2
  ac787f:	90                                              	nop
  ac7880:	55                                              	push   rbp
  ac7881:	48 89 e5                                        	mov    rbp,rsp
  ac7884:	41 57                                           	push   r15
  ac7886:	41 56                                           	push   r14
  ac7888:	53                                              	push   rbx
  ac7889:	50                                              	push   rax
  ac788a:	4c 8d 35 7f 99 1f 03                            	lea    r14,[rip+0x31f997f]        # 0x3cc1210
  ac7891:	48 89 fb                                        	mov    rbx,rdi
  ac7894:	31 f6                                           	xor    esi,esi
  ac7896:	31 d2                                           	xor    edx,edx
  ac7898:	31 c9                                           	xor    ecx,ecx
  ac789a:	4c 89 f7                                        	mov    rdi,r14
  ac789d:	e8 ee f8 9f ff                                  	call   0x4c7190
  ac78a2:	8b 43 40                                        	mov    eax,DWORD PTR [rbx+0x40]
  ac78a5:	4c 89 f7                                        	mov    rdi,r14
  ac78a8:	31 f6                                           	xor    esi,esi
  ac78aa:	31 d2                                           	xor    edx,edx
  ac78ac:	31 c9                                           	xor    ecx,ecx
  ac78ae:	41 89 c7                                        	mov    r15d,eax
  ac78b1:	83 e0 e7                                        	and    eax,0xffffffe7
  ac78b4:	41 83 e7 10                                     	and    r15d,0x10
  ac78b8:	89 43 40                                        	mov    DWORD PTR [rbx+0x40],eax
  ac78bb:	e8 60 fc 9f ff                                  	call   0x4c7520
  ac78c0:	44 89 f8                                        	mov    eax,r15d
  ac78c3:	48 83 c4 08                                     	add    rsp,0x8
  ac78c7:	5b                                              	pop    rbx
  ac78c8:	41 5e                                           	pop    r14
  ac78ca:	41 5f                                           	pop    r15
  ac78cc:	5d                                              	pop    rbp
  ac78cd:	c3                                              	ret
  ac78ce:	90                                              	nop
  ac78cf:	90                                              	nop
  ac78d0:	55                                              	push   rbp
  ac78d1:	48 89 e5                                        	mov    rbp,rsp
  ac78d4:	48 8d 3d 35 99 1f 03                            	lea    rdi,[rip+0x31f9935]        # 0x3cc1210
  ac78db:	48 8d 35 4b 4d 8a 00                            	lea    rsi,[rip+0x8a4d4b]        # 0x136c62d
  ac78e2:	b9 01 00 00 00                                  	mov    ecx,0x1
  ac78e7:	31 d2                                           	xor    edx,edx
  ac78e9:	e8 e2 04 a0 ff                                  	call   0x4c7dd0
  ac78ee:	48 8d 05 23 99 1f 03                            	lea    rax,[rip+0x31f9923]        # 0x3cc1218
  ac78f5:	48 8d 3d c7 2e 7f 00                            	lea    rdi,[rip+0x7f2ec7]        # 0x12ba7c3
  ac78fc:	be 02 00 00 00                                  	mov    esi,0x2
  ac7901:	ba 02 00 00 00                                  	mov    edx,0x2
  ac7906:	48 c7 05 07 99 1f 03 00 00 00 00                	mov    QWORD PTR [rip+0x31f9907],0x0        # 0x3cc1218
  ac7911:	48 89 05 08 99 1f 03                            	mov    QWORD PTR [rip+0x31f9908],rax        # 0x3cc1220
  ac7918:	e8 63 5d 17 00                                  	call   0xc3d680
  ac791d:	48 89 05 04 99 1f 03                            	mov    QWORD PTR [rip+0x31f9904],rax        # 0x3cc1228
  ac7924:	48 85 c0                                        	test   rax,rax
  ac7927:	74 14                                           	je     0xac793d
  ac7929:	48 8d 35 60 03 7a ff                            	lea    rsi,[rip+0xffffffffff7a0360]        # 0x267c90
  ac7930:	48 89 c7                                        	mov    rdi,rax
  ac7933:	31 d2                                           	xor    edx,edx
  ac7935:	31 c9                                           	xor    ecx,ecx
  ac7937:	5d                                              	pop    rbp
  ac7938:	e9 c3 5d 17 00                                  	jmp    0xc3d700
  ac793d:	e8 0e a0 d2 ff                                  	call   0x7f1950
  ac7942:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0xac793d
  ac7949:	e8 c2 9e d2 ff                                  	call   0x7f1810
  ac794e:	48 8d 35 6a 93 8b 00                            	lea    rsi,[rip+0x8b936a]        # 0x1380cbf
  ac7955:	bf 03 00 00 00                                  	mov    edi,0x3
  ac795a:	31 c0                                           	xor    eax,eax
  ac795c:	e8 af 30 1d 00                                  	call   0xc9aa10
  ac7961:	0f 0b                                           	ud2
  ac7963:	90                                              	nop
  ac7964:	90                                              	nop
  ac7965:	90                                              	nop
  ac7966:	90                                              	nop
  ac7967:	90                                              	nop
  ac7968:	90                                              	nop
  ac7969:	90                                              	nop
  ac796a:	90                                              	nop
  ac796b:	90                                              	nop
  ac796c:	90                                              	nop
  ac796d:	90                                              	nop
  ac796e:	90                                              	nop
  ac796f:	90                                              	nop
  ac7970:	55                                              	push   rbp
  ac7971:	48 89 e5                                        	mov    rbp,rsp
  ac7974:	41 57                                           	push   r15
  ac7976:	41 56                                           	push   r14
  ac7978:	41 55                                           	push   r13
  ac797a:	41 54                                           	push   r12
  ac797c:	53                                              	push   rbx
  ac797d:	48 83 ec 38                                     	sub    rsp,0x38
  ac7981:	48 8d 05 88 49 e5 02                            	lea    rax,[rip+0x2e54988]        # 0x391c310
  ac7988:	48 89 7d a8                                     	mov    QWORD PTR [rbp-0x58],rdi
  ac798c:	48 8d 3d 7d 98 1f 03                            	lea    rdi,[rip+0x31f987d]        # 0x3cc1210
  ac7993:	31 f6                                           	xor    esi,esi
  ac7995:	31 d2                                           	xor    edx,edx
  ac7997:	31 c9                                           	xor    ecx,ecx
  ac7999:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ac799c:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ac79a0:	e8 eb f7 9f ff                                  	call   0x4c7190
  ac79a5:	48 8d 7d c0                                     	lea    rdi,[rbp-0x40]
  ac79a9:	e8 52 78 00 00                                  	call   0xacf200
  ac79ae:	48 8b 1d 63 98 1f 03                            	mov    rbx,QWORD PTR [rip+0x31f9863]        # 0x3cc1218
  ac79b5:	48 85 db                                        	test   rbx,rbx
  ac79b8:	0f 84 0f 02 00 00                               	je     0xac7bcd
  ac79be:	4c 8d 3d 4b 98 1f 03                            	lea    r15,[rip+0x31f984b]        # 0x3cc1210
  ac79c5:	4c 8d 25 bc 04 7a ff                            	lea    r12,[rip+0xffffffffff7a04bc]        # 0x267e88
  ac79cc:	4c 8d 6d c0                                     	lea    r13,[rbp-0x40]
  ac79d0:	e9 9f 00 00 00                                  	jmp    0xac7a74
  ac79d5:	66 66 2e 0f 1f 84 00 00 00 00 00                	data16 cs nop WORD PTR [rax+rax*1+0x0]
  ac79e0:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  ac79e3:	48 8b 53 08                                     	mov    rdx,QWORD PTR [rbx+0x8]
  ac79e7:	48 89 df                                        	mov    rdi,rbx
  ac79ea:	48 8d 75 b0                                     	lea    rsi,[rbp-0x50]
  ac79ee:	48 89 0a                                        	mov    QWORD PTR [rdx],rcx
  ac79f1:	48 8b 08                                        	mov    rcx,QWORD PTR [rax]
  ac79f4:	48 8b 40 08                                     	mov    rax,QWORD PTR [rax+0x8]
  ac79f8:	48 89 45 b8                                     	mov    QWORD PTR [rbp-0x48],rax
  ac79fc:	48 89 4d b0                                     	mov    QWORD PTR [rbp-0x50],rcx
  ac7a00:	48 03 43 28                                     	add    rax,QWORD PTR [rbx+0x28]
  ac7a04:	48 89 45 b8                                     	mov    QWORD PTR [rbp-0x48],rax
  ac7a08:	48 13 4b 20                                     	adc    rcx,QWORD PTR [rbx+0x20]
  ac7a0c:	48 89 4d b0                                     	mov    QWORD PTR [rbp-0x50],rcx
  ac7a10:	e8 4b fb ff ff                                  	call   0xac7560
  ac7a15:	80 4b 40 08                                     	or     BYTE PTR [rbx+0x40],0x8
  ac7a19:	4c 89 ff                                        	mov    rdi,r15
  ac7a1c:	31 f6                                           	xor    esi,esi
  ac7a1e:	31 d2                                           	xor    edx,edx
  ac7a20:	31 c9                                           	xor    ecx,ecx
  ac7a22:	e8 f9 fa 9f ff                                  	call   0x4c7520
  ac7a27:	ff 43 44                                        	inc    DWORD PTR [rbx+0x44]
  ac7a2a:	4c 89 e0                                        	mov    rax,r12
  ac7a2d:	4c 8b 73 30                                     	mov    r14,QWORD PTR [rbx+0x30]
  ac7a31:	4c 29 f0                                        	sub    rax,r14
  ac7a34:	48 c1 c8 03                                     	ror    rax,0x3
  ac7a38:	48 3d 97 01 00 00                               	cmp    rax,0x197
  ac7a3e:	0f 87 44 01 00 00                               	ja     0xac7b88
  ac7a44:	48 8b 73 38                                     	mov    rsi,QWORD PTR [rbx+0x38]
  ac7a48:	48 89 df                                        	mov    rdi,rbx
  ac7a4b:	41 ff d6                                        	call   r14
  ac7a4e:	4c 89 ff                                        	mov    rdi,r15
  ac7a51:	31 f6                                           	xor    esi,esi
  ac7a53:	31 d2                                           	xor    edx,edx
  ac7a55:	31 c9                                           	xor    ecx,ecx
  ac7a57:	e8 34 f7 9f ff                                  	call   0x4c7190
  ac7a5c:	4c 89 ef                                        	mov    rdi,r13
  ac7a5f:	e8 9c 77 00 00                                  	call   0xacf200
  ac7a64:	48 8b 1d ad 97 1f 03                            	mov    rbx,QWORD PTR [rip+0x31f97ad]        # 0x3cc1218
  ac7a6b:	48 85 db                                        	test   rbx,rbx
  ac7a6e:	0f 84 59 01 00 00                               	je     0xac7bcd
  ac7a74:	48 8b 4b 10                                     	mov    rcx,QWORD PTR [rbx+0x10]
  ac7a78:	48 8b 75 c0                                     	mov    rsi,QWORD PTR [rbp-0x40]
  ac7a7c:	48 8d 43 10                                     	lea    rax,[rbx+0x10]
  ac7a80:	48 39 f1                                        	cmp    rcx,rsi
  ac7a83:	75 1b                                           	jne    0xac7aa0
  ac7a85:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  ac7a89:	48 39 53 18                                     	cmp    QWORD PTR [rbx+0x18],rdx
  ac7a8d:	76 17                                           	jbe    0xac7aa6
  ac7a8f:	e9 0f 01 00 00                                  	jmp    0xac7ba3
  ac7a94:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ac7aa0:	0f 8f f6 00 00 00                               	jg     0xac7b9c
  ac7aa6:	f6 43 40 02                                     	test   BYTE PTR [rbx+0x40],0x2
  ac7aaa:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  ac7aad:	75 31                                           	jne    0xac7ae0
  ac7aaf:	48 85 c9                                        	test   rcx,rcx
  ac7ab2:	74 55                                           	je     0xac7b09
  ac7ab4:	48 39 59 08                                     	cmp    QWORD PTR [rcx+0x8],rbx
  ac7ab8:	0f 85 da 01 00 00                               	jne    0xac7c98
  ac7abe:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  ac7ac2:	48 39 18                                        	cmp    QWORD PTR [rax],rbx
  ac7ac5:	0f 85 37 01 00 00                               	jne    0xac7c02
  ac7acb:	48 89 41 08                                     	mov    QWORD PTR [rcx+0x8],rax
  ac7acf:	eb 4c                                           	jmp    0xac7b1d
  ac7ad1:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ac7ae0:	48 85 c9                                        	test   rcx,rcx
  ac7ae3:	0f 84 86 00 00 00                               	je     0xac7b6f
  ac7ae9:	48 39 59 08                                     	cmp    QWORD PTR [rcx+0x8],rbx
  ac7aed:	0f 85 76 01 00 00                               	jne    0xac7c69
  ac7af3:	48 8b 53 08                                     	mov    rdx,QWORD PTR [rbx+0x8]
  ac7af7:	48 39 1a                                        	cmp    QWORD PTR [rdx],rbx
  ac7afa:	0f 85 2f 01 00 00                               	jne    0xac7c2f
  ac7b00:	48 89 51 08                                     	mov    QWORD PTR [rcx+0x8],rdx
  ac7b04:	e9 d7 fe ff ff                                  	jmp    0xac79e0
  ac7b09:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  ac7b0d:	48 39 18                                        	cmp    QWORD PTR [rax],rbx
  ac7b10:	0f 85 ec 00 00 00                               	jne    0xac7c02
  ac7b16:	48 89 05 03 97 1f 03                            	mov    QWORD PTR [rip+0x31f9703],rax        # 0x3cc1220
  ac7b1d:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ac7b20:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac7b24:	4c 89 ff                                        	mov    rdi,r15
  ac7b27:	31 f6                                           	xor    esi,esi
  ac7b29:	31 d2                                           	xor    edx,edx
  ac7b2b:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  ac7b2e:	31 c9                                           	xor    ecx,ecx
  ac7b30:	8b 43 40                                        	mov    eax,DWORD PTR [rbx+0x40]
  ac7b33:	83 e0 f3                                        	and    eax,0xfffffff3
  ac7b36:	83 c8 08                                        	or     eax,0x8
  ac7b39:	89 43 40                                        	mov    DWORD PTR [rbx+0x40],eax
  ac7b3c:	e8 df f9 9f ff                                  	call   0x4c7520
  ac7b41:	4c 8b 73 30                                     	mov    r14,QWORD PTR [rbx+0x30]
  ac7b45:	4c 89 e0                                        	mov    rax,r12
  ac7b48:	4c 29 f0                                        	sub    rax,r14
  ac7b4b:	48 c1 c8 03                                     	ror    rax,0x3
  ac7b4f:	48 3d 97 01 00 00                               	cmp    rax,0x197
  ac7b55:	0f 86 e9 fe ff ff                               	jbe    0xac7a44
  ac7b5b:	48 8d 3d 5e 23 dc 01                            	lea    rdi,[rip+0x1dc235e]        # 0x2889ec0
  ac7b62:	4c 89 f6                                        	mov    rsi,r14
  ac7b65:	e8 56 7d 98 ff                                  	call   0x44f8c0
  ac7b6a:	e9 d5 fe ff ff                                  	jmp    0xac7a44
  ac7b6f:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac7b73:	48 39 19                                        	cmp    QWORD PTR [rcx],rbx
  ac7b76:	0f 85 b3 00 00 00                               	jne    0xac7c2f
  ac7b7c:	48 89 0d 9d 96 1f 03                            	mov    QWORD PTR [rip+0x31f969d],rcx        # 0x3cc1220
  ac7b83:	e9 58 fe ff ff                                  	jmp    0xac79e0
  ac7b88:	48 8d 3d 11 23 dc 01                            	lea    rdi,[rip+0x1dc2311]        # 0x2889ea0
  ac7b8f:	4c 89 f6                                        	mov    rsi,r14
  ac7b92:	e8 29 7d 98 ff                                  	call   0x44f8c0
  ac7b97:	e9 a8 fe ff ff                                  	jmp    0xac7a44
  ac7b9c:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  ac7ba0:	48 89 f1                                        	mov    rcx,rsi
  ac7ba3:	48 8b 30                                        	mov    rsi,QWORD PTR [rax]
  ac7ba6:	48 8b 40 08                                     	mov    rax,QWORD PTR [rax+0x8]
  ac7baa:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  ac7bae:	48 89 45 b8                                     	mov    QWORD PTR [rbp-0x48],rax
  ac7bb2:	48 29 d0                                        	sub    rax,rdx
  ac7bb5:	48 89 75 b0                                     	mov    QWORD PTR [rbp-0x50],rsi
  ac7bb9:	19 ce                                           	sbb    esi,ecx
  ac7bbb:	48 c1 e8 20                                     	shr    rax,0x20
  ac7bbf:	31 d2                                           	xor    edx,edx
  ac7bc1:	48 c1 e6 20                                     	shl    rsi,0x20
  ac7bc5:	48 09 c6                                        	or     rsi,rax
  ac7bc8:	e8 73 5b 17 00                                  	call   0xc3d740
  ac7bcd:	48 8d 3d 3c 96 1f 03                            	lea    rdi,[rip+0x31f963c]        # 0x3cc1210
  ac7bd4:	31 f6                                           	xor    esi,esi
  ac7bd6:	31 d2                                           	xor    edx,edx
  ac7bd8:	31 c9                                           	xor    ecx,ecx
  ac7bda:	e8 41 f9 9f ff                                  	call   0x4c7520
  ac7bdf:	48 8d 05 2a 47 e5 02                            	lea    rax,[rip+0x2e5472a]        # 0x391c310
  ac7be6:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ac7be9:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ac7bed:	0f 85 e5 00 00 00                               	jne    0xac7cd8
  ac7bf3:	48 83 c4 38                                     	add    rsp,0x38
  ac7bf7:	5b                                              	pop    rbx
  ac7bf8:	41 5c                                           	pop    r12
  ac7bfa:	41 5d                                           	pop    r13
  ac7bfc:	41 5e                                           	pop    r14
  ac7bfe:	41 5f                                           	pop    r15
  ac7c00:	5d                                              	pop    rbp
  ac7c01:	c3                                              	ret
  ac7c02:	e8 49 9d d2 ff                                  	call   0x7f1950
  ac7c07:	48 8b 53 08                                     	mov    rdx,QWORD PTR [rbx+0x8]
  ac7c0b:	48 8d 3d f0 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff0]        # 0xac7c02
  ac7c12:	48 89 de                                        	mov    rsi,rbx
  ac7c15:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  ac7c18:	e8 a3 a4 d2 ff                                  	call   0x7f20c0
  ac7c1d:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac7c21:	48 8d 35 90 11 8b 00                            	lea    rsi,[rip+0x8b1190]        # 0x1378db8
  ac7c28:	bf 17 00 00 00                                  	mov    edi,0x17
  ac7c2d:	eb 2b                                           	jmp    0xac7c5a
  ac7c2f:	e8 1c 9d d2 ff                                  	call   0x7f1950
  ac7c34:	48 8b 53 08                                     	mov    rdx,QWORD PTR [rbx+0x8]
  ac7c38:	48 8d 3d f0 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff0]        # 0xac7c2f
  ac7c3f:	48 89 de                                        	mov    rsi,rbx
  ac7c42:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  ac7c45:	e8 76 a4 d2 ff                                  	call   0x7f20c0
  ac7c4a:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac7c4e:	48 8d 35 63 11 8b 00                            	lea    rsi,[rip+0x8b1163]        # 0x1378db8
  ac7c55:	bf 0f 00 00 00                                  	mov    edi,0xf
  ac7c5a:	4c 8b 01                                        	mov    r8,QWORD PTR [rcx]
  ac7c5d:	48 89 da                                        	mov    rdx,rbx
  ac7c60:	31 c0                                           	xor    eax,eax
  ac7c62:	e8 a9 2d 1d 00                                  	call   0xc9aa10
  ac7c67:	0f 0b                                           	ud2
  ac7c69:	e8 e2 9c d2 ff                                  	call   0x7f1950
  ac7c6e:	48 8b 13                                        	mov    rdx,QWORD PTR [rbx]
  ac7c71:	48 8d 3d f1 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff1]        # 0xac7c69
  ac7c78:	48 89 de                                        	mov    rsi,rbx
  ac7c7b:	49 89 d8                                        	mov    r8,rbx
  ac7c7e:	48 8b 4a 08                                     	mov    rcx,QWORD PTR [rdx+0x8]
  ac7c82:	e8 f9 a4 d2 ff                                  	call   0x7f2180
  ac7c87:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  ac7c8a:	48 8d 35 55 1d 7c 00                            	lea    rsi,[rip+0x7c1d55]        # 0x12899e6
  ac7c91:	bf 0b 00 00 00                                  	mov    edi,0xb
  ac7c96:	eb 2d                                           	jmp    0xac7cc5
  ac7c98:	e8 b3 9c d2 ff                                  	call   0x7f1950
  ac7c9d:	48 8b 13                                        	mov    rdx,QWORD PTR [rbx]
  ac7ca0:	48 8d 3d f1 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff1]        # 0xac7c98
  ac7ca7:	48 89 de                                        	mov    rsi,rbx
  ac7caa:	49 89 d8                                        	mov    r8,rbx
  ac7cad:	48 8b 4a 08                                     	mov    rcx,QWORD PTR [rdx+0x8]
  ac7cb1:	e8 ca a4 d2 ff                                  	call   0x7f2180
  ac7cb6:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  ac7cb9:	48 8d 35 26 1d 7c 00                            	lea    rsi,[rip+0x7c1d26]        # 0x12899e6
  ac7cc0:	bf 13 00 00 00                                  	mov    edi,0x13
  ac7cc5:	4c 8b 41 08                                     	mov    r8,QWORD PTR [rcx+0x8]
  ac7cc9:	48 89 da                                        	mov    rdx,rbx
  ac7ccc:	49 89 d9                                        	mov    r9,rbx
  ac7ccf:	31 c0                                           	xor    eax,eax
  ac7cd1:	e8 3a 2d 1d 00                                  	call   0xc9aa10
  ac7cd6:	0f 0b                                           	ud2
  ac7cd8:	e8 d3 59 c3 ff                                  	call   0x6fd6b0
  ac7cdd:	0f 0b                                           	ud2
  ac7cdf:	90                                              	nop
  ac7ce0:	55                                              	push   rbp
  ac7ce1:	48 89 e5                                        	mov    rbp,rsp
  ac7ce4:	48 8d 3d 45 95 1f 03                            	lea    rdi,[rip+0x31f9545]        # 0x3cc1230
  ac7ceb:	be 80 00 00 00                                  	mov    esi,0x80
  ac7cf0:	e8 fb 12 79 ff                                  	call   0x258ff0
  ac7cf5:	48 8d 3d b4 95 1f 03                            	lea    rdi,[rip+0x31f95b4]        # 0x3cc12b0
  ac7cfc:	be 40 00 00 00                                  	mov    esi,0x40
  ac7d01:	e8 ea 12 79 ff                                  	call   0x258ff0
  ac7d06:	48 8d 3d e3 95 1f 03                            	lea    rdi,[rip+0x31f95e3]        # 0x3cc12f0
  ac7d0d:	be 1c 00 00 00                                  	mov    esi,0x1c
  ac7d12:	e8 d9 12 79 ff                                  	call   0x258ff0
  ac7d17:	e8 b4 f5 87 ff                                  	call   0x3472d0
  ac7d1c:	48 89 05 ed 95 1f 03                            	mov    QWORD PTR [rip+0x31f95ed],rax        # 0x3cc1310
  ac7d23:	5d                                              	pop    rbp
  ac7d24:	c3                                              	ret
  ac7d25:	90                                              	nop
  ac7d26:	90                                              	nop
  ac7d27:	90                                              	nop
  ac7d28:	90                                              	nop
  ac7d29:	90                                              	nop
  ac7d2a:	90                                              	nop
  ac7d2b:	90                                              	nop
  ac7d2c:	90                                              	nop
  ac7d2d:	90                                              	nop
  ac7d2e:	90                                              	nop
  ac7d2f:	90                                              	nop
  ac7d30:	55                                              	push   rbp
  ac7d31:	48 89 e5                                        	mov    rbp,rsp
  ac7d34:	41 57                                           	push   r15
  ac7d36:	41 56                                           	push   r14
  ac7d38:	41 54                                           	push   r12
  ac7d3a:	53                                              	push   rbx
  ac7d3b:	48 83 3d ed 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94ed],0x0        # 0x3cc1230
  ac7d43:	48 89 fb                                        	mov    rbx,rdi
  ac7d46:	0f 84 df 00 00 00                               	je     0xac7e2b
  ac7d4c:	48 83 3d e4 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94e4],0x0        # 0x3cc1238
  ac7d54:	0f 84 d6 00 00 00                               	je     0xac7e30
  ac7d5a:	48 83 3d de 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94de],0x0        # 0x3cc1240
  ac7d62:	0f 84 d0 00 00 00                               	je     0xac7e38
  ac7d68:	48 83 3d d8 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94d8],0x0        # 0x3cc1248
  ac7d70:	0f 84 ca 00 00 00                               	je     0xac7e40
  ac7d76:	48 83 3d d2 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94d2],0x0        # 0x3cc1250
  ac7d7e:	0f 84 c4 00 00 00                               	je     0xac7e48
  ac7d84:	48 83 3d cc 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94cc],0x0        # 0x3cc1258
  ac7d8c:	0f 84 be 00 00 00                               	je     0xac7e50
  ac7d92:	48 83 3d c6 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94c6],0x0        # 0x3cc1260
  ac7d9a:	0f 84 b8 00 00 00                               	je     0xac7e58
  ac7da0:	48 83 3d c0 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94c0],0x0        # 0x3cc1268
  ac7da8:	0f 84 b2 00 00 00                               	je     0xac7e60
  ac7dae:	48 83 3d ba 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94ba],0x0        # 0x3cc1270
  ac7db6:	0f 84 ac 00 00 00                               	je     0xac7e68
  ac7dbc:	48 83 3d b4 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94b4],0x0        # 0x3cc1278
  ac7dc4:	0f 84 a6 00 00 00                               	je     0xac7e70
  ac7dca:	48 83 3d ae 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94ae],0x0        # 0x3cc1280
  ac7dd2:	0f 84 a0 00 00 00                               	je     0xac7e78
  ac7dd8:	48 83 3d a8 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94a8],0x0        # 0x3cc1288
  ac7de0:	0f 84 9a 00 00 00                               	je     0xac7e80
  ac7de6:	48 83 3d a2 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f94a2],0x0        # 0x3cc1290
  ac7dee:	0f 84 94 00 00 00                               	je     0xac7e88
  ac7df4:	48 83 3d 9c 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f949c],0x0        # 0x3cc1298
  ac7dfc:	0f 84 8e 00 00 00                               	je     0xac7e90
  ac7e02:	48 83 3d 96 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f9496],0x0        # 0x3cc12a0
  ac7e0a:	0f 84 88 00 00 00                               	je     0xac7e98
  ac7e10:	48 83 3d 90 94 1f 03 00                         	cmp    QWORD PTR [rip+0x31f9490],0x0        # 0x3cc12a8
  ac7e18:	b8 0a 00 3b 80                                  	mov    eax,0x803b000a
  ac7e1d:	0f 85 6b 01 00 00                               	jne    0xac7f8e
  ac7e23:	41 be 0f 00 00 00                               	mov    r14d,0xf
  ac7e29:	eb 73                                           	jmp    0xac7e9e
  ac7e2b:	45 31 f6                                        	xor    r14d,r14d
  ac7e2e:	eb 6e                                           	jmp    0xac7e9e
  ac7e30:	41 be 01 00 00 00                               	mov    r14d,0x1
  ac7e36:	eb 66                                           	jmp    0xac7e9e
  ac7e38:	41 be 02 00 00 00                               	mov    r14d,0x2
  ac7e3e:	eb 5e                                           	jmp    0xac7e9e
  ac7e40:	41 be 03 00 00 00                               	mov    r14d,0x3
  ac7e46:	eb 56                                           	jmp    0xac7e9e
  ac7e48:	41 be 04 00 00 00                               	mov    r14d,0x4
  ac7e4e:	eb 4e                                           	jmp    0xac7e9e
  ac7e50:	41 be 05 00 00 00                               	mov    r14d,0x5
  ac7e56:	eb 46                                           	jmp    0xac7e9e
  ac7e58:	41 be 06 00 00 00                               	mov    r14d,0x6
  ac7e5e:	eb 3e                                           	jmp    0xac7e9e
  ac7e60:	41 be 07 00 00 00                               	mov    r14d,0x7
  ac7e66:	eb 36                                           	jmp    0xac7e9e
  ac7e68:	41 be 08 00 00 00                               	mov    r14d,0x8
  ac7e6e:	eb 2e                                           	jmp    0xac7e9e
  ac7e70:	41 be 09 00 00 00                               	mov    r14d,0x9
  ac7e76:	eb 26                                           	jmp    0xac7e9e
  ac7e78:	41 be 0a 00 00 00                               	mov    r14d,0xa
  ac7e7e:	eb 1e                                           	jmp    0xac7e9e
  ac7e80:	41 be 0b 00 00 00                               	mov    r14d,0xb
  ac7e86:	eb 16                                           	jmp    0xac7e9e
  ac7e88:	41 be 0c 00 00 00                               	mov    r14d,0xc
  ac7e8e:	eb 0e                                           	jmp    0xac7e9e
  ac7e90:	41 be 0d 00 00 00                               	mov    r14d,0xd
  ac7e96:	eb 06                                           	jmp    0xac7e9e
  ac7e98:	41 be 0e 00 00 00                               	mov    r14d,0xe
  ac7e9e:	bf 50 27 00 00                                  	mov    edi,0x2750
  ac7ea3:	e8 c8 ee 87 ff                                  	call   0x346d70
  ac7ea8:	48 85 c0                                        	test   rax,rax
  ac7eab:	0f 84 d8 00 00 00                               	je     0xac7f89
  ac7eb1:	be 50 27 00 00                                  	mov    esi,0x2750
  ac7eb6:	48 89 c7                                        	mov    rdi,rax
  ac7eb9:	49 89 c7                                        	mov    r15,rax
  ac7ebc:	e8 2f 11 79 ff                                  	call   0x258ff0
  ac7ec1:	44 89 f6                                        	mov    esi,r14d
  ac7ec4:	31 ff                                           	xor    edi,edi
  ac7ec6:	31 d2                                           	xor    edx,edx
  ac7ec8:	e8 73 f2 8d ff                                  	call   0x3a7140
  ac7ecd:	89 43 04                                        	mov    DWORD PTR [rbx+0x4],eax
  ac7ed0:	4c 89 bb 98 01 00 00                            	mov    QWORD PTR [rbx+0x198],r15
  ac7ed7:	83 3d 12 94 1f 03 00                            	cmp    DWORD PTR [rip+0x31f9412],0x0        # 0x3cc12f0
  ac7ede:	74 29                                           	je     0xac7f09
  ac7ee0:	8b 05 1e 94 1f 03                               	mov    eax,DWORD PTR [rip+0x31f941e]        # 0x3cc1304
  ac7ee6:	41 89 87 3c 27 00 00                            	mov    DWORD PTR [r15+0x273c],eax
  ac7eed:	48 8b 05 08 94 1f 03                            	mov    rax,QWORD PTR [rip+0x31f9408]        # 0x3cc12fc
  ac7ef4:	49 89 87 34 27 00 00                            	mov    QWORD PTR [r15+0x2734],rax
  ac7efb:	48 8b 05 f2 93 1f 03                            	mov    rax,QWORD PTR [rip+0x31f93f2]        # 0x3cc12f4
  ac7f02:	49 89 87 2c 27 00 00                            	mov    QWORD PTR [r15+0x272c],rax
  ac7f09:	48 b8 00 00 00 00 04 00 00 00                   	movabs rax,0x400000000
  ac7f13:	49 89 87 40 27 00 00                            	mov    QWORD PTR [r15+0x2740],rax
  ac7f1a:	41 c7 87 48 27 00 00 01 00 00 00                	mov    DWORD PTR [r15+0x2748],0x1
  ac7f25:	80 7b 18 02                                     	cmp    BYTE PTR [rbx+0x18],0x2
  ac7f29:	75 4c                                           	jne    0xac7f77
  ac7f2b:	41 83 bf 2c 27 00 00 00                         	cmp    DWORD PTR [r15+0x272c],0x0
  ac7f33:	7e 42                                           	jle    0xac7f77
  ac7f35:	45 8b a7 30 27 00 00                            	mov    r12d,DWORD PTR [r15+0x2730]
  ac7f3c:	e8 af 74 99 ff                                  	call   0x45f3f0
  ac7f41:	48 85 c0                                        	test   rax,rax
  ac7f44:	74 31                                           	je     0xac7f77
  ac7f46:	44 39 60 04                                     	cmp    DWORD PTR [rax+0x4],r12d
  ac7f4a:	75 2b                                           	jne    0xac7f77
  ac7f4c:	31 c9                                           	xor    ecx,ecx
  ac7f4e:	eb 09                                           	jmp    0xac7f59
  ac7f50:	48 ff c1                                        	inc    rcx
  ac7f53:	48 83 f9 18                                     	cmp    rcx,0x18
  ac7f57:	74 1e                                           	je     0xac7f77
  ac7f59:	48 8b 94 c8 e8 00 00 00                         	mov    rdx,QWORD PTR [rax+rcx*8+0xe8]
  ac7f61:	48 85 d2                                        	test   rdx,rdx
  ac7f64:	74 ea                                           	je     0xac7f50
  ac7f66:	83 3a 00                                        	cmp    DWORD PTR [rdx],0x0
  ac7f69:	74 e5                                           	je     0xac7f50
  ac7f6b:	8b 52 38                                        	mov    edx,DWORD PTR [rdx+0x38]
  ac7f6e:	41 89 97 48 27 00 00                            	mov    DWORD PTR [r15+0x2748],edx
  ac7f75:	eb d9                                           	jmp    0xac7f50
  ac7f77:	44 89 f0                                        	mov    eax,r14d
  ac7f7a:	48 8d 0d af 92 1f 03                            	lea    rcx,[rip+0x31f92af]        # 0x3cc1230
  ac7f81:	48 89 1c c1                                     	mov    QWORD PTR [rcx+rax*8],rbx
  ac7f85:	31 c0                                           	xor    eax,eax
  ac7f87:	eb 05                                           	jmp    0xac7f8e
  ac7f89:	b8 0a 00 3b 80                                  	mov    eax,0x803b000a
  ac7f8e:	5b                                              	pop    rbx
  ac7f8f:	41 5c                                           	pop    r12
  ac7f91:	41 5e                                           	pop    r14
  ac7f93:	41 5f                                           	pop    r15
  ac7f95:	5d                                              	pop    rbp
  ac7f96:	c3                                              	ret
  ac7f97:	90                                              	nop
  ac7f98:	90                                              	nop
  ac7f99:	90                                              	nop
  ac7f9a:	90                                              	nop
  ac7f9b:	90                                              	nop
  ac7f9c:	90                                              	nop
  ac7f9d:	90                                              	nop
  ac7f9e:	90                                              	nop
  ac7f9f:	90                                              	nop
  ac7fa0:	55                                              	push   rbp
  ac7fa1:	48 89 e5                                        	mov    rbp,rsp
  ac7fa4:	53                                              	push   rbx
  ac7fa5:	50                                              	push   rax
  ac7fa6:	48 8d 35 83 92 1f 03                            	lea    rsi,[rip+0x31f9283]        # 0x3cc1230
  ac7fad:	ba 10 00 00 00                                  	mov    edx,0x10
  ac7fb2:	48 89 fb                                        	mov    rbx,rdi
  ac7fb5:	e8 46 fa 8d ff                                  	call   0x3a7a00
  ac7fba:	85 c0                                           	test   eax,eax
  ac7fbc:	78 2c                                           	js     0xac7fea
  ac7fbe:	83 7b 08 00                                     	cmp    DWORD PTR [rbx+0x8],0x0
  ac7fc2:	74 0a                                           	je     0xac7fce
  ac7fc4:	48 89 df                                        	mov    rdi,rbx
  ac7fc7:	31 f6                                           	xor    esi,esi
  ac7fc9:	e8 62 f7 8d ff                                  	call   0x3a7730
  ac7fce:	48 8b bb 98 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x198]
  ac7fd5:	48 85 ff                                        	test   rdi,rdi
  ac7fd8:	74 10                                           	je     0xac7fea
  ac7fda:	e8 61 ef 87 ff                                  	call   0x346f40
  ac7fdf:	48 c7 83 98 01 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x198],0x0
  ac7fea:	48 83 c4 08                                     	add    rsp,0x8
  ac7fee:	5b                                              	pop    rbx
  ac7fef:	5d                                              	pop    rbp
  ac7ff0:	c3                                              	ret
  ac7ff1:	90                                              	nop
  ac7ff2:	90                                              	nop
  ac7ff3:	90                                              	nop
  ac7ff4:	90                                              	nop
  ac7ff5:	90                                              	nop
  ac7ff6:	90                                              	nop
  ac7ff7:	90                                              	nop
  ac7ff8:	90                                              	nop
  ac7ff9:	90                                              	nop
  ac7ffa:	90                                              	nop
  ac7ffb:	90                                              	nop
  ac7ffc:	90                                              	nop
  ac7ffd:	90                                              	nop
  ac7ffe:	90                                              	nop
  ac7fff:	90                                              	nop
  ac8000:	55                                              	push   rbp
  ac8001:	48 89 e5                                        	mov    rbp,rsp
  ac8004:	41 57                                           	push   r15
  ac8006:	41 56                                           	push   r14
  ac8008:	41 55                                           	push   r13
  ac800a:	41 54                                           	push   r12
  ac800c:	53                                              	push   rbx
  ac800d:	48 8b 87 98 01 00 00                            	mov    rax,QWORD PTR [rdi+0x198]
  ac8014:	0f b7 3a                                        	movzx  edi,WORD PTR [rdx]
  ac8017:	83 ff 0c                                        	cmp    edi,0xc
  ac801a:	0f 84 f3 00 00 00                               	je     0xac8113
  ac8020:	83 ff 09                                        	cmp    edi,0x9
  ac8023:	0f 84 a5 00 00 00                               	je     0xac80ce
  ac8029:	83 ff 01                                        	cmp    edi,0x1
  ac802c:	0f 85 19 01 00 00                               	jne    0xac814b
  ac8032:	41 83 e0 07                                     	and    r8d,0x7
  ac8036:	48 8d 78 64                                     	lea    rdi,[rax+0x64]
  ac803a:	4c 8d 48 50                                     	lea    r9,[rax+0x50]
  ac803e:	48 83 c0 3c                                     	add    rax,0x3c
  ac8042:	45 31 d2                                        	xor    r10d,r10d
  ac8045:	eb 16                                           	jmp    0xac805d
  ac8047:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  ac8050:	49 ff c2                                        	inc    r10
  ac8053:	49 83 fa 20                                     	cmp    r10,0x20
  ac8057:	0f 84 ee 00 00 00                               	je     0xac814b
  ac805d:	4c 63 5a 1c                                     	movsxd r11,DWORD PTR [rdx+0x1c]
  ac8061:	4d 39 da                                        	cmp    r10,r11
  ac8064:	0f 8d e1 00 00 00                               	jge    0xac814b
  ac806a:	42 0f b7 1c 51                                  	movzx  ebx,WORD PTR [rcx+r10*2]
  ac806f:	85 db                                           	test   ebx,ebx
  ac8071:	0f 84 d4 00 00 00                               	je     0xac814b
  ac8077:	41 83 f8 06                                     	cmp    r8d,0x6
  ac807b:	75 d3                                           	jne    0xac8050
  ac807d:	49 89 c3                                        	mov    r11,rax
  ac8080:	83 fb 30                                        	cmp    ebx,0x30
  ac8083:	74 0d                                           	je     0xac8092
  ac8085:	83 fb 38                                        	cmp    ebx,0x38
  ac8088:	74 0f                                           	je     0xac8099
  ac808a:	4d 89 cb                                        	mov    r11,r9
  ac808d:	83 fb 31                                        	cmp    ebx,0x31
  ac8090:	75 be                                           	jne    0xac8050
  ac8092:	4d 85 db                                        	test   r11,r11
  ac8095:	75 0a                                           	jne    0xac80a1
  ac8097:	eb b7                                           	jmp    0xac8050
  ac8099:	49 89 fb                                        	mov    r11,rdi
  ac809c:	4d 85 db                                        	test   r11,r11
  ac809f:	74 af                                           	je     0xac8050
  ac80a1:	41 c7 03 01 00 00 00                            	mov    DWORD PTR [r11],0x1
  ac80a8:	0f b6 5a 18                                     	movzx  ebx,BYTE PTR [rdx+0x18]
  ac80ac:	41 88 5b 04                                     	mov    BYTE PTR [r11+0x4],bl
  ac80b0:	8b 5a 14                                        	mov    ebx,DWORD PTR [rdx+0x14]
  ac80b3:	41 0f af da                                     	imul   ebx,r10d
  ac80b7:	01 f3                                           	add    ebx,esi
  ac80b9:	41 89 5b 08                                     	mov    DWORD PTR [r11+0x8],ebx
  ac80bd:	8b 5a 14                                        	mov    ebx,DWORD PTR [rdx+0x14]
  ac80c0:	41 89 5b 0c                                     	mov    DWORD PTR [r11+0xc],ebx
  ac80c4:	41 c7 43 10 01 00 00 00                         	mov    DWORD PTR [r11+0x10],0x1
  ac80cc:	eb 82                                           	jmp    0xac8050
  ac80ce:	41 83 e0 07                                     	and    r8d,0x7
  ac80d2:	41 83 f8 02                                     	cmp    r8d,0x2
  ac80d6:	75 73                                           	jne    0xac814b
  ac80d8:	83 7a 04 00                                     	cmp    DWORD PTR [rdx+0x4],0x0
  ac80dc:	75 6d                                           	jne    0xac814b
  ac80de:	83 7a 08 01                                     	cmp    DWORD PTR [rdx+0x8],0x1
  ac80e2:	75 67                                           	jne    0xac814b
  ac80e4:	83 7a 14 01                                     	cmp    DWORD PTR [rdx+0x14],0x1
  ac80e8:	75 61                                           	jne    0xac814b
  ac80ea:	0f b7 79 40                                     	movzx  edi,WORD PTR [rcx+0x40]
  ac80ee:	0f b7 59 42                                     	movzx  ebx,WORD PTR [rcx+0x42]
  ac80f2:	66 39 df                                        	cmp    di,bx
  ac80f5:	77 54                                           	ja     0xac814b
  ac80f7:	4c 8d 40 24                                     	lea    r8,[rax+0x24]
  ac80fb:	4c 8d 48 18                                     	lea    r9,[rax+0x18]
  ac80ff:	4c 8d 50 0c                                     	lea    r10,[rax+0xc]
  ac8103:	4c 8d 58 30                                     	lea    r11,[rax+0x30]
  ac8107:	4c 8d 3d ba 43 e1 00                            	lea    r15,[rip+0xe143ba]        # 0x18dc4c8
  ac810e:	45 31 f6                                        	xor    r14d,r14d
  ac8111:	eb 52                                           	jmp    0xac8165
  ac8113:	41 83 e0 07                                     	and    r8d,0x7
  ac8117:	41 83 f8 06                                     	cmp    r8d,0x6
  ac811b:	75 2e                                           	jne    0xac814b
  ac811d:	66 81 39 38 02                                  	cmp    WORD PTR [rcx],0x238
  ac8122:	75 27                                           	jne    0xac814b
  ac8124:	c7 40 78 01 00 00 00                            	mov    DWORD PTR [rax+0x78],0x1
  ac812b:	0f b6 4a 18                                     	movzx  ecx,BYTE PTR [rdx+0x18]
  ac812f:	88 48 7c                                        	mov    BYTE PTR [rax+0x7c],cl
  ac8132:	89 b0 80 00 00 00                               	mov    DWORD PTR [rax+0x80],esi
  ac8138:	8b 4a 14                                        	mov    ecx,DWORD PTR [rdx+0x14]
  ac813b:	89 88 84 00 00 00                               	mov    DWORD PTR [rax+0x84],ecx
  ac8141:	c7 80 88 00 00 00 01 00 00 00                   	mov    DWORD PTR [rax+0x88],0x1
  ac814b:	5b                                              	pop    rbx
  ac814c:	41 5c                                           	pop    r12
  ac814e:	41 5d                                           	pop    r13
  ac8150:	41 5e                                           	pop    r14
  ac8152:	41 5f                                           	pop    r15
  ac8154:	5d                                              	pop    rbp
  ac8155:	c3                                              	ret
  ac8156:	41 ff c6                                        	inc    r14d
  ac8159:	44 0f b7 e3                                     	movzx  r12d,bx
  ac815d:	44 39 e7                                        	cmp    edi,r12d
  ac8160:	8d 7f 01                                        	lea    edi,[rdi+0x1]
  ac8163:	73 e6                                           	jae    0xac814b
  ac8165:	44 3b 72 1c                                     	cmp    r14d,DWORD PTR [rdx+0x1c]
  ac8169:	7d e0                                           	jge    0xac814b
  ac816b:	44 8d 67 ff                                     	lea    r12d,[rdi-0x1]
  ac816f:	41 83 fc 04                                     	cmp    r12d,0x4
  ac8173:	77 e1                                           	ja     0xac8156
  ac8175:	4f 63 2c a7                                     	movsxd r13,DWORD PTR [r15+r12*4]
  ac8179:	49 89 c4                                        	mov    r12,rax
  ac817c:	4d 01 fd                                        	add    r13,r15
  ac817f:	41 ff e5                                        	jmp    r13
  ac8182:	4d 89 d4                                        	mov    r12,r10
  ac8185:	eb 0d                                           	jmp    0xac8194
  ac8187:	4d 89 dc                                        	mov    r12,r11
  ac818a:	eb 08                                           	jmp    0xac8194
  ac818c:	4d 89 cc                                        	mov    r12,r9
  ac818f:	eb 03                                           	jmp    0xac8194
  ac8191:	4d 89 c4                                        	mov    r12,r8
  ac8194:	4d 85 e4                                        	test   r12,r12
  ac8197:	74 bd                                           	je     0xac8156
  ac8199:	41 c7 04 24 01 00 00 00                         	mov    DWORD PTR [r12],0x1
  ac81a1:	0f b6 5a 18                                     	movzx  ebx,BYTE PTR [rdx+0x18]
  ac81a5:	41 88 5c 24 04                                  	mov    BYTE PTR [r12+0x4],bl
  ac81aa:	42 8d 1c 36                                     	lea    ebx,[rsi+r14*1]
  ac81ae:	41 89 5c 24 08                                  	mov    DWORD PTR [r12+0x8],ebx
  ac81b3:	0f b7 59 42                                     	movzx  ebx,WORD PTR [rcx+0x42]
  ac81b7:	eb 9d                                           	jmp    0xac8156
  ac81b9:	90                                              	nop
  ac81ba:	90                                              	nop
  ac81bb:	90                                              	nop
  ac81bc:	90                                              	nop
  ac81bd:	90                                              	nop
  ac81be:	90                                              	nop
  ac81bf:	90                                              	nop
  ac81c0:	55                                              	push   rbp
  ac81c1:	48 89 e5                                        	mov    rbp,rsp
  ac81c4:	5d                                              	pop    rbp
  ac81c5:	c3                                              	ret
  ac81c6:	90                                              	nop
  ac81c7:	90                                              	nop
  ac81c8:	90                                              	nop
  ac81c9:	90                                              	nop
  ac81ca:	90                                              	nop
  ac81cb:	90                                              	nop
  ac81cc:	90                                              	nop
  ac81cd:	90                                              	nop
  ac81ce:	90                                              	nop
  ac81cf:	90                                              	nop
  ac81d0:	55                                              	push   rbp
  ac81d1:	48 89 e5                                        	mov    rbp,rsp
  ac81d4:	5d                                              	pop    rbp
  ac81d5:	c3                                              	ret
  ac81d6:	90                                              	nop
  ac81d7:	90                                              	nop
  ac81d8:	90                                              	nop
  ac81d9:	90                                              	nop
  ac81da:	90                                              	nop
  ac81db:	90                                              	nop
  ac81dc:	90                                              	nop
  ac81dd:	90                                              	nop
  ac81de:	90                                              	nop
  ac81df:	90                                              	nop
  ac81e0:	55                                              	push   rbp
  ac81e1:	48 89 e5                                        	mov    rbp,rsp
  ac81e4:	41 56                                           	push   r14
  ac81e6:	53                                              	push   rbx
  ac81e7:	48 89 fb                                        	mov    rbx,rdi
  ac81ea:	31 ff                                           	xor    edi,edi
  ac81ec:	e8 4f 77 f9 ff                                  	call   0xa5f940
  ac81f1:	85 c0                                           	test   eax,eax
  ac81f3:	75 50                                           	jne    0xac8245
  ac81f5:	48 89 df                                        	mov    rdi,rbx
  ac81f8:	be 01 00 00 00                                  	mov    esi,0x1
  ac81fd:	c7 43 08 01 00 00 00                            	mov    DWORD PTR [rbx+0x8],0x1
  ac8204:	e8 27 f5 8d ff                                  	call   0x3a7730
  ac8209:	85 c0                                           	test   eax,eax
  ac820b:	74 2e                                           	je     0xac823b
  ac820d:	48 8d 3d bf 8b 82 00                            	lea    rdi,[rip+0x828bbf]        # 0x12f0dd3
  ac8214:	48 8d 35 a7 54 7b 00                            	lea    rsi,[rip+0x7b54a7]        # 0x127d6c2
  ac821b:	ba 74 02 00 00                                  	mov    edx,0x274
  ac8220:	41 89 c6                                        	mov    r14d,eax
  ac8223:	31 c0                                           	xor    eax,eax
  ac8225:	e8 e6 51 79 ff                                  	call   0x25d410
  ac822a:	48 8d 3d 5e 7d 7d 00                            	lea    rdi,[rip+0x7d7d5e]        # 0x129ff8f
  ac8231:	44 89 f6                                        	mov    esi,r14d
  ac8234:	31 c0                                           	xor    eax,eax
  ac8236:	e8 d5 51 79 ff                                  	call   0x25d410
  ac823b:	c7 83 90 01 00 00 01 00 00 00                   	mov    DWORD PTR [rbx+0x190],0x1
  ac8245:	b8 01 00 00 00                                  	mov    eax,0x1
  ac824a:	5b                                              	pop    rbx
  ac824b:	41 5e                                           	pop    r14
  ac824d:	5d                                              	pop    rbp
  ac824e:	c3                                              	ret
  ac824f:	90                                              	nop
  ac8250:	55                                              	push   rbp
  ac8251:	48 89 e5                                        	mov    rbp,rsp
  ac8254:	48 8b 8f 98 01 00 00                            	mov    rcx,QWORD PTR [rdi+0x198]
  ac825b:	83 39 00                                        	cmp    DWORD PTR [rcx],0x0
  ac825e:	74 0f                                           	je     0xac826f
  ac8260:	b8 01 00 00 00                                  	mov    eax,0x1
  ac8265:	40 38 71 04                                     	cmp    BYTE PTR [rcx+0x4],sil
  ac8269:	0f 84 8a 00 00 00                               	je     0xac82f9
  ac826f:	83 79 0c 00                                     	cmp    DWORD PTR [rcx+0xc],0x0
  ac8273:	74 0b                                           	je     0xac8280
  ac8275:	b8 01 00 00 00                                  	mov    eax,0x1
  ac827a:	40 38 71 10                                     	cmp    BYTE PTR [rcx+0x10],sil
  ac827e:	74 79                                           	je     0xac82f9
  ac8280:	83 79 18 00                                     	cmp    DWORD PTR [rcx+0x18],0x0
  ac8284:	74 0b                                           	je     0xac8291
  ac8286:	b8 01 00 00 00                                  	mov    eax,0x1
  ac828b:	40 38 71 1c                                     	cmp    BYTE PTR [rcx+0x1c],sil
  ac828f:	74 68                                           	je     0xac82f9
  ac8291:	83 79 24 00                                     	cmp    DWORD PTR [rcx+0x24],0x0
  ac8295:	74 0b                                           	je     0xac82a2
  ac8297:	b8 01 00 00 00                                  	mov    eax,0x1
  ac829c:	40 38 71 28                                     	cmp    BYTE PTR [rcx+0x28],sil
  ac82a0:	74 57                                           	je     0xac82f9
  ac82a2:	83 79 30 00                                     	cmp    DWORD PTR [rcx+0x30],0x0
  ac82a6:	74 0b                                           	je     0xac82b3
  ac82a8:	b8 01 00 00 00                                  	mov    eax,0x1
  ac82ad:	40 38 71 34                                     	cmp    BYTE PTR [rcx+0x34],sil
  ac82b1:	74 46                                           	je     0xac82f9
  ac82b3:	83 79 3c 00                                     	cmp    DWORD PTR [rcx+0x3c],0x0
  ac82b7:	74 0b                                           	je     0xac82c4
  ac82b9:	b8 01 00 00 00                                  	mov    eax,0x1
  ac82be:	40 38 71 40                                     	cmp    BYTE PTR [rcx+0x40],sil
  ac82c2:	74 35                                           	je     0xac82f9
  ac82c4:	83 79 50 00                                     	cmp    DWORD PTR [rcx+0x50],0x0
  ac82c8:	74 0b                                           	je     0xac82d5
  ac82ca:	b8 01 00 00 00                                  	mov    eax,0x1
  ac82cf:	40 38 71 54                                     	cmp    BYTE PTR [rcx+0x54],sil
  ac82d3:	74 24                                           	je     0xac82f9
  ac82d5:	83 79 64 00                                     	cmp    DWORD PTR [rcx+0x64],0x0
  ac82d9:	74 0b                                           	je     0xac82e6
  ac82db:	b8 01 00 00 00                                  	mov    eax,0x1
  ac82e0:	40 38 71 68                                     	cmp    BYTE PTR [rcx+0x68],sil
  ac82e4:	74 13                                           	je     0xac82f9
  ac82e6:	83 79 78 00                                     	cmp    DWORD PTR [rcx+0x78],0x0
  ac82ea:	74 0b                                           	je     0xac82f7
  ac82ec:	b8 01 00 00 00                                  	mov    eax,0x1
  ac82f1:	40 38 71 7c                                     	cmp    BYTE PTR [rcx+0x7c],sil
  ac82f5:	74 02                                           	je     0xac82f9
  ac82f7:	31 c0                                           	xor    eax,eax
  ac82f9:	5d                                              	pop    rbp
  ac82fa:	c3                                              	ret
  ac82fb:	90                                              	nop
  ac82fc:	90                                              	nop
  ac82fd:	90                                              	nop
  ac82fe:	90                                              	nop
  ac82ff:	90                                              	nop
  ac8300:	55                                              	push   rbp
  ac8301:	48 89 e5                                        	mov    rbp,rsp
  ac8304:	41 57                                           	push   r15
  ac8306:	41 56                                           	push   r14
  ac8308:	41 55                                           	push   r13
  ac830a:	41 54                                           	push   r12
  ac830c:	53                                              	push   rbx
  ac830d:	48 83 ec 38                                     	sub    rsp,0x38
  ac8311:	4c 8d 3d f8 3f e5 02                            	lea    r15,[rip+0x2e53ff8]        # 0x391c310
  ac8318:	4c 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],r8
  ac831c:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  ac831f:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ac8323:	48 85 ff                                        	test   rdi,rdi
  ac8326:	74 1e                                           	je     0xac8346
  ac8328:	49 89 d6                                        	mov    r14,rdx
  ac832b:	48 85 d2                                        	test   rdx,rdx
  ac832e:	74 16                                           	je     0xac8346
  ac8330:	41 89 cd                                        	mov    r13d,ecx
  ac8333:	85 c9                                           	test   ecx,ecx
  ac8335:	7e 0f                                           	jle    0xac8346
  ac8337:	41 89 f4                                        	mov    r12d,esi
  ac833a:	48 89 fb                                        	mov    rbx,rdi
  ac833d:	e8 4e ee 87 ff                                  	call   0x347190
  ac8342:	85 c0                                           	test   eax,eax
  ac8344:	74 1c                                           	je     0xac8362
  ac8346:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  ac8349:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ac834d:	0f 85 f5 04 00 00                               	jne    0xac8848
  ac8353:	48 83 c4 38                                     	add    rsp,0x38
  ac8357:	5b                                              	pop    rbx
  ac8358:	41 5c                                           	pop    r12
  ac835a:	41 5d                                           	pop    r13
  ac835c:	41 5e                                           	pop    r14
  ac835e:	41 5f                                           	pop    r15
  ac8360:	5d                                              	pop    rbp
  ac8361:	c3                                              	ret
  ac8362:	4c 8b bb 98 01 00 00                            	mov    r15,QWORD PTR [rbx+0x198]
  ac8369:	4d 85 ff                                        	test   r15,r15
  ac836c:	0f 84 78 01 00 00                               	je     0xac84ea
  ac8372:	48 63 83 04 01 00 00                            	movsxd rax,DWORD PTR [rbx+0x104]
  ac8379:	be 98 00 00 00                                  	mov    esi,0x98
  ac837e:	48 69 c0 98 00 00 00                            	imul   rax,rax,0x98
  ac8385:	49 8d bc 07 90 00 00 00                         	lea    rdi,[r15+rax*1+0x90]
  ac838d:	48 89 45 b8                                     	mov    QWORD PTR [rbp-0x48],rax
  ac8391:	48 89 7d a8                                     	mov    QWORD PTR [rbp-0x58],rdi
  ac8395:	e8 56 0c 79 ff                                  	call   0x258ff0
  ac839a:	48 8b 45 a0                                     	mov    rax,QWORD PTR [rbp-0x60]
  ac839e:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  ac83a2:	45 0f b6 e4                                     	movzx  r12d,r12b
  ac83a6:	4c 89 ff                                        	mov    rdi,r15
  ac83a9:	4c 89 f2                                        	mov    rdx,r14
  ac83ac:	44 89 e6                                        	mov    esi,r12d
  ac83af:	49 89 84 0f 90 00 00 00                         	mov    QWORD PTR [r15+rcx*1+0x90],rax
  ac83b7:	49 c7 84 0f 98 00 00 00 00 00 00 00             	mov    QWORD PTR [r15+rcx*1+0x98],0x0
  ac83c3:	44 89 e9                                        	mov    ecx,r13d
  ac83c6:	e8 55 91 86 ff                                  	call   0x331520
  ac83cb:	49 8d 7f 0c                                     	lea    rdi,[r15+0xc]
  ac83cf:	44 89 e6                                        	mov    esi,r12d
  ac83d2:	4c 89 f2                                        	mov    rdx,r14
  ac83d5:	44 89 e9                                        	mov    ecx,r13d
  ac83d8:	89 45 c0                                        	mov    DWORD PTR [rbp-0x40],eax
  ac83db:	44 89 65 c4                                     	mov    DWORD PTR [rbp-0x3c],r12d
  ac83df:	e8 3c 91 86 ff                                  	call   0x331520
  ac83e4:	01 c0                                           	add    eax,eax
  ac83e6:	0b 45 c0                                        	or     eax,DWORD PTR [rbp-0x40]
  ac83e9:	49 8d 7f 18                                     	lea    rdi,[r15+0x18]
  ac83ed:	44 89 e6                                        	mov    esi,r12d
  ac83f0:	4c 89 f2                                        	mov    rdx,r14
  ac83f3:	44 89 e9                                        	mov    ecx,r13d
  ac83f6:	89 45 c0                                        	mov    DWORD PTR [rbp-0x40],eax
  ac83f9:	e8 22 91 86 ff                                  	call   0x331520
  ac83fe:	c1 e0 02                                        	shl    eax,0x2
  ac8401:	49 8d 7f 24                                     	lea    rdi,[r15+0x24]
  ac8405:	44 89 e6                                        	mov    esi,r12d
  ac8408:	4c 89 f2                                        	mov    rdx,r14
  ac840b:	44 89 e9                                        	mov    ecx,r13d
  ac840e:	89 45 b4                                        	mov    DWORD PTR [rbp-0x4c],eax
  ac8411:	e8 0a 91 86 ff                                  	call   0x331520
  ac8416:	41 89 c4                                        	mov    r12d,eax
  ac8419:	8b 75 c4                                        	mov    esi,DWORD PTR [rbp-0x3c]
  ac841c:	49 8d 7f 30                                     	lea    rdi,[r15+0x30]
  ac8420:	4c 89 f2                                        	mov    rdx,r14
  ac8423:	44 89 e9                                        	mov    ecx,r13d
  ac8426:	41 c1 e4 03                                     	shl    r12d,0x3
  ac842a:	44 0b 65 b4                                     	or     r12d,DWORD PTR [rbp-0x4c]
  ac842e:	44 0b 65 c0                                     	or     r12d,DWORD PTR [rbp-0x40]
  ac8432:	e8 e9 90 86 ff                                  	call   0x331520
  ac8437:	c1 e0 04                                        	shl    eax,0x4
  ac843a:	8b 75 c4                                        	mov    esi,DWORD PTR [rbp-0x3c]
  ac843d:	49 8d 7f 3c                                     	lea    rdi,[r15+0x3c]
  ac8441:	4c 89 f2                                        	mov    rdx,r14
  ac8444:	44 89 e9                                        	mov    ecx,r13d
  ac8447:	44 09 e0                                        	or     eax,r12d
  ac844a:	4c 8b 65 b8                                     	mov    r12,QWORD PTR [rbp-0x48]
  ac844e:	43 88 84 27 aa 00 00 00                         	mov    BYTE PTR [r15+r12*1+0xaa],al
  ac8456:	e8 75 90 86 ff                                  	call   0x3314d0
  ac845b:	66 43 89 84 27 a6 00 00 00                      	mov    WORD PTR [r15+r12*1+0xa6],ax
  ac8464:	44 8b 65 c4                                     	mov    r12d,DWORD PTR [rbp-0x3c]
  ac8468:	49 8d 7f 50                                     	lea    rdi,[r15+0x50]
  ac846c:	4c 89 f2                                        	mov    rdx,r14
  ac846f:	44 89 e9                                        	mov    ecx,r13d
  ac8472:	44 89 e6                                        	mov    esi,r12d
  ac8475:	e8 56 90 86 ff                                  	call   0x3314d0
  ac847a:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  ac847e:	49 8d 7f 64                                     	lea    rdi,[r15+0x64]
  ac8482:	44 89 e6                                        	mov    esi,r12d
  ac8485:	4c 89 f2                                        	mov    rdx,r14
  ac8488:	66 41 89 84 0f a8 00 00 00                      	mov    WORD PTR [r15+rcx*1+0xa8],ax
  ac8491:	44 89 e9                                        	mov    ecx,r13d
  ac8494:	e8 37 90 86 ff                                  	call   0x3314d0
  ac8499:	4c 8b 65 b8                                     	mov    r12,QWORD PTR [rbp-0x48]
  ac849d:	8b 75 c4                                        	mov    esi,DWORD PTR [rbp-0x3c]
  ac84a0:	49 8d 7f 78                                     	lea    rdi,[r15+0x78]
  ac84a4:	4c 89 f2                                        	mov    rdx,r14
  ac84a7:	44 89 e9                                        	mov    ecx,r13d
  ac84aa:	43 88 84 27 ab 00 00 00                         	mov    BYTE PTR [r15+r12*1+0xab],al
  ac84b2:	e8 19 90 86 ff                                  	call   0x3314d0
  ac84b7:	43 88 84 27 ac 00 00 00                         	mov    BYTE PTR [r15+r12*1+0xac],al
  ac84bf:	43 c6 84 27 a0 00 00 00 01                      	mov    BYTE PTR [r15+r12*1+0xa0],0x1
  ac84c8:	66 43 c7 84 27 a4 00 00 00 00 00                	mov    WORD PTR [r15+r12*1+0xa4],0x0
  ac84d3:	41 be 01 00 00 00                               	mov    r14d,0x1
  ac84d9:	43 80 bc 27 aa 00 00 00 00                      	cmp    BYTE PTR [r15+r12*1+0xaa],0x0
  ac84e2:	74 2d                                           	je     0xac8511
  ac84e4:	4c 8b 65 a8                                     	mov    r12,QWORD PTR [rbp-0x58]
  ac84e8:	eb 51                                           	jmp    0xac853b
  ac84ea:	48 8d 05 1f 3e e5 02                            	lea    rax,[rip+0x2e53e1f]        # 0x391c310
  ac84f1:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ac84f4:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ac84f8:	0f 85 4a 03 00 00                               	jne    0xac8848
  ac84fe:	48 83 c4 38                                     	add    rsp,0x38
  ac8502:	5b                                              	pop    rbx
  ac8503:	41 5c                                           	pop    r12
  ac8505:	41 5d                                           	pop    r13
  ac8507:	41 5e                                           	pop    r14
  ac8509:	41 5f                                           	pop    r15
  ac850b:	5d                                              	pop    rbp
  ac850c:	e9 cf ec 87 ff                                  	jmp    0x3471e0
  ac8511:	4c 8b 65 a8                                     	mov    r12,QWORD PTR [rbp-0x58]
  ac8515:	41 0f b7 4c 24 16                               	movzx  ecx,WORD PTR [r12+0x16]
  ac851b:	89 ca                                           	mov    edx,ecx
  ac851d:	66 f7 da                                        	neg    dx
  ac8520:	66 0f 48 d1                                     	cmovs  dx,cx
  ac8524:	66 83 fa 1d                                     	cmp    dx,0x1d
  ac8528:	77 11                                           	ja     0xac853b
  ac852a:	41 80 7c 24 1b 00                               	cmp    BYTE PTR [r12+0x1b],0x0
  ac8530:	75 09                                           	jne    0xac853b
  ac8532:	45 31 f6                                        	xor    r14d,r14d
  ac8535:	84 c0                                           	test   al,al
  ac8537:	41 0f 95 c6                                     	setne  r14b
  ac853b:	31 ff                                           	xor    edi,edi
  ac853d:	e8 fe 73 f9 ff                                  	call   0xa5f940
  ac8542:	85 c0                                           	test   eax,eax
  ac8544:	75 0b                                           	jne    0xac8551
  ac8546:	48 89 df                                        	mov    rdi,rbx
  ac8549:	44 89 f6                                        	mov    esi,r14d
  ac854c:	e8 ef fe 8d ff                                  	call   0x3a8440
  ac8551:	83 7b 08 00                                     	cmp    DWORD PTR [rbx+0x8],0x0
  ac8555:	74 10                                           	je     0xac8567
  ac8557:	45 85 f6                                        	test   r14d,r14d
  ac855a:	74 0b                                           	je     0xac8567
  ac855c:	48 8b 45 a0                                     	mov    rax,QWORD PTR [rbp-0x60]
  ac8560:	48 89 05 a9 8d 1f 03                            	mov    QWORD PTR [rip+0x31f8da9],rax        # 0x3cc1310
  ac8567:	41 8b 8f 28 27 00 00                            	mov    ecx,DWORD PTR [r15+0x2728]
  ac856e:	85 c9                                           	test   ecx,ecx
  ac8570:	0f 84 89 00 00 00                               	je     0xac85ff
  ac8576:	41 0f b6 54 24 1a                               	movzx  edx,BYTE PTR [r12+0x1a]
  ac857c:	0f b6 43 18                                     	movzx  eax,BYTE PTR [rbx+0x18]
  ac8580:	89 d6                                           	mov    esi,edx
  ac8582:	24 fe                                           	and    al,0xfe
  ac8584:	40 80 e6 3f                                     	and    sil,0x3f
  ac8588:	3c 02                                           	cmp    al,0x2
  ac858a:	40 0f b6 f6                                     	movzx  esi,sil
  ac858e:	0f 45 f2                                        	cmovne esi,edx
  ac8591:	40 84 f6                                        	test   sil,sil
  ac8594:	74 35                                           	je     0xac85cb
  ac8596:	48 63 93 00 01 00 00                            	movsxd rdx,DWORD PTR [rbx+0x100]
  ac859d:	3b 93 04 01 00 00                               	cmp    edx,DWORD PTR [rbx+0x104]
  ac85a3:	74 26                                           	je     0xac85cb
  ac85a5:	48 69 d2 98 00 00 00                            	imul   rdx,rdx,0x98
  ac85ac:	49 8d b7 90 00 00 00                            	lea    rsi,[r15+0x90]
  ac85b3:	0f b6 54 16 1a                                  	movzx  edx,BYTE PTR [rsi+rdx*1+0x1a]
  ac85b8:	89 d6                                           	mov    esi,edx
  ac85ba:	40 80 e6 3f                                     	and    sil,0x3f
  ac85be:	3c 02                                           	cmp    al,0x2
  ac85c0:	40 0f b6 c6                                     	movzx  eax,sil
  ac85c4:	0f 45 c2                                        	cmovne eax,edx
  ac85c7:	84 c0                                           	test   al,al
  ac85c9:	75 36                                           	jne    0xac8601
  ac85cb:	8b 05 33 8d 1f 03                               	mov    eax,DWORD PTR [rip+0x31f8d33]        # 0x3cc1304
  ac85d1:	41 89 87 3c 27 00 00                            	mov    DWORD PTR [r15+0x273c],eax
  ac85d8:	48 8b 05 1d 8d 1f 03                            	mov    rax,QWORD PTR [rip+0x31f8d1d]        # 0x3cc12fc
  ac85df:	49 89 87 34 27 00 00                            	mov    QWORD PTR [r15+0x2734],rax
  ac85e6:	48 8b 05 07 8d 1f 03                            	mov    rax,QWORD PTR [rip+0x31f8d07]        # 0x3cc12f4
  ac85ed:	49 89 87 2c 27 00 00                            	mov    QWORD PTR [r15+0x272c],rax
  ac85f4:	41 c7 87 28 27 00 00 00 00 00 00                	mov    DWORD PTR [r15+0x2728],0x0
  ac85ff:	31 c9                                           	xor    ecx,ecx
  ac8601:	49 81 c7 2c 27 00 00                            	add    r15,0x272c
  ac8608:	49 8d 54 24 50                                  	lea    rdx,[r12+0x50]
  ac860d:	48 8d 3d e0 8c 1f 03                            	lea    rdi,[rip+0x31f8ce0]        # 0x3cc12f4
  ac8614:	4c 89 fe                                        	mov    rsi,r15
  ac8617:	e8 84 fc 8d ff                                  	call   0x3a82a0
  ac861c:	e8 bf eb 87 ff                                  	call   0x3471e0
  ac8621:	48 8d 55 cc                                     	lea    rdx,[rbp-0x34]
  ac8625:	48 8d 4d c8                                     	lea    rcx,[rbp-0x38]
  ac8629:	48 89 df                                        	mov    rdi,rbx
  ac862c:	4c 89 e6                                        	mov    rsi,r12
  ac862f:	e8 1c 02 00 00                                  	call   0xac8850
  ac8634:	e8 57 eb 87 ff                                  	call   0x347190
  ac8639:	48 39 1d f0 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bf0],rbx        # 0x3cc1230
  ac8640:	0f 84 a0 00 00 00                               	je     0xac86e6
  ac8646:	48 39 1d eb 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8beb],rbx        # 0x3cc1238
  ac864d:	0f 84 93 00 00 00                               	je     0xac86e6
  ac8653:	48 39 1d e6 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8be6],rbx        # 0x3cc1240
  ac865a:	0f 84 86 00 00 00                               	je     0xac86e6
  ac8660:	48 39 1d e1 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8be1],rbx        # 0x3cc1248
  ac8667:	74 7d                                           	je     0xac86e6
  ac8669:	48 39 1d e0 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8be0],rbx        # 0x3cc1250
  ac8670:	74 74                                           	je     0xac86e6
  ac8672:	48 39 1d df 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bdf],rbx        # 0x3cc1258
  ac8679:	74 6b                                           	je     0xac86e6
  ac867b:	48 39 1d de 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bde],rbx        # 0x3cc1260
  ac8682:	74 62                                           	je     0xac86e6
  ac8684:	48 39 1d dd 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bdd],rbx        # 0x3cc1268
  ac868b:	74 59                                           	je     0xac86e6
  ac868d:	48 39 1d dc 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bdc],rbx        # 0x3cc1270
  ac8694:	74 50                                           	je     0xac86e6
  ac8696:	48 39 1d db 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bdb],rbx        # 0x3cc1278
  ac869d:	74 47                                           	je     0xac86e6
  ac869f:	48 39 1d da 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bda],rbx        # 0x3cc1280
  ac86a6:	74 3e                                           	je     0xac86e6
  ac86a8:	48 39 1d d9 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bd9],rbx        # 0x3cc1288
  ac86af:	74 35                                           	je     0xac86e6
  ac86b1:	48 39 1d d8 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bd8],rbx        # 0x3cc1290
  ac86b8:	74 2c                                           	je     0xac86e6
  ac86ba:	48 39 1d d7 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bd7],rbx        # 0x3cc1298
  ac86c1:	74 23                                           	je     0xac86e6
  ac86c3:	48 39 1d d6 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bd6],rbx        # 0x3cc12a0
  ac86ca:	74 1a                                           	je     0xac86e6
  ac86cc:	48 39 1d d5 8b 1f 03                            	cmp    QWORD PTR [rip+0x31f8bd5],rbx        # 0x3cc12a8
  ac86d3:	74 11                                           	je     0xac86e6
  ac86d5:	e8 06 eb 87 ff                                  	call   0x3471e0
  ac86da:	4c 8d 3d 2f 3c e5 02                            	lea    r15,[rip+0x2e53c2f]        # 0x391c310
  ac86e1:	e9 60 fc ff ff                                  	jmp    0xac8346
  ac86e6:	8b 83 04 01 00 00                               	mov    eax,DWORD PTR [rbx+0x104]
  ac86ec:	8d 48 01                                        	lea    ecx,[rax+0x1]
  ac86ef:	89 83 00 01 00 00                               	mov    DWORD PTR [rbx+0x100],eax
  ac86f5:	48 63 c9                                        	movsxd rcx,ecx
  ac86f8:	48 69 c9 7f e0 07 7e                            	imul   rcx,rcx,0x7e07e07f
  ac86ff:	48 89 ca                                        	mov    rdx,rcx
  ac8702:	48 c1 f9 25                                     	sar    rcx,0x25
  ac8706:	48 c1 ea 3f                                     	shr    rdx,0x3f
  ac870a:	01 d1                                           	add    ecx,edx
  ac870c:	89 ca                                           	mov    edx,ecx
  ac870e:	c1 e2 06                                        	shl    edx,0x6
  ac8711:	01 ca                                           	add    edx,ecx
  ac8713:	f7 da                                           	neg    edx
  ac8715:	8d 44 10 01                                     	lea    eax,[rax+rdx*1+0x1]
  ac8719:	89 83 04 01 00 00                               	mov    DWORD PTR [rbx+0x104],eax
  ac871f:	3b 83 08 01 00 00                               	cmp    eax,DWORD PTR [rbx+0x108]
  ac8725:	75 2c                                           	jne    0xac8753
  ac8727:	fe c0                                           	inc    al
  ac8729:	0f be c0                                        	movsx  eax,al
  ac872c:	89 c1                                           	mov    ecx,eax
  ac872e:	c1 e1 07                                        	shl    ecx,0x7
  ac8731:	29 c1                                           	sub    ecx,eax
  ac8733:	0f b7 d1                                        	movzx  edx,cx
  ac8736:	c1 e9 0d                                        	shr    ecx,0xd
  ac8739:	c1 ea 0f                                        	shr    edx,0xf
  ac873c:	00 ca                                           	add    dl,cl
  ac873e:	0f b6 ca                                        	movzx  ecx,dl
  ac8741:	89 ca                                           	mov    edx,ecx
  ac8743:	c1 e2 06                                        	shl    edx,0x6
  ac8746:	01 ca                                           	add    edx,ecx
  ac8748:	28 d0                                           	sub    al,dl
  ac874a:	0f be c0                                        	movsx  eax,al
  ac874d:	89 83 08 01 00 00                               	mov    DWORD PTR [rbx+0x108],eax
  ac8753:	4c 8d 3d b6 3b e5 02                            	lea    r15,[rip+0x2e53bb6]        # 0x391c310
  ac875a:	31 c0                                           	xor    eax,eax
  ac875c:	eb 0f                                           	jmp    0xac876d
  ac875e:	66 90                                           	xchg   ax,ax
  ac8760:	48 ff c0                                        	inc    rax
  ac8763:	48 83 f8 10                                     	cmp    rax,0x10
  ac8767:	0f 84 d1 00 00 00                               	je     0xac883e
  ac876d:	48 8b 8c c3 10 01 00 00                         	mov    rcx,QWORD PTR [rbx+rax*8+0x110]
  ac8775:	48 85 c9                                        	test   rcx,rcx
  ac8778:	74 e6                                           	je     0xac8760
  ac877a:	8b 93 04 01 00 00                               	mov    edx,DWORD PTR [rbx+0x104]
  ac8780:	3b 51 18                                        	cmp    edx,DWORD PTR [rcx+0x18]
  ac8783:	74 1b                                           	je     0xac87a0
  ac8785:	3b 51 1c                                        	cmp    edx,DWORD PTR [rcx+0x1c]
  ac8788:	74 4e                                           	je     0xac87d8
  ac878a:	3b 51 20                                        	cmp    edx,DWORD PTR [rcx+0x20]
  ac878d:	75 d1                                           	jne    0xac8760
  ac878f:	e9 80 00 00 00                                  	jmp    0xac8814
  ac8794:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ac87a0:	ff c2                                           	inc    edx
  ac87a2:	48 63 d2                                        	movsxd rdx,edx
  ac87a5:	48 69 f2 7f e0 07 7e                            	imul   rsi,rdx,0x7e07e07f
  ac87ac:	48 89 f7                                        	mov    rdi,rsi
  ac87af:	48 c1 fe 25                                     	sar    rsi,0x25
  ac87b3:	48 c1 ef 3f                                     	shr    rdi,0x3f
  ac87b7:	01 fe                                           	add    esi,edi
  ac87b9:	89 f7                                           	mov    edi,esi
  ac87bb:	c1 e7 06                                        	shl    edi,0x6
  ac87be:	01 f7                                           	add    edi,esi
  ac87c0:	29 fa                                           	sub    edx,edi
  ac87c2:	89 51 18                                        	mov    DWORD PTR [rcx+0x18],edx
  ac87c5:	8b 93 04 01 00 00                               	mov    edx,DWORD PTR [rbx+0x104]
  ac87cb:	48 8b 8c c3 10 01 00 00                         	mov    rcx,QWORD PTR [rbx+rax*8+0x110]
  ac87d3:	3b 51 1c                                        	cmp    edx,DWORD PTR [rcx+0x1c]
  ac87d6:	75 b2                                           	jne    0xac878a
  ac87d8:	ff c2                                           	inc    edx
  ac87da:	48 63 d2                                        	movsxd rdx,edx
  ac87dd:	48 69 f2 7f e0 07 7e                            	imul   rsi,rdx,0x7e07e07f
  ac87e4:	48 89 f7                                        	mov    rdi,rsi
  ac87e7:	48 c1 fe 25                                     	sar    rsi,0x25
  ac87eb:	48 c1 ef 3f                                     	shr    rdi,0x3f
  ac87ef:	01 fe                                           	add    esi,edi
  ac87f1:	89 f7                                           	mov    edi,esi
  ac87f3:	c1 e7 06                                        	shl    edi,0x6
  ac87f6:	01 f7                                           	add    edi,esi
  ac87f8:	29 fa                                           	sub    edx,edi
  ac87fa:	89 51 1c                                        	mov    DWORD PTR [rcx+0x1c],edx
  ac87fd:	8b 93 04 01 00 00                               	mov    edx,DWORD PTR [rbx+0x104]
  ac8803:	48 8b 8c c3 10 01 00 00                         	mov    rcx,QWORD PTR [rbx+rax*8+0x110]
  ac880b:	3b 51 20                                        	cmp    edx,DWORD PTR [rcx+0x20]
  ac880e:	0f 85 4c ff ff ff                               	jne    0xac8760
  ac8814:	ff c2                                           	inc    edx
  ac8816:	48 63 d2                                        	movsxd rdx,edx
  ac8819:	48 69 f2 7f e0 07 7e                            	imul   rsi,rdx,0x7e07e07f
  ac8820:	48 89 f7                                        	mov    rdi,rsi
  ac8823:	48 c1 fe 25                                     	sar    rsi,0x25
  ac8827:	48 c1 ef 3f                                     	shr    rdi,0x3f
  ac882b:	01 fe                                           	add    esi,edi
  ac882d:	89 f7                                           	mov    edi,esi
  ac882f:	c1 e7 06                                        	shl    edi,0x6
  ac8832:	01 f7                                           	add    edi,esi
  ac8834:	29 fa                                           	sub    edx,edi
  ac8836:	89 51 20                                        	mov    DWORD PTR [rcx+0x20],edx
  ac8839:	e9 22 ff ff ff                                  	jmp    0xac8760
  ac883e:	e8 9d e9 87 ff                                  	call   0x3471e0
  ac8843:	e9 fe fa ff ff                                  	jmp    0xac8346
  ac8848:	e8 63 4e c3 ff                                  	call   0x6fd6b0
  ac884d:	0f 0b                                           	ud2
  ac884f:	90                                              	nop
  ac8850:	55                                              	push   rbp
  ac8851:	48 89 e5                                        	mov    rbp,rsp
  ac8854:	41 57                                           	push   r15
  ac8856:	41 56                                           	push   r14
  ac8858:	41 55                                           	push   r13
  ac885a:	41 54                                           	push   r12
  ac885c:	53                                              	push   rbx
  ac885d:	48 83 ec 68                                     	sub    rsp,0x68
  ac8861:	48 8d 1d a8 3a e5 02                            	lea    rbx,[rip+0x2e53aa8]        # 0x391c310
  ac8868:	49 89 cc                                        	mov    r12,rcx
  ac886b:	49 89 d6                                        	mov    r14,rdx
  ac886e:	49 89 f5                                        	mov    r13,rsi
  ac8871:	49 89 ff                                        	mov    r15,rdi
  ac8874:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ac8877:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ac887b:	e8 10 e9 87 ff                                  	call   0x347190
  ac8880:	4c 39 3d a9 89 1f 03                            	cmp    QWORD PTR [rip+0x31f89a9],r15        # 0x3cc1230
  ac8887:	0f 84 8f 00 00 00                               	je     0xac891c
  ac888d:	4c 39 3d a4 89 1f 03                            	cmp    QWORD PTR [rip+0x31f89a4],r15        # 0x3cc1238
  ac8894:	0f 84 82 00 00 00                               	je     0xac891c
  ac889a:	4c 39 3d 9f 89 1f 03                            	cmp    QWORD PTR [rip+0x31f899f],r15        # 0x3cc1240
  ac88a1:	74 79                                           	je     0xac891c
  ac88a3:	4c 39 3d 9e 89 1f 03                            	cmp    QWORD PTR [rip+0x31f899e],r15        # 0x3cc1248
  ac88aa:	74 70                                           	je     0xac891c
  ac88ac:	4c 39 3d 9d 89 1f 03                            	cmp    QWORD PTR [rip+0x31f899d],r15        # 0x3cc1250
  ac88b3:	74 67                                           	je     0xac891c
  ac88b5:	4c 39 3d 9c 89 1f 03                            	cmp    QWORD PTR [rip+0x31f899c],r15        # 0x3cc1258
  ac88bc:	74 5e                                           	je     0xac891c
  ac88be:	4c 39 3d 9b 89 1f 03                            	cmp    QWORD PTR [rip+0x31f899b],r15        # 0x3cc1260
  ac88c5:	74 55                                           	je     0xac891c
  ac88c7:	4c 39 3d 9a 89 1f 03                            	cmp    QWORD PTR [rip+0x31f899a],r15        # 0x3cc1268
  ac88ce:	74 4c                                           	je     0xac891c
  ac88d0:	4c 39 3d 99 89 1f 03                            	cmp    QWORD PTR [rip+0x31f8999],r15        # 0x3cc1270
  ac88d7:	74 43                                           	je     0xac891c
  ac88d9:	4c 39 3d 98 89 1f 03                            	cmp    QWORD PTR [rip+0x31f8998],r15        # 0x3cc1278
  ac88e0:	74 3a                                           	je     0xac891c
  ac88e2:	4c 39 3d 97 89 1f 03                            	cmp    QWORD PTR [rip+0x31f8997],r15        # 0x3cc1280
  ac88e9:	74 31                                           	je     0xac891c
  ac88eb:	4c 39 3d 96 89 1f 03                            	cmp    QWORD PTR [rip+0x31f8996],r15        # 0x3cc1288
  ac88f2:	74 28                                           	je     0xac891c
  ac88f4:	4c 39 3d 95 89 1f 03                            	cmp    QWORD PTR [rip+0x31f8995],r15        # 0x3cc1290
  ac88fb:	74 1f                                           	je     0xac891c
  ac88fd:	4c 39 3d 94 89 1f 03                            	cmp    QWORD PTR [rip+0x31f8994],r15        # 0x3cc1298
  ac8904:	74 16                                           	je     0xac891c
  ac8906:	4c 39 3d 93 89 1f 03                            	cmp    QWORD PTR [rip+0x31f8993],r15        # 0x3cc12a0
  ac890d:	74 0d                                           	je     0xac891c
  ac890f:	4c 39 3d 92 89 1f 03                            	cmp    QWORD PTR [rip+0x31f8992],r15        # 0x3cc12a8
  ac8916:	0f 85 6a 01 00 00                               	jne    0xac8a86
  ac891c:	41 83 3f 00                                     	cmp    DWORD PTR [r15],0x0
  ac8920:	0f 85 60 01 00 00                               	jne    0xac8a86
  ac8926:	48 83 3d ea 89 1f 03 00                         	cmp    QWORD PTR [rip+0x31f89ea],0x0        # 0x3cc1318
  ac892e:	0f 84 52 01 00 00                               	je     0xac8a86
  ac8934:	41 83 7f 08 00                                  	cmp    DWORD PTR [r15+0x8],0x0
  ac8939:	0f 84 47 01 00 00                               	je     0xac8a86
  ac893f:	41 8b 77 04                                     	mov    esi,DWORD PTR [r15+0x4]
  ac8943:	31 ff                                           	xor    edi,edi
  ac8945:	4c 89 ad 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],r13
  ac894c:	e8 5f 78 f9 ff                                  	call   0xa601b0
  ac8951:	85 c0                                           	test   eax,eax
  ac8953:	0f 88 2d 01 00 00                               	js     0xac8a86
  ac8959:	48 8b b5 78 ff ff ff                            	mov    rsi,QWORD PTR [rbp-0x88]
  ac8960:	41 c7 06 00 00 00 00                            	mov    DWORD PTR [r14],0x0
  ac8967:	41 c7 04 24 00 00 00 00                         	mov    DWORD PTR [r12],0x0
  ac896f:	48 8d 7d 80                                     	lea    rdi,[rbp-0x80]
  ac8973:	b9 0a 00 00 00                                  	mov    ecx,0xa
  ac8978:	41 89 c5                                        	mov    r13d,eax
  ac897b:	f3 48 a5                                        	rep movs QWORD PTR [rdi],QWORD PTR [rsi]
  ac897e:	e8 5d e8 87 ff                                  	call   0x3471e0
  ac8983:	48 8b 1d 8e 89 1f 03                            	mov    rbx,QWORD PTR [rip+0x31f898e]        # 0x3cc1318
  ac898a:	48 8d 05 87 69 7a ff                            	lea    rax,[rip+0xffffffffff7a6987]        # 0x26f318
  ac8991:	48 29 d8                                        	sub    rax,rbx
  ac8994:	48 c1 c8 03                                     	ror    rax,0x3
  ac8998:	48 83 f8 01                                     	cmp    rax,0x1
  ac899c:	0f 87 0d 01 00 00                               	ja     0xac8aaf
  ac89a2:	48 8d 75 80                                     	lea    rsi,[rbp-0x80]
  ac89a6:	44 89 ef                                        	mov    edi,r13d
  ac89a9:	4c 89 f2                                        	mov    rdx,r14
  ac89ac:	4c 89 e1                                        	mov    rcx,r12
  ac89af:	ff d3                                           	call   rbx
  ac89b1:	e8 da e7 87 ff                                  	call   0x347190
  ac89b6:	4c 39 3d 73 88 1f 03                            	cmp    QWORD PTR [rip+0x31f8873],r15        # 0x3cc1230
  ac89bd:	0f 84 87 00 00 00                               	je     0xac8a4a
  ac89c3:	4c 39 3d 6e 88 1f 03                            	cmp    QWORD PTR [rip+0x31f886e],r15        # 0x3cc1238
  ac89ca:	74 7e                                           	je     0xac8a4a
  ac89cc:	4c 39 3d 6d 88 1f 03                            	cmp    QWORD PTR [rip+0x31f886d],r15        # 0x3cc1240
  ac89d3:	74 75                                           	je     0xac8a4a
  ac89d5:	4c 39 3d 6c 88 1f 03                            	cmp    QWORD PTR [rip+0x31f886c],r15        # 0x3cc1248
  ac89dc:	74 6c                                           	je     0xac8a4a
  ac89de:	4c 39 3d 6b 88 1f 03                            	cmp    QWORD PTR [rip+0x31f886b],r15        # 0x3cc1250
  ac89e5:	74 63                                           	je     0xac8a4a
  ac89e7:	4c 39 3d 6a 88 1f 03                            	cmp    QWORD PTR [rip+0x31f886a],r15        # 0x3cc1258
  ac89ee:	74 5a                                           	je     0xac8a4a
  ac89f0:	4c 39 3d 69 88 1f 03                            	cmp    QWORD PTR [rip+0x31f8869],r15        # 0x3cc1260
  ac89f7:	74 51                                           	je     0xac8a4a
  ac89f9:	4c 39 3d 68 88 1f 03                            	cmp    QWORD PTR [rip+0x31f8868],r15        # 0x3cc1268
  ac8a00:	74 48                                           	je     0xac8a4a
  ac8a02:	4c 39 3d 67 88 1f 03                            	cmp    QWORD PTR [rip+0x31f8867],r15        # 0x3cc1270
  ac8a09:	74 3f                                           	je     0xac8a4a
  ac8a0b:	4c 39 3d 66 88 1f 03                            	cmp    QWORD PTR [rip+0x31f8866],r15        # 0x3cc1278
  ac8a12:	74 36                                           	je     0xac8a4a
  ac8a14:	4c 39 3d 65 88 1f 03                            	cmp    QWORD PTR [rip+0x31f8865],r15        # 0x3cc1280
  ac8a1b:	74 2d                                           	je     0xac8a4a
  ac8a1d:	4c 39 3d 64 88 1f 03                            	cmp    QWORD PTR [rip+0x31f8864],r15        # 0x3cc1288
  ac8a24:	74 24                                           	je     0xac8a4a
  ac8a26:	4c 39 3d 63 88 1f 03                            	cmp    QWORD PTR [rip+0x31f8863],r15        # 0x3cc1290
  ac8a2d:	74 1b                                           	je     0xac8a4a
  ac8a2f:	4c 39 3d 62 88 1f 03                            	cmp    QWORD PTR [rip+0x31f8862],r15        # 0x3cc1298
  ac8a36:	74 12                                           	je     0xac8a4a
  ac8a38:	4c 39 3d 61 88 1f 03                            	cmp    QWORD PTR [rip+0x31f8861],r15        # 0x3cc12a0
  ac8a3f:	74 09                                           	je     0xac8a4a
  ac8a41:	4c 39 3d 60 88 1f 03                            	cmp    QWORD PTR [rip+0x31f8860],r15        # 0x3cc12a8
  ac8a48:	75 2c                                           	jne    0xac8a76
  ac8a4a:	41 83 3e 01                                     	cmp    DWORD PTR [r14],0x1
  ac8a4e:	75 26                                           	jne    0xac8a76
  ac8a50:	48 8b 95 78 ff ff ff                            	mov    rdx,QWORD PTR [rbp-0x88]
  ac8a57:	48 8d 75 80                                     	lea    rsi,[rbp-0x80]
  ac8a5b:	b9 0a 00 00 00                                  	mov    ecx,0xa
  ac8a60:	48 89 d7                                        	mov    rdi,rdx
  ac8a63:	48 8b 02                                        	mov    rax,QWORD PTR [rdx]
  ac8a66:	f3 48 a5                                        	rep movs QWORD PTR [rdi],QWORD PTR [rsi]
  ac8a69:	48 89 02                                        	mov    QWORD PTR [rdx],rax
  ac8a6c:	c6 42 10 01                                     	mov    BYTE PTR [rdx+0x10],0x1
  ac8a70:	66 c7 42 12 00 00                               	mov    WORD PTR [rdx+0x12],0x0
  ac8a76:	e8 65 e7 87 ff                                  	call   0x3471e0
  ac8a7b:	48 8d 1d 8e 38 e5 02                            	lea    rbx,[rip+0x2e5388e]        # 0x391c310
  ac8a82:	31 c0                                           	xor    eax,eax
  ac8a84:	eb 0a                                           	jmp    0xac8a90
  ac8a86:	e8 55 e7 87 ff                                  	call   0x3471e0
  ac8a8b:	b8 03 00 3b 80                                  	mov    eax,0x803b0003
  ac8a90:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  ac8a93:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  ac8a97:	75 0f                                           	jne    0xac8aa8
  ac8a99:	48 83 c4 68                                     	add    rsp,0x68
  ac8a9d:	5b                                              	pop    rbx
  ac8a9e:	41 5c                                           	pop    r12
  ac8aa0:	41 5d                                           	pop    r13
  ac8aa2:	41 5e                                           	pop    r14
  ac8aa4:	41 5f                                           	pop    r15
  ac8aa6:	5d                                              	pop    rbp
  ac8aa7:	c3                                              	ret
  ac8aa8:	e8 03 4c c3 ff                                  	call   0x6fd6b0
  ac8aad:	0f 0b                                           	ud2
  ac8aaf:	48 8d 3d 2a 14 dc 01                            	lea    rdi,[rip+0x1dc142a]        # 0x2889ee0
  ac8ab6:	48 89 de                                        	mov    rsi,rbx
  ac8ab9:	e8 02 6e 98 ff                                  	call   0x44f8c0
  ac8abe:	e9 df fe ff ff                                  	jmp    0xac89a2
  ac8ac3:	90                                              	nop
  ac8ac4:	90                                              	nop
  ac8ac5:	90                                              	nop
  ac8ac6:	90                                              	nop
  ac8ac7:	90                                              	nop
  ac8ac8:	90                                              	nop
  ac8ac9:	90                                              	nop
  ac8aca:	90                                              	nop
  ac8acb:	90                                              	nop
  ac8acc:	90                                              	nop
  ac8acd:	90                                              	nop
  ac8ace:	90                                              	nop
  ac8acf:	90                                              	nop
  ac8ad0:	55                                              	push   rbp
  ac8ad1:	48 89 e5                                        	mov    rbp,rsp
  ac8ad4:	48 85 f6                                        	test   rsi,rsi
  ac8ad7:	74 0b                                           	je     0xac8ae4
  ac8ad9:	83 ff 0f                                        	cmp    edi,0xf
  ac8adc:	77 18                                           	ja     0xac8af6
  ac8ade:	c7 06 00 00 00 00                               	mov    DWORD PTR [rsi],0x0
  ac8ae4:	48 8d 35 45 87 1f 03                            	lea    rsi,[rip+0x31f8745]        # 0x3cc1230
  ac8aeb:	ba 10 00 00 00                                  	mov    edx,0x10
  ac8af0:	5d                                              	pop    rbp
  ac8af1:	e9 da ed 8d ff                                  	jmp    0x3a78d0
  ac8af6:	c7 06 01 00 00 00                               	mov    DWORD PTR [rsi],0x1
  ac8afc:	31 c0                                           	xor    eax,eax
  ac8afe:	5d                                              	pop    rbp
  ac8aff:	c3                                              	ret
  ac8b00:	55                                              	push   rbp
  ac8b01:	48 89 e5                                        	mov    rbp,rsp
  ac8b04:	48 8d 35 25 87 1f 03                            	lea    rsi,[rip+0x31f8725]        # 0x3cc1230
  ac8b0b:	ba 10 00 00 00                                  	mov    edx,0x10
  ac8b10:	5d                                              	pop    rbp
  ac8b11:	e9 7a ed 8d ff                                  	jmp    0x3a7890
  ac8b16:	90                                              	nop
  ac8b17:	90                                              	nop
  ac8b18:	90                                              	nop
  ac8b19:	90                                              	nop
  ac8b1a:	90                                              	nop
  ac8b1b:	90                                              	nop
  ac8b1c:	90                                              	nop
  ac8b1d:	90                                              	nop
  ac8b1e:	90                                              	nop
  ac8b1f:	90                                              	nop
  ac8b20:	55                                              	push   rbp
  ac8b21:	48 89 e5                                        	mov    rbp,rsp
  ac8b24:	89 fa                                           	mov    edx,edi
  ac8b26:	48 8d 3d 83 87 1f 03                            	lea    rdi,[rip+0x31f8783]        # 0x3cc12b0
  ac8b2d:	85 f6                                           	test   esi,esi
  ac8b2f:	74 0b                                           	je     0xac8b3c
  ac8b31:	be 08 00 00 00                                  	mov    esi,0x8
  ac8b36:	5d                                              	pop    rbp
  ac8b37:	e9 f4 f5 8d ff                                  	jmp    0x3a8130
  ac8b3c:	be 08 00 00 00                                  	mov    esi,0x8
  ac8b41:	5d                                              	pop    rbp
  ac8b42:	e9 49 f6 8d ff                                  	jmp    0x3a8190
  ac8b47:	90                                              	nop
  ac8b48:	90                                              	nop
  ac8b49:	90                                              	nop
  ac8b4a:	90                                              	nop
  ac8b4b:	90                                              	nop
  ac8b4c:	90                                              	nop
  ac8b4d:	90                                              	nop
  ac8b4e:	90                                              	nop
  ac8b4f:	90                                              	nop
  ac8b50:	48 85 ff                                        	test   rdi,rdi
  ac8b53:	74 07                                           	je     0xac8b5c
  ac8b55:	31 c0                                           	xor    eax,eax
  ac8b57:	85 f6                                           	test   esi,esi
  ac8b59:	74 07                                           	je     0xac8b62
  ac8b5b:	c3                                              	ret
  ac8b5c:	b8 01 00 3b 80                                  	mov    eax,0x803b0001
  ac8b61:	c3                                              	ret
  ac8b62:	55                                              	push   rbp
  ac8b63:	48 89 e5                                        	mov    rbp,rsp
  ac8b66:	41 56                                           	push   r14
  ac8b68:	53                                              	push   rbx
  ac8b69:	83 3f 00                                        	cmp    DWORD PTR [rdi],0x0
  ac8b6c:	0f 84 94 00 00 00                               	je     0xac8c06
  ac8b72:	8b 4f 04                                        	mov    ecx,DWORD PTR [rdi+0x4]
  ac8b75:	48 8d 35 b4 86 1f 03                            	lea    rsi,[rip+0x31f86b4]        # 0x3cc1230
  ac8b7c:	31 d2                                           	xor    edx,edx
  ac8b7e:	eb 09                                           	jmp    0xac8b89
  ac8b80:	48 ff c2                                        	inc    rdx
  ac8b83:	48 83 fa 10                                     	cmp    rdx,0x10
  ac8b87:	74 7d                                           	je     0xac8c06
  ac8b89:	4c 8b 0c d6                                     	mov    r9,QWORD PTR [rsi+rdx*8]
  ac8b8d:	4d 85 c9                                        	test   r9,r9
  ac8b90:	74 ee                                           	je     0xac8b80
  ac8b92:	4d 8b 81 98 01 00 00                            	mov    r8,QWORD PTR [r9+0x198]
  ac8b99:	41 b2 01                                        	mov    r10b,0x1
  ac8b9c:	45 31 db                                        	xor    r11d,r11d
  ac8b9f:	eb 18                                           	jmp    0xac8bb9
  ac8ba1:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ac8bb0:	49 ff c3                                        	inc    r11
  ac8bb3:	49 83 fb 10                                     	cmp    r11,0x10
  ac8bb7:	74 37                                           	je     0xac8bf0
  ac8bb9:	4b 8b 9c d9 10 01 00 00                         	mov    rbx,QWORD PTR [r9+r11*8+0x110]
  ac8bc1:	48 85 db                                        	test   rbx,rbx
  ac8bc4:	74 ea                                           	je     0xac8bb0
  ac8bc6:	4c 8b 73 08                                     	mov    r14,QWORD PTR [rbx+0x8]
  ac8bca:	4d 85 f6                                        	test   r14,r14
  ac8bcd:	74 e1                                           	je     0xac8bb0
  ac8bcf:	41 39 4e 04                                     	cmp    DWORD PTR [r14+0x4],ecx
  ac8bd3:	75 db                                           	jne    0xac8bb0
  ac8bd5:	44 8b 53 38                                     	mov    r10d,DWORD PTR [rbx+0x38]
  ac8bd9:	45 89 90 48 27 00 00                            	mov    DWORD PTR [r8+0x2748],r10d
  ac8be0:	45 31 d2                                        	xor    r10d,r10d
  ac8be3:	49 83 fb 0f                                     	cmp    r11,0xf
  ac8be7:	4d 8d 5b 01                                     	lea    r11,[r11+0x1]
  ac8beb:	75 cc                                           	jne    0xac8bb9
  ac8bed:	eb 91                                           	jmp    0xac8b80
  ac8bef:	90                                              	nop
  ac8bf0:	41 f6 c2 01                                     	test   r10b,0x1
  ac8bf4:	74 8a                                           	je     0xac8b80
  ac8bf6:	41 c7 80 48 27 00 00 01 00 00 00                	mov    DWORD PTR [r8+0x2748],0x1
  ac8c01:	e9 7a ff ff ff                                  	jmp    0xac8b80
  ac8c06:	83 3d e3 86 1f 03 00                            	cmp    DWORD PTR [rip+0x31f86e3],0x0        # 0x3cc12f0
  ac8c0d:	75 0f                                           	jne    0xac8c1e
  ac8c0f:	83 3f 00                                        	cmp    DWORD PTR [rdi],0x0
  ac8c12:	7e 0a                                           	jle    0xac8c1e
  ac8c14:	c7 05 d2 86 1f 03 01 00 00 00                   	mov    DWORD PTR [rip+0x31f86d2],0x1        # 0x3cc12f0
  ac8c1e:	8b 4f 10                                        	mov    ecx,DWORD PTR [rdi+0x10]
  ac8c21:	89 0d dd 86 1f 03                               	mov    DWORD PTR [rip+0x31f86dd],ecx        # 0x3cc1304
  ac8c27:	48 8b 0f                                        	mov    rcx,QWORD PTR [rdi]
  ac8c2a:	48 8b 57 08                                     	mov    rdx,QWORD PTR [rdi+0x8]
  ac8c2e:	48 89 0d bf 86 1f 03                            	mov    QWORD PTR [rip+0x31f86bf],rcx        # 0x3cc12f4
  ac8c35:	48 8b 0d f4 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f85f4]        # 0x3cc1230
  ac8c3c:	48 89 15 b9 86 1f 03                            	mov    QWORD PTR [rip+0x31f86b9],rdx        # 0x3cc12fc
  ac8c43:	48 85 c9                                        	test   rcx,rcx
  ac8c46:	74 11                                           	je     0xac8c59
  ac8c48:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8c4f:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8c59:	48 8b 0d d8 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f85d8]        # 0x3cc1238
  ac8c60:	48 85 c9                                        	test   rcx,rcx
  ac8c63:	74 11                                           	je     0xac8c76
  ac8c65:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8c6c:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8c76:	48 8b 0d c3 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f85c3]        # 0x3cc1240
  ac8c7d:	48 85 c9                                        	test   rcx,rcx
  ac8c80:	74 11                                           	je     0xac8c93
  ac8c82:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8c89:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8c93:	48 8b 0d ae 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f85ae]        # 0x3cc1248
  ac8c9a:	48 85 c9                                        	test   rcx,rcx
  ac8c9d:	74 11                                           	je     0xac8cb0
  ac8c9f:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8ca6:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8cb0:	48 8b 0d 99 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f8599]        # 0x3cc1250
  ac8cb7:	48 85 c9                                        	test   rcx,rcx
  ac8cba:	74 11                                           	je     0xac8ccd
  ac8cbc:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8cc3:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8ccd:	48 8b 0d 84 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f8584]        # 0x3cc1258
  ac8cd4:	48 85 c9                                        	test   rcx,rcx
  ac8cd7:	74 11                                           	je     0xac8cea
  ac8cd9:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8ce0:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8cea:	48 8b 0d 6f 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f856f]        # 0x3cc1260
  ac8cf1:	48 85 c9                                        	test   rcx,rcx
  ac8cf4:	74 11                                           	je     0xac8d07
  ac8cf6:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8cfd:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8d07:	48 8b 0d 5a 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f855a]        # 0x3cc1268
  ac8d0e:	48 85 c9                                        	test   rcx,rcx
  ac8d11:	74 11                                           	je     0xac8d24
  ac8d13:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8d1a:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8d24:	48 8b 0d 45 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f8545]        # 0x3cc1270
  ac8d2b:	48 85 c9                                        	test   rcx,rcx
  ac8d2e:	74 11                                           	je     0xac8d41
  ac8d30:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8d37:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8d41:	48 8b 0d 30 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f8530]        # 0x3cc1278
  ac8d48:	48 85 c9                                        	test   rcx,rcx
  ac8d4b:	74 11                                           	je     0xac8d5e
  ac8d4d:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8d54:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8d5e:	48 8b 0d 1b 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f851b]        # 0x3cc1280
  ac8d65:	48 85 c9                                        	test   rcx,rcx
  ac8d68:	74 11                                           	je     0xac8d7b
  ac8d6a:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8d71:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8d7b:	48 8b 0d 06 85 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f8506]        # 0x3cc1288
  ac8d82:	48 85 c9                                        	test   rcx,rcx
  ac8d85:	74 11                                           	je     0xac8d98
  ac8d87:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8d8e:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8d98:	48 8b 0d f1 84 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f84f1]        # 0x3cc1290
  ac8d9f:	48 85 c9                                        	test   rcx,rcx
  ac8da2:	74 11                                           	je     0xac8db5
  ac8da4:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8dab:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8db5:	48 8b 0d dc 84 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f84dc]        # 0x3cc1298
  ac8dbc:	48 85 c9                                        	test   rcx,rcx
  ac8dbf:	74 11                                           	je     0xac8dd2
  ac8dc1:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8dc8:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8dd2:	48 8b 0d c7 84 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f84c7]        # 0x3cc12a0
  ac8dd9:	48 85 c9                                        	test   rcx,rcx
  ac8ddc:	74 11                                           	je     0xac8def
  ac8dde:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8de5:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8def:	48 8b 0d b2 84 1f 03                            	mov    rcx,QWORD PTR [rip+0x31f84b2]        # 0x3cc12a8
  ac8df6:	48 85 c9                                        	test   rcx,rcx
  ac8df9:	74 11                                           	je     0xac8e0c
  ac8dfb:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac8e02:	c7 81 28 27 00 00 01 00 00 00                   	mov    DWORD PTR [rcx+0x2728],0x1
  ac8e0c:	5b                                              	pop    rbx
  ac8e0d:	41 5e                                           	pop    r14
  ac8e0f:	5d                                              	pop    rbp
  ac8e10:	c3                                              	ret
  ac8e11:	90                                              	nop
  ac8e12:	90                                              	nop
  ac8e13:	90                                              	nop
  ac8e14:	90                                              	nop
  ac8e15:	90                                              	nop
  ac8e16:	90                                              	nop
  ac8e17:	90                                              	nop
  ac8e18:	90                                              	nop
  ac8e19:	90                                              	nop
  ac8e1a:	90                                              	nop
  ac8e1b:	90                                              	nop
  ac8e1c:	90                                              	nop
  ac8e1d:	90                                              	nop
  ac8e1e:	90                                              	nop
  ac8e1f:	90                                              	nop
  ac8e20:	55                                              	push   rbp
  ac8e21:	48 89 e5                                        	mov    rbp,rsp
  ac8e24:	53                                              	push   rbx
  ac8e25:	50                                              	push   rax
  ac8e26:	89 fb                                           	mov    ebx,edi
  ac8e28:	48 8d 3d 81 84 1f 03                            	lea    rdi,[rip+0x31f8481]        # 0x3cc12b0
  ac8e2f:	be 08 00 00 00                                  	mov    esi,0x8
  ac8e34:	89 da                                           	mov    edx,ebx
  ac8e36:	e8 c5 f2 8d ff                                  	call   0x3a8100
  ac8e3b:	85 c0                                           	test   eax,eax
  ac8e3d:	74 13                                           	je     0xac8e52
  ac8e3f:	48 8d 3d 6a 84 1f 03                            	lea    rdi,[rip+0x31f846a]        # 0x3cc12b0
  ac8e46:	be 08 00 00 00                                  	mov    esi,0x8
  ac8e4b:	89 da                                           	mov    edx,ebx
  ac8e4d:	e8 3e f3 8d ff                                  	call   0x3a8190
  ac8e52:	31 c0                                           	xor    eax,eax
  ac8e54:	48 83 c4 08                                     	add    rsp,0x8
  ac8e58:	5b                                              	pop    rbx
  ac8e59:	5d                                              	pop    rbp
  ac8e5a:	c3                                              	ret
  ac8e5b:	90                                              	nop
  ac8e5c:	90                                              	nop
  ac8e5d:	90                                              	nop
  ac8e5e:	90                                              	nop
  ac8e5f:	90                                              	nop
  ac8e60:	55                                              	push   rbp
  ac8e61:	48 89 e5                                        	mov    rbp,rsp
  ac8e64:	48 89 3d ad 84 1f 03                            	mov    QWORD PTR [rip+0x31f84ad],rdi        # 0x3cc1318
  ac8e6b:	31 c0                                           	xor    eax,eax
  ac8e6d:	5d                                              	pop    rbp
  ac8e6e:	c3                                              	ret
  ac8e6f:	90                                              	nop
  ac8e70:	55                                              	push   rbp
  ac8e71:	48 89 e5                                        	mov    rbp,rsp
  ac8e74:	41 57                                           	push   r15
  ac8e76:	41 56                                           	push   r14
  ac8e78:	41 55                                           	push   r13
  ac8e7a:	41 54                                           	push   r12
  ac8e7c:	53                                              	push   rbx
  ac8e7d:	48 83 ec 68                                     	sub    rsp,0x68
  ac8e81:	48 8d 05 88 34 e5 02                            	lea    rax,[rip+0x2e53488]        # 0x391c310
  ac8e88:	45 31 ff                                        	xor    r15d,r15d
  ac8e8b:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ac8e8e:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ac8e92:	e8 39 e4 87 ff                                  	call   0x3472d0
  ac8e97:	48 89 c3                                        	mov    rbx,rax
  ac8e9a:	4c 8d 25 8f 83 1f 03                            	lea    r12,[rip+0x31f838f]        # 0x3cc1230
  ac8ea1:	4c 8d 75 80                                     	lea    r14,[rbp-0x80]
  ac8ea5:	eb 16                                           	jmp    0xac8ebd
  ac8ea7:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  ac8eb0:	49 83 c7 08                                     	add    r15,0x8
  ac8eb4:	49 81 ff 80 00 00 00                            	cmp    r15,0x80
  ac8ebb:	74 7b                                           	je     0xac8f38
  ac8ebd:	4f 8b 2c 27                                     	mov    r13,QWORD PTR [r15+r12*1]
  ac8ec1:	4d 85 ed                                        	test   r13,r13
  ac8ec4:	74 ea                                           	je     0xac8eb0
  ac8ec6:	41 80 7d 18 03                                  	cmp    BYTE PTR [r13+0x18],0x3
  ac8ecb:	75 e3                                           	jne    0xac8eb0
  ac8ecd:	41 80 7d 38 02                                  	cmp    BYTE PTR [r13+0x38],0x2
  ac8ed2:	75 dc                                           	jne    0xac8eb0
  ac8ed4:	be 50 00 00 00                                  	mov    esi,0x50
  ac8ed9:	4c 89 f7                                        	mov    rdi,r14
  ac8edc:	c7 85 7c ff ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x84],0x0
  ac8ee6:	c7 85 78 ff ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x88],0x0
  ac8ef0:	e8 fb 00 79 ff                                  	call   0x258ff0
  ac8ef5:	4c 89 ef                                        	mov    rdi,r13
  ac8ef8:	4c 89 f6                                        	mov    rsi,r14
  ac8efb:	48 8d 95 7c ff ff ff                            	lea    rdx,[rbp-0x84]
  ac8f02:	48 8d 8d 78 ff ff ff                            	lea    rcx,[rbp-0x88]
  ac8f09:	48 89 5d 80                                     	mov    QWORD PTR [rbp-0x80],rbx
  ac8f0d:	e8 3e f9 ff ff                                  	call   0xac8850
  ac8f12:	85 c0                                           	test   eax,eax
  ac8f14:	75 9a                                           	jne    0xac8eb0
  ac8f16:	83 bd 7c ff ff ff 01                            	cmp    DWORD PTR [rbp-0x84],0x1
  ac8f1d:	75 91                                           	jne    0xac8eb0
  ac8f1f:	83 bd 78 ff ff ff 00                            	cmp    DWORD PTR [rbp-0x88],0x0
  ac8f26:	75 88                                           	jne    0xac8eb0
  ac8f28:	4c 89 ef                                        	mov    rdi,r13
  ac8f2b:	4c 89 f6                                        	mov    rsi,r14
  ac8f2e:	e8 dd 06 00 00                                  	call   0xac9610
  ac8f33:	e9 78 ff ff ff                                  	jmp    0xac8eb0
  ac8f38:	48 8d 05 d1 33 e5 02                            	lea    rax,[rip+0x2e533d1]        # 0x391c310
  ac8f3f:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ac8f42:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ac8f46:	75 0f                                           	jne    0xac8f57
  ac8f48:	48 83 c4 68                                     	add    rsp,0x68
  ac8f4c:	5b                                              	pop    rbx
  ac8f4d:	41 5c                                           	pop    r12
  ac8f4f:	41 5d                                           	pop    r13
  ac8f51:	41 5e                                           	pop    r14
  ac8f53:	41 5f                                           	pop    r15
  ac8f55:	5d                                              	pop    rbp
  ac8f56:	c3                                              	ret
  ac8f57:	e8 54 47 c3 ff                                  	call   0x6fd6b0
  ac8f5c:	0f 0b                                           	ud2
  ac8f5e:	90                                              	nop
  ac8f5f:	90                                              	nop
  ac8f60:	80 7f 18 00                                     	cmp    BYTE PTR [rdi+0x18],0x0
  ac8f64:	74 03                                           	je     0xac8f69
  ac8f66:	31 c0                                           	xor    eax,eax
  ac8f68:	c3                                              	ret
  ac8f69:	8b 87 04 01 00 00                               	mov    eax,DWORD PTR [rdi+0x104]
  ac8f6f:	3b 87 08 01 00 00                               	cmp    eax,DWORD PTR [rdi+0x108]
  ac8f75:	74 43                                           	je     0xac8fba
  ac8f77:	83 e8 01                                        	sub    eax,0x1
  ac8f7a:	b9 40 00 00 00                                  	mov    ecx,0x40
  ac8f7f:	0f 43 c8                                        	cmovae ecx,eax
  ac8f82:	48 63 c1                                        	movsxd rax,ecx
  ac8f85:	48 69 c0 98 00 00 00                            	imul   rax,rax,0x98
  ac8f8c:	48 03 87 98 01 00 00                            	add    rax,QWORD PTR [rdi+0x198]
  ac8f93:	48 05 90 00 00 00                               	add    rax,0x90
  ac8f99:	74 1f                                           	je     0xac8fba
  ac8f9b:	80 78 1a 00                                     	cmp    BYTE PTR [rax+0x1a],0x0
  ac8f9f:	74 19                                           	je     0xac8fba
  ac8fa1:	55                                              	push   rbp
  ac8fa2:	48 89 e5                                        	mov    rbp,rsp
  ac8fa5:	53                                              	push   rbx
  ac8fa6:	50                                              	push   rax
  ac8fa7:	48 89 fb                                        	mov    rbx,rdi
  ac8faa:	e8 51 f4 8d ff                                  	call   0x3a8400
  ac8faf:	48 89 df                                        	mov    rdi,rbx
  ac8fb2:	48 83 c4 08                                     	add    rsp,0x8
  ac8fb6:	5b                                              	pop    rbx
  ac8fb7:	5d                                              	pop    rbp
  ac8fb8:	eb 0b                                           	jmp    0xac8fc5
  ac8fba:	48 c7 87 90 01 00 00 00 00 00 00                	mov    QWORD PTR [rdi+0x190],0x0
  ac8fc5:	c7 87 08 01 00 00 00 00 00 00                   	mov    DWORD PTR [rdi+0x108],0x0
  ac8fcf:	48 c7 87 00 01 00 00 00 00 00 00                	mov    QWORD PTR [rdi+0x100],0x0
  ac8fda:	31 c0                                           	xor    eax,eax
  ac8fdc:	c3                                              	ret
  ac8fdd:	90                                              	nop
  ac8fde:	90                                              	nop
  ac8fdf:	90                                              	nop
  ac8fe0:	55                                              	push   rbp
  ac8fe1:	48 89 e5                                        	mov    rbp,rsp
  ac8fe4:	41 57                                           	push   r15
  ac8fe6:	41 56                                           	push   r14
  ac8fe8:	41 55                                           	push   r13
  ac8fea:	41 54                                           	push   r12
  ac8fec:	53                                              	push   rbx
  ac8fed:	48 83 ec 28                                     	sub    rsp,0x28
  ac8ff1:	41 89 d4                                        	mov    r12d,edx
  ac8ff4:	41 89 ce                                        	mov    r14d,ecx
  ac8ff7:	48 85 f6                                        	test   rsi,rsi
  ac8ffa:	41 8d 4c 24 be                                  	lea    ecx,[r12-0x42]
  ac8fff:	0f 94 c0                                        	sete   al
  ac9002:	83 f9 bf                                        	cmp    ecx,0xffffffbf
  ac9005:	0f 92 c1                                        	setb   cl
  ac9008:	08 c1                                           	or     cl,al
  ac900a:	b8 01 00 3b 80                                  	mov    eax,0x803b0001
  ac900f:	0f 85 9b 01 00 00                               	jne    0xac91b0
  ac9015:	49 89 f7                                        	mov    r15,rsi
  ac9018:	48 8d 35 11 82 1f 03                            	lea    rsi,[rip+0x31f8211]        # 0x3cc1230
  ac901f:	ba 10 00 00 00                                  	mov    edx,0x10
  ac9024:	4c 89 c3                                        	mov    rbx,r8
  ac9027:	e8 a4 e8 8d ff                                  	call   0x3a78d0
  ac902c:	48 89 c1                                        	mov    rcx,rax
  ac902f:	31 c0                                           	xor    eax,eax
  ac9031:	48 85 c9                                        	test   rcx,rcx
  ac9034:	74 34                                           	je     0xac906a
  ac9036:	45 85 f6                                        	test   r14d,r14d
  ac9039:	74 41                                           	je     0xac907c
  ac903b:	8b b1 04 01 00 00                               	mov    esi,DWORD PTR [rcx+0x104]
  ac9041:	8d 56 01                                        	lea    edx,[rsi+0x1]
  ac9044:	48 63 d2                                        	movsxd rdx,edx
  ac9047:	48 69 d2 7f e0 07 7e                            	imul   rdx,rdx,0x7e07e07f
  ac904e:	48 89 d7                                        	mov    rdi,rdx
  ac9051:	48 c1 fa 25                                     	sar    rdx,0x25
  ac9055:	48 c1 ef 3f                                     	shr    rdi,0x3f
  ac9059:	01 fa                                           	add    edx,edi
  ac905b:	89 d7                                           	mov    edi,edx
  ac905d:	c1 e7 06                                        	shl    edi,0x6
  ac9060:	01 d7                                           	add    edi,edx
  ac9062:	f7 df                                           	neg    edi
  ac9064:	8d 54 3e 01                                     	lea    edx,[rsi+rdi*1+0x1]
  ac9068:	eb 1e                                           	jmp    0xac9088
  ac906a:	31 c9                                           	xor    ecx,ecx
  ac906c:	31 ff                                           	xor    edi,edi
  ac906e:	48 85 db                                        	test   rbx,rbx
  ac9071:	0f 85 32 01 00 00                               	jne    0xac91a9
  ac9077:	e9 2f 01 00 00                                  	jmp    0xac91ab
  ac907c:	8b b1 04 01 00 00                               	mov    esi,DWORD PTR [rcx+0x104]
  ac9082:	8b 91 08 01 00 00                               	mov    edx,DWORD PTR [rcx+0x108]
  ac9088:	8b 79 04                                        	mov    edi,DWORD PTR [rcx+0x4]
  ac908b:	29 d6                                           	sub    esi,edx
  ac908d:	75 10                                           	jne    0xac909f
  ac908f:	31 c9                                           	xor    ecx,ecx
  ac9091:	48 85 db                                        	test   rbx,rbx
  ac9094:	0f 85 0f 01 00 00                               	jne    0xac91a9
  ac909a:	e9 0c 01 00 00                                  	jmp    0xac91ab
  ac909f:	4c 8b a9 98 01 00 00                            	mov    r13,QWORD PTR [rcx+0x198]
  ac90a6:	8d 46 41                                        	lea    eax,[rsi+0x41]
  ac90a9:	85 f6                                           	test   esi,esi
  ac90ab:	0f 49 c6                                        	cmovns eax,esi
  ac90ae:	44 39 e0                                        	cmp    eax,r12d
  ac90b1:	7e 2a                                           	jle    0xac90dd
  ac90b3:	44 29 e2                                        	sub    edx,r12d
  ac90b6:	01 c2                                           	add    edx,eax
  ac90b8:	48 63 d2                                        	movsxd rdx,edx
  ac90bb:	48 69 c2 7f e0 07 7e                            	imul   rax,rdx,0x7e07e07f
  ac90c2:	48 89 c6                                        	mov    rsi,rax
  ac90c5:	48 c1 f8 25                                     	sar    rax,0x25
  ac90c9:	48 c1 ee 3f                                     	shr    rsi,0x3f
  ac90cd:	01 f0                                           	add    eax,esi
  ac90cf:	89 c6                                           	mov    esi,eax
  ac90d1:	c1 e6 06                                        	shl    esi,0x6
  ac90d4:	01 c6                                           	add    esi,eax
  ac90d6:	44 89 e0                                        	mov    eax,r12d
  ac90d9:	29 f2                                           	sub    edx,esi
  ac90db:	eb 08                                           	jmp    0xac90e5
  ac90dd:	85 c0                                           	test   eax,eax
  ac90df:	0f 8e a7 00 00 00                               	jle    0xac918c
  ac90e5:	44 89 75 d0                                     	mov    DWORD PTR [rbp-0x30],r14d
  ac90e9:	4d 8d a5 90 00 00 00                            	lea    r12,[r13+0x90]
  ac90f0:	41 89 c6                                        	mov    r14d,eax
  ac90f3:	89 7d d4                                        	mov    DWORD PTR [rbp-0x2c],edi
  ac90f6:	48 89 5d c0                                     	mov    QWORD PTR [rbp-0x40],rbx
  ac90fa:	48 89 4d b8                                     	mov    QWORD PTR [rbp-0x48],rcx
  ac90fe:	89 45 cc                                        	mov    DWORD PTR [rbp-0x34],eax
  ac9101:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ac9110:	48 63 da                                        	movsxd rbx,edx
  ac9113:	b9 0a 00 00 00                                  	mov    ecx,0xa
  ac9118:	4c 89 ff                                        	mov    rdi,r15
  ac911b:	48 69 f3 98 00 00 00                            	imul   rsi,rbx,0x98
  ac9122:	4c 01 e6                                        	add    rsi,r12
  ac9125:	f3 48 a5                                        	rep movs QWORD PTR [rdi],QWORD PTR [rsi]
  ac9128:	49 8b 37                                        	mov    rsi,QWORD PTR [r15]
  ac912b:	31 ff                                           	xor    edi,edi
  ac912d:	e8 8e e2 87 ff                                  	call   0x3473c0
  ac9132:	49 89 07                                        	mov    QWORD PTR [r15],rax
  ac9135:	41 8b 85 40 27 00 00                            	mov    eax,DWORD PTR [r13+0x2740]
  ac913c:	41 89 47 20                                     	mov    DWORD PTR [r15+0x20],eax
  ac9140:	41 8b 85 44 27 00 00                            	mov    eax,DWORD PTR [r13+0x2744]
  ac9147:	41 89 47 24                                     	mov    DWORD PTR [r15+0x24],eax
  ac914b:	8d 43 01                                        	lea    eax,[rbx+0x1]
  ac914e:	49 83 c7 50                                     	add    r15,0x50
  ac9152:	48 98                                           	cdqe
  ac9154:	48 69 c0 7f e0 07 7e                            	imul   rax,rax,0x7e07e07f
  ac915b:	48 89 c1                                        	mov    rcx,rax
  ac915e:	48 c1 f8 25                                     	sar    rax,0x25
  ac9162:	48 c1 e9 3f                                     	shr    rcx,0x3f
  ac9166:	01 c8                                           	add    eax,ecx
  ac9168:	89 c1                                           	mov    ecx,eax
  ac916a:	c1 e1 06                                        	shl    ecx,0x6
  ac916d:	01 c1                                           	add    ecx,eax
  ac916f:	f7 d9                                           	neg    ecx
  ac9171:	49 ff ce                                        	dec    r14
  ac9174:	8d 54 0b 01                                     	lea    edx,[rbx+rcx*1+0x1]
  ac9178:	75 96                                           	jne    0xac9110
  ac917a:	8b 45 cc                                        	mov    eax,DWORD PTR [rbp-0x34]
  ac917d:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  ac9181:	48 8b 5d c0                                     	mov    rbx,QWORD PTR [rbp-0x40]
  ac9185:	44 8b 75 d0                                     	mov    r14d,DWORD PTR [rbp-0x30]
  ac9189:	8b 7d d4                                        	mov    edi,DWORD PTR [rbp-0x2c]
  ac918c:	45 85 f6                                        	test   r14d,r14d
  ac918f:	75 0c                                           	jne    0xac919d
  ac9191:	8b 91 04 01 00 00                               	mov    edx,DWORD PTR [rcx+0x104]
  ac9197:	89 91 08 01 00 00                               	mov    DWORD PTR [rcx+0x108],edx
  ac919d:	89 c1                                           	mov    ecx,eax
  ac919f:	c1 f9 1f                                        	sar    ecx,0x1f
  ac91a2:	21 c1                                           	and    ecx,eax
  ac91a4:	48 85 db                                        	test   rbx,rbx
  ac91a7:	74 02                                           	je     0xac91ab
  ac91a9:	89 3b                                           	mov    DWORD PTR [rbx],edi
  ac91ab:	85 c9                                           	test   ecx,ecx
  ac91ad:	0f 48 c1                                        	cmovs  eax,ecx
  ac91b0:	48 83 c4 28                                     	add    rsp,0x28
  ac91b4:	5b                                              	pop    rbx
  ac91b5:	41 5c                                           	pop    r12
  ac91b7:	41 5d                                           	pop    r13
  ac91b9:	41 5e                                           	pop    r14
  ac91bb:	41 5f                                           	pop    r15
  ac91bd:	5d                                              	pop    rbp
  ac91be:	c3                                              	ret
  ac91bf:	90                                              	nop
  ac91c0:	55                                              	push   rbp
  ac91c1:	48 89 e5                                        	mov    rbp,rsp
  ac91c4:	41 57                                           	push   r15
  ac91c6:	41 56                                           	push   r14
  ac91c8:	41 55                                           	push   r13
  ac91ca:	41 54                                           	push   r12
  ac91cc:	53                                              	push   rbx
  ac91cd:	48 83 ec 58                                     	sub    rsp,0x58
  ac91d1:	41 89 cf                                        	mov    r15d,ecx
  ac91d4:	48 85 d2                                        	test   rdx,rdx
  ac91d7:	45 89 c4                                        	mov    r12d,r8d
  ac91da:	41 b8 01 00 3b 80                               	mov    r8d,0x803b0001
  ac91e0:	41 8d 4f be                                     	lea    ecx,[r15-0x42]
  ac91e4:	0f 94 c0                                        	sete   al
  ac91e7:	83 f9 bf                                        	cmp    ecx,0xffffffbf
  ac91ea:	0f 92 c1                                        	setb   cl
  ac91ed:	08 c1                                           	or     cl,al
  ac91ef:	0f 85 35 01 00 00                               	jne    0xac932a
  ac91f5:	41 89 f6                                        	mov    r14d,esi
  ac91f8:	48 89 55 a8                                     	mov    QWORD PTR [rbp-0x58],rdx
  ac91fc:	48 8d 35 2d 80 1f 03                            	lea    rsi,[rip+0x31f802d]        # 0x3cc1230
  ac9203:	ba 10 00 00 00                                  	mov    edx,0x10
  ac9208:	e8 83 e6 8d ff                                  	call   0x3a7890
  ac920d:	48 85 c0                                        	test   rax,rax
  ac9210:	0f 84 11 01 00 00                               	je     0xac9327
  ac9216:	48 89 c7                                        	mov    rdi,rax
  ac9219:	44 89 f6                                        	mov    esi,r14d
  ac921c:	49 89 c5                                        	mov    r13,rax
  ac921f:	e8 6c ed 8d ff                                  	call   0x3a7f90
  ac9224:	48 85 c0                                        	test   rax,rax
  ac9227:	0f 84 fa 00 00 00                               	je     0xac9327
  ac922d:	48 8b 58 08                                     	mov    rbx,QWORD PTR [rax+0x8]
  ac9231:	41 b8 01 00 3b 80                               	mov    r8d,0x803b0001
  ac9237:	48 85 db                                        	test   rbx,rbx
  ac923a:	0f 84 ea 00 00 00                               	je     0xac932a
  ac9240:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  ac9244:	49 8b 85 98 01 00 00                            	mov    rax,QWORD PTR [r13+0x198]
  ac924b:	8b 53 04                                        	mov    edx,DWORD PTR [rbx+0x4]
  ac924e:	48 8d 3d 5b 80 1f 03                            	lea    rdi,[rip+0x31f805b]        # 0x3cc12b0
  ac9255:	be 08 00 00 00                                  	mov    esi,0x8
  ac925a:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  ac925e:	e8 9d ee 8d ff                                  	call   0x3a8100
  ac9263:	4d 89 ee                                        	mov    r14,r13
  ac9266:	41 89 c5                                        	mov    r13d,eax
  ac9269:	e8 72 df 87 ff                                  	call   0x3471e0
  ac926e:	48 8b 43 18                                     	mov    rax,QWORD PTR [rbx+0x18]
  ac9272:	48 89 5d b8                                     	mov    QWORD PTR [rbp-0x48],rbx
  ac9276:	48 89 45 98                                     	mov    QWORD PTR [rbp-0x68],rax
  ac927a:	48 83 f8 ff                                     	cmp    rax,0xffffffffffffffff
  ac927e:	75 17                                           	jne    0xac9297
  ac9280:	8b 7b 04                                        	mov    edi,DWORD PTR [rbx+0x4]
  ac9283:	e8 98 e0 87 ff                                  	call   0x347320
  ac9288:	48 8b 55 b8                                     	mov    rdx,QWORD PTR [rbp-0x48]
  ac928c:	48 89 c1                                        	mov    rcx,rax
  ac928f:	48 89 4d 98                                     	mov    QWORD PTR [rbp-0x68],rcx
  ac9293:	48 89 4a 18                                     	mov    QWORD PTR [rdx+0x18],rcx
  ac9297:	e8 f4 de 87 ff                                  	call   0x347190
  ac929c:	48 8d 35 8d 7f 1f 03                            	lea    rsi,[rip+0x31f7f8d]        # 0x3cc1230
  ac92a3:	4c 89 f7                                        	mov    rdi,r14
  ac92a6:	ba 10 00 00 00                                  	mov    edx,0x10
  ac92ab:	e8 10 e7 8d ff                                  	call   0x3a79c0
  ac92b0:	85 c0                                           	test   eax,eax
  ac92b2:	74 73                                           	je     0xac9327
  ac92b4:	83 3d 35 80 1f 03 00                            	cmp    DWORD PTR [rip+0x31f8035],0x0        # 0x3cc12f0
  ac92bb:	48 8b 7d c0                                     	mov    rdi,QWORD PTR [rbp-0x40]
  ac92bf:	41 8b 96 04 01 00 00                            	mov    edx,DWORD PTR [r14+0x104]
  ac92c6:	45 89 e1                                        	mov    r9d,r12d
  ac92c9:	41 b8 00 00 00 00                               	mov    r8d,0x0
  ac92cf:	89 d6                                           	mov    esi,edx
  ac92d1:	41 0f 95 c2                                     	setne  r10b
  ac92d5:	45 85 ed                                        	test   r13d,r13d
  ac92d8:	0f 94 c0                                        	sete   al
  ac92db:	41 83 fc 01                                     	cmp    r12d,0x1
  ac92df:	46 8b 64 8f 18                                  	mov    r12d,DWORD PTR [rdi+r9*4+0x18]
  ac92e4:	0f 95 c1                                        	setne  cl
  ac92e7:	44 29 e6                                        	sub    esi,r12d
  ac92ea:	74 3e                                           	je     0xac932a
  ac92ec:	44 8d 46 41                                     	lea    r8d,[rsi+0x41]
  ac92f0:	85 f6                                           	test   esi,esi
  ac92f2:	44 0f 49 c6                                     	cmovns r8d,esi
  ac92f6:	45 39 f8                                        	cmp    r8d,r15d
  ac92f9:	7e 41                                           	jle    0xac933c
  ac92fb:	45 29 fc                                        	sub    r12d,r15d
  ac92fe:	45 01 c4                                        	add    r12d,r8d
  ac9301:	45 89 f8                                        	mov    r8d,r15d
  ac9304:	4d 63 e4                                        	movsxd r12,r12d
  ac9307:	49 69 d4 7f e0 07 7e                            	imul   rdx,r12,0x7e07e07f
  ac930e:	48 89 d6                                        	mov    rsi,rdx
  ac9311:	48 c1 fa 25                                     	sar    rdx,0x25
  ac9315:	48 c1 ee 3f                                     	shr    rsi,0x3f
  ac9319:	01 f2                                           	add    edx,esi
  ac931b:	89 d6                                           	mov    esi,edx
  ac931d:	c1 e6 06                                        	shl    esi,0x6
  ac9320:	01 d6                                           	add    esi,edx
  ac9322:	41 29 f4                                        	sub    r12d,esi
  ac9325:	eb 1e                                           	jmp    0xac9345
  ac9327:	45 31 c0                                        	xor    r8d,r8d
  ac932a:	44 89 c0                                        	mov    eax,r8d
  ac932d:	48 83 c4 58                                     	add    rsp,0x58
  ac9331:	5b                                              	pop    rbx
  ac9332:	41 5c                                           	pop    r12
  ac9334:	41 5d                                           	pop    r13
  ac9336:	41 5e                                           	pop    r14
  ac9338:	41 5f                                           	pop    r15
  ac933a:	5d                                              	pop    rbp
  ac933b:	c3                                              	ret
  ac933c:	45 85 c0                                        	test   r8d,r8d
  ac933f:	0f 8e 68 01 00 00                               	jle    0xac94ad
  ac9345:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  ac9349:	4c 8b 7d a8                                     	mov    r15,QWORD PTR [rbp-0x58]
  ac934d:	41 20 ca                                        	and    r10b,cl
  ac9350:	44 89 c3                                        	mov    ebx,r8d
  ac9353:	45 31 ed                                        	xor    r13d,r13d
  ac9356:	4c 89 4d 90                                     	mov    QWORD PTR [rbp-0x70],r9
  ac935a:	4c 89 75 88                                     	mov    QWORD PTR [rbp-0x78],r14
  ac935e:	44 89 45 d0                                     	mov    DWORD PTR [rbp-0x30],r8d
  ac9362:	41 20 c2                                        	and    r10b,al
  ac9365:	44 88 55 d6                                     	mov    BYTE PTR [rbp-0x2a],r10b
  ac9369:	48 8d 8a e0 00 00 00                            	lea    rcx,[rdx+0xe0]
  ac9370:	48 8d 82 90 00 00 00                            	lea    rax,[rdx+0x90]
  ac9377:	48 89 4d 80                                     	mov    QWORD PTR [rbp-0x80],rcx
  ac937b:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  ac937f:	e9 8a 00 00 00                                  	jmp    0xac940e
  ac9384:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ac9390:	48 69 f0 98 00 00 00                            	imul   rsi,rax,0x98
  ac9397:	48 03 75 b0                                     	add    rsi,QWORD PTR [rbp-0x50]
  ac939b:	4f 8d 74 ad 00                                  	lea    r14,[r13+r13*4+0x0]
  ac93a0:	b9 0a 00 00 00                                  	mov    ecx,0xa
  ac93a5:	4c 89 ff                                        	mov    rdi,r15
  ac93a8:	49 c1 e6 04                                     	shl    r14,0x4
  ac93ac:	4c 03 75 a8                                     	add    r14,QWORD PTR [rbp-0x58]
  ac93b0:	f3 48 a5                                        	rep movs QWORD PTR [rdi],QWORD PTR [rsi]
  ac93b3:	49 8b 36                                        	mov    rsi,QWORD PTR [r14]
  ac93b6:	48 8b 7d 98                                     	mov    rdi,QWORD PTR [rbp-0x68]
  ac93ba:	e8 01 e0 87 ff                                  	call   0x3473c0
  ac93bf:	48 8b 4d a0                                     	mov    rcx,QWORD PTR [rbp-0x60]
  ac93c3:	49 89 06                                        	mov    QWORD PTR [r14],rax
  ac93c6:	41 ff c4                                        	inc    r12d
  ac93c9:	49 ff c5                                        	inc    r13
  ac93cc:	4d 63 e4                                        	movsxd r12,r12d
  ac93cf:	8b 81 40 27 00 00                               	mov    eax,DWORD PTR [rcx+0x2740]
  ac93d5:	41 89 47 20                                     	mov    DWORD PTR [r15+0x20],eax
  ac93d9:	8b 81 44 27 00 00                               	mov    eax,DWORD PTR [rcx+0x2744]
  ac93df:	41 89 47 24                                     	mov    DWORD PTR [r15+0x24],eax
  ac93e3:	49 69 c4 7f e0 07 7e                            	imul   rax,r12,0x7e07e07f
  ac93ea:	49 83 c7 50                                     	add    r15,0x50
  ac93ee:	48 89 c1                                        	mov    rcx,rax
  ac93f1:	48 c1 f8 25                                     	sar    rax,0x25
  ac93f5:	48 c1 e9 3f                                     	shr    rcx,0x3f
  ac93f9:	01 c8                                           	add    eax,ecx
  ac93fb:	89 c1                                           	mov    ecx,eax
  ac93fd:	c1 e1 06                                        	shl    ecx,0x6
  ac9400:	01 c1                                           	add    ecx,eax
  ac9402:	41 29 cc                                        	sub    r12d,ecx
  ac9405:	48 ff cb                                        	dec    rbx
  ac9408:	0f 84 89 00 00 00                               	je     0xac9497
  ac940e:	80 7d d6 00                                     	cmp    BYTE PTR [rbp-0x2a],0x0
  ac9412:	49 63 c4                                        	movsxd rax,r12d
  ac9415:	0f 84 75 ff ff ff                               	je     0xac9390
  ac941b:	4c 69 f0 98 00 00 00                            	imul   r14,rax,0x98
  ac9422:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  ac9426:	48 8b 4d 80                                     	mov    rcx,QWORD PTR [rbp-0x80]
  ac942a:	8b 70 04                                        	mov    esi,DWORD PTR [rax+0x4]
  ac942d:	4a 8d 3c 31                                     	lea    rdi,[rcx+r14*1]
  ac9431:	e8 0a ee 8d ff                                  	call   0x3a8240
  ac9436:	4c 03 75 b0                                     	add    r14,QWORD PTR [rbp-0x50]
  ac943a:	b9 0a 00 00 00                                  	mov    ecx,0xa
  ac943f:	4c 89 ff                                        	mov    rdi,r15
  ac9442:	4c 89 f6                                        	mov    rsi,r14
  ac9445:	f3 48 a5                                        	rep movs QWORD PTR [rdi],QWORD PTR [rsi]
  ac9448:	85 c0                                           	test   eax,eax
  ac944a:	74 0d                                           	je     0xac9459
  ac944c:	4d 89 fe                                        	mov    r14,r15
  ac944f:	83 f8 02                                        	cmp    eax,0x2
  ac9452:	74 36                                           	je     0xac948a
  ac9454:	e9 5a ff ff ff                                  	jmp    0xac93b3
  ac9459:	41 0f b6 47 10                                  	movzx  eax,BYTE PTR [r15+0x10]
  ac945e:	41 8b 4f 12                                     	mov    ecx,DWORD PTR [r15+0x12]
  ac9462:	4d 8b 37                                        	mov    r14,QWORD PTR [r15]
  ac9465:	be 50 00 00 00                                  	mov    esi,0x50
  ac946a:	4c 89 ff                                        	mov    rdi,r15
  ac946d:	88 45 d7                                        	mov    BYTE PTR [rbp-0x29],al
  ac9470:	89 4d cc                                        	mov    DWORD PTR [rbp-0x34],ecx
  ac9473:	e8 78 fb 78 ff                                  	call   0x258ff0
  ac9478:	0f b6 45 d7                                     	movzx  eax,BYTE PTR [rbp-0x29]
  ac947c:	8b 4d cc                                        	mov    ecx,DWORD PTR [rbp-0x34]
  ac947f:	4d 89 37                                        	mov    QWORD PTR [r15],r14
  ac9482:	41 88 47 10                                     	mov    BYTE PTR [r15+0x10],al
  ac9486:	41 89 4f 12                                     	mov    DWORD PTR [r15+0x12],ecx
  ac948a:	4d 89 fe                                        	mov    r14,r15
  ac948d:	41 c6 47 11 01                                  	mov    BYTE PTR [r15+0x11],0x1
  ac9492:	e9 1c ff ff ff                                  	jmp    0xac93b3
  ac9497:	48 8b 45 88                                     	mov    rax,QWORD PTR [rbp-0x78]
  ac949b:	48 8b 7d c0                                     	mov    rdi,QWORD PTR [rbp-0x40]
  ac949f:	44 8b 45 d0                                     	mov    r8d,DWORD PTR [rbp-0x30]
  ac94a3:	4c 8b 4d 90                                     	mov    r9,QWORD PTR [rbp-0x70]
  ac94a7:	8b 90 04 01 00 00                               	mov    edx,DWORD PTR [rax+0x104]
  ac94ad:	42 89 54 8f 18                                  	mov    DWORD PTR [rdi+r9*4+0x18],edx
  ac94b2:	e9 73 fe ff ff                                  	jmp    0xac932a
  ac94b7:	90                                              	nop
  ac94b8:	90                                              	nop
  ac94b9:	90                                              	nop
  ac94ba:	90                                              	nop
  ac94bb:	90                                              	nop
  ac94bc:	90                                              	nop
  ac94bd:	90                                              	nop
  ac94be:	90                                              	nop
  ac94bf:	90                                              	nop
  ac94c0:	48 85 ff                                        	test   rdi,rdi
  ac94c3:	74 29                                           	je     0xac94ee
  ac94c5:	55                                              	push   rbp
  ac94c6:	48 89 e5                                        	mov    rbp,rsp
  ac94c9:	53                                              	push   rbx
  ac94ca:	50                                              	push   rax
  ac94cb:	48 89 fb                                        	mov    rbx,rdi
  ac94ce:	e8 fd dd 87 ff                                  	call   0x3472d0
  ac94d3:	48 8b 35 36 7e 1f 03                            	mov    rsi,QWORD PTR [rip+0x31f7e36]        # 0x3cc1310
  ac94da:	48 89 c7                                        	mov    rdi,rax
  ac94dd:	e8 ce de 87 ff                                  	call   0x3473b0
  ac94e2:	48 89 03                                        	mov    QWORD PTR [rbx],rax
  ac94e5:	31 c0                                           	xor    eax,eax
  ac94e7:	48 83 c4 08                                     	add    rsp,0x8
  ac94eb:	5b                                              	pop    rbx
  ac94ec:	5d                                              	pop    rbp
  ac94ed:	c3                                              	ret
  ac94ee:	b8 01 00 3b 80                                  	mov    eax,0x803b0001
  ac94f3:	c3                                              	ret
  ac94f4:	90                                              	nop
  ac94f5:	90                                              	nop
  ac94f6:	90                                              	nop
  ac94f7:	90                                              	nop
  ac94f8:	90                                              	nop
  ac94f9:	90                                              	nop
  ac94fa:	90                                              	nop
  ac94fb:	90                                              	nop
  ac94fc:	90                                              	nop
  ac94fd:	90                                              	nop
  ac94fe:	90                                              	nop
  ac94ff:	90                                              	nop
  ac9500:	b8 01 00 3b 80                                  	mov    eax,0x803b0001
  ac9505:	83 fe 01                                        	cmp    esi,0x1
  ac9508:	77 46                                           	ja     0xac9550
  ac950a:	55                                              	push   rbp
  ac950b:	48 89 e5                                        	mov    rbp,rsp
  ac950e:	53                                              	push   rbx
  ac950f:	50                                              	push   rax
  ac9510:	89 f3                                           	mov    ebx,esi
  ac9512:	48 8d 35 17 7d 1f 03                            	lea    rsi,[rip+0x31f7d17]        # 0x3cc1230
  ac9519:	ba 10 00 00 00                                  	mov    edx,0x10
  ac951e:	e8 6d e3 8d ff                                  	call   0x3a7890
  ac9523:	48 85 c0                                        	test   rax,rax
  ac9526:	74 16                                           	je     0xac953e
  ac9528:	48 8b 80 98 01 00 00                            	mov    rax,QWORD PTR [rax+0x198]
  ac952f:	48 85 c0                                        	test   rax,rax
  ac9532:	74 11                                           	je     0xac9545
  ac9534:	89 98 40 27 00 00                               	mov    DWORD PTR [rax+0x2740],ebx
  ac953a:	31 c0                                           	xor    eax,eax
  ac953c:	eb 0c                                           	jmp    0xac954a
  ac953e:	b8 03 00 3b 80                                  	mov    eax,0x803b0003
  ac9543:	eb 05                                           	jmp    0xac954a
  ac9545:	b8 02 00 3b 80                                  	mov    eax,0x803b0002
  ac954a:	48 83 c4 08                                     	add    rsp,0x8
  ac954e:	5b                                              	pop    rbx
  ac954f:	5d                                              	pop    rbp
  ac9550:	c3                                              	ret
  ac9551:	90                                              	nop
  ac9552:	90                                              	nop
  ac9553:	90                                              	nop
  ac9554:	90                                              	nop
  ac9555:	90                                              	nop
  ac9556:	90                                              	nop
  ac9557:	90                                              	nop
  ac9558:	90                                              	nop
  ac9559:	90                                              	nop
  ac955a:	90                                              	nop
  ac955b:	90                                              	nop
  ac955c:	90                                              	nop
  ac955d:	90                                              	nop
  ac955e:	90                                              	nop
  ac955f:	90                                              	nop
  ac9560:	b8 01 00 3b 80                                  	mov    eax,0x803b0001
  ac9565:	83 fe 08                                        	cmp    esi,0x8
  ac9568:	77 46                                           	ja     0xac95b0
  ac956a:	55                                              	push   rbp
  ac956b:	48 89 e5                                        	mov    rbp,rsp
  ac956e:	53                                              	push   rbx
  ac956f:	50                                              	push   rax
  ac9570:	89 f3                                           	mov    ebx,esi
  ac9572:	48 8d 35 b7 7c 1f 03                            	lea    rsi,[rip+0x31f7cb7]        # 0x3cc1230
  ac9579:	ba 10 00 00 00                                  	mov    edx,0x10
  ac957e:	e8 0d e3 8d ff                                  	call   0x3a7890
  ac9583:	48 85 c0                                        	test   rax,rax
  ac9586:	74 16                                           	je     0xac959e
  ac9588:	48 8b 80 98 01 00 00                            	mov    rax,QWORD PTR [rax+0x198]
  ac958f:	48 85 c0                                        	test   rax,rax
  ac9592:	74 11                                           	je     0xac95a5
  ac9594:	89 98 44 27 00 00                               	mov    DWORD PTR [rax+0x2744],ebx
  ac959a:	31 c0                                           	xor    eax,eax
  ac959c:	eb 0c                                           	jmp    0xac95aa
  ac959e:	b8 03 00 3b 80                                  	mov    eax,0x803b0003
  ac95a3:	eb 05                                           	jmp    0xac95aa
  ac95a5:	b8 02 00 3b 80                                  	mov    eax,0x803b0002
  ac95aa:	48 83 c4 08                                     	add    rsp,0x8
  ac95ae:	5b                                              	pop    rbx
  ac95af:	5d                                              	pop    rbp
  ac95b0:	c3                                              	ret
  ac95b1:	90                                              	nop
  ac95b2:	90                                              	nop
  ac95b3:	90                                              	nop
  ac95b4:	90                                              	nop
  ac95b5:	90                                              	nop
  ac95b6:	90                                              	nop
  ac95b7:	90                                              	nop
  ac95b8:	90                                              	nop
  ac95b9:	90                                              	nop
  ac95ba:	90                                              	nop
  ac95bb:	90                                              	nop
  ac95bc:	90                                              	nop
  ac95bd:	90                                              	nop
  ac95be:	90                                              	nop
  ac95bf:	90                                              	nop
  ac95c0:	55                                              	push   rbp
  ac95c1:	48 89 e5                                        	mov    rbp,rsp
  ac95c4:	41 56                                           	push   r14
  ac95c6:	53                                              	push   rbx
  ac95c7:	48 89 f3                                        	mov    rbx,rsi
  ac95ca:	48 8d 35 5f 7c 1f 03                            	lea    rsi,[rip+0x31f7c5f]        # 0x3cc1230
  ac95d1:	ba 10 00 00 00                                  	mov    edx,0x10
  ac95d6:	e8 b5 e2 8d ff                                  	call   0x3a7890
  ac95db:	48 85 c0                                        	test   rax,rax
  ac95de:	74 1f                                           	je     0xac95ff
  ac95e0:	48 85 db                                        	test   rbx,rbx
  ac95e3:	74 21                                           	je     0xac9606
  ac95e5:	49 89 c6                                        	mov    r14,rax
  ac95e8:	e8 e3 dc 87 ff                                  	call   0x3472d0
  ac95ed:	48 89 03                                        	mov    QWORD PTR [rbx],rax
  ac95f0:	4c 89 f7                                        	mov    rdi,r14
  ac95f3:	48 89 de                                        	mov    rsi,rbx
  ac95f6:	5b                                              	pop    rbx
  ac95f7:	41 5e                                           	pop    r14
  ac95f9:	5d                                              	pop    rbp
  ac95fa:	e9 11 00 00 00                                  	jmp    0xac9610
  ac95ff:	b8 03 00 3b 80                                  	mov    eax,0x803b0003
  ac9604:	eb 05                                           	jmp    0xac960b
  ac9606:	b8 01 00 3b 80                                  	mov    eax,0x803b0001
  ac960b:	5b                                              	pop    rbx
  ac960c:	41 5e                                           	pop    r14
  ac960e:	5d                                              	pop    rbp
  ac960f:	c3                                              	ret
  ac9610:	55                                              	push   rbp
  ac9611:	48 89 e5                                        	mov    rbp,rsp
  ac9614:	41 57                                           	push   r15
  ac9616:	41 56                                           	push   r14
  ac9618:	41 55                                           	push   r13
  ac961a:	41 54                                           	push   r12
  ac961c:	53                                              	push   rbx
  ac961d:	50                                              	push   rax
  ac961e:	49 89 f4                                        	mov    r12,rsi
  ac9621:	48 89 fb                                        	mov    rbx,rdi
  ac9624:	e8 67 db 87 ff                                  	call   0x347190
  ac9629:	85 c0                                           	test   eax,eax
  ac962b:	0f 85 bd 02 00 00                               	jne    0xac98ee
  ac9631:	4c 8b b3 98 01 00 00                            	mov    r14,QWORD PTR [rbx+0x198]
  ac9638:	4d 85 f6                                        	test   r14,r14
  ac963b:	0f 84 a1 02 00 00                               	je     0xac98e2
  ac9641:	48 63 83 04 01 00 00                            	movsxd rax,DWORD PTR [rbx+0x104]
  ac9648:	be 98 00 00 00                                  	mov    esi,0x98
  ac964d:	4c 69 e8 98 00 00 00                            	imul   r13,rax,0x98
  ac9654:	4f 8d bc 2e 90 00 00 00                         	lea    r15,[r14+r13*1+0x90]
  ac965c:	4c 89 ff                                        	mov    rdi,r15
  ac965f:	e8 8c f9 78 ff                                  	call   0x258ff0
  ac9664:	4c 89 e6                                        	mov    rsi,r12
  ac9667:	b9 0a 00 00 00                                  	mov    ecx,0xa
  ac966c:	4c 89 ff                                        	mov    rdi,r15
  ac966f:	41 bc 01 00 00 00                               	mov    r12d,0x1
  ac9675:	f3 48 a5                                        	rep movs QWORD PTR [rdi],QWORD PTR [rsi]
  ac9678:	43 80 bc 2e aa 00 00 00 00                      	cmp    BYTE PTR [r14+r13*1+0xaa],0x0
  ac9681:	75 27                                           	jne    0xac96aa
  ac9683:	41 0f b7 47 16                                  	movzx  eax,WORD PTR [r15+0x16]
  ac9688:	89 c1                                           	mov    ecx,eax
  ac968a:	66 f7 d9                                        	neg    cx
  ac968d:	66 0f 48 c8                                     	cmovs  cx,ax
  ac9691:	66 83 f9 1d                                     	cmp    cx,0x1d
  ac9695:	77 13                                           	ja     0xac96aa
  ac9697:	41 80 7f 1b 00                                  	cmp    BYTE PTR [r15+0x1b],0x0
  ac969c:	75 0c                                           	jne    0xac96aa
  ac969e:	45 31 e4                                        	xor    r12d,r12d
  ac96a1:	41 80 7f 1c 00                                  	cmp    BYTE PTR [r15+0x1c],0x0
  ac96a6:	41 0f 95 c4                                     	setne  r12b
  ac96aa:	48 89 df                                        	mov    rdi,rbx
  ac96ad:	44 89 e6                                        	mov    esi,r12d
  ac96b0:	e8 8b ed 8d ff                                  	call   0x3a8440
  ac96b5:	45 85 e4                                        	test   r12d,r12d
  ac96b8:	74 10                                           	je     0xac96ca
  ac96ba:	83 7b 08 00                                     	cmp    DWORD PTR [rbx+0x8],0x0
  ac96be:	74 0a                                           	je     0xac96ca
  ac96c0:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  ac96c3:	48 89 05 46 7c 1f 03                            	mov    QWORD PTR [rip+0x31f7c46],rax        # 0x3cc1310
  ac96ca:	41 8b 8e 28 27 00 00                            	mov    ecx,DWORD PTR [r14+0x2728]
  ac96d1:	85 c9                                           	test   ecx,ecx
  ac96d3:	0f 84 88 00 00 00                               	je     0xac9761
  ac96d9:	41 0f b6 57 1a                                  	movzx  edx,BYTE PTR [r15+0x1a]
  ac96de:	0f b6 43 18                                     	movzx  eax,BYTE PTR [rbx+0x18]
  ac96e2:	89 d6                                           	mov    esi,edx
  ac96e4:	24 fe                                           	and    al,0xfe
  ac96e6:	40 80 e6 3f                                     	and    sil,0x3f
  ac96ea:	3c 02                                           	cmp    al,0x2
  ac96ec:	40 0f b6 f6                                     	movzx  esi,sil
  ac96f0:	0f 45 f2                                        	cmovne esi,edx
  ac96f3:	40 84 f6                                        	test   sil,sil
  ac96f6:	74 35                                           	je     0xac972d
  ac96f8:	48 63 93 00 01 00 00                            	movsxd rdx,DWORD PTR [rbx+0x100]
  ac96ff:	3b 93 04 01 00 00                               	cmp    edx,DWORD PTR [rbx+0x104]
  ac9705:	74 26                                           	je     0xac972d
  ac9707:	48 69 d2 98 00 00 00                            	imul   rdx,rdx,0x98
  ac970e:	49 8d b6 90 00 00 00                            	lea    rsi,[r14+0x90]
  ac9715:	0f b6 54 16 1a                                  	movzx  edx,BYTE PTR [rsi+rdx*1+0x1a]
  ac971a:	89 d6                                           	mov    esi,edx
  ac971c:	40 80 e6 3f                                     	and    sil,0x3f
  ac9720:	3c 02                                           	cmp    al,0x2
  ac9722:	40 0f b6 c6                                     	movzx  eax,sil
  ac9726:	0f 45 c2                                        	cmovne eax,edx
  ac9729:	84 c0                                           	test   al,al
  ac972b:	75 36                                           	jne    0xac9763
  ac972d:	8b 05 d1 7b 1f 03                               	mov    eax,DWORD PTR [rip+0x31f7bd1]        # 0x3cc1304
  ac9733:	41 89 86 3c 27 00 00                            	mov    DWORD PTR [r14+0x273c],eax
  ac973a:	48 8b 05 bb 7b 1f 03                            	mov    rax,QWORD PTR [rip+0x31f7bbb]        # 0x3cc12fc
  ac9741:	49 89 86 34 27 00 00                            	mov    QWORD PTR [r14+0x2734],rax
  ac9748:	48 8b 05 a5 7b 1f 03                            	mov    rax,QWORD PTR [rip+0x31f7ba5]        # 0x3cc12f4
  ac974f:	49 89 86 2c 27 00 00                            	mov    QWORD PTR [r14+0x272c],rax
  ac9756:	41 c7 86 28 27 00 00 00 00 00 00                	mov    DWORD PTR [r14+0x2728],0x0
  ac9761:	31 c9                                           	xor    ecx,ecx
  ac9763:	49 81 c6 2c 27 00 00                            	add    r14,0x272c
  ac976a:	49 83 c7 50                                     	add    r15,0x50
  ac976e:	48 8d 3d 7f 7b 1f 03                            	lea    rdi,[rip+0x31f7b7f]        # 0x3cc12f4
  ac9775:	4c 89 f6                                        	mov    rsi,r14
  ac9778:	4c 89 fa                                        	mov    rdx,r15
  ac977b:	e8 20 eb 8d ff                                  	call   0x3a82a0
  ac9780:	8b 83 04 01 00 00                               	mov    eax,DWORD PTR [rbx+0x104]
  ac9786:	8d 48 01                                        	lea    ecx,[rax+0x1]
  ac9789:	89 83 00 01 00 00                               	mov    DWORD PTR [rbx+0x100],eax
  ac978f:	48 63 c9                                        	movsxd rcx,ecx
  ac9792:	48 69 c9 7f e0 07 7e                            	imul   rcx,rcx,0x7e07e07f
  ac9799:	48 89 ca                                        	mov    rdx,rcx
  ac979c:	48 c1 f9 25                                     	sar    rcx,0x25
  ac97a0:	48 c1 ea 3f                                     	shr    rdx,0x3f
  ac97a4:	01 d1                                           	add    ecx,edx
  ac97a6:	89 ca                                           	mov    edx,ecx
  ac97a8:	c1 e2 06                                        	shl    edx,0x6
  ac97ab:	01 ca                                           	add    edx,ecx
  ac97ad:	f7 da                                           	neg    edx
  ac97af:	8d 44 10 01                                     	lea    eax,[rax+rdx*1+0x1]
  ac97b3:	89 83 04 01 00 00                               	mov    DWORD PTR [rbx+0x104],eax
  ac97b9:	3b 83 08 01 00 00                               	cmp    eax,DWORD PTR [rbx+0x108]
  ac97bf:	75 2c                                           	jne    0xac97ed
  ac97c1:	fe c0                                           	inc    al
  ac97c3:	0f be c0                                        	movsx  eax,al
  ac97c6:	89 c1                                           	mov    ecx,eax
  ac97c8:	c1 e1 07                                        	shl    ecx,0x7
  ac97cb:	29 c1                                           	sub    ecx,eax
  ac97cd:	0f b7 d1                                        	movzx  edx,cx
  ac97d0:	c1 e9 0d                                        	shr    ecx,0xd
  ac97d3:	c1 ea 0f                                        	shr    edx,0xf
  ac97d6:	00 ca                                           	add    dl,cl
  ac97d8:	0f b6 ca                                        	movzx  ecx,dl
  ac97db:	89 ca                                           	mov    edx,ecx
  ac97dd:	c1 e2 06                                        	shl    edx,0x6
  ac97e0:	01 ca                                           	add    edx,ecx
  ac97e2:	28 d0                                           	sub    al,dl
  ac97e4:	0f be c0                                        	movsx  eax,al
  ac97e7:	89 83 08 01 00 00                               	mov    DWORD PTR [rbx+0x108],eax
  ac97ed:	31 c0                                           	xor    eax,eax
  ac97ef:	eb 1c                                           	jmp    0xac980d
  ac97f1:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ac9800:	48 ff c0                                        	inc    rax
  ac9803:	48 83 f8 10                                     	cmp    rax,0x10
  ac9807:	0f 84 d1 00 00 00                               	je     0xac98de
  ac980d:	48 8b 8c c3 10 01 00 00                         	mov    rcx,QWORD PTR [rbx+rax*8+0x110]
  ac9815:	48 85 c9                                        	test   rcx,rcx
  ac9818:	74 e6                                           	je     0xac9800
  ac981a:	8b 93 04 01 00 00                               	mov    edx,DWORD PTR [rbx+0x104]
  ac9820:	3b 51 18                                        	cmp    edx,DWORD PTR [rcx+0x18]
  ac9823:	74 1b                                           	je     0xac9840
  ac9825:	3b 51 1c                                        	cmp    edx,DWORD PTR [rcx+0x1c]
  ac9828:	74 4e                                           	je     0xac9878
  ac982a:	3b 51 20                                        	cmp    edx,DWORD PTR [rcx+0x20]
  ac982d:	75 d1                                           	jne    0xac9800
  ac982f:	e9 80 00 00 00                                  	jmp    0xac98b4
  ac9834:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ac9840:	ff c2                                           	inc    edx
  ac9842:	48 63 d2                                        	movsxd rdx,edx
  ac9845:	48 69 f2 7f e0 07 7e                            	imul   rsi,rdx,0x7e07e07f
  ac984c:	48 89 f7                                        	mov    rdi,rsi
  ac984f:	48 c1 fe 25                                     	sar    rsi,0x25
  ac9853:	48 c1 ef 3f                                     	shr    rdi,0x3f
  ac9857:	01 fe                                           	add    esi,edi
  ac9859:	89 f7                                           	mov    edi,esi
  ac985b:	c1 e7 06                                        	shl    edi,0x6
  ac985e:	01 f7                                           	add    edi,esi
  ac9860:	29 fa                                           	sub    edx,edi
  ac9862:	89 51 18                                        	mov    DWORD PTR [rcx+0x18],edx
  ac9865:	8b 93 04 01 00 00                               	mov    edx,DWORD PTR [rbx+0x104]
  ac986b:	48 8b 8c c3 10 01 00 00                         	mov    rcx,QWORD PTR [rbx+rax*8+0x110]
  ac9873:	3b 51 1c                                        	cmp    edx,DWORD PTR [rcx+0x1c]
  ac9876:	75 b2                                           	jne    0xac982a
  ac9878:	ff c2                                           	inc    edx
  ac987a:	48 63 d2                                        	movsxd rdx,edx
  ac987d:	48 69 f2 7f e0 07 7e                            	imul   rsi,rdx,0x7e07e07f
  ac9884:	48 89 f7                                        	mov    rdi,rsi
  ac9887:	48 c1 fe 25                                     	sar    rsi,0x25
  ac988b:	48 c1 ef 3f                                     	shr    rdi,0x3f
  ac988f:	01 fe                                           	add    esi,edi
  ac9891:	89 f7                                           	mov    edi,esi
  ac9893:	c1 e7 06                                        	shl    edi,0x6
  ac9896:	01 f7                                           	add    edi,esi
  ac9898:	29 fa                                           	sub    edx,edi
  ac989a:	89 51 1c                                        	mov    DWORD PTR [rcx+0x1c],edx
  ac989d:	8b 93 04 01 00 00                               	mov    edx,DWORD PTR [rbx+0x104]
  ac98a3:	48 8b 8c c3 10 01 00 00                         	mov    rcx,QWORD PTR [rbx+rax*8+0x110]
  ac98ab:	3b 51 20                                        	cmp    edx,DWORD PTR [rcx+0x20]
  ac98ae:	0f 85 4c ff ff ff                               	jne    0xac9800
  ac98b4:	ff c2                                           	inc    edx
  ac98b6:	48 63 d2                                        	movsxd rdx,edx
  ac98b9:	48 69 f2 7f e0 07 7e                            	imul   rsi,rdx,0x7e07e07f
  ac98c0:	48 89 f7                                        	mov    rdi,rsi
  ac98c3:	48 c1 fe 25                                     	sar    rsi,0x25
  ac98c7:	48 c1 ef 3f                                     	shr    rdi,0x3f
  ac98cb:	01 fe                                           	add    esi,edi
  ac98cd:	89 f7                                           	mov    edi,esi
  ac98cf:	c1 e7 06                                        	shl    edi,0x6
  ac98d2:	01 f7                                           	add    edi,esi
  ac98d4:	29 fa                                           	sub    edx,edi
  ac98d6:	89 51 20                                        	mov    DWORD PTR [rcx+0x20],edx
  ac98d9:	e9 22 ff ff ff                                  	jmp    0xac9800
  ac98de:	31 db                                           	xor    ebx,ebx
  ac98e0:	eb 05                                           	jmp    0xac98e7
  ac98e2:	bb 03 00 3b 80                                  	mov    ebx,0x803b0003
  ac98e7:	e8 f4 d8 87 ff                                  	call   0x3471e0
  ac98ec:	89 d8                                           	mov    eax,ebx
  ac98ee:	48 83 c4 08                                     	add    rsp,0x8
  ac98f2:	5b                                              	pop    rbx
  ac98f3:	41 5c                                           	pop    r12
  ac98f5:	41 5d                                           	pop    r13
  ac98f7:	41 5e                                           	pop    r14
  ac98f9:	41 5f                                           	pop    r15
  ac98fb:	5d                                              	pop    rbp
  ac98fc:	c3                                              	ret
  ac98fd:	90                                              	nop
  ac98fe:	90                                              	nop
  ac98ff:	90                                              	nop
  ac9900:	55                                              	push   rbp
  ac9901:	48 89 e5                                        	mov    rbp,rsp
  ac9904:	41 57                                           	push   r15
  ac9906:	41 56                                           	push   r14
  ac9908:	53                                              	push   rbx
  ac9909:	50                                              	push   rax
  ac990a:	41 89 d6                                        	mov    r14d,edx
  ac990d:	89 f3                                           	mov    ebx,esi
  ac990f:	48 8d 35 1a 79 1f 03                            	lea    rsi,[rip+0x31f791a]        # 0x3cc1230
  ac9916:	ba 10 00 00 00                                  	mov    edx,0x10
  ac991b:	41 89 cf                                        	mov    r15d,ecx
  ac991e:	e8 6d df 8d ff                                  	call   0x3a7890
  ac9923:	48 89 c1                                        	mov    rcx,rax
  ac9926:	b8 03 00 3b 80                                  	mov    eax,0x803b0003
  ac992b:	48 85 c9                                        	test   rcx,rcx
  ac992e:	74 24                                           	je     0xac9954
  ac9930:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac9937:	48 85 c9                                        	test   rcx,rcx
  ac993a:	74 18                                           	je     0xac9954
  ac993c:	45 85 ff                                        	test   r15d,r15d
  ac993f:	74 0b                                           	je     0xac994c
  ac9941:	31 c0                                           	xor    eax,eax
  ac9943:	44 3b b1 30 27 00 00                            	cmp    r14d,DWORD PTR [rcx+0x2730]
  ac994a:	75 08                                           	jne    0xac9954
  ac994c:	31 c0                                           	xor    eax,eax
  ac994e:	89 99 48 27 00 00                               	mov    DWORD PTR [rcx+0x2748],ebx
  ac9954:	48 83 c4 08                                     	add    rsp,0x8
  ac9958:	5b                                              	pop    rbx
  ac9959:	41 5e                                           	pop    r14
  ac995b:	41 5f                                           	pop    r15
  ac995d:	5d                                              	pop    rbp
  ac995e:	c3                                              	ret
  ac995f:	90                                              	nop
  ac9960:	55                                              	push   rbp
  ac9961:	48 89 e5                                        	mov    rbp,rsp
  ac9964:	53                                              	push   rbx
  ac9965:	50                                              	push   rax
  ac9966:	48 89 f3                                        	mov    rbx,rsi
  ac9969:	48 8d 35 c0 78 1f 03                            	lea    rsi,[rip+0x31f78c0]        # 0x3cc1230
  ac9970:	ba 10 00 00 00                                  	mov    edx,0x10
  ac9975:	e8 16 df 8d ff                                  	call   0x3a7890
  ac997a:	48 89 c1                                        	mov    rcx,rax
  ac997d:	b8 03 00 3b 80                                  	mov    eax,0x803b0003
  ac9982:	48 85 c9                                        	test   rcx,rcx
  ac9985:	74 1b                                           	je     0xac99a2
  ac9987:	48 8b 89 98 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x198]
  ac998e:	48 85 c9                                        	test   rcx,rcx
  ac9991:	74 0f                                           	je     0xac99a2
  ac9993:	31 c0                                           	xor    eax,eax
  ac9995:	48 85 db                                        	test   rbx,rbx
  ac9998:	74 08                                           	je     0xac99a2
  ac999a:	8b 89 48 27 00 00                               	mov    ecx,DWORD PTR [rcx+0x2748]
  ac99a0:	89 0b                                           	mov    DWORD PTR [rbx],ecx
  ac99a2:	48 83 c4 08                                     	add    rsp,0x8
  ac99a6:	5b                                              	pop    rbx
  ac99a7:	5d                                              	pop    rbp
  ac99a8:	c3                                              	ret
  ac99a9:	90                                              	nop
  ac99aa:	90                                              	nop
  ac99ab:	90                                              	nop
  ac99ac:	90                                              	nop
  ac99ad:	90                                              	nop
  ac99ae:	90                                              	nop
  ac99af:	90                                              	nop
  ac99b0:	48 85 ff                                        	test   rdi,rdi
  ac99b3:	74 4f                                           	je     0xac9a04
  ac99b5:	55                                              	push   rbp
  ac99b6:	48 89 e5                                        	mov    rbp,rsp
  ac99b9:	48 8d 15 70 78 1f 03                            	lea    rdx,[rip+0x31f7870]        # 0x3cc1230
  ac99c0:	c7 07 00 00 00 00                               	mov    DWORD PTR [rdi],0x0
  ac99c6:	31 c9                                           	xor    ecx,ecx
  ac99c8:	31 f6                                           	xor    esi,esi
  ac99ca:	eb 11                                           	jmp    0xac99dd
  ac99cc:	0f 1f 40 00                                     	nop    DWORD PTR [rax+0x0]
  ac99d0:	48 83 f9 0e                                     	cmp    rcx,0xe
  ac99d4:	77 34                                           	ja     0xac9a0a
  ac99d6:	48 ff c1                                        	inc    rcx
  ac99d9:	48 83 c2 08                                     	add    rdx,0x8
  ac99dd:	48 8b 02                                        	mov    rax,QWORD PTR [rdx]
  ac99e0:	48 85 c0                                        	test   rax,rax
  ac99e3:	74 eb                                           	je     0xac99d0
  ac99e5:	8b 40 04                                        	mov    eax,DWORD PTR [rax+0x4]
  ac99e8:	48 63 f6                                        	movsxd rsi,esi
  ac99eb:	89 44 b7 04                                     	mov    DWORD PTR [rdi+rsi*4+0x4],eax
  ac99ef:	31 c0                                           	xor    eax,eax
  ac99f1:	8b 37                                           	mov    esi,DWORD PTR [rdi]
  ac99f3:	ff c6                                           	inc    esi
  ac99f5:	89 37                                           	mov    DWORD PTR [rdi],esi
  ac99f7:	48 83 f9 0e                                     	cmp    rcx,0xe
  ac99fb:	77 05                                           	ja     0xac9a02
  ac99fd:	83 fe 10                                        	cmp    esi,0x10
  ac9a00:	75 d4                                           	jne    0xac99d6
  ac9a02:	5d                                              	pop    rbp
  ac9a03:	c3                                              	ret
  ac9a04:	b8 01 00 3b 80                                  	mov    eax,0x803b0001
  ac9a09:	c3                                              	ret
  ac9a0a:	31 c0                                           	xor    eax,eax
  ac9a0c:	5d                                              	pop    rbp
  ac9a0d:	c3                                              	ret
  ac9a0e:	90                                              	nop
  ac9a0f:	90                                              	nop
  ac9a10:	55                                              	push   rbp
  ac9a11:	48 89 e5                                        	mov    rbp,rsp
  ac9a14:	53                                              	push   rbx
  ac9a15:	50                                              	push   rax
  ac9a16:	48 89 fb                                        	mov    rbx,rdi
  ac9a19:	e8 02 fe bf ff                                  	call   0x6c9820
  ac9a1e:	31 c9                                           	xor    ecx,ecx
  ac9a20:	48 85 c0                                        	test   rax,rax
  ac9a23:	48 89 03                                        	mov    QWORD PTR [rbx],rax
  ac9a26:	0f 95 c1                                        	setne  cl
  ac9a29:	89 c8                                           	mov    eax,ecx
  ac9a2b:	48 83 c4 08                                     	add    rsp,0x8
  ac9a2f:	5b                                              	pop    rbx
  ac9a30:	5d                                              	pop    rbp
  ac9a31:	c3                                              	ret
  ac9a32:	90                                              	nop
  ac9a33:	90                                              	nop
  ac9a34:	90                                              	nop
  ac9a35:	90                                              	nop
  ac9a36:	90                                              	nop
  ac9a37:	90                                              	nop
  ac9a38:	90                                              	nop
  ac9a39:	90                                              	nop
  ac9a3a:	90                                              	nop
  ac9a3b:	90                                              	nop
  ac9a3c:	90                                              	nop
  ac9a3d:	90                                              	nop
  ac9a3e:	90                                              	nop
  ac9a3f:	90                                              	nop
  ac9a40:	55                                              	push   rbp
  ac9a41:	48 89 e5                                        	mov    rbp,rsp
  ac9a44:	53                                              	push   rbx
  ac9a45:	50                                              	push   rax
  ac9a46:	48 89 fb                                        	mov    rbx,rdi
  ac9a49:	48 8b 3f                                        	mov    rdi,QWORD PTR [rdi]
  ac9a4c:	48 85 ff                                        	test   rdi,rdi
  ac9a4f:	74 0c                                           	je     0xac9a5d
  ac9a51:	e8 fa fc bf ff                                  	call   0x6c9750
  ac9a56:	48 c7 03 00 00 00 00                            	mov    QWORD PTR [rbx],0x0
  ac9a5d:	48 83 c4 08                                     	add    rsp,0x8
  ac9a61:	5b                                              	pop    rbx
  ac9a62:	5d                                              	pop    rbp
  ac9a63:	c3                                              	ret
  ac9a64:	90                                              	nop
  ac9a65:	90                                              	nop
  ac9a66:	90                                              	nop
  ac9a67:	90                                              	nop
  ac9a68:	90                                              	nop
  ac9a69:	90                                              	nop
  ac9a6a:	90                                              	nop
  ac9a6b:	90                                              	nop
  ac9a6c:	90                                              	nop
  ac9a6d:	90                                              	nop
  ac9a6e:	90                                              	nop
  ac9a6f:	90                                              	nop
  ac9a70:	55                                              	push   rbp
  ac9a71:	48 89 e5                                        	mov    rbp,rsp
  ac9a74:	41 57                                           	push   r15
  ac9a76:	41 56                                           	push   r14
  ac9a78:	53                                              	push   rbx
  ac9a79:	50                                              	push   rax
  ac9a7a:	41 89 d6                                        	mov    r14d,edx
  ac9a7d:	48 8b 17                                        	mov    rdx,QWORD PTR [rdi]
  ac9a80:	49 89 f7                                        	mov    r15,rsi
  ac9a83:	48 89 fb                                        	mov    rbx,rdi
  ac9a86:	48 85 d2                                        	test   rdx,rdx
  ac9a89:	75 10                                           	jne    0xac9a9b
  ac9a8b:	e8 90 fd bf ff                                  	call   0x6c9820
  ac9a90:	48 89 c2                                        	mov    rdx,rax
  ac9a93:	48 89 03                                        	mov    QWORD PTR [rbx],rax
  ac9a96:	48 85 c0                                        	test   rax,rax
  ac9a99:	74 32                                           	je     0xac9acd
  ac9a9b:	4c 89 ff                                        	mov    rdi,r15
  ac9a9e:	44 89 f6                                        	mov    esi,r14d
  ac9aa1:	e8 aa 01 c0 ff                                  	call   0x6c9c50
  ac9aa6:	48 89 c1                                        	mov    rcx,rax
  ac9aa9:	b8 01 00 00 00                                  	mov    eax,0x1
  ac9aae:	48 85 c9                                        	test   rcx,rcx
  ac9ab1:	75 1c                                           	jne    0xac9acf
  ac9ab3:	48 8b 3b                                        	mov    rdi,QWORD PTR [rbx]
  ac9ab6:	31 c0                                           	xor    eax,eax
  ac9ab8:	48 85 ff                                        	test   rdi,rdi
  ac9abb:	74 12                                           	je     0xac9acf
  ac9abd:	e8 8e fc bf ff                                  	call   0x6c9750
  ac9ac2:	31 c0                                           	xor    eax,eax
  ac9ac4:	48 c7 03 00 00 00 00                            	mov    QWORD PTR [rbx],0x0
  ac9acb:	eb 02                                           	jmp    0xac9acf
  ac9acd:	31 c0                                           	xor    eax,eax
  ac9acf:	48 83 c4 08                                     	add    rsp,0x8
  ac9ad3:	5b                                              	pop    rbx
  ac9ad4:	41 5e                                           	pop    r14
  ac9ad6:	41 5f                                           	pop    r15
  ac9ad8:	5d                                              	pop    rbp
  ac9ad9:	c3                                              	ret
  ac9ada:	90                                              	nop
  ac9adb:	90                                              	nop
  ac9adc:	90                                              	nop
  ac9add:	90                                              	nop
  ac9ade:	90                                              	nop
  ac9adf:	90                                              	nop
  ac9ae0:	55                                              	push   rbp
  ac9ae1:	48 89 e5                                        	mov    rbp,rsp
  ac9ae4:	41 57                                           	push   r15
  ac9ae6:	41 56                                           	push   r14
  ac9ae8:	53                                              	push   rbx
  ac9ae9:	50                                              	push   rax
  ac9aea:	4c 8b 37                                        	mov    r14,QWORD PTR [rdi]
  ac9aed:	4d 85 f6                                        	test   r14,r14
  ac9af0:	74 30                                           	je     0xac9b22
  ac9af2:	4c 89 f7                                        	mov    rdi,r14
  ac9af5:	48 89 f3                                        	mov    rbx,rsi
  ac9af8:	e8 63 fb bf ff                                  	call   0x6c9660
  ac9afd:	45 31 ff                                        	xor    r15d,r15d
  ac9b00:	a8 07                                           	test   al,0x7
  ac9b02:	41 0f 94 c7                                     	sete   r15b
  ac9b06:	48 85 db                                        	test   rbx,rbx
  ac9b09:	74 1e                                           	je     0xac9b29
  ac9b0b:	a8 07                                           	test   al,0x7
  ac9b0d:	75 06                                           	jne    0xac9b15
  ac9b0f:	c6 03 00                                        	mov    BYTE PTR [rbx],0x0
  ac9b12:	48 ff c3                                        	inc    rbx
  ac9b15:	4c 89 f7                                        	mov    rdi,r14
  ac9b18:	48 89 de                                        	mov    rsi,rbx
  ac9b1b:	e8 10 03 c0 ff                                  	call   0x6c9e30
  ac9b20:	eb 1d                                           	jmp    0xac9b3f
  ac9b22:	b8 ff ff ff ff                                  	mov    eax,0xffffffff
  ac9b27:	eb 19                                           	jmp    0xac9b42
  ac9b29:	4c 89 f7                                        	mov    rdi,r14
  ac9b2c:	e8 2f fb bf ff                                  	call   0x6c9660
  ac9b31:	8d 48 07                                        	lea    ecx,[rax+0x7]
  ac9b34:	83 c0 0e                                        	add    eax,0xe
  ac9b37:	85 c9                                           	test   ecx,ecx
  ac9b39:	0f 49 c1                                        	cmovns eax,ecx
  ac9b3c:	c1 f8 03                                        	sar    eax,0x3
  ac9b3f:	44 01 f8                                        	add    eax,r15d
  ac9b42:	48 83 c4 08                                     	add    rsp,0x8
  ac9b46:	5b                                              	pop    rbx
  ac9b47:	41 5e                                           	pop    r14
  ac9b49:	41 5f                                           	pop    r15
  ac9b4b:	5d                                              	pop    rbp
  ac9b4c:	c3                                              	ret
  ac9b4d:	90                                              	nop
  ac9b4e:	90                                              	nop
  ac9b4f:	90                                              	nop
  ac9b50:	55                                              	push   rbp
  ac9b51:	48 89 e5                                        	mov    rbp,rsp
  ac9b54:	41 57                                           	push   r15
  ac9b56:	41 56                                           	push   r14
  ac9b58:	41 55                                           	push   r13
  ac9b5a:	41 54                                           	push   r12
  ac9b5c:	53                                              	push   rbx
  ac9b5d:	50                                              	push   rax
  ac9b5e:	44 8b b6 bc 00 00 00                            	mov    r14d,DWORD PTR [rsi+0xbc]
  ac9b65:	49 89 f4                                        	mov    r12,rsi
  ac9b68:	48 89 fb                                        	mov    rbx,rdi
  ac9b6b:	be a4 00 00 00                                  	mov    esi,0xa4
  ac9b70:	44 89 b7 90 00 00 00                            	mov    DWORD PTR [rdi+0x90],r14d
  ac9b77:	bf 14 00 00 00                                  	mov    edi,0x14
  ac9b7c:	e8 3f 16 0b 00                                  	call   0xb7b1c0
  ac9b81:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  ac9b85:	8b 8b 88 00 00 00                               	mov    ecx,DWORD PTR [rbx+0x88]
  ac9b8b:	4c 8d 7b 10                                     	lea    r15,[rbx+0x10]
  ac9b8f:	4c 89 e7                                        	mov    rdi,r12
  ac9b92:	41 b8 10 00 00 00                               	mov    r8d,0x10
  ac9b98:	4c 89 fe                                        	mov    rsi,r15
  ac9b9b:	48 63 90 3c 0a 02 00                            	movsxd rdx,DWORD PTR [rax+0x20a3c]
  ac9ba2:	e8 29 62 12 00                                  	call   0xbefdd0
  ac9ba7:	bf 14 00 00 00                                  	mov    edi,0x14
  ac9bac:	be a6 00 00 00                                  	mov    esi,0xa6
  ac9bb1:	41 89 c5                                        	mov    r13d,eax
  ac9bb4:	e8 27 16 0b 00                                  	call   0xb7b1e0
  ac9bb9:	45 85 ed                                        	test   r13d,r13d
  ac9bbc:	0f 85 47 01 00 00                               	jne    0xac9d09
  ac9bc2:	83 7b 7c 00                                     	cmp    DWORD PTR [rbx+0x7c],0x0
  ac9bc6:	0f 84 81 00 00 00                               	je     0xac9c4d
  ac9bcc:	bf 14 00 00 00                                  	mov    edi,0x14
  ac9bd1:	be ad 00 00 00                                  	mov    esi,0xad
  ac9bd6:	e8 e5 15 0b 00                                  	call   0xb7b1c0
  ac9bdb:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  ac9bdf:	8b 8b 88 00 00 00                               	mov    ecx,DWORD PTR [rbx+0x88]
  ac9be5:	48 8d 73 30                                     	lea    rsi,[rbx+0x30]
  ac9be9:	4c 89 e7                                        	mov    rdi,r12
  ac9bec:	41 b8 10 00 00 00                               	mov    r8d,0x10
  ac9bf2:	48 63 90 3c 0a 02 00                            	movsxd rdx,DWORD PTR [rax+0x20a3c]
  ac9bf9:	e8 d2 61 12 00                                  	call   0xbefdd0
  ac9bfe:	bf 14 00 00 00                                  	mov    edi,0x14
  ac9c03:	be af 00 00 00                                  	mov    esi,0xaf
  ac9c08:	41 89 c4                                        	mov    r12d,eax
  ac9c0b:	e8 d0 15 0b 00                                  	call   0xb7b1e0
  ac9c10:	45 85 e4                                        	test   r12d,r12d
  ac9c13:	0f 84 c3 00 00 00                               	je     0xac9cdc
  ac9c19:	bf 14 00 00 00                                  	mov    edi,0x14
  ac9c1e:	be b1 00 00 00                                  	mov    esi,0xb1
  ac9c23:	e8 98 15 0b 00                                  	call   0xb7b1c0
  ac9c28:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  ac9c2c:	44 89 f7                                        	mov    edi,r14d
  ac9c2f:	4c 89 fe                                        	mov    rsi,r15
  ac9c32:	48 63 90 3c 0a 02 00                            	movsxd rdx,DWORD PTR [rax+0x20a3c]
  ac9c39:	e8 82 5f 12 00                                  	call   0xbefbc0
  ac9c3e:	bf 14 00 00 00                                  	mov    edi,0x14
  ac9c43:	be b3 00 00 00                                  	mov    esi,0xb3
  ac9c48:	e9 85 00 00 00                                  	jmp    0xac9cd2
  ac9c4d:	80 bb 80 00 00 00 01                            	cmp    BYTE PTR [rbx+0x80],0x1
  ac9c54:	0f 85 82 00 00 00                               	jne    0xac9cdc
  ac9c5a:	bf 14 00 00 00                                  	mov    edi,0x14
  ac9c5f:	be b7 00 00 00                                  	mov    esi,0xb7
  ac9c64:	e8 57 15 0b 00                                  	call   0xb7b1c0
  ac9c69:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  ac9c6d:	8b 8b 88 00 00 00                               	mov    ecx,DWORD PTR [rbx+0x88]
  ac9c73:	48 8d 73 50                                     	lea    rsi,[rbx+0x50]
  ac9c77:	4c 89 e7                                        	mov    rdi,r12
  ac9c7a:	41 b8 10 00 00 00                               	mov    r8d,0x10
  ac9c80:	48 63 90 48 0a 02 00                            	movsxd rdx,DWORD PTR [rax+0x20a48]
  ac9c87:	e8 44 61 12 00                                  	call   0xbefdd0
  ac9c8c:	bf 14 00 00 00                                  	mov    edi,0x14
  ac9c91:	be b9 00 00 00                                  	mov    esi,0xb9
  ac9c96:	41 89 c4                                        	mov    r12d,eax
  ac9c99:	e8 42 15 0b 00                                  	call   0xb7b1e0
  ac9c9e:	45 85 e4                                        	test   r12d,r12d
  ac9ca1:	74 39                                           	je     0xac9cdc
  ac9ca3:	bf 14 00 00 00                                  	mov    edi,0x14
  ac9ca8:	be bb 00 00 00                                  	mov    esi,0xbb
  ac9cad:	e8 0e 15 0b 00                                  	call   0xb7b1c0
  ac9cb2:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  ac9cb6:	44 89 f7                                        	mov    edi,r14d
  ac9cb9:	4c 89 fe                                        	mov    rsi,r15
  ac9cbc:	48 63 90 3c 0a 02 00                            	movsxd rdx,DWORD PTR [rax+0x20a3c]
  ac9cc3:	e8 f8 5e 12 00                                  	call   0xbefbc0
  ac9cc8:	bf 14 00 00 00                                  	mov    edi,0x14
  ac9ccd:	be bd 00 00 00                                  	mov    esi,0xbd
  ac9cd2:	e8 09 15 0b 00                                  	call   0xb7b1e0
  ac9cd7:	45 89 e5                                        	mov    r13d,r12d
  ac9cda:	eb 2d                                           	jmp    0xac9d09
  ac9cdc:	48 8b 4b 08                                     	mov    rcx,QWORD PTR [rbx+0x8]
  ac9ce0:	45 31 ed                                        	xor    r13d,r13d
  ac9ce3:	80 b9 9a 02 00 00 00                            	cmp    BYTE PTR [rcx+0x29a],0x0
  ac9cea:	74 1d                                           	je     0xac9d09
  ac9cec:	8b 89 b8 02 00 00                               	mov    ecx,DWORD PTR [rcx+0x2b8]
  ac9cf2:	ba ab aa aa aa                                  	mov    edx,0xaaaaaaab
  ac9cf7:	01 c9                                           	add    ecx,ecx
  ac9cf9:	48 0f af d1                                     	imul   rdx,rcx
  ac9cfd:	48 c1 ea 21                                     	shr    rdx,0x21
  ac9d01:	48 03 53 18                                     	add    rdx,QWORD PTR [rbx+0x18]
  ac9d05:	48 89 53 58                                     	mov    QWORD PTR [rbx+0x58],rdx
  ac9d09:	44 89 e8                                        	mov    eax,r13d
  ac9d0c:	48 83 c4 08                                     	add    rsp,0x8
  ac9d10:	5b                                              	pop    rbx
  ac9d11:	41 5c                                           	pop    r12
  ac9d13:	41 5d                                           	pop    r13
  ac9d15:	41 5e                                           	pop    r14
  ac9d17:	41 5f                                           	pop    r15
  ac9d19:	5d                                              	pop    rbp
  ac9d1a:	c3                                              	ret
  ac9d1b:	90                                              	nop
  ac9d1c:	90                                              	nop
  ac9d1d:	90                                              	nop
  ac9d1e:	90                                              	nop
  ac9d1f:	90                                              	nop
  ac9d20:	55                                              	push   rbp
  ac9d21:	48 89 e5                                        	mov    rbp,rsp
  ac9d24:	83 bf 84 00 00 00 0f                            	cmp    DWORD PTR [rdi+0x84],0xf
  ac9d2b:	77 06                                           	ja     0xac9d33
  ac9d2d:	ff 87 9c 00 00 00                               	inc    DWORD PTR [rdi+0x9c]
  ac9d33:	5d                                              	pop    rbp
  ac9d34:	c3                                              	ret
  ac9d35:	90                                              	nop
  ac9d36:	90                                              	nop
  ac9d37:	90                                              	nop
  ac9d38:	90                                              	nop
  ac9d39:	90                                              	nop
  ac9d3a:	90                                              	nop
  ac9d3b:	90                                              	nop
  ac9d3c:	90                                              	nop
  ac9d3d:	90                                              	nop
  ac9d3e:	90                                              	nop
  ac9d3f:	90                                              	nop
  ac9d40:	55                                              	push   rbp
  ac9d41:	48 89 e5                                        	mov    rbp,rsp
  ac9d44:	83 bf 84 00 00 00 0f                            	cmp    DWORD PTR [rdi+0x84],0xf
  ac9d4b:	77 06                                           	ja     0xac9d53
  ac9d4d:	ff 8f 9c 00 00 00                               	dec    DWORD PTR [rdi+0x9c]
  ac9d53:	5d                                              	pop    rbp
  ac9d54:	c3                                              	ret
  ac9d55:	90                                              	nop
  ac9d56:	90                                              	nop
  ac9d57:	90                                              	nop
  ac9d58:	90                                              	nop
  ac9d59:	90                                              	nop
  ac9d5a:	90                                              	nop
  ac9d5b:	90                                              	nop
  ac9d5c:	90                                              	nop
  ac9d5d:	90                                              	nop
  ac9d5e:	90                                              	nop
  ac9d5f:	90                                              	nop
  ac9d60:	55                                              	push   rbp
  ac9d61:	48 89 e5                                        	mov    rbp,rsp
  ac9d64:	83 bf 84 00 00 00 0f                            	cmp    DWORD PTR [rdi+0x84],0xf
  ac9d6b:	77 06                                           	ja     0xac9d73
  ac9d6d:	ff 87 a0 00 00 00                               	inc    DWORD PTR [rdi+0xa0]
  ac9d73:	5d                                              	pop    rbp
  ac9d74:	c3                                              	ret
  ac9d75:	90                                              	nop
  ac9d76:	90                                              	nop
  ac9d77:	90                                              	nop
  ac9d78:	90                                              	nop
  ac9d79:	90                                              	nop
  ac9d7a:	90                                              	nop
  ac9d7b:	90                                              	nop
  ac9d7c:	90                                              	nop
  ac9d7d:	90                                              	nop
  ac9d7e:	90                                              	nop
  ac9d7f:	90                                              	nop
  ac9d80:	55                                              	push   rbp
  ac9d81:	48 89 e5                                        	mov    rbp,rsp
  ac9d84:	48 8b 47 70                                     	mov    rax,QWORD PTR [rdi+0x70]
  ac9d88:	48 c7 00 00 00 00 00                            	mov    QWORD PTR [rax],0x0
  ac9d8f:	5d                                              	pop    rbp
  ac9d90:	c3                                              	ret
  ac9d91:	90                                              	nop
  ac9d92:	90                                              	nop
  ac9d93:	90                                              	nop
  ac9d94:	90                                              	nop
  ac9d95:	90                                              	nop
  ac9d96:	90                                              	nop
  ac9d97:	90                                              	nop
  ac9d98:	90                                              	nop
  ac9d99:	90                                              	nop
  ac9d9a:	90                                              	nop
  ac9d9b:	90                                              	nop
  ac9d9c:	90                                              	nop
  ac9d9d:	90                                              	nop
  ac9d9e:	90                                              	nop
  ac9d9f:	90                                              	nop
  ac9da0:	83 bf 84 00 00 00 0f                            	cmp    DWORD PTR [rdi+0x84],0xf
  ac9da7:	77 10                                           	ja     0xac9db9
  ac9da9:	55                                              	push   rbp
  ac9daa:	48 89 e5                                        	mov    rbp,rsp
  ac9dad:	48 8b 47 70                                     	mov    rax,QWORD PTR [rdi+0x70]
  ac9db1:	48 c7 00 01 00 00 00                            	mov    QWORD PTR [rax],0x1
  ac9db8:	5d                                              	pop    rbp
  ac9db9:	c3                                              	ret
  ac9dba:	90                                              	nop
  ac9dbb:	90                                              	nop
  ac9dbc:	90                                              	nop
  ac9dbd:	90                                              	nop
  ac9dbe:	90                                              	nop
  ac9dbf:	90                                              	nop
  ac9dc0:	83 bf 84 00 00 00 0f                            	cmp    DWORD PTR [rdi+0x84],0xf
  ac9dc7:	77 08                                           	ja     0xac9dd1
  ac9dc9:	ff 8f a0 00 00 00                               	dec    DWORD PTR [rdi+0xa0]
  ac9dcf:	74 01                                           	je     0xac9dd2
  ac9dd1:	c3                                              	ret
  ac9dd2:	55                                              	push   rbp
  ac9dd3:	48 89 e5                                        	mov    rbp,rsp
  ac9dd6:	48 8b 47 70                                     	mov    rax,QWORD PTR [rdi+0x70]
  ac9dda:	48 c7 00 00 00 00 00                            	mov    QWORD PTR [rax],0x0
  ac9de1:	5d                                              	pop    rbp
  ac9de2:	c3                                              	ret
  ac9de3:	90                                              	nop
  ac9de4:	90                                              	nop
  ac9de5:	90                                              	nop
  ac9de6:	90                                              	nop
  ac9de7:	90                                              	nop
  ac9de8:	90                                              	nop
  ac9de9:	90                                              	nop
  ac9dea:	90                                              	nop
  ac9deb:	90                                              	nop
  ac9dec:	90                                              	nop
  ac9ded:	90                                              	nop
  ac9dee:	90                                              	nop
  ac9def:	90                                              	nop
  ac9df0:	55                                              	push   rbp
  ac9df1:	48 89 e5                                        	mov    rbp,rsp
  ac9df4:	89 b7 94 00 00 00                               	mov    DWORD PTR [rdi+0x94],esi
  ac9dfa:	5d                                              	pop    rbp
  ac9dfb:	c3                                              	ret
  ac9dfc:	90                                              	nop
  ac9dfd:	90                                              	nop
  ac9dfe:	90                                              	nop
  ac9dff:	90                                              	nop
  ac9e00:	55                                              	push   rbp
  ac9e01:	48 89 e5                                        	mov    rbp,rsp
  ac9e04:	83 bf 94 00 00 00 01                            	cmp    DWORD PTR [rdi+0x94],0x1
  ac9e0b:	0f 94 c0                                        	sete   al
  ac9e0e:	5d                                              	pop    rbp
  ac9e0f:	c3                                              	ret
  ac9e10:	55                                              	push   rbp
  ac9e11:	48 89 e5                                        	mov    rbp,rsp
  ac9e14:	41 57                                           	push   r15
  ac9e16:	41 56                                           	push   r14
  ac9e18:	41 55                                           	push   r13
  ac9e1a:	41 54                                           	push   r12
  ac9e1c:	53                                              	push   rbx
  ac9e1d:	48 83 ec 18                                     	sub    rsp,0x18
  ac9e21:	4c 8d 25 e8 24 e5 02                            	lea    r12,[rip+0x2e524e8]        # 0x391c310
  ac9e28:	bf 00 c0 04 00                                  	mov    edi,0x4c000
  ac9e2d:	be 14 00 00 00                                  	mov    esi,0x14
  ac9e32:	ba 30 01 00 00                                  	mov    edx,0x130
  ac9e37:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  ac9e3b:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ac9e3f:	e8 5c 65 12 00                                  	call   0xbf03a0
  ac9e44:	48 85 c0                                        	test   rax,rax
  ac9e47:	74 63                                           	je     0xac9eac
  ac9e49:	48 89 c7                                        	mov    rdi,rax
  ac9e4c:	48 89 c3                                        	mov    rbx,rax
  ac9e4f:	e8 dc 44 e1 ff                                  	call   0x8de330
  ac9e54:	4c 8d 45 c8                                     	lea    r8,[rbp-0x38]
  ac9e58:	be 00 c0 04 00                                  	mov    esi,0x4c000
  ac9e5d:	ba 00 40 00 00                                  	mov    edx,0x4000
  ac9e62:	b9 60 01 00 00                                  	mov    ecx,0x160
  ac9e67:	48 89 c7                                        	mov    rdi,rax
  ac9e6a:	49 89 c6                                        	mov    r14,rax
  ac9e6d:	e8 1e f8 f1 ff                                  	call   0x9e9690
  ac9e72:	85 c0                                           	test   eax,eax
  ac9e74:	74 69                                           	je     0xac9edf
  ac9e76:	41 89 c0                                        	mov    r8d,eax
  ac9e79:	48 8d 15 80 26 e1 00                            	lea    rdx,[rip+0xe12680]        # 0x18dc500
  ac9e80:	b9 41 01 00 00                                  	mov    ecx,0x141
  ac9e85:	31 ff                                           	xor    edi,edi
  ac9e87:	31 f6                                           	xor    esi,esi
  ac9e89:	31 c0                                           	xor    eax,eax
  ac9e8b:	e8 40 a6 03 00                                  	call   0xb044d0
  ac9e90:	be 00 c0 04 00                                  	mov    esi,0x4c000
  ac9e95:	48 89 df                                        	mov    rdi,rbx
  ac9e98:	ba 14 00 00 00                                  	mov    edx,0x14
  ac9e9d:	b9 42 01 00 00                                  	mov    ecx,0x142
  ac9ea2:	e8 39 65 12 00                                  	call   0xbf03e0
  ac9ea7:	e9 28 01 00 00                                  	jmp    0xac9fd4
  ac9eac:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  ac9eb0:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ac9eb4:	0f 85 33 01 00 00                               	jne    0xac9fed
  ac9eba:	48 8d 15 25 26 e1 00                            	lea    rdx,[rip+0xe12625]        # 0x18dc4e6
  ac9ec1:	31 ff                                           	xor    edi,edi
  ac9ec3:	31 f6                                           	xor    esi,esi
  ac9ec5:	b9 32 01 00 00                                  	mov    ecx,0x132
  ac9eca:	31 c0                                           	xor    eax,eax
  ac9ecc:	48 83 c4 18                                     	add    rsp,0x18
  ac9ed0:	5b                                              	pop    rbx
  ac9ed1:	41 5c                                           	pop    r12
  ac9ed3:	41 5d                                           	pop    r13
  ac9ed5:	41 5e                                           	pop    r14
  ac9ed7:	41 5f                                           	pop    r15
  ac9ed9:	5d                                              	pop    rbp
  ac9eda:	e9 f1 a5 03 00                                  	jmp    0xb044d0
  ac9edf:	ba 00 c0 04 00                                  	mov    edx,0x4c000
  ac9ee4:	bf 02 00 00 00                                  	mov    edi,0x2
  ac9ee9:	4c 89 f6                                        	mov    rsi,r14
  ac9eec:	e8 ef c7 1e 00                                  	call   0xcb66e0
  ac9ef1:	85 c0                                           	test   eax,eax
  ac9ef3:	74 3f                                           	je     0xac9f34
  ac9ef5:	41 89 c0                                        	mov    r8d,eax
  ac9ef8:	48 8d 15 11 26 e1 00                            	lea    rdx,[rip+0xe12611]        # 0x18dc510
  ac9eff:	b9 48 01 00 00                                  	mov    ecx,0x148
  ac9f04:	31 ff                                           	xor    edi,edi
  ac9f06:	31 f6                                           	xor    esi,esi
  ac9f08:	31 c0                                           	xor    eax,eax
  ac9f0a:	e8 c1 a5 03 00                                  	call   0xb044d0
  ac9f0f:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  ac9f13:	e8 18 f9 f1 ff                                  	call   0x9e9830
  ac9f18:	be 00 c0 04 00                                  	mov    esi,0x4c000
  ac9f1d:	48 89 df                                        	mov    rdi,rbx
  ac9f20:	ba 14 00 00 00                                  	mov    edx,0x14
  ac9f25:	b9 4a 01 00 00                                  	mov    ecx,0x14a
  ac9f2a:	e8 b1 64 12 00                                  	call   0xbf03e0
  ac9f2f:	e9 a0 00 00 00                                  	jmp    0xac9fd4
  ac9f34:	4c 8b 6d c8                                     	mov    r13,QWORD PTR [rbp-0x38]
  ac9f38:	4c 8d 3d f9 0b de 01                            	lea    r15,[rip+0x1de0bf9]        # 0x28aab38
  ac9f3f:	48 8d 35 8a 01 dc 01                            	lea    rsi,[rip+0x1dc018a]        # 0x288a0d0
  ac9f46:	ba 68 0a 02 00                                  	mov    edx,0x20a68
  ac9f4b:	48 8d 1d ee ff db 01                            	lea    rbx,[rip+0x1dbffee]        # 0x2889f40
  ac9f52:	c7 05 ac 0b de 01 ff ff ff ff                   	mov    DWORD PTR [rip+0x1de0bac],0xffffffff        # 0x28aab08
  ac9f5c:	4c 89 ff                                        	mov    rdi,r15
  ac9f5f:	48 89 35 e2 ff db 01                            	mov    QWORD PTR [rip+0x1dbffe2],rsi        # 0x2889f48
  ac9f66:	4c 89 35 eb ff db 01                            	mov    QWORD PTR [rip+0x1dbffeb],r14        # 0x2889f58
  ac9f6d:	4c 89 2d dc ff db 01                            	mov    QWORD PTR [rip+0x1dbffdc],r13        # 0x2889f50
  ac9f74:	c7 05 46 00 dc 01 ff ff ff ff                   	mov    DWORD PTR [rip+0x1dc0046],0xffffffff        # 0x2889fc4
  ac9f7e:	c7 05 50 00 dc 01 ff ff ff ff                   	mov    DWORD PTR [rip+0x1dc0050],0xffffffff        # 0x2889fd8
  ac9f88:	e8 23 f1 78 ff                                  	call   0x2590b0
  ac9f8d:	48 8d 3d 74 00 dc 01                            	lea    rdi,[rip+0x1dc0074]        # 0x288a008
  ac9f94:	ba c8 00 00 00                                  	mov    edx,0xc8
  ac9f99:	48 89 de                                        	mov    rsi,rbx
  ac9f9c:	e8 0f f1 78 ff                                  	call   0x2590b0
  ac9fa1:	4c 89 3d 68 00 dc 01                            	mov    QWORD PTR [rip+0x1dc0068],r15        # 0x288a010
  ac9fa8:	4c 89 35 71 00 dc 01                            	mov    QWORD PTR [rip+0x1dc0071],r14        # 0x288a020
  ac9faf:	4c 89 2d 62 00 dc 01                            	mov    QWORD PTR [rip+0x1dc0062],r13        # 0x288a018
  ac9fb6:	c7 05 cc 00 dc 01 fe ff ff ff                   	mov    DWORD PTR [rip+0x1dc00cc],0xfffffffe        # 0x288a08c
  ac9fc0:	c7 05 a6 15 e0 01 fe ff ff ff                   	mov    DWORD PTR [rip+0x1e015a6],0xfffffffe        # 0x28cb570
  ac9fca:	c7 05 cc 00 dc 01 fe ff ff ff                   	mov    DWORD PTR [rip+0x1dc00cc],0xfffffffe        # 0x288a0a0
  ac9fd4:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  ac9fd8:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ac9fdc:	75 0f                                           	jne    0xac9fed
  ac9fde:	48 83 c4 18                                     	add    rsp,0x18
  ac9fe2:	5b                                              	pop    rbx
  ac9fe3:	41 5c                                           	pop    r12
  ac9fe5:	41 5d                                           	pop    r13
  ac9fe7:	41 5e                                           	pop    r14
  ac9fe9:	41 5f                                           	pop    r15
  ac9feb:	5d                                              	pop    rbp
  ac9fec:	c3                                              	ret
  ac9fed:	e8 be 36 c3 ff                                  	call   0x6fd6b0
  ac9ff2:	0f 0b                                           	ud2
  ac9ff4:	90                                              	nop
  ac9ff5:	90                                              	nop
  ac9ff6:	90                                              	nop
  ac9ff7:	90                                              	nop
  ac9ff8:	90                                              	nop
  ac9ff9:	90                                              	nop
  ac9ffa:	90                                              	nop
  ac9ffb:	90                                              	nop
  ac9ffc:	90                                              	nop
  ac9ffd:	90                                              	nop
  ac9ffe:	90                                              	nop
  ac9fff:	90                                              	nop
  aca000:	83 bf 94 00 00 00 00                            	cmp    DWORD PTR [rdi+0x94],0x0
  aca007:	b8 16 00 00 00                                  	mov    eax,0x16
  aca00c:	74 01                                           	je     0xaca00f
  aca00e:	c3                                              	ret
  aca00f:	83 be 54 0a 02 00 01                            	cmp    DWORD PTR [rsi+0x20a54],0x1
  aca016:	75 f6                                           	jne    0xaca00e
  aca018:	55                                              	push   rbp
  aca019:	48 89 e5                                        	mov    rbp,rsp
  aca01c:	41 57                                           	push   r15
  aca01e:	41 56                                           	push   r14
  aca020:	41 55                                           	push   r13
  aca022:	41 54                                           	push   r12
  aca024:	53                                              	push   rbx
  aca025:	50                                              	push   rax
  aca026:	49 89 f7                                        	mov    r15,rsi
  aca029:	be c8 00 00 00                                  	mov    esi,0xc8
  aca02e:	48 89 fb                                        	mov    rbx,rdi
  aca031:	4d 89 cc                                        	mov    r12,r9
  aca034:	48 89 4d d0                                     	mov    QWORD PTR [rbp-0x30],rcx
  aca038:	4d 89 c6                                        	mov    r14,r8
  aca03b:	49 89 d5                                        	mov    r13,rdx
  aca03e:	e8 ad ef 78 ff                                  	call   0x258ff0
  aca043:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  aca047:	c7 43 2c 00 00 00 00                            	mov    DWORD PTR [rbx+0x2c],0x0
  aca04e:	c7 43 4c 01 00 00 00                            	mov    DWORD PTR [rbx+0x4c],0x1
  aca055:	c7 43 6c 02 00 00 00                            	mov    DWORD PTR [rbx+0x6c],0x2
  aca05c:	4c 89 2b                                        	mov    QWORD PTR [rbx],r13
  aca05f:	44 89 b3 84 00 00 00                            	mov    DWORD PTR [rbx+0x84],r14d
  aca066:	4c 89 7b 08                                     	mov    QWORD PTR [rbx+0x8],r15
  aca06a:	44 89 a3 98 00 00 00                            	mov    DWORD PTR [rbx+0x98],r12d
  aca071:	48 8b 55 10                                     	mov    rdx,QWORD PTR [rbp+0x10]
  aca075:	48 8b 89 00 02 00 00                            	mov    rcx,QWORD PTR [rcx+0x200]
  aca07c:	8b 89 ec 01 00 00                               	mov    ecx,DWORD PTR [rcx+0x1ec]
  aca082:	89 8b 88 00 00 00                               	mov    DWORD PTR [rbx+0x88],ecx
  aca088:	31 c9                                           	xor    ecx,ecx
  aca08a:	48 83 7a 18 00                                  	cmp    QWORD PTR [rdx+0x18],0x0
  aca08f:	0f 95 c1                                        	setne  cl
  aca092:	89 4b 7c                                        	mov    DWORD PTR [rbx+0x7c],ecx
  aca095:	48 8b 4a 10                                     	mov    rcx,QWORD PTR [rdx+0x10]
  aca099:	48 89 4b 10                                     	mov    QWORD PTR [rbx+0x10],rcx
  aca09d:	41 83 bf 44 0a 02 00 00                         	cmp    DWORD PTR [r15+0x20a44],0x0
  aca0a5:	74 11                                           	je     0xaca0b8
  aca0a7:	48 8b 42 20                                     	mov    rax,QWORD PTR [rdx+0x20]
  aca0ab:	48 89 43 50                                     	mov    QWORD PTR [rbx+0x50],rax
  aca0af:	c6 83 80 00 00 00 01                            	mov    BYTE PTR [rbx+0x80],0x1
  aca0b6:	eb 12                                           	jmp    0xaca0ca
  aca0b8:	41 83 bf 4c 0a 02 00 00                         	cmp    DWORD PTR [r15+0x20a4c],0x0
  aca0c0:	74 08                                           	je     0xaca0ca
  aca0c2:	48 8b 42 18                                     	mov    rax,QWORD PTR [rdx+0x18]
  aca0c6:	48 89 43 30                                     	mov    QWORD PTR [rbx+0x30],rax
  aca0ca:	48 8b 05 4f 72 1f 03                            	mov    rax,QWORD PTR [rip+0x31f724f]        # 0x3cc1320
  aca0d1:	48 8d 48 01                                     	lea    rcx,[rax+0x1]
  aca0d5:	48 89 0d 44 72 1f 03                            	mov    QWORD PTR [rip+0x31f7244],rcx        # 0x3cc1320
  aca0dc:	48 89 83 a8 00 00 00                            	mov    QWORD PTR [rbx+0xa8],rax
  aca0e3:	31 c0                                           	xor    eax,eax
  aca0e5:	48 83 c4 08                                     	add    rsp,0x8
  aca0e9:	5b                                              	pop    rbx
  aca0ea:	41 5c                                           	pop    r12
  aca0ec:	41 5d                                           	pop    r13
  aca0ee:	41 5e                                           	pop    r14
  aca0f0:	41 5f                                           	pop    r15
  aca0f2:	5d                                              	pop    rbp
  aca0f3:	c3                                              	ret
  aca0f4:	90                                              	nop
  aca0f5:	90                                              	nop
  aca0f6:	90                                              	nop
  aca0f7:	90                                              	nop
  aca0f8:	90                                              	nop
  aca0f9:	90                                              	nop
  aca0fa:	90                                              	nop
  aca0fb:	90                                              	nop
  aca0fc:	90                                              	nop
  aca0fd:	90                                              	nop
  aca0fe:	90                                              	nop
  aca0ff:	90                                              	nop
  aca100:	55                                              	push   rbp
  aca101:	48 89 e5                                        	mov    rbp,rsp
  aca104:	48 8b 87 c8 02 00 00                            	mov    rax,QWORD PTR [rdi+0x2c8]
  aca10b:	31 d2                                           	xor    edx,edx
  aca10d:	89 c1                                           	mov    ecx,eax
  aca10f:	f7 d1                                           	not    ecx
  aca111:	f6 c1 07                                        	test   cl,0x7
  aca114:	0f 94 c2                                        	sete   dl
  aca117:	a9 00 02 00 00                                  	test   eax,0x200
  aca11c:	b8 02 00 00 00                                  	mov    eax,0x2
  aca121:	0f 44 c2                                        	cmove  eax,edx
  aca124:	5d                                              	pop    rbp
  aca125:	c3                                              	ret
  aca126:	90                                              	nop
  aca127:	90                                              	nop
  aca128:	90                                              	nop
  aca129:	90                                              	nop
  aca12a:	90                                              	nop
  aca12b:	90                                              	nop
  aca12c:	90                                              	nop
  aca12d:	90                                              	nop
  aca12e:	90                                              	nop
  aca12f:	90                                              	nop
  aca130:	b8 16 00 00 00                                  	mov    eax,0x16
  aca135:	83 ff 03                                        	cmp    edi,0x3
  aca138:	0f 87 97 02 00 00                               	ja     0xaca3d5
  aca13e:	0f b6 4a 09                                     	movzx  ecx,BYTE PTR [rdx+0x9]
  aca142:	80 f9 01                                        	cmp    cl,0x1
  aca145:	0f 87 8a 02 00 00                               	ja     0xaca3d5
  aca14b:	0f b6 7a 0a                                     	movzx  edi,BYTE PTR [rdx+0xa]
  aca14f:	40 80 ff 01                                     	cmp    dil,0x1
  aca153:	0f 87 7c 02 00 00                               	ja     0xaca3d5
  aca159:	55                                              	push   rbp
  aca15a:	48 89 e5                                        	mov    rbp,rsp
  aca15d:	41 57                                           	push   r15
  aca15f:	41 56                                           	push   r14
  aca161:	41 55                                           	push   r13
  aca163:	41 54                                           	push   r12
  aca165:	53                                              	push   rbx
  aca166:	48 83 ec 18                                     	sub    rsp,0x18
  aca16a:	44 0f b6 62 0b                                  	movzx  r12d,BYTE PTR [rdx+0xb]
  aca16f:	41 80 fc 01                                     	cmp    r12b,0x1
  aca173:	0f 87 4e 02 00 00                               	ja     0xaca3c7
  aca179:	44 8b 42 14                                     	mov    r8d,DWORD PTR [rdx+0x14]
  aca17d:	41 81 f8 00 20 00 00                            	cmp    r8d,0x2000
  aca184:	0f 87 3d 02 00 00                               	ja     0xaca3c7
  aca18a:	44 8b 4a 18                                     	mov    r9d,DWORD PTR [rdx+0x18]
  aca18e:	41 81 f9 00 20 00 00                            	cmp    r9d,0x2000
  aca195:	0f 87 2c 02 00 00                               	ja     0xaca3c7
  aca19b:	44 8b 6a 1c                                     	mov    r13d,DWORD PTR [rdx+0x1c]
  aca19f:	41 81 fd 00 20 00 00                            	cmp    r13d,0x2000
  aca1a6:	0f 87 1b 02 00 00                               	ja     0xaca3c7
  aca1ac:	80 7a 21 00                                     	cmp    BYTE PTR [rdx+0x21],0x0
  aca1b0:	0f 85 11 02 00 00                               	jne    0xaca3c7
  aca1b6:	80 7a 20 00                                     	cmp    BYTE PTR [rdx+0x20],0x0
  aca1ba:	0f 85 07 02 00 00                               	jne    0xaca3c7
  aca1c0:	45 84 e4                                        	test   r12b,r12b
  aca1c3:	41 0f 95 c2                                     	setne  r10b
  aca1c7:	40 84 ff                                        	test   dil,dil
  aca1ca:	41 0f 95 c3                                     	setne  r11b
  aca1ce:	45 84 d3                                        	test   r11b,r10b
  aca1d1:	0f 85 f0 01 00 00                               	jne    0xaca3c7
  aca1d7:	44 8b 52 2c                                     	mov    r10d,DWORD PTR [rdx+0x2c]
  aca1db:	45 84 e4                                        	test   r12b,r12b
  aca1de:	74 1a                                           	je     0xaca1fa
  aca1e0:	41 81 fa 07 02 00 00                            	cmp    r10d,0x207
  aca1e7:	7f 27                                           	jg     0xaca210
  aca1e9:	41 83 fa 24                                     	cmp    r10d,0x24
  aca1ed:	74 37                                           	je     0xaca226
  aca1ef:	41 83 fa 48                                     	cmp    r10d,0x48
  aca1f3:	74 31                                           	je     0xaca226
  aca1f5:	e9 cd 01 00 00                                  	jmp    0xaca3c7
  aca1fa:	45 85 d2                                        	test   r10d,r10d
  aca1fd:	0f 85 c4 01 00 00                               	jne    0xaca3c7
  aca203:	48 83 7a 38 00                                  	cmp    QWORD PTR [rdx+0x38],0x0
  aca208:	0f 85 b9 01 00 00                               	jne    0xaca3c7
  aca20e:	eb 16                                           	jmp    0xaca226
  aca210:	41 81 fa 08 02 00 00                            	cmp    r10d,0x208
  aca217:	74 0d                                           	je     0xaca226
  aca219:	41 81 fa 24 00 10 00                            	cmp    r10d,0x100024
  aca220:	0f 85 a1 01 00 00                               	jne    0xaca3c7
  aca226:	40 84 ff                                        	test   dil,dil
  aca229:	40 0f 95 c7                                     	setne  dil
  aca22d:	84 c9                                           	test   cl,cl
  aca22f:	0f 95 c1                                        	setne  cl
  aca232:	41 81 f9 40 01 00 00                            	cmp    r9d,0x140
  aca239:	41 0f 92 c2                                     	setb   r10b
  aca23d:	40 20 f9                                        	and    cl,dil
  aca240:	45 39 c1                                        	cmp    r9d,r8d
  aca243:	40 0f 97 c7                                     	seta   dil
  aca247:	44 08 d7                                        	or     dil,r10b
  aca24a:	40 08 cf                                        	or     dil,cl
  aca24d:	0f 85 74 01 00 00                               	jne    0xaca3c7
  aca253:	48 8b 5a 30                                     	mov    rbx,QWORD PTR [rdx+0x30]
  aca257:	48 89 75 c8                                     	mov    QWORD PTR [rbp-0x38],rsi
  aca25b:	48 89 55 d0                                     	mov    QWORD PTR [rbp-0x30],rdx
  aca25f:	48 89 df                                        	mov    rdi,rbx
  aca262:	e8 f9 01 00 00                                  	call   0xaca460
  aca267:	85 c0                                           	test   eax,eax
  aca269:	0f 85 58 01 00 00                               	jne    0xaca3c7
  aca26f:	49 89 df                                        	mov    r15,rbx
  aca272:	49 c1 ef 28                                     	shr    r15,0x28
  aca276:	45 0f b6 f7                                     	movzx  r14d,r15b
  aca27a:	41 83 c6 f4                                     	add    r14d,0xfffffff4
  aca27e:	41 83 fe 06                                     	cmp    r14d,0x6
  aca282:	77 6a                                           	ja     0xaca2ee
  aca284:	41 81 fd 37 04 00 00                            	cmp    r13d,0x437
  aca28b:	7f 20                                           	jg     0xaca2ad
  aca28d:	41 81 fd 68 01 00 00                            	cmp    r13d,0x168
  aca294:	74 36                                           	je     0xaca2cc
  aca296:	41 81 fd 1c 02 00 00                            	cmp    r13d,0x21c
  aca29d:	74 2d                                           	je     0xaca2cc
  aca29f:	41 81 fd d0 02 00 00                            	cmp    r13d,0x2d0
  aca2a6:	74 24                                           	je     0xaca2cc
  aca2a8:	e9 46 01 00 00                                  	jmp    0xaca3f3
  aca2ad:	41 81 fd 38 04 00 00                            	cmp    r13d,0x438
  aca2b4:	74 16                                           	je     0xaca2cc
  aca2b6:	41 81 fd a0 05 00 00                            	cmp    r13d,0x5a0
  aca2bd:	74 0d                                           	je     0xaca2cc
  aca2bf:	41 81 fd 70 08 00 00                            	cmp    r13d,0x870
  aca2c6:	0f 85 27 01 00 00                               	jne    0xaca3f3
  aca2cc:	45 84 e4                                        	test   r12b,r12b
  aca2cf:	74 0a                                           	je     0xaca2db
  aca2d1:	b8 16 00 00 00                                  	mov    eax,0x16
  aca2d6:	e9 ec 00 00 00                                  	jmp    0xaca3c7
  aca2db:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  aca2df:	83 78 10 00                                     	cmp    DWORD PTR [rax+0x10],0x0
  aca2e3:	b8 16 00 00 00                                  	mov    eax,0x16
  aca2e8:	0f 85 d9 00 00 00                               	jne    0xaca3c7
  aca2ee:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  aca2f2:	0f b7 78 22                                     	movzx  edi,WORD PTR [rax+0x22]
  aca2f6:	e8 45 04 00 00                                  	call   0xaca740
  aca2fb:	85 c0                                           	test   eax,eax
  aca2fd:	0f 85 c4 00 00 00                               	jne    0xaca3c7
  aca303:	48 8b 4d c8                                     	mov    rcx,QWORD PTR [rbp-0x38]
  aca307:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  aca30b:	48 89 d8                                        	mov    rax,rbx
  aca30e:	48 c1 e8 3e                                     	shr    rax,0x3e
  aca312:	41 83 fe 07                                     	cmp    r14d,0x7
  aca316:	48 89 99 90 02 00 00                            	mov    QWORD PTR [rcx+0x290],rbx
  aca31d:	8b 72 10                                        	mov    esi,DWORD PTR [rdx+0x10]
  aca320:	89 b1 a0 02 00 00                               	mov    DWORD PTR [rcx+0x2a0],esi
  aca326:	8b 72 14                                        	mov    esi,DWORD PTR [rdx+0x14]
  aca329:	89 b1 a4 02 00 00                               	mov    DWORD PTR [rcx+0x2a4],esi
  aca32f:	8b 72 18                                        	mov    esi,DWORD PTR [rdx+0x18]
  aca332:	89 b1 a8 02 00 00                               	mov    DWORD PTR [rcx+0x2a8],esi
  aca338:	8b 72 1c                                        	mov    esi,DWORD PTR [rdx+0x1c]
  aca33b:	89 b1 ac 02 00 00                               	mov    DWORD PTR [rcx+0x2ac],esi
  aca341:	0f b6 72 20                                     	movzx  esi,BYTE PTR [rdx+0x20]
  aca345:	89 b1 b0 02 00 00                               	mov    DWORD PTR [rcx+0x2b0],esi
  aca34b:	48 8b 72 38                                     	mov    rsi,QWORD PTR [rdx+0x38]
  aca34f:	48 89 b1 c8 0b 00 00                            	mov    QWORD PTR [rcx+0xbc8],rsi
  aca356:	0f b7 52 22                                     	movzx  edx,WORD PTR [rdx+0x22]
  aca35a:	0f 92 81 9a 02 00 00                            	setb   BYTE PTR [rcx+0x29a]
  aca361:	48 89 91 c8 02 00 00                            	mov    QWORD PTR [rcx+0x2c8],rdx
  aca368:	89 81 b4 02 00 00                               	mov    DWORD PTR [rcx+0x2b4],eax
  aca36e:	73 0e                                           	jae    0xaca37e
  aca370:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  aca374:	c7 80 a0 02 00 00 00 01 00 00                   	mov    DWORD PTR [rax+0x2a0],0x100
  aca37e:	41 80 ff 12                                     	cmp    r15b,0x12
  aca382:	0f 87 c5 00 00 00                               	ja     0xaca44d
  aca388:	41 0f b6 cf                                     	movzx  ecx,r15b
  aca38c:	ba 80 03 04 00                                  	mov    edx,0x40380
  aca391:	b0 01                                           	mov    al,0x1
  aca393:	0f a3 ca                                        	bt     edx,ecx
  aca396:	0f 83 b1 00 00 00                               	jae    0xaca44d
  aca39c:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  aca3a0:	88 87 9b 02 00 00                               	mov    BYTE PTR [rdi+0x29b],al
  aca3a6:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  aca3aa:	0f b6 48 0b                                     	movzx  ecx,BYTE PTR [rax+0xb]
  aca3ae:	66 89 8f 98 02 00 00                            	mov    WORD PTR [rdi+0x298],cx
  aca3b5:	8b 40 2c                                        	mov    eax,DWORD PTR [rax+0x2c]
  aca3b8:	89 87 9c 02 00 00                               	mov    DWORD PTR [rdi+0x29c],eax
  aca3be:	e8                                              	.byte 0xe8
  aca3bf:	dd                                              	.byte 0xdd
