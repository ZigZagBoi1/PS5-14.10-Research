
/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/deep_669.bin:     file format binary


Disassembly of section .data:

00000000003b2060 <.data>:
  3b2060:	55                                              	push   rbp
  3b2061:	48 89 e5                                        	mov    rbp,rsp
  3b2064:	8b 06                                           	mov    eax,DWORD PTR [rsi]
  3b2066:	48 8b 56 08                                     	mov    rdx,QWORD PTR [rsi+0x8]
  3b206a:	8b 4e 10                                        	mov    ecx,DWORD PTR [rsi+0x10]
  3b206d:	44 8b 46 18                                     	mov    r8d,DWORD PTR [rsi+0x18]
  3b2071:	4c 8b 4e 20                                     	mov    r9,QWORD PTR [rsi+0x20]
  3b2075:	89 c6                                           	mov    esi,eax
  3b2077:	5d                                              	pop    rbp
  3b2078:	e9 03 00 00 00                                  	jmp    0x3b2080
  3b207d:	90                                              	nop
  3b207e:	90                                              	nop
  3b207f:	90                                              	nop
  3b2080:	55                                              	push   rbp
  3b2081:	48 89 e5                                        	mov    rbp,rsp
  3b2084:	41 57                                           	push   r15
  3b2086:	41 56                                           	push   r14
  3b2088:	41 55                                           	push   r13
  3b208a:	41 54                                           	push   r12
  3b208c:	53                                              	push   rbx
  3b208d:	48 83 e4 e0                                     	and    rsp,0xffffffffffffffe0
  3b2091:	48 81 ec a0 00 00 00                            	sub    rsp,0xa0
  3b2098:	48 89 e3                                        	mov    rbx,rsp
  3b209b:	48 8d 05 6e a2 56 03                            	lea    rax,[rip+0x356a26e]        # 0x391c310
  3b20a2:	4c 89 4b 68                                     	mov    QWORD PTR [rbx+0x68],r9
  3b20a6:	4c 89 43 38                                     	mov    QWORD PTR [rbx+0x38],r8
  3b20aa:	48 89 4b 10                                     	mov    QWORD PTR [rbx+0x10],rcx
  3b20ae:	49 89 d4                                        	mov    r12,rdx
  3b20b1:	41 89 f7                                        	mov    r15d,esi
  3b20b4:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  3b20b7:	48 89 83 80 00 00 00                            	mov    QWORD PTR [rbx+0x80],rax
  3b20be:	48 89 7b 60                                     	mov    QWORD PTR [rbx+0x60],rdi
  3b20c2:	4c 8b 6f 08                                     	mov    r13,QWORD PTR [rdi+0x8]
  3b20c6:	49 8b 85 48 0c 00 00                            	mov    rax,QWORD PTR [r13+0xc48]
  3b20cd:	4c 89 ef                                        	mov    rdi,r13
  3b20d0:	48 89 43 30                                     	mov    QWORD PTR [rbx+0x30],rax
  3b20d4:	e8 a7 60 64 00                                  	call   0x9f8180
  3b20d9:	48 8d 73 70                                     	lea    rsi,[rbx+0x70]
  3b20dd:	4c 89 ef                                        	mov    rdi,r13
  3b20e0:	49 89 c6                                        	mov    r14,rax
  3b20e3:	e8 d8 60 64 00                                  	call   0x9f81c0
  3b20e8:	85 c0                                           	test   eax,eax
  3b20ea:	75 2a                                           	jne    0x3b2116
  3b20ec:	8b 43 70                                        	mov    eax,DWORD PTR [rbx+0x70]
  3b20ef:	3d ff ff ff 00                                  	cmp    eax,0xffffff
  3b20f4:	77 20                                           	ja     0x3b2116
  3b20f6:	3d ff ff 00 00                                  	cmp    eax,0xffff
  3b20fb:	0f 86 8d 01 00 00                               	jbe    0x3b228e
  3b2101:	25 00 00 ff 00                                  	and    eax,0xff0000
  3b2106:	3d 00 00 01 00                                  	cmp    eax,0x10000
  3b210b:	75 09                                           	jne    0x3b2116
  3b210d:	4c 8d 35 5c dd 11 03                            	lea    r14,[rip+0x311dd5c]        # 0x34cfe70
  3b2114:	eb 07                                           	jmp    0x3b211d
  3b2116:	4c 8d 35 ab d7 11 03                            	lea    r14,[rip+0x311d7ab]        # 0x34cf8c8
  3b211d:	44 89 f9                                        	mov    ecx,r15d
  3b2120:	41 bd 16 00 00 00                               	mov    r13d,0x16
  3b2126:	81 e1 ff 0f 00 00                               	and    ecx,0xfff
  3b212c:	8d 41 ff                                        	lea    eax,[rcx-0x1]
  3b212f:	83 f8 01                                        	cmp    eax,0x1
  3b2132:	0f 87 af 01 00 00                               	ja     0x3b22e7
  3b2138:	41 83 be a0 04 00 00 01                         	cmp    DWORD PTR [r14+0x4a0],0x1
  3b2140:	74 34                                           	je     0x3b2176
  3b2142:	bf 01 00 00 00                                  	mov    edi,0x1
  3b2147:	4c 89 f6                                        	mov    rsi,r14
  3b214a:	49 89 cd                                        	mov    r13,rcx
  3b214d:	e8 be 12 00 00                                  	call   0x3b3410
  3b2152:	4c 89 e9                                        	mov    rcx,r13
  3b2155:	85 c0                                           	test   eax,eax
  3b2157:	74 1d                                           	je     0x3b2176
  3b2159:	41 89 c5                                        	mov    r13d,eax
  3b215c:	48 8d 3d a5 9d f6 00                            	lea    rdi,[rip+0xf69da5]        # 0x131bf08
  3b2163:	48 8d 35 02 7c fc 00                            	lea    rsi,[rip+0xfc7c02]        # 0x1379d6c
  3b216a:	ba b7 0d 00 00                                  	mov    edx,0xdb7
  3b216f:	89 c1                                           	mov    ecx,eax
  3b2171:	e9 6a 01 00 00                                  	jmp    0x3b22e0
  3b2176:	4c 89 73 50                                     	mov    QWORD PTR [rbx+0x50],r14
  3b217a:	4c 8b 73 10                                     	mov    r14,QWORD PTR [rbx+0x10]
  3b217e:	41 8d 86 7f ff ff ff                            	lea    eax,[r14-0x81]
  3b2185:	3d 7f ff ff ff                                  	cmp    eax,0xffffff7f
  3b218a:	77 1e                                           	ja     0x3b21aa
  3b218c:	48 8d 3d 75 9d f6 00                            	lea    rdi,[rip+0xf69d75]        # 0x131bf08
  3b2193:	48 8d 35 d2 7b fc 00                            	lea    rsi,[rip+0xfc7bd2]        # 0x1379d6c
  3b219a:	41 bd 16 00 00 00                               	mov    r13d,0x16
  3b21a0:	ba bd 0d 00 00                                  	mov    edx,0xdbd
  3b21a5:	e9 31 01 00 00                                  	jmp    0x3b22db
  3b21aa:	48 8b 43 38                                     	mov    rax,QWORD PTR [rbx+0x38]
  3b21ae:	ff c8                                           	dec    eax
  3b21b0:	83 f8 03                                        	cmp    eax,0x3
  3b21b3:	0f 83 09 01 00 00                               	jae    0x3b22c2
  3b21b9:	48 8b 7b 30                                     	mov    rdi,QWORD PTR [rbx+0x30]
  3b21bd:	48 8d 73 70                                     	lea    rsi,[rbx+0x70]
  3b21c1:	48 89 4b 28                                     	mov    QWORD PTR [rbx+0x28],rcx
  3b21c5:	e8 16 77 fe ff                                  	call   0x3998e0
  3b21ca:	89 43 7c                                        	mov    DWORD PTR [rbx+0x7c],eax
  3b21cd:	83 f8 ff                                        	cmp    eax,0xffffffff
  3b21d0:	0f 84 46 01 00 00                               	je     0x3b231c
  3b21d6:	89 43 1c                                        	mov    DWORD PTR [rbx+0x1c],eax
  3b21d9:	42 8d 04 f5 00 00 00 00                         	lea    eax,[r14*8+0x0]
  3b21e1:	48 8d 35 a8 36 70 01                            	lea    rsi,[rip+0x17036a8]        # 0x1ab5890
  3b21e8:	ba 02 01 00 00                                  	mov    edx,0x102
  3b21ed:	44 8d 2c 80                                     	lea    r13d,[rax+rax*4]
  3b21f1:	4c 89 ef                                        	mov    rdi,r13
  3b21f4:	e8 57 69 85 00                                  	call   0xc08b50
  3b21f9:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  3b2202:	48 8d 35 34 5d fe 00                            	lea    rsi,[rip+0xfe5d34]        # 0x1397f3d
  3b2209:	31 d2                                           	xor    edx,edx
  3b220b:	49 89 c6                                        	mov    r14,rax
  3b220e:	e8 cd 81 86 00                                  	call   0xc1a3e0
  3b2213:	4c 89 e7                                        	mov    rdi,r12
  3b2216:	4c 89 f6                                        	mov    rsi,r14
  3b2219:	4c 89 ea                                        	mov    rdx,r13
  3b221c:	e8 5f 70 ea ff                                  	call   0x259280
  3b2221:	85 c0                                           	test   eax,eax
  3b2223:	0f 84 1f 01 00 00                               	je     0x3b2348
  3b2229:	4c 8d 3d d8 9c f6 00                            	lea    r15,[rip+0xf69cd8]        # 0x131bf08
  3b2230:	48 8d 35 e5 a1 f4 00                            	lea    rsi,[rip+0xf4a1e5]        # 0x12fc41c
  3b2237:	ba 13 0b 00 00                                  	mov    edx,0xb13
  3b223c:	89 c1                                           	mov    ecx,eax
  3b223e:	41 89 c5                                        	mov    r13d,eax
  3b2241:	31 c0                                           	xor    eax,eax
  3b2243:	4c 89 ff                                        	mov    rdi,r15
  3b2246:	e8 c5 b1 ea ff                                  	call   0x25d410
  3b224b:	48 8d 35 3e 36 70 01                            	lea    rsi,[rip+0x170363e]        # 0x1ab5890
  3b2252:	4c 89 f7                                        	mov    rdi,r14
  3b2255:	e8 96 6b 85 00                                  	call   0xc08df0
  3b225a:	48 8d 35 0b 7b fc 00                            	lea    rsi,[rip+0xfc7b0b]        # 0x1379d6c
  3b2261:	4c 89 ff                                        	mov    rdi,r15
  3b2264:	ba d6 0d 00 00                                  	mov    edx,0xdd6
  3b2269:	44 89 e9                                        	mov    ecx,r13d
  3b226c:	31 c0                                           	xor    eax,eax
  3b226e:	e8 9d b1 ea ff                                  	call   0x25d410
  3b2273:	48 8b 53 70                                     	mov    rdx,QWORD PTR [rbx+0x70]
  3b2277:	48 8b 7b 30                                     	mov    rdi,QWORD PTR [rbx+0x30]
  3b227b:	8b 73 1c                                        	mov    esi,DWORD PTR [rbx+0x1c]
  3b227e:	e8 ad 7b fe ff                                  	call   0x399e30
  3b2283:	48 8b 7b 70                                     	mov    rdi,QWORD PTR [rbx+0x70]
  3b2287:	e8 24 7c fe ff                                  	call   0x399eb0
  3b228c:	eb 59                                           	jmp    0x3b22e7
  3b228e:	4c 39 35 33 d5 11 03                            	cmp    QWORD PTR [rip+0x311d533],r14        # 0x34cf7c8
  3b2295:	74 79                                           	je     0x3b2310
  3b2297:	4c 39 35 22 e6 11 03                            	cmp    QWORD PTR [rip+0x311e622],r14        # 0x34d08c0
  3b229e:	0f 84 98 00 00 00                               	je     0x3b233c
  3b22a4:	83 3d 15 d5 11 03 00                            	cmp    DWORD PTR [rip+0x311d515],0x0        # 0x34cf7c0
  3b22ab:	48 8d 05 6e d0 11 03                            	lea    rax,[rip+0x311d06e]        # 0x34cf320
  3b22b2:	4c 8d 35 5f e1 11 03                            	lea    r14,[rip+0x311e15f]        # 0x34d0418
  3b22b9:	4c 0f 44 f0                                     	cmove  r14,rax
  3b22bd:	e9 5b fe ff ff                                  	jmp    0x3b211d
  3b22c2:	48 8d 3d 3f 9c f6 00                            	lea    rdi,[rip+0xf69c3f]        # 0x131bf08
  3b22c9:	48 8d 35 9c 7a fc 00                            	lea    rsi,[rip+0xfc7a9c]        # 0x1379d6c
  3b22d0:	41 bd 16 00 00 00                               	mov    r13d,0x16
  3b22d6:	ba c7 0d 00 00                                  	mov    edx,0xdc7
  3b22db:	b9 16 00 00 00                                  	mov    ecx,0x16
  3b22e0:	31 c0                                           	xor    eax,eax
  3b22e2:	e8 29 b1 ea ff                                  	call   0x25d410
  3b22e7:	48 8d 05 22 a0 56 03                            	lea    rax,[rip+0x356a022]        # 0x391c310
  3b22ee:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  3b22f1:	48 3b 83 80 00 00 00                            	cmp    rax,QWORD PTR [rbx+0x80]
  3b22f8:	0f 85 be 05 00 00                               	jne    0x3b28bc
  3b22fe:	44 89 e8                                        	mov    eax,r13d
  3b2301:	48 8d 65 d8                                     	lea    rsp,[rbp-0x28]
  3b2305:	5b                                              	pop    rbx
  3b2306:	41 5c                                           	pop    r12
  3b2308:	41 5d                                           	pop    r13
  3b230a:	41 5e                                           	pop    r14
  3b230c:	41 5f                                           	pop    r15
  3b230e:	5d                                              	pop    rbp
  3b230f:	c3                                              	ret
  3b2310:	4c 8d 35 09 d0 11 03                            	lea    r14,[rip+0x311d009]        # 0x34cf320
  3b2317:	e9 01 fe ff ff                                  	jmp    0x3b211d
  3b231c:	48 8d 3d e5 9b f6 00                            	lea    rdi,[rip+0xf69be5]        # 0x131bf08
  3b2323:	48 8d 35 42 7a fc 00                            	lea    rsi,[rip+0xfc7a42]        # 0x1379d6c
  3b232a:	41 bd 23 00 00 00                               	mov    r13d,0x23
  3b2330:	ba cf 0d 00 00                                  	mov    edx,0xdcf
  3b2335:	b9 23 00 00 00                                  	mov    ecx,0x23
  3b233a:	eb a4                                           	jmp    0x3b22e0
  3b233c:	4c 8d 35 d5 e0 11 03                            	lea    r14,[rip+0x311e0d5]        # 0x34d0418
  3b2343:	e9 d5 fd ff ff                                  	jmp    0x3b211d
  3b2348:	44 89 f8                                        	mov    eax,r15d
  3b234b:	4c 89 73 40                                     	mov    QWORD PTR [rbx+0x40],r14
  3b234f:	25 00 10 00 00                                  	and    eax,0x1000
  3b2354:	89 43 0c                                        	mov    DWORD PTR [rbx+0xc],eax
  3b2357:	75 54                                           	jne    0x3b23ad
  3b2359:	48 8d 35 10 36 70 01                            	lea    rsi,[rip+0x1703610]        # 0x1ab5970
  3b2360:	bf 58 00 00 00                                  	mov    edi,0x58
  3b2365:	ba 02 01 00 00                                  	mov    edx,0x102
  3b236a:	e8 e1 67 85 00                                  	call   0xc08b50
  3b236f:	49 89 c6                                        	mov    r14,rax
  3b2372:	48 8b 43 10                                     	mov    rax,QWORD PTR [rbx+0x10]
  3b2376:	48 8d 15 22 e7 f7 00                            	lea    rdx,[rip+0xf7e722]        # 0x1330a9f
  3b237d:	41 b8 01 00 00 00                               	mov    r8d,0x1
  3b2383:	31 f6                                           	xor    esi,esi
  3b2385:	31 c9                                           	xor    ecx,ecx
  3b2387:	49 8d 7e 20                                     	lea    rdi,[r14+0x20]
  3b238b:	41 89 06                                        	mov    DWORD PTR [r14],eax
  3b238e:	41 89 46 04                                     	mov    DWORD PTR [r14+0x4],eax
  3b2392:	41 c7 46 08 01 00 00 00                         	mov    DWORD PTR [r14+0x8],0x1
  3b239a:	49 c7 46 50 00 00 00 00                         	mov    QWORD PTR [r14+0x50],0x0
  3b23a2:	e8 e9 f2 83 00                                  	call   0xbf1690
  3b23a7:	44 8b 6b 1c                                     	mov    r13d,DWORD PTR [rbx+0x1c]
  3b23ab:	eb 68                                           	jmp    0x3b2415
  3b23ad:	4c 8b 63 10                                     	mov    r12,QWORD PTR [rbx+0x10]
  3b23b1:	48 8d 35 b8 35 70 01                            	lea    rsi,[rip+0x17035b8]        # 0x1ab5970
  3b23b8:	ba 02 01 00 00                                  	mov    edx,0x102
  3b23bd:	41 6b fc 58                                     	imul   edi,r12d,0x58
  3b23c1:	e8 8a 67 85 00                                  	call   0xc08b50
  3b23c6:	49 89 c6                                        	mov    r14,rax
  3b23c9:	49 89 c5                                        	mov    r13,rax
  3b23cc:	0f 1f 40 00                                     	nop    DWORD PTR [rax+0x0]
  3b23d0:	48 b8 01 00 00 00 01 00 00 00                   	movabs rax,0x100000001
  3b23da:	49 8d 7d 20                                     	lea    rdi,[r13+0x20]
  3b23de:	48 8d 15 ba e6 f7 00                            	lea    rdx,[rip+0xf7e6ba]        # 0x1330a9f
  3b23e5:	41 b8 01 00 00 00                               	mov    r8d,0x1
  3b23eb:	31 f6                                           	xor    esi,esi
  3b23ed:	31 c9                                           	xor    ecx,ecx
  3b23ef:	49 89 45 00                                     	mov    QWORD PTR [r13+0x0],rax
  3b23f3:	41 c7 45 08 01 00 00 00                         	mov    DWORD PTR [r13+0x8],0x1
  3b23fb:	49 c7 45 50 00 00 00 00                         	mov    QWORD PTR [r13+0x50],0x0
  3b2403:	e8 88 f2 83 00                                  	call   0xbf1690
  3b2408:	49 83 c5 58                                     	add    r13,0x58
  3b240c:	41 ff cc                                        	dec    r12d
  3b240f:	75 bf                                           	jne    0x3b23d0
  3b2411:	44 8b 6b 7c                                     	mov    r13d,DWORD PTR [rbx+0x7c]
  3b2415:	48 8d 35 34 36 70 01                            	lea    rsi,[rip+0x1703634]        # 0x1ab5a50
  3b241c:	bf 30 00 00 00                                  	mov    edi,0x30
  3b2421:	ba 02 01 00 00                                  	mov    edx,0x102
  3b2426:	e8 25 67 85 00                                  	call   0xc08b50
  3b242b:	49 89 c4                                        	mov    r12,rax
  3b242e:	8b 43 10                                        	mov    eax,DWORD PTR [rbx+0x10]
  3b2431:	48 8d 35 18 36 70 01                            	lea    rsi,[rip+0x1703618]        # 0x1ab5a50
  3b2438:	ba 02 01 00 00                                  	mov    edx,0x102
  3b243d:	48 8d 3c c5 00 00 00 00                         	lea    rdi,[rax*8+0x0]
  3b2445:	48 89 43 20                                     	mov    QWORD PTR [rbx+0x20],rax
  3b2449:	e8 02 67 85 00                                  	call   0xc08b50
  3b244e:	83 7b 0c 00                                     	cmp    DWORD PTR [rbx+0xc],0x0
  3b2452:	49 89 44 24 28                                  	mov    QWORD PTR [r12+0x28],rax
  3b2457:	4d 89 74 24 10                                  	mov    QWORD PTR [r12+0x10],r14
  3b245c:	4c 89 63 48                                     	mov    QWORD PTR [rbx+0x48],r12
  3b2460:	45 89 6c 24 08                                  	mov    DWORD PTR [r12+0x8],r13d
  3b2465:	4c 8b 63 40                                     	mov    r12,QWORD PTR [rbx+0x40]
  3b2469:	44 89 6b 1c                                     	mov    DWORD PTR [rbx+0x1c],r13d
  3b246d:	75 0a                                           	jne    0x3b2479
  3b246f:	49 89 46 18                                     	mov    QWORD PTR [r14+0x18],rax
  3b2473:	66 b8 01 00                                     	mov    ax,0x1
  3b2477:	eb 04                                           	jmp    0x3b247d
  3b2479:	48 8b 43 10                                     	mov    rax,QWORD PTR [rbx+0x10]
  3b247d:	48 8b 4b 48                                     	mov    rcx,QWORD PTR [rbx+0x48]
  3b2481:	4c 8b 6b 38                                     	mov    r13,QWORD PTR [rbx+0x38]
  3b2485:	66 89 41 02                                     	mov    WORD PTR [rcx+0x2],ax
  3b2489:	66 89 01                                        	mov    WORD PTR [rcx],ax
  3b248c:	48 8b 43 50                                     	mov    rax,QWORD PTR [rbx+0x50]
  3b2490:	44 89 69 04                                     	mov    DWORD PTR [rcx+0x4],r13d
  3b2494:	4c 89 61 20                                     	mov    QWORD PTR [rcx+0x20],r12
  3b2498:	48 89 41 18                                     	mov    QWORD PTR [rcx+0x18],rax
  3b249c:	e8 2f 54 75 00                                  	call   0xb078d0
  3b24a1:	85 c0                                           	test   eax,eax
  3b24a3:	74 16                                           	je     0x3b24bb
  3b24a5:	48 8b 4b 60                                     	mov    rcx,QWORD PTR [rbx+0x60]
  3b24a9:	44 89 fe                                        	mov    esi,r15d
  3b24ac:	4c 89 e2                                        	mov    rdx,r12
  3b24af:	45 89 e8                                        	mov    r8d,r13d
  3b24b2:	48 8b 7b 10                                     	mov    rdi,QWORD PTR [rbx+0x10]
  3b24b6:	e8 15 12 cf ff                                  	call   0xa36d0
  3b24bb:	48 8d 35 1e 35 70 01                            	lea    rsi,[rip+0x170351e]        # 0x1ab59e0
  3b24c2:	bf 30 00 00 00                                  	mov    edi,0x30
  3b24c7:	ba 02 01 00 00                                  	mov    edx,0x102
  3b24cc:	e8 7f 66 85 00                                  	call   0xc08b50
  3b24d1:	49 89 c7                                        	mov    r15,rax
  3b24d4:	65 48 8b 04 25 00 00 00 00                      	mov    rax,QWORD PTR gs:0x0
  3b24dd:	48 8b 88 90 03 00 00                            	mov    rcx,QWORD PTR [rax+0x390]
  3b24e4:	49 89 0f                                        	mov    QWORD PTR [r15],rcx
  3b24e7:	48 8b 48 08                                     	mov    rcx,QWORD PTR [rax+0x8]
  3b24eb:	49 89 4f 08                                     	mov    QWORD PTR [r15+0x8],rcx
  3b24ef:	48 8b b8 40 01 00 00                            	mov    rdi,QWORD PTR [rax+0x140]
  3b24f6:	e8 a5 8e ef ff                                  	call   0x2ab3a0
  3b24fb:	4c 8b 6b 48                                     	mov    r13,QWORD PTR [rbx+0x48]
  3b24ff:	49 89 47 10                                     	mov    QWORD PTR [r15+0x10],rax
  3b2503:	4d 89 6f 28                                     	mov    QWORD PTR [r15+0x28],r13
  3b2507:	e8 44 ea 23 00                                  	call   0x5f0f50
  3b250c:	83 7b 0c 00                                     	cmp    DWORD PTR [rbx+0xc],0x0
  3b2510:	4c 89 7b 58                                     	mov    QWORD PTR [rbx+0x58],r15
  3b2514:	41 89 47 20                                     	mov    DWORD PTR [r15+0x20],eax
  3b2518:	75 59                                           	jne    0x3b2573
  3b251a:	45 31 ff                                        	xor    r15d,r15d
  3b251d:	4d 89 6e 10                                     	mov    QWORD PTR [r14+0x10],r13
  3b2521:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b2530:	bf 58 00 00 00                                  	mov    edi,0x58
  3b2535:	48 8d 35 c4 33 70 01                            	lea    rsi,[rip+0x17033c4]        # 0x1ab5900
  3b253c:	ba 02 01 00 00                                  	mov    edx,0x102
  3b2541:	e8 0a 66 85 00                                  	call   0xc08b50
  3b2546:	48 8b 4b 28                                     	mov    rcx,QWORD PTR [rbx+0x28]
  3b254a:	48 8b 73 58                                     	mov    rsi,QWORD PTR [rbx+0x58]
  3b254e:	49 8b 55 28                                     	mov    rdx,QWORD PTR [r13+0x28]
  3b2552:	89 08                                           	mov    DWORD PTR [rax],ecx
  3b2554:	4c 89 60 10                                     	mov    QWORD PTR [rax+0x10],r12
  3b2558:	48 89 70 18                                     	mov    QWORD PTR [rax+0x18],rsi
  3b255c:	4c 89 70 20                                     	mov    QWORD PTR [rax+0x20],r14
  3b2560:	4a 89 04 fa                                     	mov    QWORD PTR [rdx+r15*8],rax
  3b2564:	49 ff c7                                        	inc    r15
  3b2567:	49 83 c4 28                                     	add    r12,0x28
  3b256b:	4c 39 7b 20                                     	cmp    QWORD PTR [rbx+0x20],r15
  3b256f:	75 bf                                           	jne    0x3b2530
  3b2571:	eb 56                                           	jmp    0x3b25c9
  3b2573:	4d 89 e7                                        	mov    r15,r12
  3b2576:	45 31 e4                                        	xor    r12d,r12d
  3b2579:	0f 1f 80 00 00 00 00                            	nop    DWORD PTR [rax+0x0]
  3b2580:	bf 58 00 00 00                                  	mov    edi,0x58
  3b2585:	48 8d 35 74 33 70 01                            	lea    rsi,[rip+0x1703374]        # 0x1ab5900
  3b258c:	ba 02 01 00 00                                  	mov    edx,0x102
  3b2591:	e8 ba 65 85 00                                  	call   0xc08b50
  3b2596:	48 8b 4b 28                                     	mov    rcx,QWORD PTR [rbx+0x28]
  3b259a:	48 8b 73 58                                     	mov    rsi,QWORD PTR [rbx+0x58]
  3b259e:	49 8b 55 28                                     	mov    rdx,QWORD PTR [r13+0x28]
  3b25a2:	4d 89 6e 10                                     	mov    QWORD PTR [r14+0x10],r13
  3b25a6:	89 08                                           	mov    DWORD PTR [rax],ecx
  3b25a8:	4c 89 78 10                                     	mov    QWORD PTR [rax+0x10],r15
  3b25ac:	48 89 70 18                                     	mov    QWORD PTR [rax+0x18],rsi
  3b25b0:	4c 89 70 20                                     	mov    QWORD PTR [rax+0x20],r14
  3b25b4:	4a 89 04 e2                                     	mov    QWORD PTR [rdx+r12*8],rax
  3b25b8:	49 ff c4                                        	inc    r12
  3b25bb:	49 83 c6 58                                     	add    r14,0x58
  3b25bf:	49 83 c7 28                                     	add    r15,0x28
  3b25c3:	4c 39 63 20                                     	cmp    QWORD PTR [rbx+0x20],r12
  3b25c7:	75 b7                                           	jne    0x3b2580
  3b25c9:	48 8b 7b 70                                     	mov    rdi,QWORD PTR [rbx+0x70]
  3b25cd:	4c 8b 73 20                                     	mov    r14,QWORD PTR [rbx+0x20]
  3b25d1:	be 60 01 00 00                                  	mov    esi,0x160
  3b25d6:	4c 89 ea                                        	mov    rdx,r13
  3b25d9:	31 c9                                           	xor    ecx,ecx
  3b25db:	45 31 ff                                        	xor    r15d,r15d
  3b25de:	e8 fd 77 fe ff                                  	call   0x399de0
  3b25e3:	48 8b 7b 70                                     	mov    rdi,QWORD PTR [rbx+0x70]
  3b25e7:	e8 c4 78 fe ff                                  	call   0x399eb0
  3b25ec:	83 7b 0c 00                                     	cmp    DWORD PTR [rbx+0xc],0x0
  3b25f0:	4d 89 ec                                        	mov    r12,r13
  3b25f3:	75 0f                                           	jne    0x3b2604
  3b25f5:	4c 8b 73 68                                     	mov    r14,QWORD PTR [rbx+0x68]
  3b25f9:	48 8d 7b 7c                                     	lea    rdi,[rbx+0x7c]
  3b25fd:	ba 04 00 00 00                                  	mov    edx,0x4
  3b2602:	eb 53                                           	jmp    0x3b2657
  3b2604:	4a 8d 04 b5 0f 00 00 00                         	lea    rax,[r14*4+0xf]
  3b260c:	48 89 e7                                        	mov    rdi,rsp
  3b260f:	4a 8d 14 b5 00 00 00 00                         	lea    rdx,[r14*4+0x0]
  3b2617:	4d 89 f0                                        	mov    r8,r14
  3b261a:	48 83 e0 f0                                     	and    rax,0xfffffffffffffff0
  3b261e:	48 29 c7                                        	sub    rdi,rax
  3b2621:	48 83 e7 e0                                     	and    rdi,0xffffffffffffffe0
  3b2625:	48 89 fc                                        	mov    rsp,rdi
  3b2628:	4c 8b 73 68                                     	mov    r14,QWORD PTR [rbx+0x68]
  3b262c:	8b 73 1c                                        	mov    esi,DWORD PTR [rbx+0x1c]
  3b262f:	31 c0                                           	xor    eax,eax
  3b2631:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b2640:	44 89 f9                                        	mov    ecx,r15d
  3b2643:	41 81 c7 00 00 01 00                            	add    r15d,0x10000
  3b264a:	09 f1                                           	or     ecx,esi
  3b264c:	89 0c 87                                        	mov    DWORD PTR [rdi+rax*4],ecx
  3b264f:	48 ff c0                                        	inc    rax
  3b2652:	49 39 c0                                        	cmp    r8,rax
  3b2655:	75 e9                                           	jne    0x3b2640
  3b2657:	4c 89 f6                                        	mov    rsi,r14
  3b265a:	e8 e1 13 00 00                                  	call   0x3b3a40
  3b265f:	41 89 c5                                        	mov    r13d,eax
  3b2662:	85 c0                                           	test   eax,eax
  3b2664:	74 15                                           	je     0x3b267b
  3b2666:	48 8d 3d 9b 98 f6 00                            	lea    rdi,[rip+0xf6989b]        # 0x131bf08
  3b266d:	48 8d 35 f8 76 fc 00                            	lea    rsi,[rip+0xfc76f8]        # 0x1379d6c
  3b2674:	ba 1a 0e 00 00                                  	mov    edx,0xe1a
  3b2679:	eb 39                                           	jmp    0x3b26b4
  3b267b:	4c 8b 7b 50                                     	mov    r15,QWORD PTR [rbx+0x50]
  3b267f:	4c 89 e1                                        	mov    rcx,r12
  3b2682:	48 8b 7b 10                                     	mov    rdi,QWORD PTR [rbx+0x10]
  3b2686:	48 8b 73 38                                     	mov    rsi,QWORD PTR [rbx+0x38]
  3b268a:	48 8b 53 28                                     	mov    rdx,QWORD PTR [rbx+0x28]
  3b268e:	4d 89 f8                                        	mov    r8,r15
  3b2691:	e8 fa 13 00 00                                  	call   0x3b3a90
  3b2696:	85 c0                                           	test   eax,eax
  3b2698:	0f 84 ab 01 00 00                               	je     0x3b2849
  3b269e:	41 89 c5                                        	mov    r13d,eax
  3b26a1:	48 8d 3d 60 98 f6 00                            	lea    rdi,[rip+0xf69860]        # 0x131bf08
  3b26a8:	48 8d 35 bd 76 fc 00                            	lea    rsi,[rip+0xfc76bd]        # 0x1379d6c
  3b26af:	ba 21 0e 00 00                                  	mov    edx,0xe21
  3b26b4:	44 89 e9                                        	mov    ecx,r13d
  3b26b7:	31 c0                                           	xor    eax,eax
  3b26b9:	e8 52 ad ea ff                                  	call   0x25d410
  3b26be:	4c 8b 7b 30                                     	mov    r15,QWORD PTR [rbx+0x30]
  3b26c2:	8b 73 7c                                        	mov    esi,DWORD PTR [rbx+0x7c]
  3b26c5:	48 8d 4b 70                                     	lea    rcx,[rbx+0x70]
  3b26c9:	ba 60 01 00 00                                  	mov    edx,0x160
  3b26ce:	4c 89 ff                                        	mov    rdi,r15
  3b26d1:	e8 ca 7b fe ff                                  	call   0x39a2a0
  3b26d6:	8b 73 7c                                        	mov    esi,DWORD PTR [rbx+0x7c]
  3b26d9:	48 8b 53 70                                     	mov    rdx,QWORD PTR [rbx+0x70]
  3b26dd:	4c 89 ff                                        	mov    rdi,r15
  3b26e0:	49 89 c6                                        	mov    r14,rax
  3b26e3:	e8 48 77 fe ff                                  	call   0x399e30
  3b26e8:	48 8b 7b 70                                     	mov    rdi,QWORD PTR [rbx+0x70]
  3b26ec:	e8 bf 77 fe ff                                  	call   0x399eb0
  3b26f1:	83 7b 0c 00                                     	cmp    DWORD PTR [rbx+0xc],0x0
  3b26f5:	0f 85 1e 01 00 00                               	jne    0x3b2819
  3b26fb:	49 8b 46 28                                     	mov    rax,QWORD PTR [r14+0x28]
  3b26ff:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  3b2702:	48 8b 78 20                                     	mov    rdi,QWORD PTR [rax+0x20]
  3b2706:	48 83 c7 20                                     	add    rdi,0x20
  3b270a:	e8 51 f0 83 00                                  	call   0xbf1760
  3b270f:	49 8b 46 28                                     	mov    rax,QWORD PTR [r14+0x28]
  3b2713:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  3b2716:	48 8b 40 18                                     	mov    rax,QWORD PTR [rax+0x18]
  3b271a:	48 8b 78 10                                     	mov    rdi,QWORD PTR [rax+0x10]
  3b271e:	e8 4d 6f ef ff                                  	call   0x2a9670
  3b2723:	49 8b 46 28                                     	mov    rax,QWORD PTR [r14+0x28]
  3b2727:	48 8d 35 b2 32 70 01                            	lea    rsi,[rip+0x17032b2]        # 0x1ab59e0
  3b272e:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  3b2731:	48 8b 78 18                                     	mov    rdi,QWORD PTR [rax+0x18]
  3b2735:	e8 b6 66 85 00                                  	call   0xc08df0
  3b273a:	83 7b 10 00                                     	cmp    DWORD PTR [rbx+0x10],0x0
  3b273e:	0f 8e 92 00 00 00                               	jle    0x3b27d6
  3b2744:	45 31 ff                                        	xor    r15d,r15d
  3b2747:	eb 2d                                           	jmp    0x3b2776
  3b2749:	49 c7 44 24 40 00 00 00 00                      	mov    QWORD PTR [r12+0x40],0x0
  3b2752:	4c 89 e7                                        	mov    rdi,r12
  3b2755:	48 8d 35 a4 31 70 01                            	lea    rsi,[rip+0x17031a4]        # 0x1ab5900
  3b275c:	e8 8f 66 85 00                                  	call   0xc08df0
  3b2761:	49 8b 46 28                                     	mov    rax,QWORD PTR [r14+0x28]
  3b2765:	4a c7 04 f8 00 00 00 00                         	mov    QWORD PTR [rax+r15*8],0x0
  3b276d:	49 ff c7                                        	inc    r15
  3b2770:	4c 39 7b 20                                     	cmp    QWORD PTR [rbx+0x20],r15
  3b2774:	74 60                                           	je     0x3b27d6
  3b2776:	49 8b 46 28                                     	mov    rax,QWORD PTR [r14+0x28]
  3b277a:	4e 8b 24 f8                                     	mov    r12,QWORD PTR [rax+r15*8]
  3b277e:	4d 85 e4                                        	test   r12,r12
  3b2781:	74 ea                                           	je     0x3b276d
  3b2783:	49 83 7c 24 28 00                               	cmp    QWORD PTR [r12+0x28],0x0
  3b2789:	74 1a                                           	je     0x3b27a5
  3b278b:	48 8d 3d 65 42 f5 00                            	lea    rdi,[rip+0xf54265]        # 0x13069f7
  3b2792:	48 8d 35 e5 d3 fb 00                            	lea    rsi,[rip+0xfbd3e5]        # 0x136fb7e
  3b2799:	ba 35 0b 00 00                                  	mov    edx,0xb35
  3b279e:	31 c0                                           	xor    eax,eax
  3b27a0:	e8 6b ac ea ff                                  	call   0x25d410
  3b27a5:	49 8b 44 24 40                                  	mov    rax,QWORD PTR [r12+0x40]
  3b27aa:	48 85 c0                                        	test   rax,rax
  3b27ad:	74 a3                                           	je     0x3b2752
  3b27af:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  3b27b4:	f0 0f c1 48 28                                  	lock xadd DWORD PTR [rax+0x28],ecx
  3b27b9:	83 f9 01                                        	cmp    ecx,0x1
  3b27bc:	75 8b                                           	jne    0x3b2749
  3b27be:	49 8b 7c 24 40                                  	mov    rdi,QWORD PTR [r12+0x40]
  3b27c3:	65 48 8b 34 25 00 00 00 00                      	mov    rsi,QWORD PTR gs:0x0
  3b27cc:	e8 af 8b 37 00                                  	call   0x72b380
  3b27d1:	e9 73 ff ff ff                                  	jmp    0x3b2749
  3b27d6:	49 8b 7e 10                                     	mov    rdi,QWORD PTR [r14+0x10]
  3b27da:	48 8d 35 8f 31 70 01                            	lea    rsi,[rip+0x170318f]        # 0x1ab5970
  3b27e1:	e8 0a 66 85 00                                  	call   0xc08df0
  3b27e6:	49 8b 7e 28                                     	mov    rdi,QWORD PTR [r14+0x28]
  3b27ea:	4c 8d 3d 5f 32 70 01                            	lea    r15,[rip+0x170325f]        # 0x1ab5a50
  3b27f1:	4c 89 fe                                        	mov    rsi,r15
  3b27f4:	e8 f7 65 85 00                                  	call   0xc08df0
  3b27f9:	4c 89 f7                                        	mov    rdi,r14
  3b27fc:	4c 89 fe                                        	mov    rsi,r15
  3b27ff:	e8 ec 65 85 00                                  	call   0xc08df0
  3b2804:	48 8b 7b 40                                     	mov    rdi,QWORD PTR [rbx+0x40]
  3b2808:	48 8d 35 81 30 70 01                            	lea    rsi,[rip+0x1703081]        # 0x1ab5890
  3b280f:	e8 dc 65 85 00                                  	call   0xc08df0
  3b2814:	e9 ce fa ff ff                                  	jmp    0x3b22e7
  3b2819:	45 31 ff                                        	xor    r15d,r15d
  3b281c:	eb 0f                                           	jmp    0x3b282d
  3b281e:	66 90                                           	xchg   ax,ax
  3b2820:	49 ff c7                                        	inc    r15
  3b2823:	4c 39 7b 20                                     	cmp    QWORD PTR [rbx+0x20],r15
  3b2827:	0f 84 e2 fe ff ff                               	je     0x3b270f
  3b282d:	49 8b 46 28                                     	mov    rax,QWORD PTR [r14+0x28]
  3b2831:	4a 8b 04 f8                                     	mov    rax,QWORD PTR [rax+r15*8]
  3b2835:	48 85 c0                                        	test   rax,rax
  3b2838:	74 e6                                           	je     0x3b2820
  3b283a:	48 8b 78 20                                     	mov    rdi,QWORD PTR [rax+0x20]
  3b283e:	48 83 c7 20                                     	add    rdi,0x20
  3b2842:	e8 19 ef 83 00                                  	call   0xbf1760
  3b2847:	eb d7                                           	jmp    0x3b2820
  3b2849:	48 8d 3d 98 ca 11 03                            	lea    rdi,[rip+0x311ca98]        # 0x34cf2e8
  3b2850:	31 f6                                           	xor    esi,esi
  3b2852:	31 d2                                           	xor    edx,edx
  3b2854:	31 c9                                           	xor    ecx,ecx
  3b2856:	e8 a5 41 11 00                                  	call   0x4c6a00
  3b285b:	49 8b b7 b0 04 00 00                            	mov    rsi,QWORD PTR [r15+0x4b0]
  3b2862:	48 85 f6                                        	test   rsi,rsi
  3b2865:	75 0c                                           	jne    0x3b2873
  3b2867:	49 8b b7 28 05 00 00                            	mov    rsi,QWORD PTR [r15+0x528]
  3b286e:	48 85 f6                                        	test   rsi,rsi
  3b2871:	74 0c                                           	je     0x3b287f
  3b2873:	48 8d 3d 76 ca 11 03                            	lea    rdi,[rip+0x311ca76]        # 0x34cf2f0
  3b287a:	e8 01 c7 38 00                                  	call   0x73ef80
  3b287f:	48 8d 3d 62 ca 11 03                            	lea    rdi,[rip+0x311ca62]        # 0x34cf2e8
  3b2886:	45 31 ed                                        	xor    r13d,r13d
  3b2889:	31 f6                                           	xor    esi,esi
  3b288b:	31 d2                                           	xor    edx,edx
  3b288d:	31 c9                                           	xor    ecx,ecx
  3b288f:	e8 0c 47 11 00                                  	call   0x4c6fa0
  3b2894:	e8 37 50 75 00                                  	call   0xb078d0
  3b2899:	85 c0                                           	test   eax,eax
  3b289b:	0f 84 46 fa ff ff                               	je     0x3b22e7
  3b28a1:	8b 73 0c                                        	mov    esi,DWORD PTR [rbx+0xc]
  3b28a4:	48 8b 53 60                                     	mov    rdx,QWORD PTR [rbx+0x60]
  3b28a8:	4c 89 f1                                        	mov    rcx,r14
  3b28ab:	48 8b 7b 10                                     	mov    rdi,QWORD PTR [rbx+0x10]
  3b28af:	c1 ee 0c                                        	shr    esi,0xc
  3b28b2:	e8 99 0f cf ff                                  	call   0xa3850
  3b28b7:	e9 2b fa ff ff                                  	jmp    0x3b22e7
  3b28bc:	e8 ef ad 34 00                                  	call   0x6fd6b0
  3b28c1:	0f 0b                                           	ud2
  3b28c3:	90                                              	nop
  3b28c4:	90                                              	nop
  3b28c5:	90                                              	nop
  3b28c6:	90                                              	nop
  3b28c7:	90                                              	nop
  3b28c8:	90                                              	nop
  3b28c9:	90                                              	nop
  3b28ca:	90                                              	nop
  3b28cb:	90                                              	nop
  3b28cc:	90                                              	nop
  3b28cd:	90                                              	nop
  3b28ce:	90                                              	nop
  3b28cf:	90                                              	nop
  3b28d0:	55                                              	push   rbp
  3b28d1:	48 89 e5                                        	mov    rbp,rsp
  3b28d4:	41 57                                           	push   r15
  3b28d6:	41 56                                           	push   r14
  3b28d8:	41 55                                           	push   r13
  3b28da:	41 54                                           	push   r12
  3b28dc:	53                                              	push   rbx
  3b28dd:	48 83 ec 58                                     	sub    rsp,0x58
  3b28e1:	48 8d 05 28 9a 56 03                            	lea    rax,[rip+0x3569a28]        # 0x391c310
  3b28e8:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  3b28eb:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  3b28ef:	48 89 7d 88                                     	mov    QWORD PTR [rbp-0x78],rdi
  3b28f3:	4c 8b 7f 08                                     	mov    r15,QWORD PTR [rdi+0x8]
  3b28f7:	8b 46 08                                        	mov    eax,DWORD PTR [rsi+0x8]
  3b28fa:	4c 8b 26                                        	mov    r12,QWORD PTR [rsi]
  3b28fd:	4c 8b 6e 10                                     	mov    r13,QWORD PTR [rsi+0x10]
  3b2901:	44 8b 76 18                                     	mov    r14d,DWORD PTR [rsi+0x18]
  3b2905:	4c 89 ff                                        	mov    rdi,r15
  3b2908:	89 45 90                                        	mov    DWORD PTR [rbp-0x70],eax
  3b290b:	e8 70 58 64 00                                  	call   0x9f8180
  3b2910:	48 8d 75 94                                     	lea    rsi,[rbp-0x6c]
  3b2914:	4c 89 ff                                        	mov    rdi,r15
  3b2917:	48 89 c3                                        	mov    rbx,rax
  3b291a:	e8 a1 58 64 00                                  	call   0x9f81c0
  3b291f:	48 8d 0d a2 cf 11 03                            	lea    rcx,[rip+0x311cfa2]        # 0x34cf8c8
  3b2926:	85 c0                                           	test   eax,eax
  3b2928:	75 36                                           	jne    0x3b2960
  3b292a:	8b 45 94                                        	mov    eax,DWORD PTR [rbp-0x6c]
  3b292d:	3d ff ff ff 00                                  	cmp    eax,0xffffff
  3b2932:	77 2c                                           	ja     0x3b2960
  3b2934:	3d ff ff 00 00                                  	cmp    eax,0xffff
  3b2939:	0f 86 0d 01 00 00                               	jbe    0x3b2a4c
  3b293f:	25 00 00 ff 00                                  	and    eax,0xff0000
  3b2944:	48 8d 15 25 d5 11 03                            	lea    rdx,[rip+0x311d525]        # 0x34cfe70
  3b294b:	48 8d 0d 76 cf 11 03                            	lea    rcx,[rip+0x311cf76]        # 0x34cf8c8
  3b2952:	41 b7 01                                        	mov    r15b,0x1
  3b2955:	3d 00 00 01 00                                  	cmp    eax,0x10000
  3b295a:	48 0f 44 ca                                     	cmove  rcx,rdx
  3b295e:	eb 03                                           	jmp    0x3b2963
  3b2960:	45 31 ff                                        	xor    r15d,r15d
  3b2963:	4d 85 ed                                        	test   r13,r13
  3b2966:	74 1a                                           	je     0x3b2982
  3b2968:	48 8d 3d 99 95 f6 00                            	lea    rdi,[rip+0xf69599]        # 0x131bf08
  3b296f:	48 8d 35 3a 74 fc 00                            	lea    rsi,[rip+0xfc743a]        # 0x1379db0
  3b2976:	bb 16 00 00 00                                  	mov    ebx,0x16
  3b297b:	ba 1f 13 00 00                                  	mov    edx,0x131f
  3b2980:	eb 1d                                           	jmp    0x3b299f
  3b2982:	45 85 f6                                        	test   r14d,r14d
  3b2985:	74 49                                           	je     0x3b29d0
  3b2987:	48 8d 3d 7a 95 f6 00                            	lea    rdi,[rip+0xf6957a]        # 0x131bf08
  3b298e:	48 8d 35 1b 74 fc 00                            	lea    rsi,[rip+0xfc741b]        # 0x1379db0
  3b2995:	bb 16 00 00 00                                  	mov    ebx,0x16
  3b299a:	ba 24 13 00 00                                  	mov    edx,0x1324
  3b299f:	b9 16 00 00 00                                  	mov    ecx,0x16
  3b29a4:	31 c0                                           	xor    eax,eax
  3b29a6:	e8 65 aa ea ff                                  	call   0x25d410
  3b29ab:	48 8d 05 5e 99 56 03                            	lea    rax,[rip+0x356995e]        # 0x391c310
  3b29b2:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  3b29b5:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  3b29b9:	0f 85 89 03 00 00                               	jne    0x3b2d48
  3b29bf:	89 d8                                           	mov    eax,ebx
  3b29c1:	48 83 c4 58                                     	add    rsp,0x58
  3b29c5:	5b                                              	pop    rbx
  3b29c6:	41 5c                                           	pop    r12
  3b29c8:	41 5d                                           	pop    r13
  3b29ca:	41 5e                                           	pop    r14
  3b29cc:	41 5f                                           	pop    r15
  3b29ce:	5d                                              	pop    rbp
  3b29cf:	c3                                              	ret
  3b29d0:	48 8d 3d 29 c9 11 03                            	lea    rdi,[rip+0x311c929]        # 0x34cf300
  3b29d7:	49 89 ce                                        	mov    r14,rcx
  3b29da:	31 db                                           	xor    ebx,ebx
  3b29dc:	31 f6                                           	xor    esi,esi
  3b29de:	31 d2                                           	xor    edx,edx
  3b29e0:	31 c9                                           	xor    ecx,ecx
  3b29e2:	e8 39 91 89 00                                  	call   0xc4bb20
  3b29e7:	4d 85 e4                                        	test   r12,r12
  3b29ea:	41 bd 01 00 00 00                               	mov    r13d,0x1
  3b29f0:	0f 94 c0                                        	sete   al
  3b29f3:	41 80 f7 01                                     	xor    r15b,0x1
  3b29f7:	41 08 c7                                        	or     r15b,al
  3b29fa:	75 0e                                           	jne    0x3b2a0a
  3b29fc:	41 83 be a0 04 00 00 00                         	cmp    DWORD PTR [r14+0x4a0],0x0
  3b2a04:	0f 84 81 00 00 00                               	je     0x3b2a8b
  3b2a0a:	48 8d 3d ef c8 11 03                            	lea    rdi,[rip+0x311c8ef]        # 0x34cf300
  3b2a11:	31 f6                                           	xor    esi,esi
  3b2a13:	31 d2                                           	xor    edx,edx
  3b2a15:	e8 96 9a 89 00                                  	call   0xc4c4b0
  3b2a1a:	44 89 ef                                        	mov    edi,r13d
  3b2a1d:	4c 89 f6                                        	mov    rsi,r14
  3b2a20:	e8 eb 09 00 00                                  	call   0x3b3410
  3b2a25:	85 c0                                           	test   eax,eax
  3b2a27:	74 82                                           	je     0x3b29ab
  3b2a29:	48 8d 3d d8 94 f6 00                            	lea    rdi,[rip+0xf694d8]        # 0x131bf08
  3b2a30:	48 8d 35 79 73 fc 00                            	lea    rsi,[rip+0xfc7379]        # 0x1379db0
  3b2a37:	ba 83 13 00 00                                  	mov    edx,0x1383
  3b2a3c:	89 c1                                           	mov    ecx,eax
  3b2a3e:	89 c3                                           	mov    ebx,eax
  3b2a40:	31 c0                                           	xor    eax,eax
  3b2a42:	e8 c9 a9 ea ff                                  	call   0x25d410
  3b2a47:	e9 5f ff ff ff                                  	jmp    0x3b29ab
  3b2a4c:	41 b7 01                                        	mov    r15b,0x1
  3b2a4f:	48 39 1d 72 cd 11 03                            	cmp    QWORD PTR [rip+0x311cd72],rbx        # 0x34cf7c8
  3b2a56:	74 27                                           	je     0x3b2a7f
  3b2a58:	48 39 1d 61 de 11 03                            	cmp    QWORD PTR [rip+0x311de61],rbx        # 0x34d08c0
  3b2a5f:	74 73                                           	je     0x3b2ad4
  3b2a61:	83 3d 58 cd 11 03 00                            	cmp    DWORD PTR [rip+0x311cd58],0x0        # 0x34cf7c0
  3b2a68:	48 8d 05 b1 c8 11 03                            	lea    rax,[rip+0x311c8b1]        # 0x34cf320
  3b2a6f:	48 8d 0d a2 d9 11 03                            	lea    rcx,[rip+0x311d9a2]        # 0x34d0418
  3b2a76:	48 0f 44 c8                                     	cmove  rcx,rax
  3b2a7a:	e9 e4 fe ff ff                                  	jmp    0x3b2963
  3b2a7f:	48 8d 0d 9a c8 11 03                            	lea    rcx,[rip+0x311c89a]        # 0x34cf320
  3b2a86:	e9 d8 fe ff ff                                  	jmp    0x3b2963
  3b2a8b:	83 7d 90 3c                                     	cmp    DWORD PTR [rbp-0x70],0x3c
  3b2a8f:	75 4f                                           	jne    0x3b2ae0
  3b2a91:	48 8d 75 94                                     	lea    rsi,[rbp-0x6c]
  3b2a95:	4c 89 e7                                        	mov    rdi,r12
  3b2a98:	e8 73 14 00 00                                  	call   0x3b3f10
  3b2a9d:	85 c0                                           	test   eax,eax
  3b2a9f:	74 78                                           	je     0x3b2b19
  3b2aa1:	48 8d 3d 60 94 f6 00                            	lea    rdi,[rip+0xf69460]        # 0x131bf08
  3b2aa8:	48 8d 35 01 73 fc 00                            	lea    rsi,[rip+0xfc7301]        # 0x1379db0
  3b2aaf:	ba 3a 13 00 00                                  	mov    edx,0x133a
  3b2ab4:	89 c1                                           	mov    ecx,eax
  3b2ab6:	89 c3                                           	mov    ebx,eax
  3b2ab8:	31 c0                                           	xor    eax,eax
  3b2aba:	e8 51 a9 ea ff                                  	call   0x25d410
  3b2abf:	48 8d 3d 3a c8 11 03                            	lea    rdi,[rip+0x311c83a]        # 0x34cf300
  3b2ac6:	31 f6                                           	xor    esi,esi
  3b2ac8:	31 d2                                           	xor    edx,edx
  3b2aca:	e8 e1 99 89 00                                  	call   0xc4c4b0
  3b2acf:	e9 73 ff ff ff                                  	jmp    0x3b2a47
  3b2ad4:	48 8d 0d 3d d9 11 03                            	lea    rcx,[rip+0x311d93d]        # 0x34d0418
  3b2adb:	e9 83 fe ff ff                                  	jmp    0x3b2963
  3b2ae0:	48 8d 3d 21 94 f6 00                            	lea    rdi,[rip+0xf69421]        # 0x131bf08
  3b2ae7:	48 8d 35 c2 72 fc 00                            	lea    rsi,[rip+0xfc72c2]        # 0x1379db0
  3b2aee:	bb 16 00 00 00                                  	mov    ebx,0x16
  3b2af3:	ba 31 13 00 00                                  	mov    edx,0x1331
  3b2af8:	b9 16 00 00 00                                  	mov    ecx,0x16
  3b2afd:	31 c0                                           	xor    eax,eax
  3b2aff:	e8 0c a9 ea ff                                  	call   0x25d410
  3b2b04:	48 8d 3d f5 c7 11 03                            	lea    rdi,[rip+0x311c7f5]        # 0x34cf300
  3b2b0b:	31 f6                                           	xor    esi,esi
  3b2b0d:	31 d2                                           	xor    edx,edx
  3b2b0f:	e8 9c 99 89 00                                  	call   0xc4c4b0
  3b2b14:	e9 92 fe ff ff                                  	jmp    0x3b29ab
  3b2b19:	8b 45 94                                        	mov    eax,DWORD PTR [rbp-0x6c]
  3b2b1c:	3d 80 00 00 00                                  	cmp    eax,0x80
  3b2b21:	76 1a                                           	jbe    0x3b2b3d
  3b2b23:	48 8d 3d de 93 f6 00                            	lea    rdi,[rip+0xf693de]        # 0x131bf08
  3b2b2a:	48 8d 35 7f 72 fc 00                            	lea    rsi,[rip+0xfc727f]        # 0x1379db0
  3b2b31:	bb 16 00 00 00                                  	mov    ebx,0x16
  3b2b36:	ba 43 13 00 00                                  	mov    edx,0x1343
  3b2b3b:	eb bb                                           	jmp    0x3b2af8
  3b2b3d:	8b 4d 98                                        	mov    ecx,DWORD PTR [rbp-0x68]
  3b2b40:	81 f9 81 00 00 00                               	cmp    ecx,0x81
  3b2b46:	72 1a                                           	jb     0x3b2b62
  3b2b48:	48 8d 3d b9 93 f6 00                            	lea    rdi,[rip+0xf693b9]        # 0x131bf08
  3b2b4f:	48 8d 35 5a 72 fc 00                            	lea    rsi,[rip+0xfc725a]        # 0x1379db0
  3b2b56:	bb 16 00 00 00                                  	mov    ebx,0x16
  3b2b5b:	ba 4a 13 00 00                                  	mov    edx,0x134a
  3b2b60:	eb 96                                           	jmp    0x3b2af8
  3b2b62:	8b 55 9c                                        	mov    edx,DWORD PTR [rbp-0x64]
  3b2b65:	89 d6                                           	mov    esi,edx
  3b2b67:	89 d7                                           	mov    edi,edx
  3b2b69:	85 d2                                           	test   edx,edx
  3b2b6b:	74 67                                           	je     0x3b2bd4
  3b2b6d:	83 fa 01                                        	cmp    edx,0x1
  3b2b70:	0f 85 b5 01 00 00                               	jne    0x3b2d2b
  3b2b76:	8b 75 a0                                        	mov    esi,DWORD PTR [rbp-0x60]
  3b2b79:	8d be ff ff ff fe                               	lea    edi,[rsi-0x1000001]
  3b2b7f:	81 ff ff ff ff fe                               	cmp    edi,0xfeffffff
  3b2b85:	77 1d                                           	ja     0x3b2ba4
  3b2b87:	48 8d 3d 7a 93 f6 00                            	lea    rdi,[rip+0xf6937a]        # 0x131bf08
  3b2b8e:	48 8d 35 1b 72 fc 00                            	lea    rsi,[rip+0xfc721b]        # 0x1379db0
  3b2b95:	bb 16 00 00 00                                  	mov    ebx,0x16
  3b2b9a:	ba 59 13 00 00                                  	mov    edx,0x1359
  3b2b9f:	e9 54 ff ff ff                                  	jmp    0x3b2af8
  3b2ba4:	8b 7d a4                                        	mov    edi,DWORD PTR [rbp-0x5c]
  3b2ba7:	44 8d 87 ff ff ff fe                            	lea    r8d,[rdi-0x1000001]
  3b2bae:	41 81 f8 ff ff ff fe                            	cmp    r8d,0xfeffffff
  3b2bb5:	77 1d                                           	ja     0x3b2bd4
  3b2bb7:	48 8d 3d 4a 93 f6 00                            	lea    rdi,[rip+0xf6934a]        # 0x131bf08
  3b2bbe:	48 8d 35 eb 71 fc 00                            	lea    rsi,[rip+0xfc71eb]        # 0x1379db0
  3b2bc5:	bb 16 00 00 00                                  	mov    ebx,0x16
  3b2bca:	ba 61 13 00 00                                  	mov    edx,0x1361
  3b2bcf:	e9 24 ff ff ff                                  	jmp    0x3b2af8
  3b2bd4:	41 89 b6 b4 01 00 00                            	mov    DWORD PTR [r14+0x1b4],esi
  3b2bdb:	41 89 be 94 01 00 00                            	mov    DWORD PTR [r14+0x194],edi
  3b2be2:	41 89 96 a4 01 00 00                            	mov    DWORD PTR [r14+0x1a4],edx
  3b2be9:	41 89 86 74 01 00 00                            	mov    DWORD PTR [r14+0x174],eax
  3b2bf0:	8b 45 a8                                        	mov    eax,DWORD PTR [rbp-0x58]
  3b2bf3:	41 89 8e 84 01 00 00                            	mov    DWORD PTR [r14+0x184],ecx
  3b2bfa:	3d 80 00 00 00                                  	cmp    eax,0x80
  3b2bff:	0f 87 1e ff ff ff                               	ja     0x3b2b23
  3b2c05:	8b 4d ac                                        	mov    ecx,DWORD PTR [rbp-0x54]
  3b2c08:	81 f9 80 00 00 00                               	cmp    ecx,0x80
  3b2c0e:	0f 87 34 ff ff ff                               	ja     0x3b2b48
  3b2c14:	8b 55 b0                                        	mov    edx,DWORD PTR [rbp-0x50]
  3b2c17:	89 d6                                           	mov    esi,edx
  3b2c19:	89 d7                                           	mov    edi,edx
  3b2c1b:	85 d2                                           	test   edx,edx
  3b2c1d:	74 35                                           	je     0x3b2c54
  3b2c1f:	83 fa 01                                        	cmp    edx,0x1
  3b2c22:	0f 85 03 01 00 00                               	jne    0x3b2d2b
  3b2c28:	8b 75 b4                                        	mov    esi,DWORD PTR [rbp-0x4c]
  3b2c2b:	8d be ff ff ff fe                               	lea    edi,[rsi-0x1000001]
  3b2c31:	81 ff 00 00 00 ff                               	cmp    edi,0xff000000
  3b2c37:	0f 82 4a ff ff ff                               	jb     0x3b2b87
  3b2c3d:	8b 7d b8                                        	mov    edi,DWORD PTR [rbp-0x48]
  3b2c40:	44 8d 87 ff ff ff fe                            	lea    r8d,[rdi-0x1000001]
  3b2c47:	41 81 f8 00 00 00 ff                            	cmp    r8d,0xff000000
  3b2c4e:	0f 82 63 ff ff ff                               	jb     0x3b2bb7
  3b2c54:	41 89 b6 b8 01 00 00                            	mov    DWORD PTR [r14+0x1b8],esi
  3b2c5b:	41 89 be 98 01 00 00                            	mov    DWORD PTR [r14+0x198],edi
  3b2c62:	41 89 96 a8 01 00 00                            	mov    DWORD PTR [r14+0x1a8],edx
  3b2c69:	41 89 86 78 01 00 00                            	mov    DWORD PTR [r14+0x178],eax
  3b2c70:	8b 45 bc                                        	mov    eax,DWORD PTR [rbp-0x44]
  3b2c73:	41 89 8e 88 01 00 00                            	mov    DWORD PTR [r14+0x188],ecx
  3b2c7a:	3d 80 00 00 00                                  	cmp    eax,0x80
  3b2c7f:	0f 87 9e fe ff ff                               	ja     0x3b2b23
  3b2c85:	8b 4d c0                                        	mov    ecx,DWORD PTR [rbp-0x40]
  3b2c88:	81 f9 80 00 00 00                               	cmp    ecx,0x80
  3b2c8e:	0f 87 b4 fe ff ff                               	ja     0x3b2b48
  3b2c94:	8b 55 c4                                        	mov    edx,DWORD PTR [rbp-0x3c]
  3b2c97:	89 d6                                           	mov    esi,edx
  3b2c99:	89 d7                                           	mov    edi,edx
  3b2c9b:	85 d2                                           	test   edx,edx
  3b2c9d:	74 35                                           	je     0x3b2cd4
  3b2c9f:	83 fa 01                                        	cmp    edx,0x1
  3b2ca2:	0f 85 83 00 00 00                               	jne    0x3b2d2b
  3b2ca8:	8b 75 c8                                        	mov    esi,DWORD PTR [rbp-0x38]
  3b2cab:	8d be ff ff ff fe                               	lea    edi,[rsi-0x1000001]
  3b2cb1:	81 ff 00 00 00 ff                               	cmp    edi,0xff000000
  3b2cb7:	0f 82 ca fe ff ff                               	jb     0x3b2b87
  3b2cbd:	8b 7d cc                                        	mov    edi,DWORD PTR [rbp-0x34]
  3b2cc0:	44 8d 87 ff ff ff fe                            	lea    r8d,[rdi-0x1000001]
  3b2cc7:	41 81 f8 00 00 00 ff                            	cmp    r8d,0xff000000
  3b2cce:	0f 82 e3 fe ff ff                               	jb     0x3b2bb7
  3b2cd4:	41 89 b6 bc 01 00 00                            	mov    DWORD PTR [r14+0x1bc],esi
  3b2cdb:	41 89 be 9c 01 00 00                            	mov    DWORD PTR [r14+0x19c],edi
  3b2ce2:	41 89 96 ac 01 00 00                            	mov    DWORD PTR [r14+0x1ac],edx
  3b2ce9:	41 89 86 7c 01 00 00                            	mov    DWORD PTR [r14+0x17c],eax
  3b2cf0:	41 89 8e 8c 01 00 00                            	mov    DWORD PTR [r14+0x18c],ecx
  3b2cf7:	e8 d4 4b 75 00                                  	call   0xb078d0
  3b2cfc:	85 c0                                           	test   eax,eax
  3b2cfe:	74 0c                                           	je     0x3b2d0c
  3b2d00:	48 8b 7d 88                                     	mov    rdi,QWORD PTR [rbp-0x78]
  3b2d04:	4c 89 f6                                        	mov    rsi,r14
  3b2d07:	e8 24 11 cf ff                                  	call   0xa3e30
  3b2d0c:	45 31 ed                                        	xor    r13d,r13d
  3b2d0f:	41 83 be a0 04 00 00 01                         	cmp    DWORD PTR [r14+0x4a0],0x1
  3b2d17:	0f 85 ed fc ff ff                               	jne    0x3b2a0a
  3b2d1d:	48 8d 3d dc c5 11 03                            	lea    rdi,[rip+0x311c5dc]        # 0x34cf300
  3b2d24:	31 db                                           	xor    ebx,ebx
  3b2d26:	e9 e0 fd ff ff                                  	jmp    0x3b2b0b
  3b2d2b:	48 8d 3d d6 91 f6 00                            	lea    rdi,[rip+0xf691d6]        # 0x131bf08
  3b2d32:	48 8d 35 77 70 fc 00                            	lea    rsi,[rip+0xfc7077]        # 0x1379db0
  3b2d39:	bb 16 00 00 00                                  	mov    ebx,0x16
  3b2d3e:	ba 52 13 00 00                                  	mov    edx,0x1352
  3b2d43:	e9 b0 fd ff ff                                  	jmp    0x3b2af8
  3b2d48:	e8 63 a9 34 00                                  	call   0x6fd6b0
  3b2d4d:	0f 0b                                           	ud2
  3b2d4f:	90                                              	nop
  3b2d50:	55                                              	push   rbp
  3b2d51:	48 89 e5                                        	mov    rbp,rsp
  3b2d54:	41 57                                           	push   r15
  3b2d56:	41 56                                           	push   r14
  3b2d58:	41 55                                           	push   r13
  3b2d5a:	41 54                                           	push   r12
  3b2d5c:	53                                              	push   rbx
  3b2d5d:	48 83 ec 38                                     	sub    rsp,0x38
  3b2d61:	4c 8d 2d a8 95 56 03                            	lea    r13,[rip+0x35695a8]        # 0x391c310
  3b2d68:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  3b2d6c:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  3b2d70:	48 8b 56 08                                     	mov    rdx,QWORD PTR [rsi+0x8]
  3b2d74:	4c 8b 66 18                                     	mov    r12,QWORD PTR [rsi+0x18]
  3b2d78:	44 8b 3e                                        	mov    r15d,DWORD PTR [rsi]
  3b2d7b:	44 8b 76 10                                     	mov    r14d,DWORD PTR [rsi+0x10]
  3b2d7f:	c7 45 cc 00 00 00 00                            	mov    DWORD PTR [rbp-0x34],0x0
  3b2d86:	48 85 d2                                        	test   rdx,rdx
  3b2d89:	0f 95 c0                                        	setne  al
  3b2d8c:	4d 85 e4                                        	test   r12,r12
  3b2d8f:	0f 95 c1                                        	setne  cl
  3b2d92:	84 c8                                           	test   al,cl
  3b2d94:	75 1f                                           	jne    0x3b2db5
  3b2d96:	48 8d 3d 6b 91 f6 00                            	lea    rdi,[rip+0xf6916b]        # 0x131bf08
  3b2d9d:	48 8d 35 25 da f9 00                            	lea    rsi,[rip+0xf9da25]        # 0x13507c9
  3b2da4:	bb 0e 00 00 00                                  	mov    ebx,0xe
  3b2da9:	ba fe 14 00 00                                  	mov    edx,0x14fe
  3b2dae:	b9 0e 00 00 00                                  	mov    ecx,0xe
  3b2db3:	eb 30                                           	jmp    0x3b2de5
  3b2db5:	48 89 55 a8                                     	mov    QWORD PTR [rbp-0x58],rdx
  3b2db9:	48 8d 55 b8                                     	lea    rdx,[rbp-0x48]
  3b2dbd:	44 89 ff                                        	mov    edi,r15d
  3b2dc0:	be 15 00 00 00                                  	mov    esi,0x15
  3b2dc5:	e8 96 94 18 00                                  	call   0x53c260
  3b2dca:	85 c0                                           	test   eax,eax
  3b2dcc:	74 3d                                           	je     0x3b2e0b
  3b2dce:	89 c3                                           	mov    ebx,eax
  3b2dd0:	48 8d 3d 31 91 f6 00                            	lea    rdi,[rip+0xf69131]        # 0x131bf08
  3b2dd7:	48 8d 35 eb d9 f9 00                            	lea    rsi,[rip+0xf9d9eb]        # 0x13507c9
  3b2dde:	ba 06 15 00 00                                  	mov    edx,0x1506
  3b2de3:	89 c1                                           	mov    ecx,eax
  3b2de5:	31 c0                                           	xor    eax,eax
  3b2de7:	e8 24 a6 ea ff                                  	call   0x25d410
  3b2dec:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  3b2df0:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  3b2df4:	0f 85 80 02 00 00                               	jne    0x3b307a
  3b2dfa:	89 d8                                           	mov    eax,ebx
  3b2dfc:	48 83 c4 38                                     	add    rsp,0x38
  3b2e00:	5b                                              	pop    rbx
  3b2e01:	41 5c                                           	pop    r12
  3b2e03:	41 5d                                           	pop    r13
  3b2e05:	41 5e                                           	pop    r14
  3b2e07:	41 5f                                           	pop    r15
  3b2e09:	5d                                              	pop    rbp
  3b2e0a:	c3                                              	ret
  3b2e0b:	44 89 ff                                        	mov    edi,r15d
  3b2e0e:	e8 fd 52 1f 00                                  	call   0x5a8110
  3b2e13:	83 f8 ff                                        	cmp    eax,0xffffffff
  3b2e16:	74 41                                           	je     0x3b2e59
  3b2e18:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  3b2e1c:	48 8b 80 48 0c 00 00                            	mov    rax,QWORD PTR [rax+0xc48]
  3b2e23:	48 85 c0                                        	test   rax,rax
  3b2e26:	74 4b                                           	je     0x3b2e73
  3b2e28:	45 85 f6                                        	test   r14d,r14d
  3b2e2b:	7e 0d                                           	jle    0x3b2e3a
  3b2e2d:	44 3b b0 28 02 00 00                            	cmp    r14d,DWORD PTR [rax+0x228]
  3b2e34:	0f 8e b8 00 00 00                               	jle    0x3b2ef2
  3b2e3a:	48 8d 3d c7 90 f6 00                            	lea    rdi,[rip+0xf690c7]        # 0x131bf08
  3b2e41:	48 8d 35 81 d9 f9 00                            	lea    rsi,[rip+0xf9d981]        # 0x13507c9
  3b2e48:	bb 16 00 00 00                                  	mov    ebx,0x16
  3b2e4d:	ba 1c 15 00 00                                  	mov    edx,0x151c
  3b2e52:	b9 16 00 00 00                                  	mov    ecx,0x16
  3b2e57:	eb 37                                           	jmp    0x3b2e90
  3b2e59:	48 8d 3d a8 90 f6 00                            	lea    rdi,[rip+0xf690a8]        # 0x131bf08
  3b2e60:	48 8d 35 62 d9 f9 00                            	lea    rsi,[rip+0xf9d962]        # 0x13507c9
  3b2e67:	bb 03 00 00 00                                  	mov    ebx,0x3
  3b2e6c:	ba 0d 15 00 00                                  	mov    edx,0x150d
  3b2e71:	eb 18                                           	jmp    0x3b2e8b
  3b2e73:	48 8d 3d 8e 90 f6 00                            	lea    rdi,[rip+0xf6908e]        # 0x131bf08
  3b2e7a:	48 8d 35 48 d9 f9 00                            	lea    rsi,[rip+0xf9d948]        # 0x13507c9
  3b2e81:	bb 03 00 00 00                                  	mov    ebx,0x3
  3b2e86:	ba 15 15 00 00                                  	mov    edx,0x1515
  3b2e8b:	b9 03 00 00 00                                  	mov    ecx,0x3
  3b2e90:	31 c0                                           	xor    eax,eax
  3b2e92:	e8 79 a5 ea ff                                  	call   0x25d410
  3b2e97:	bf 48 01 00 00                                  	mov    edi,0x148
  3b2e9c:	48 03 7d b8                                     	add    rdi,QWORD PTR [rbp-0x48]
  3b2ea0:	31 f6                                           	xor    esi,esi
  3b2ea2:	31 d2                                           	xor    edx,edx
  3b2ea4:	31 c9                                           	xor    ecx,ecx
  3b2ea6:	e8 55 3b 11 00                                  	call   0x4c6a00
  3b2eab:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  3b2eaf:	ff 88 58 03 00 00                               	dec    DWORD PTR [rax+0x358]
  3b2eb5:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  3b2eb9:	f6 87 b1 00 00 00 20                            	test   BYTE PTR [rdi+0xb1],0x20
  3b2ec0:	74 19                                           	je     0x3b2edb
  3b2ec2:	83 bf 58 03 00 00 00                            	cmp    DWORD PTR [rdi+0x358],0x0
  3b2ec9:	75 10                                           	jne    0x3b2edb
  3b2ecb:	48 81 c7 58 03 00 00                            	add    rdi,0x358
  3b2ed2:	e8 39 3a 85 00                                  	call   0xc06910
  3b2ed7:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  3b2edb:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  3b2ee2:	31 f6                                           	xor    esi,esi
  3b2ee4:	31 d2                                           	xor    edx,edx
  3b2ee6:	31 c9                                           	xor    ecx,ecx
  3b2ee8:	e8 b3 40 11 00                                  	call   0x4c6fa0
  3b2eed:	e9 fa fe ff ff                                  	jmp    0x3b2dec
  3b2ef2:	4c 89 f7                                        	mov    rdi,r14
  3b2ef5:	48 8d 35 c4 2b 70 01                            	lea    rsi,[rip+0x1702bc4]        # 0x1ab5ac0
  3b2efc:	ba 02 01 00 00                                  	mov    edx,0x102
  3b2f01:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  3b2f05:	48 c1 e7 04                                     	shl    rdi,0x4
  3b2f09:	e8 42 5c 85 00                                  	call   0xc08b50
  3b2f0e:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  3b2f12:	49 89 c7                                        	mov    r15,rax
  3b2f15:	8b 87 20 02 00 00                               	mov    eax,DWORD PTR [rdi+0x220]
  3b2f1b:	c1 e0 07                                        	shl    eax,0x7
  3b2f1e:	85 c0                                           	test   eax,eax
  3b2f20:	0f 8e a9 00 00 00                               	jle    0x3b2fcf
  3b2f26:	31 db                                           	xor    ebx,ebx
  3b2f28:	45 31 ed                                        	xor    r13d,r13d
  3b2f2b:	eb 25                                           	jmp    0x3b2f52
  3b2f2d:	0f 1f 00                                        	nop    DWORD PTR [rax]
  3b2f30:	48 8b 7d c0                                     	mov    rdi,QWORD PTR [rbp-0x40]
  3b2f34:	e8 77 6f fe ff                                  	call   0x399eb0
  3b2f39:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  3b2f3d:	41 ff c5                                        	inc    r13d
  3b2f40:	8b 87 20 02 00 00                               	mov    eax,DWORD PTR [rdi+0x220]
  3b2f46:	c1 e0 07                                        	shl    eax,0x7
  3b2f49:	41 39 c5                                        	cmp    r13d,eax
  3b2f4c:	0f 8d 7d 00 00 00                               	jge    0x3b2fcf
  3b2f52:	44 89 ee                                        	mov    esi,r13d
  3b2f55:	ba 60 01 00 00                                  	mov    edx,0x160
  3b2f5a:	48 8d 4d c0                                     	lea    rcx,[rbp-0x40]
  3b2f5e:	e8 8d 71 fe ff                                  	call   0x39a0f0
  3b2f63:	48 85 c0                                        	test   rax,rax
  3b2f66:	74 d1                                           	je     0x3b2f39
  3b2f68:	48 0f bf 08                                     	movsx  rcx,WORD PTR [rax]
  3b2f6c:	48 85 c9                                        	test   rcx,rcx
  3b2f6f:	7e bf                                           	jle    0x3b2f30
  3b2f71:	48 8b 50 28                                     	mov    rdx,QWORD PTR [rax+0x28]
  3b2f75:	48 c1 e1 10                                     	shl    rcx,0x10
  3b2f79:	31 f6                                           	xor    esi,esi
  3b2f7b:	eb 18                                           	jmp    0x3b2f95
  3b2f7d:	0f 1f 00                                        	nop    DWORD PTR [rax]
  3b2f80:	ff c3                                           	inc    ebx
  3b2f82:	89 5d cc                                        	mov    DWORD PTR [rbp-0x34],ebx
  3b2f85:	48 81 c6 00 00 01 00                            	add    rsi,0x10000
  3b2f8c:	48 83 c2 08                                     	add    rdx,0x8
  3b2f90:	48 39 f1                                        	cmp    rcx,rsi
  3b2f93:	74 9b                                           	je     0x3b2f30
  3b2f95:	48 8b 3a                                        	mov    rdi,QWORD PTR [rdx]
  3b2f98:	48 85 ff                                        	test   rdi,rdi
  3b2f9b:	74 e8                                           	je     0x3b2f85
  3b2f9d:	44 39 f3                                        	cmp    ebx,r14d
  3b2fa0:	7d de                                           	jge    0x3b2f80
  3b2fa2:	44 8b 40 08                                     	mov    r8d,DWORD PTR [rax+0x8]
  3b2fa6:	4c 63 cb                                        	movsxd r9,ebx
  3b2fa9:	49 c1 e1 04                                     	shl    r9,0x4
  3b2fad:	41 09 f0                                        	or     r8d,esi
  3b2fb0:	47 89 04 0f                                     	mov    DWORD PTR [r15+r9*1],r8d
  3b2fb4:	44 8b 47 38                                     	mov    r8d,DWORD PTR [rdi+0x38]
  3b2fb8:	47 89 44 0f 04                                  	mov    DWORD PTR [r15+r9*1+0x4],r8d
  3b2fbd:	44 8b 40 04                                     	mov    r8d,DWORD PTR [rax+0x4]
  3b2fc1:	47 89 44 0f 08                                  	mov    DWORD PTR [r15+r9*1+0x8],r8d
  3b2fc6:	8b 3f                                           	mov    edi,DWORD PTR [rdi]
  3b2fc8:	43 89 7c 0f 0c                                  	mov    DWORD PTR [r15+r9*1+0xc],edi
  3b2fcd:	eb b1                                           	jmp    0x3b2f80
  3b2fcf:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  3b2fd8:	48 8d 35 b8 c2 f9 00                            	lea    rsi,[rip+0xf9c2b8]        # 0x134f297
  3b2fdf:	31 d2                                           	xor    edx,edx
  3b2fe1:	31 db                                           	xor    ebx,ebx
  3b2fe3:	e8 f8 73 86 00                                  	call   0xc1a3e0
  3b2fe8:	48 8d 7d cc                                     	lea    rdi,[rbp-0x34]
  3b2fec:	ba 04 00 00 00                                  	mov    edx,0x4
  3b2ff1:	4c 89 e6                                        	mov    rsi,r12
  3b2ff4:	e8 d7 61 ea ff                                  	call   0x2591d0
  3b2ff9:	85 c0                                           	test   eax,eax
  3b2ffb:	74 27                                           	je     0x3b3024
  3b2ffd:	48 8d 3d 04 8f f6 00                            	lea    rdi,[rip+0xf68f04]        # 0x131bf08
  3b3004:	48 8d 35 be d7 f9 00                            	lea    rsi,[rip+0xf9d7be]        # 0x13507c9
  3b300b:	ba 53 15 00 00                                  	mov    edx,0x1553
  3b3010:	89 c1                                           	mov    ecx,eax
  3b3012:	89 c3                                           	mov    ebx,eax
  3b3014:	31 c0                                           	xor    eax,eax
  3b3016:	e8 f5 a3 ea ff                                  	call   0x25d410
  3b301b:	4c 8d 2d ee 92 56 03                            	lea    r13,[rip+0x35692ee]        # 0x391c310
  3b3022:	eb 42                                           	jmp    0x3b3066
  3b3024:	48 63 55 cc                                     	movsxd rdx,DWORD PTR [rbp-0x34]
  3b3028:	4c 8d 2d e1 92 56 03                            	lea    r13,[rip+0x35692e1]        # 0x391c310
  3b302f:	44 39 f2                                        	cmp    edx,r14d
  3b3032:	7f 32                                           	jg     0x3b3066
  3b3034:	48 8b 75 a8                                     	mov    rsi,QWORD PTR [rbp-0x58]
  3b3038:	48 c1 e2 04                                     	shl    rdx,0x4
  3b303c:	4c 89 ff                                        	mov    rdi,r15
  3b303f:	e8 fc 09 00 00                                  	call   0x3b3a40
  3b3044:	85 c0                                           	test   eax,eax
  3b3046:	74 1e                                           	je     0x3b3066
  3b3048:	48 8d 3d b9 8e f6 00                            	lea    rdi,[rip+0xf68eb9]        # 0x131bf08
  3b304f:	48 8d 35 73 d7 f9 00                            	lea    rsi,[rip+0xf9d773]        # 0x13507c9
  3b3056:	ba 62 15 00 00                                  	mov    edx,0x1562
  3b305b:	89 c1                                           	mov    ecx,eax
  3b305d:	89 c3                                           	mov    ebx,eax
  3b305f:	31 c0                                           	xor    eax,eax
  3b3061:	e8 aa a3 ea ff                                  	call   0x25d410
  3b3066:	48 8d 35 53 2a 70 01                            	lea    rsi,[rip+0x1702a53]        # 0x1ab5ac0
  3b306d:	4c 89 ff                                        	mov    rdi,r15
  3b3070:	e8 7b 5d 85 00                                  	call   0xc08df0
  3b3075:	e9 1d fe ff ff                                  	jmp    0x3b2e97
  3b307a:	e8 31 a6 34 00                                  	call   0x6fd6b0
  3b307f:	0f 0b                                           	ud2
  3b3081:	90                                              	nop
  3b3082:	90                                              	nop
  3b3083:	90                                              	nop
  3b3084:	90                                              	nop
  3b3085:	90                                              	nop
  3b3086:	90                                              	nop
  3b3087:	90                                              	nop
  3b3088:	90                                              	nop
  3b3089:	90                                              	nop
  3b308a:	90                                              	nop
  3b308b:	90                                              	nop
  3b308c:	90                                              	nop
  3b308d:	90                                              	nop
  3b308e:	90                                              	nop
  3b308f:	90                                              	nop
  3b3090:	55                                              	push   rbp
  3b3091:	48 89 e5                                        	mov    rbp,rsp
  3b3094:	41 57                                           	push   r15
  3b3096:	41 56                                           	push   r14
  3b3098:	41 55                                           	push   r13
  3b309a:	41 54                                           	push   r12
  3b309c:	53                                              	push   rbx
  3b309d:	48 83 ec 48                                     	sub    rsp,0x48
  3b30a1:	4c 8d 2d 68 92 56 03                            	lea    r13,[rip+0x3569268]        # 0x391c310
  3b30a8:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  3b30ac:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  3b30b0:	4c 8b 76 10                                     	mov    r14,QWORD PTR [rsi+0x10]
  3b30b4:	4c 8b 66 20                                     	mov    r12,QWORD PTR [rsi+0x20]
  3b30b8:	44 8b 3e                                        	mov    r15d,DWORD PTR [rsi]
  3b30bb:	8b 7e 08                                        	mov    edi,DWORD PTR [rsi+0x8]
  3b30be:	8b 56 18                                        	mov    edx,DWORD PTR [rsi+0x18]
  3b30c1:	c7 45 cc 00 00 00 00                            	mov    DWORD PTR [rbp-0x34],0x0
  3b30c8:	4d 85 f6                                        	test   r14,r14
  3b30cb:	0f 95 c0                                        	setne  al
  3b30ce:	4d 85 e4                                        	test   r12,r12
  3b30d1:	0f 95 c1                                        	setne  cl
  3b30d4:	84 c8                                           	test   al,cl
  3b30d6:	75 1f                                           	jne    0x3b30f7
  3b30d8:	48 8d 3d 29 8e f6 00                            	lea    rdi,[rip+0xf68e29]        # 0x131bf08
  3b30df:	48 8d 35 e5 63 ef 00                            	lea    rsi,[rip+0xef63e5]        # 0x12a94cb
  3b30e6:	bb 0e 00 00 00                                  	mov    ebx,0xe
  3b30eb:	ba 66 14 00 00                                  	mov    edx,0x1466
  3b30f0:	b9 0e 00 00 00                                  	mov    ecx,0xe
  3b30f5:	eb 33                                           	jmp    0x3b312a
  3b30f7:	89 7d b4                                        	mov    DWORD PTR [rbp-0x4c],edi
  3b30fa:	48 89 55 a0                                     	mov    QWORD PTR [rbp-0x60],rdx
  3b30fe:	48 8d 55 b8                                     	lea    rdx,[rbp-0x48]
  3b3102:	44 89 ff                                        	mov    edi,r15d
  3b3105:	be 15 00 00 00                                  	mov    esi,0x15
  3b310a:	e8 51 91 18 00                                  	call   0x53c260
  3b310f:	85 c0                                           	test   eax,eax
  3b3111:	74 3d                                           	je     0x3b3150
  3b3113:	89 c3                                           	mov    ebx,eax
  3b3115:	48 8d 3d ec 8d f6 00                            	lea    rdi,[rip+0xf68dec]        # 0x131bf08
  3b311c:	48 8d 35 a8 63 ef 00                            	lea    rsi,[rip+0xef63a8]        # 0x12a94cb
  3b3123:	ba 6e 14 00 00                                  	mov    edx,0x146e
  3b3128:	89 c1                                           	mov    ecx,eax
  3b312a:	31 c0                                           	xor    eax,eax
  3b312c:	e8 df a2 ea ff                                  	call   0x25d410
  3b3131:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  3b3135:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  3b3139:	0f 85 c4 02 00 00                               	jne    0x3b3403
  3b313f:	89 d8                                           	mov    eax,ebx
  3b3141:	48 83 c4 48                                     	add    rsp,0x48
  3b3145:	5b                                              	pop    rbx
  3b3146:	41 5c                                           	pop    r12
  3b3148:	41 5d                                           	pop    r13
  3b314a:	41 5e                                           	pop    r14
  3b314c:	41 5f                                           	pop    r15
  3b314e:	5d                                              	pop    rbp
  3b314f:	c3                                              	ret
  3b3150:	44 89 ff                                        	mov    edi,r15d
  3b3153:	e8 b8 4f 1f 00                                  	call   0x5a8110
  3b3158:	83 f8 ff                                        	cmp    eax,0xffffffff
  3b315b:	74 3f                                           	je     0x3b319c
  3b315d:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  3b3161:	48 8b 98 48 0c 00 00                            	mov    rbx,QWORD PTR [rax+0xc48]
  3b3168:	48 85 db                                        	test   rbx,rbx
  3b316b:	74 49                                           	je     0x3b31b6
  3b316d:	48 8b 45 a0                                     	mov    rax,QWORD PTR [rbp-0x60]
  3b3171:	85 c0                                           	test   eax,eax
  3b3173:	7e 08                                           	jle    0x3b317d
  3b3175:	3b 83 28 02 00 00                               	cmp    eax,DWORD PTR [rbx+0x228]
  3b317b:	7e 53                                           	jle    0x3b31d0
  3b317d:	48 8d 3d 84 8d f6 00                            	lea    rdi,[rip+0xf68d84]        # 0x131bf08
  3b3184:	48 8d 35 40 63 ef 00                            	lea    rsi,[rip+0xef6340]        # 0x12a94cb
  3b318b:	bb 16 00 00 00                                  	mov    ebx,0x16
  3b3190:	ba 84 14 00 00                                  	mov    edx,0x1484
  3b3195:	b9 16 00 00 00                                  	mov    ecx,0x16
  3b319a:	eb 5f                                           	jmp    0x3b31fb
  3b319c:	48 8d 3d 65 8d f6 00                            	lea    rdi,[rip+0xf68d65]        # 0x131bf08
  3b31a3:	48 8d 35 21 63 ef 00                            	lea    rsi,[rip+0xef6321]        # 0x12a94cb
  3b31aa:	bb 03 00 00 00                                  	mov    ebx,0x3
  3b31af:	ba 75 14 00 00                                  	mov    edx,0x1475
  3b31b4:	eb 40                                           	jmp    0x3b31f6
  3b31b6:	48 8d 3d 4b 8d f6 00                            	lea    rdi,[rip+0xf68d4b]        # 0x131bf08
  3b31bd:	48 8d 35 07 63 ef 00                            	lea    rsi,[rip+0xef6307]        # 0x12a94cb
  3b31c4:	bb 03 00 00 00                                  	mov    ebx,0x3
  3b31c9:	ba 7d 14 00 00                                  	mov    edx,0x147d
  3b31ce:	eb 26                                           	jmp    0x3b31f6
  3b31d0:	8b 4d b4                                        	mov    ecx,DWORD PTR [rbp-0x4c]
  3b31d3:	c1 f9 10                                        	sar    ecx,0x10
  3b31d6:	81 f9 80 00 00 00                               	cmp    ecx,0x80
  3b31dc:	72 7f                                           	jb     0x3b325d
  3b31de:	48 8d 3d 23 8d f6 00                            	lea    rdi,[rip+0xf68d23]        # 0x131bf08
  3b31e5:	48 8d 35 df 62 ef 00                            	lea    rsi,[rip+0xef62df]        # 0x12a94cb
  3b31ec:	bb 03 00 00 00                                  	mov    ebx,0x3
  3b31f1:	ba 8d 14 00 00                                  	mov    edx,0x148d
  3b31f6:	b9 03 00 00 00                                  	mov    ecx,0x3
  3b31fb:	31 c0                                           	xor    eax,eax
  3b31fd:	e8 0e a2 ea ff                                  	call   0x25d410
  3b3202:	bf 48 01 00 00                                  	mov    edi,0x148
  3b3207:	48 03 7d b8                                     	add    rdi,QWORD PTR [rbp-0x48]
  3b320b:	31 f6                                           	xor    esi,esi
  3b320d:	31 d2                                           	xor    edx,edx
  3b320f:	31 c9                                           	xor    ecx,ecx
  3b3211:	e8 ea 37 11 00                                  	call   0x4c6a00
  3b3216:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  3b321a:	ff 88 58 03 00 00                               	dec    DWORD PTR [rax+0x358]
  3b3220:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  3b3224:	f6 87 b1 00 00 00 20                            	test   BYTE PTR [rdi+0xb1],0x20
  3b322b:	74 19                                           	je     0x3b3246
  3b322d:	83 bf 58 03 00 00 00                            	cmp    DWORD PTR [rdi+0x358],0x0
  3b3234:	75 10                                           	jne    0x3b3246
  3b3236:	48 81 c7 58 03 00 00                            	add    rdi,0x358
  3b323d:	e8 ce 36 85 00                                  	call   0xc06910
  3b3242:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  3b3246:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  3b324d:	31 f6                                           	xor    esi,esi
  3b324f:	31 d2                                           	xor    edx,edx
  3b3251:	31 c9                                           	xor    ecx,ecx
  3b3253:	e8 48 3d 11 00                                  	call   0x4c6fa0
  3b3258:	e9 d4 fe ff ff                                  	jmp    0x3b3131
  3b325d:	48 8d 04 c5 00 00 00 00                         	lea    rax,[rax*8+0x0]
  3b3265:	48 8d 35 54 28 70 01                            	lea    rsi,[rip+0x1702854]        # 0x1ab5ac0
  3b326c:	ba 02 01 00 00                                  	mov    edx,0x102
  3b3271:	48 89 4d 98                                     	mov    QWORD PTR [rbp-0x68],rcx
  3b3275:	48 8d 3c 40                                     	lea    rdi,[rax+rax*2]
  3b3279:	e8 d2 58 85 00                                  	call   0xc08b50
  3b327e:	8b 8b 20 02 00 00                               	mov    ecx,DWORD PTR [rbx+0x220]
  3b3284:	48 89 45 a8                                     	mov    QWORD PTR [rbp-0x58],rax
  3b3288:	c1 e1 07                                        	shl    ecx,0x7
  3b328b:	85 c9                                           	test   ecx,ecx
  3b328d:	0f 8e ce 00 00 00                               	jle    0x3b3361
  3b3293:	44 8b 7d b4                                     	mov    r15d,DWORD PTR [rbp-0x4c]
  3b3297:	8b 45 98                                        	mov    eax,DWORD PTR [rbp-0x68]
  3b329a:	45 31 ed                                        	xor    r13d,r13d
  3b329d:	41 81 e7 00 00 ff ff                            	and    r15d,0xffff0000
  3b32a4:	48 89 45 90                                     	mov    QWORD PTR [rbp-0x70],rax
  3b32a8:	eb 1e                                           	jmp    0x3b32c8
  3b32aa:	48 8b 7d c0                                     	mov    rdi,QWORD PTR [rbp-0x40]
  3b32ae:	e8 fd 6b fe ff                                  	call   0x399eb0
  3b32b3:	8b 83 20 02 00 00                               	mov    eax,DWORD PTR [rbx+0x220]
  3b32b9:	41 ff c5                                        	inc    r13d
  3b32bc:	c1 e0 07                                        	shl    eax,0x7
  3b32bf:	41 39 c5                                        	cmp    r13d,eax
  3b32c2:	0f 8d 99 00 00 00                               	jge    0x3b3361
  3b32c8:	48 89 df                                        	mov    rdi,rbx
  3b32cb:	44 89 ee                                        	mov    esi,r13d
  3b32ce:	ba 60 01 00 00                                  	mov    edx,0x160
  3b32d3:	48 8d 4d c0                                     	lea    rcx,[rbp-0x40]
  3b32d7:	e8 14 6e fe ff                                  	call   0x39a0f0
  3b32dc:	48 85 c0                                        	test   rax,rax
  3b32df:	74 d2                                           	je     0x3b32b3
  3b32e1:	8b 48 08                                        	mov    ecx,DWORD PTR [rax+0x8]
  3b32e4:	44 09 f9                                        	or     ecx,r15d
  3b32e7:	39 4d b4                                        	cmp    DWORD PTR [rbp-0x4c],ecx
  3b32ea:	75 be                                           	jne    0x3b32aa
  3b32ec:	48 8b 48 28                                     	mov    rcx,QWORD PTR [rax+0x28]
  3b32f0:	48 8b 55 90                                     	mov    rdx,QWORD PTR [rbp-0x70]
  3b32f4:	48 8b 0c d1                                     	mov    rcx,QWORD PTR [rcx+rdx*8]
  3b32f8:	48 85 c9                                        	test   rcx,rcx
  3b32fb:	74 ad                                           	je     0x3b32aa
  3b32fd:	48 8b 49 20                                     	mov    rcx,QWORD PTR [rcx+0x20]
  3b3301:	4c 8b 55 a0                                     	mov    r10,QWORD PTR [rbp-0x60]
  3b3305:	4c 8b 5d a8                                     	mov    r11,QWORD PTR [rbp-0x58]
  3b3309:	48 8b 5d 98                                     	mov    rbx,QWORD PTR [rbp-0x68]
  3b330d:	8b 09                                           	mov    ecx,DWORD PTR [rcx]
  3b330f:	85 c9                                           	test   ecx,ecx
  3b3311:	74 45                                           	je     0x3b3358
  3b3313:	31 d2                                           	xor    edx,edx
  3b3315:	eb 09                                           	jmp    0x3b3320
  3b3317:	ff c2                                           	inc    edx
  3b3319:	89 55 cc                                        	mov    DWORD PTR [rbp-0x34],edx
  3b331c:	39 d1                                           	cmp    ecx,edx
  3b331e:	74 38                                           	je     0x3b3358
  3b3320:	44 39 d2                                        	cmp    edx,r10d
  3b3323:	7d f2                                           	jge    0x3b3317
  3b3325:	8d 3c 13                                        	lea    edi,[rbx+rdx*1]
  3b3328:	48 8b 70 20                                     	mov    rsi,QWORD PTR [rax+0x20]
  3b332c:	4c 63 ca                                        	movsxd r9,edx
  3b332f:	48 63 ff                                        	movsxd rdi,edi
  3b3332:	4f 8d 0c 49                                     	lea    r9,[r9+r9*2]
  3b3336:	48 8d 3c bf                                     	lea    rdi,[rdi+rdi*4]
  3b333a:	44 8b 44 fe 20                                  	mov    r8d,DWORD PTR [rsi+rdi*8+0x20]
  3b333f:	47 89 04 cb                                     	mov    DWORD PTR [r11+r9*8],r8d
  3b3343:	4c 8b 44 fe 08                                  	mov    r8,QWORD PTR [rsi+rdi*8+0x8]
  3b3348:	4f 89 44 cb 08                                  	mov    QWORD PTR [r11+r9*8+0x8],r8
  3b334d:	48 8b 34 fe                                     	mov    rsi,QWORD PTR [rsi+rdi*8]
  3b3351:	4b 89 74 cb 10                                  	mov    QWORD PTR [r11+r9*8+0x10],rsi
  3b3356:	eb bf                                           	jmp    0x3b3317
  3b3358:	48 8b 7d c0                                     	mov    rdi,QWORD PTR [rbp-0x40]
  3b335c:	e8 4f 6b fe ff                                  	call   0x399eb0
  3b3361:	48 8d 7d cc                                     	lea    rdi,[rbp-0x34]
  3b3365:	ba 04 00 00 00                                  	mov    edx,0x4
  3b336a:	4c 89 e6                                        	mov    rsi,r12
  3b336d:	e8 ce 06 00 00                                  	call   0x3b3a40
  3b3372:	85 c0                                           	test   eax,eax
  3b3374:	74 2b                                           	je     0x3b33a1
  3b3376:	48 8d 3d 8b 8b f6 00                            	lea    rdi,[rip+0xf68b8b]        # 0x131bf08
  3b337d:	48 8d 35 47 61 ef 00                            	lea    rsi,[rip+0xef6147]        # 0x12a94cb
  3b3384:	ba d1 14 00 00                                  	mov    edx,0x14d1
  3b3389:	89 c1                                           	mov    ecx,eax
  3b338b:	89 c3                                           	mov    ebx,eax
  3b338d:	31 c0                                           	xor    eax,eax
  3b338f:	e8 7c a0 ea ff                                  	call   0x25d410
  3b3394:	4c 8d 2d 75 8f 56 03                            	lea    r13,[rip+0x3568f75]        # 0x391c310
  3b339b:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  3b339f:	eb 51                                           	jmp    0x3b33f2
  3b33a1:	48 63 45 cc                                     	movsxd rax,DWORD PTR [rbp-0x34]
  3b33a5:	4c 8d 2d 64 8f 56 03                            	lea    r13,[rip+0x3568f64]        # 0x391c310
  3b33ac:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  3b33b0:	31 db                                           	xor    ebx,ebx
  3b33b2:	3b 45 a0                                        	cmp    eax,DWORD PTR [rbp-0x60]
  3b33b5:	7f 3b                                           	jg     0x3b33f2
  3b33b7:	48 c1 e0 03                                     	shl    rax,0x3
  3b33bb:	4c 89 f6                                        	mov    rsi,r14
  3b33be:	49 89 ff                                        	mov    r15,rdi
  3b33c1:	48 8d 14 40                                     	lea    rdx,[rax+rax*2]
  3b33c5:	e8 76 06 00 00                                  	call   0x3b3a40
  3b33ca:	4c 89 ff                                        	mov    rdi,r15
  3b33cd:	85 c0                                           	test   eax,eax
  3b33cf:	74 21                                           	je     0x3b33f2
  3b33d1:	48 8d 3d 30 8b f6 00                            	lea    rdi,[rip+0xf68b30]        # 0x131bf08
  3b33d8:	48 8d 35 ec 60 ef 00                            	lea    rsi,[rip+0xef60ec]        # 0x12a94cb
  3b33df:	ba e0 14 00 00                                  	mov    edx,0x14e0
  3b33e4:	89 c1                                           	mov    ecx,eax
  3b33e6:	89 c3                                           	mov    ebx,eax
  3b33e8:	31 c0                                           	xor    eax,eax
  3b33ea:	e8 21 a0 ea ff                                  	call   0x25d410
  3b33ef:	4c 89 ff                                        	mov    rdi,r15
  3b33f2:	48 8d 35 c7 26 70 01                            	lea    rsi,[rip+0x17026c7]        # 0x1ab5ac0
  3b33f9:	e8 f2 59 85 00                                  	call   0xc08df0
  3b33fe:	e9 ff fd ff ff                                  	jmp    0x3b3202
  3b3403:	e8 a8 a2 34 00                                  	call   0x6fd6b0
  3b3408:	0f 0b                                           	ud2
  3b340a:	90                                              	nop
  3b340b:	90                                              	nop
  3b340c:	90                                              	nop
  3b340d:	90                                              	nop
  3b340e:	90                                              	nop
  3b340f:	90                                              	nop
  3b3410:	55                                              	push   rbp
  3b3411:	48 89 e5                                        	mov    rbp,rsp
  3b3414:	41 57                                           	push   r15
  3b3416:	41 56                                           	push   r14
  3b3418:	41 55                                           	push   r13
  3b341a:	41 54                                           	push   r12
  3b341c:	53                                              	push   rbx
  3b341d:	48 83 ec 38                                     	sub    rsp,0x38
  3b3421:	48 8d 05 e8 8e 56 03                            	lea    rax,[rip+0x3568ee8]        # 0x391c310
  3b3428:	89 7d b8                                        	mov    DWORD PTR [rbp-0x48],edi
  3b342b:	48 89 f3                                        	mov    rbx,rsi
  3b342e:	48 8d 75 cc                                     	lea    rsi,[rbp-0x34]
  3b3432:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  3b3435:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  3b3439:	65 48 8b 04 25 00 00 00 00                      	mov    rax,QWORD PTR gs:0x0
  3b3442:	48 8b 78 08                                     	mov    rdi,QWORD PTR [rax+0x8]
  3b3446:	48 89 7d a8                                     	mov    QWORD PTR [rbp-0x58],rdi
  3b344a:	e8 71 4d 64 00                                  	call   0x9f81c0
  3b344f:	85 c0                                           	test   eax,eax
  3b3451:	48 8d 3d 90 be 11 03                            	lea    rdi,[rip+0x311be90]        # 0x34cf2e8
  3b3458:	0f 95 45 be                                     	setne  BYTE PTR [rbp-0x42]
  3b345c:	81 7d cc 00 00 00 01                            	cmp    DWORD PTR [rbp-0x34],0x1000000
  3b3463:	0f 93 45 bf                                     	setae  BYTE PTR [rbp-0x41]
  3b3467:	31 f6                                           	xor    esi,esi
  3b3469:	31 d2                                           	xor    edx,edx
  3b346b:	31 c9                                           	xor    ecx,ecx
  3b346d:	e8 8e 35 11 00                                  	call   0x4c6a00
  3b3472:	83 bb a0 04 00 00 00                            	cmp    DWORD PTR [rbx+0x4a0],0x0
  3b3479:	0f 84 83 00 00 00                               	je     0x3b3502
  3b347f:	41 bc 10 00 00 00                               	mov    r12d,0x10
  3b3485:	7e 23                                           	jle    0x3b34aa
  3b3487:	48 8d 05 3a c4 11 03                            	lea    rax,[rip+0x311c43a]        # 0x34cf8c8
  3b348e:	31 c9                                           	xor    ecx,ecx
  3b3490:	48 39 c3                                        	cmp    rbx,rax
  3b3493:	44 0f 44 e1                                     	cmove  r12d,ecx
  3b3497:	4c 8d 3d 72 8e 56 03                            	lea    r15,[rip+0x3568e72]        # 0x391c310
  3b349e:	48 8d 3d 43 be 11 03                            	lea    rdi,[rip+0x311be43]        # 0x34cf2e8
  3b34a5:	e9 f7 02 00 00                                  	jmp    0x3b37a1
  3b34aa:	4c 8d 2d 3f be 11 03                            	lea    r13,[rip+0x311be3f]        # 0x34cf2f0
  3b34b1:	4c 8d 35 18 be 11 03                            	lea    r14,[rip+0x311be18]        # 0x34cf2d0
  3b34b8:	4c 8d 3d 29 be 11 03                            	lea    r15,[rip+0x311be29]        # 0x34cf2e8
  3b34bf:	90                                              	nop
  3b34c0:	4c 89 ef                                        	mov    rdi,r13
  3b34c3:	4c 89 f6                                        	mov    rsi,r14
  3b34c6:	31 d2                                           	xor    edx,edx
  3b34c8:	e8 b3 b2 38 00                                  	call   0x73e780
  3b34cd:	83 bb a0 04 00 00 00                            	cmp    DWORD PTR [rbx+0x4a0],0x0
  3b34d4:	41 89 c4                                        	mov    r12d,eax
  3b34d7:	75 be                                           	jne    0x3b3497
  3b34d9:	4c 89 ff                                        	mov    rdi,r15
  3b34dc:	31 f6                                           	xor    esi,esi
  3b34de:	31 d2                                           	xor    edx,edx
  3b34e0:	31 c9                                           	xor    ecx,ecx
  3b34e2:	e8 b9 3a 11 00                                  	call   0x4c6fa0
  3b34e7:	4c 89 ff                                        	mov    rdi,r15
  3b34ea:	31 f6                                           	xor    esi,esi
  3b34ec:	31 d2                                           	xor    edx,edx
  3b34ee:	31 c9                                           	xor    ecx,ecx
  3b34f0:	e8 0b 35 11 00                                  	call   0x4c6a00
  3b34f5:	83 bb a0 04 00 00 00                            	cmp    DWORD PTR [rbx+0x4a0],0x0
  3b34fc:	74 04                                           	je     0x3b3502
  3b34fe:	7e c0                                           	jle    0x3b34c0
  3b3500:	eb 85                                           	jmp    0x3b3487
  3b3502:	80 3d c7 d4 11 03 00                            	cmp    BYTE PTR [rip+0x311d4c7],0x0        # 0x34d09d0
  3b3509:	75 1a                                           	jne    0x3b3525
  3b350b:	48 8d 3d de bd 11 03                            	lea    rdi,[rip+0x311bdde]        # 0x34cf2f0
  3b3512:	48 8d 35 df b7 fd 00                            	lea    rsi,[rip+0xfdb7df]        # 0x138ecf8
  3b3519:	e8 02 b0 38 00                                  	call   0x73e520
  3b351e:	c6 05 ab d4 11 03 01                            	mov    BYTE PTR [rip+0x311d4ab],0x1        # 0x34d09d0
  3b3525:	4c 8d 25 d3 b7 fd 00                            	lea    r12,[rip+0xfdb7d3]        # 0x138ecff
  3b352c:	48 8d bb d8 00 00 00                            	lea    rdi,[rbx+0xd8]
  3b3533:	c7 83 a0 04 00 00 ff ff ff ff                   	mov    DWORD PTR [rbx+0x4a0],0xffffffff
  3b353d:	4c 8d 73 40                                     	lea    r14,[rbx+0x40]
  3b3541:	4c 8d bb 80 00 00 00                            	lea    r15,[rbx+0x80]
  3b3548:	31 d2                                           	xor    edx,edx
  3b354a:	31 c9                                           	xor    ecx,ecx
  3b354c:	4c 89 e6                                        	mov    rsi,r12
  3b354f:	e8 7c 48 11 00                                  	call   0x4c7dd0
  3b3554:	48 8d bb f8 00 00 00                            	lea    rdi,[rbx+0xf8]
  3b355b:	4c 89 e6                                        	mov    rsi,r12
  3b355e:	48 c7 03 00 00 00 00                            	mov    QWORD PTR [rbx],0x0
  3b3565:	48 89 5b 08                                     	mov    QWORD PTR [rbx+0x8],rbx
  3b3569:	48 c7 43 40 00 00 00 00                         	mov    QWORD PTR [rbx+0x40],0x0
  3b3571:	4c 89 73 48                                     	mov    QWORD PTR [rbx+0x48],r14
  3b3575:	48 c7 83 80 00 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x80],0x0
  3b3580:	4c 89 bb 88 00 00 00                            	mov    QWORD PTR [rbx+0x88],r15
  3b3587:	c7 83 c0 01 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0x1c0],0x0
  3b3591:	c7 83 d0 01 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0x1d0],0x0
  3b359b:	31 d2                                           	xor    edx,edx
  3b359d:	31 c9                                           	xor    ecx,ecx
  3b359f:	e8 2c 48 11 00                                  	call   0x4c7dd0
  3b35a4:	48 8d 43 10                                     	lea    rax,[rbx+0x10]
  3b35a8:	48 8d 7b 50                                     	lea    rdi,[rbx+0x50]
  3b35ac:	48 8d b3 90 00 00 00                            	lea    rsi,[rbx+0x90]
  3b35b3:	48 c7 43 10 00 00 00 00                         	mov    QWORD PTR [rbx+0x10],0x0
  3b35bb:	31 d2                                           	xor    edx,edx
  3b35bd:	31 c9                                           	xor    ecx,ecx
  3b35bf:	48 89 43 18                                     	mov    QWORD PTR [rbx+0x18],rax
  3b35c3:	48 c7 43 50 00 00 00 00                         	mov    QWORD PTR [rbx+0x50],0x0
  3b35cb:	48 89 7b 58                                     	mov    QWORD PTR [rbx+0x58],rdi
  3b35cf:	48 c7 83 90 00 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x90],0x0
  3b35da:	48 89 b3 98 00 00 00                            	mov    QWORD PTR [rbx+0x98],rsi
  3b35e1:	48 8d bb 18 01 00 00                            	lea    rdi,[rbx+0x118]
  3b35e8:	4c 89 e6                                        	mov    rsi,r12
  3b35eb:	c7 83 c4 01 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0x1c4],0x0
  3b35f5:	c7 83 d4 01 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0x1d4],0x0
  3b35ff:	e8 cc 47 11 00                                  	call   0x4c7dd0
  3b3604:	48 8d 43 20                                     	lea    rax,[rbx+0x20]
  3b3608:	48 8d 7b 60                                     	lea    rdi,[rbx+0x60]
  3b360c:	48 8d b3 a0 00 00 00                            	lea    rsi,[rbx+0xa0]
  3b3613:	48 c7 43 20 00 00 00 00                         	mov    QWORD PTR [rbx+0x20],0x0
  3b361b:	31 d2                                           	xor    edx,edx
  3b361d:	31 c9                                           	xor    ecx,ecx
  3b361f:	48 89 43 28                                     	mov    QWORD PTR [rbx+0x28],rax
  3b3623:	48 c7 43 60 00 00 00 00                         	mov    QWORD PTR [rbx+0x60],0x0
  3b362b:	48 89 7b 68                                     	mov    QWORD PTR [rbx+0x68],rdi
  3b362f:	48 c7 83 a0 00 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0xa0],0x0
  3b363a:	48 89 b3 a8 00 00 00                            	mov    QWORD PTR [rbx+0xa8],rsi
  3b3641:	48 8d bb 38 01 00 00                            	lea    rdi,[rbx+0x138]
  3b3648:	4c 89 e6                                        	mov    rsi,r12
  3b364b:	c7 83 c8 01 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0x1c8],0x0
  3b3655:	c7 83 d8 01 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0x1d8],0x0
  3b365f:	e8 6c 47 11 00                                  	call   0x4c7dd0
  3b3664:	48 8d 43 30                                     	lea    rax,[rbx+0x30]
  3b3668:	4c 8d 43 70                                     	lea    r8,[rbx+0x70]
  3b366c:	48 8d bb b0 00 00 00                            	lea    rdi,[rbx+0xb0]
  3b3673:	48 c7 43 30 00 00 00 00                         	mov    QWORD PTR [rbx+0x30],0x0
  3b367b:	31 f6                                           	xor    esi,esi
  3b367d:	31 d2                                           	xor    edx,edx
  3b367f:	31 c9                                           	xor    ecx,ecx
  3b3681:	48 89 43 38                                     	mov    QWORD PTR [rbx+0x38],rax
  3b3685:	48 c7 43 70 00 00 00 00                         	mov    QWORD PTR [rbx+0x70],0x0
  3b368d:	4c 89 43 78                                     	mov    QWORD PTR [rbx+0x78],r8
  3b3691:	48 c7 83 b0 00 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0xb0],0x0
  3b369c:	48 89 bb b8 00 00 00                            	mov    QWORD PTR [rbx+0xb8],rdi
  3b36a3:	48 8d 3d 3e bc 11 03                            	lea    rdi,[rip+0x311bc3e]        # 0x34cf2e8
  3b36aa:	c7 83 cc 01 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0x1cc],0x0
  3b36b4:	c7 83 dc 01 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0x1dc],0x0
  3b36be:	e8 dd 38 11 00                                  	call   0x4c6fa0
  3b36c3:	4c 8d 3d 24 42 f3 00                            	lea    r15,[rip+0xf34224]        # 0x12e78ee
  3b36ca:	4c 8d 2d d0 a3 f0 00                            	lea    r13,[rip+0xf0a3d0]        # 0x12bdaa1
  3b36d1:	4c 8d 35 ea a1 eb 00                            	lea    r14,[rip+0xeba1ea]        # 0x126d8c2
  3b36d8:	48 c7 45 c0 00 00 00 00                         	mov    QWORD PTR [rbp-0x40],0x0
  3b36e0:	31 c0                                           	xor    eax,eax
  3b36e2:	48 8d b3 b0 04 00 00                            	lea    rsi,[rbx+0x4b0]
  3b36e9:	48 89 9b c8 04 00 00                            	mov    QWORD PTR [rbx+0x4c8],rbx
  3b36f0:	48 8d 8b b8 04 00 00                            	lea    rcx,[rbx+0x4b8]
  3b36f7:	48 8d 3d 92 e0 ea ff                            	lea    rdi,[rip+0xffffffffffeae092]        # 0x261790
  3b36fe:	48 8d 55 c0                                     	lea    rdx,[rbp-0x40]
  3b3702:	45 31 c0                                        	xor    r8d,r8d
  3b3705:	45 31 c9                                        	xor    r9d,r9d
  3b3708:	6a 00                                           	push   0x0
  3b370a:	41 57                                           	push   r15
  3b370c:	41 55                                           	push   r13
  3b370e:	41 56                                           	push   r14
  3b3710:	e8 bb 2b 57 00                                  	call   0x9262d0
  3b3715:	48 83 c4 20                                     	add    rsp,0x20
  3b3719:	85 c0                                           	test   eax,eax
  3b371b:	75 54                                           	jne    0x3b3771
  3b371d:	48 8d b3 28 05 00 00                            	lea    rsi,[rbx+0x528]
  3b3724:	48 c7 83 b0 04 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x4b0],0x0
  3b372f:	48 c7 45 c0 00 00 00 00                         	mov    QWORD PTR [rbp-0x40],0x0
  3b3737:	31 c0                                           	xor    eax,eax
  3b3739:	48 89 9b 40 05 00 00                            	mov    QWORD PTR [rbx+0x540],rbx
  3b3740:	48 8d 8b 30 05 00 00                            	lea    rcx,[rbx+0x530]
  3b3747:	48 8d 3d 42 e0 ea ff                            	lea    rdi,[rip+0xffffffffffeae042]        # 0x261790
  3b374e:	48 8d 55 c0                                     	lea    rdx,[rbp-0x40]
  3b3752:	45 31 c0                                        	xor    r8d,r8d
  3b3755:	45 31 c9                                        	xor    r9d,r9d
  3b3758:	48 89 75 b0                                     	mov    QWORD PTR [rbp-0x50],rsi
  3b375c:	6a 01                                           	push   0x1
  3b375e:	41 57                                           	push   r15
  3b3760:	41 55                                           	push   r13
  3b3762:	41 56                                           	push   r14
  3b3764:	e8 67 2b 57 00                                  	call   0x9262d0
  3b3769:	48 83 c4 20                                     	add    rsp,0x20
  3b376d:	85 c0                                           	test   eax,eax
  3b376f:	74 5a                                           	je     0x3b37cb
  3b3771:	4c 8d 3d 98 8b 56 03                            	lea    r15,[rip+0x3568b98]        # 0x391c310
  3b3778:	48 8d 1d 69 bb 11 03                            	lea    rbx,[rip+0x311bb69]        # 0x34cf2e8
  3b377f:	41 89 c4                                        	mov    r12d,eax
  3b3782:	31 f6                                           	xor    esi,esi
  3b3784:	31 d2                                           	xor    edx,edx
  3b3786:	31 c9                                           	xor    ecx,ecx
  3b3788:	48 89 df                                        	mov    rdi,rbx
  3b378b:	e8 70 32 11 00                                  	call   0x4c6a00
  3b3790:	48 8d 3d 59 bb 11 03                            	lea    rdi,[rip+0x311bb59]        # 0x34cf2f0
  3b3797:	31 f6                                           	xor    esi,esi
  3b3799:	e8 72 b8 38 00                                  	call   0x73f010
  3b379e:	48 89 df                                        	mov    rdi,rbx
  3b37a1:	31 f6                                           	xor    esi,esi
  3b37a3:	31 d2                                           	xor    edx,edx
  3b37a5:	31 c9                                           	xor    ecx,ecx
  3b37a7:	e8 f4 37 11 00                                  	call   0x4c6fa0
  3b37ac:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  3b37af:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  3b37b3:	0f 85 74 02 00 00                               	jne    0x3b3a2d
  3b37b9:	44 89 e0                                        	mov    eax,r12d
  3b37bc:	48 83 c4 38                                     	add    rsp,0x38
  3b37c0:	5b                                              	pop    rbx
  3b37c1:	41 5c                                           	pop    r12
  3b37c3:	41 5d                                           	pop    r13
  3b37c5:	41 5e                                           	pop    r14
  3b37c7:	41 5f                                           	pop    r15
  3b37c9:	5d                                              	pop    rbp
  3b37ca:	c3                                              	ret
  3b37cb:	44 0f b6 65 be                                  	movzx  r12d,BYTE PTR [rbp-0x42]
  3b37d0:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  3b37d4:	44 0a 65 bf                                     	or     r12b,BYTE PTR [rbp-0x41]
  3b37d8:	48 8d 3d 21 bb 11 03                            	lea    rdi,[rip+0x311bb21]        # 0x34cf300
  3b37df:	31 f6                                           	xor    esi,esi
  3b37e1:	31 d2                                           	xor    edx,edx
  3b37e3:	31 c9                                           	xor    ecx,ecx
  3b37e5:	48 c7 00 00 00 00 00                            	mov    QWORD PTR [rax],0x0
  3b37ec:	e8 2f 83 89 00                                  	call   0xc4bb20
  3b37f1:	48 83 3d df d1 11 03 00                         	cmp    QWORD PTR [rip+0x311d1df],0x0        # 0x34d09d8
  3b37f9:	4c 8d 3d 10 8b 56 03                            	lea    r15,[rip+0x3568b10]        # 0x391c310
  3b3800:	0f 85 57 01 00 00                               	jne    0x3b395d
  3b3806:	48 8d 35 a7 12 fb 00                            	lea    rsi,[rip+0xfb12a7]        # 0x1364ab4
  3b380d:	48 8d 15 0c 3b eb ff                            	lea    rdx,[rip+0xffffffffffeb3b0c]        # 0x267320
  3b3814:	48 8d 0d 8c a2 f0 00                            	lea    rcx,[rip+0xf0a28c]        # 0x12bdaa7
  3b381b:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  3b3821:	45 31 f6                                        	xor    r14d,r14d
  3b3824:	31 ff                                           	xor    edi,edi
  3b3826:	45 31 c0                                        	xor    r8d,r8d
  3b3829:	e8 12 a5 38 00                                  	call   0x73dd40
  3b382e:	48 8d 35 da d9 f3 00                            	lea    rsi,[rip+0xf3d9da]        # 0x12f120f
  3b3835:	48 8d 15 ec 3a eb ff                            	lea    rdx,[rip+0xffffffffffeb3aec]        # 0x267328
  3b383c:	48 8d 0d 54 72 ed 00                            	lea    rcx,[rip+0xed7254]        # 0x128aa97
  3b3843:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  3b3849:	48 89 05 88 d1 11 03                            	mov    QWORD PTR [rip+0x311d188],rax        # 0x34d09d8
  3b3850:	31 ff                                           	xor    edi,edi
  3b3852:	45 31 c0                                        	xor    r8d,r8d
  3b3855:	e8 e6 a4 38 00                                  	call   0x73dd40
  3b385a:	48 8d 35 0c f7 fe 00                            	lea    rsi,[rip+0xfef70c]        # 0x13a2f6d
  3b3861:	48 8d 15 c8 3a eb ff                            	lea    rdx,[rip+0xffffffffffeb3ac8]        # 0x267330
  3b3868:	48 8d 0d dd da f5 00                            	lea    rcx,[rip+0xf5dadd]        # 0x131134c
  3b386f:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  3b3875:	48 89 05 64 d1 11 03                            	mov    QWORD PTR [rip+0x311d164],rax        # 0x34d09e0
  3b387c:	31 ff                                           	xor    edi,edi
  3b387e:	45 31 c0                                        	xor    r8d,r8d
  3b3881:	e8 ba a4 38 00                                  	call   0x73dd40
  3b3886:	48 8d 35 11 3e f3 00                            	lea    rsi,[rip+0xf33e11]        # 0x12e769e
  3b388d:	48 8d 15 d4 1e eb ff                            	lea    rdx,[rip+0xffffffffffeb1ed4]        # 0x265768
  3b3894:	48 8d 0d 10 1d ee 00                            	lea    rcx,[rip+0xee1d10]        # 0x12955ab
  3b389b:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  3b38a1:	48 89 05 40 d1 11 03                            	mov    QWORD PTR [rip+0x311d140],rax        # 0x34d09e8
  3b38a8:	31 ff                                           	xor    edi,edi
  3b38aa:	45 31 c0                                        	xor    r8d,r8d
  3b38ad:	e8 8e a4 38 00                                  	call   0x73dd40
  3b38b2:	48 8d 35 6c 31 ec 00                            	lea    rsi,[rip+0xec316c]        # 0x1276a25
  3b38b9:	48 8d 15 b0 1e eb ff                            	lea    rdx,[rip+0xffffffffffeb1eb0]        # 0x265770
  3b38c0:	48 8d 0d bf 73 f8 00                            	lea    rcx,[rip+0xf873bf]        # 0x133ac86
  3b38c7:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  3b38cd:	48 89 05 1c d1 11 03                            	mov    QWORD PTR [rip+0x311d11c],rax        # 0x34d09f0
  3b38d4:	31 ff                                           	xor    edi,edi
  3b38d6:	45 31 c0                                        	xor    r8d,r8d
  3b38d9:	e8 62 a4 38 00                                  	call   0x73dd40
  3b38de:	48 8d 35 31 86 f6 00                            	lea    rsi,[rip+0xf68631]        # 0x131bf16
  3b38e5:	48 8d 15 4c 3a eb ff                            	lea    rdx,[rip+0xffffffffffeb3a4c]        # 0x267338
  3b38ec:	48 8d 0d 65 9f f2 00                            	lea    rcx,[rip+0xf29f65]        # 0x12dd858
  3b38f3:	41 b9 0f 27 00 00                               	mov    r9d,0x270f
  3b38f9:	48 89 05 f8 d0 11 03                            	mov    QWORD PTR [rip+0x311d0f8],rax        # 0x34d09f8
  3b3900:	31 ff                                           	xor    edi,edi
  3b3902:	45 31 c0                                        	xor    r8d,r8d
  3b3905:	e8 36 a4 38 00                                  	call   0x73dd40
  3b390a:	48 89 05 ef d0 11 03                            	mov    QWORD PTR [rip+0x311d0ef],rax        # 0x34d0a00
  3b3911:	48 8d 05 f8 d0 11 03                            	lea    rax,[rip+0x311d0f8]        # 0x34d0a10
  3b3918:	31 c9                                           	xor    ecx,ecx
  3b391a:	48 c7 05 9b d0 11 03 00 00 00 00                	mov    QWORD PTR [rip+0x311d09b],0x0        # 0x34d09c0
  3b3925:	66 66 2e 0f 1f 84 00 00 00 00 00                	data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b3930:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  3b3934:	48 89 c1                                        	mov    rcx,rax
  3b3937:	49 83 c6 f0                                     	add    r14,0xfffffffffffffff0
  3b393b:	48 83 c0 10                                     	add    rax,0x10
  3b393f:	49 81 fe 00 fc ff ff                            	cmp    r14,0xfffffffffffffc00
  3b3946:	75 e8                                           	jne    0x3b3930
  3b3948:	48 8d 05 c1 d0 11 03                            	lea    rax,[rip+0x311d0c1]        # 0x34d0a10
  3b394f:	4c 29 f0                                        	sub    rax,r14
  3b3952:	48 83 c0 f0                                     	add    rax,0xfffffffffffffff0
  3b3956:	48 89 05 6b d0 11 03                            	mov    QWORD PTR [rip+0x311d06b],rax        # 0x34d09c8
  3b395d:	48 8d 3d 9c b9 11 03                            	lea    rdi,[rip+0x311b99c]        # 0x34cf300
  3b3964:	31 f6                                           	xor    esi,esi
  3b3966:	31 d2                                           	xor    edx,edx
  3b3968:	e8 43 8b 89 00                                  	call   0xc4c4b0
  3b396d:	48 8d 3d 74 b9 11 03                            	lea    rdi,[rip+0x311b974]        # 0x34cf2e8
  3b3974:	31 f6                                           	xor    esi,esi
  3b3976:	31 d2                                           	xor    edx,edx
  3b3978:	31 c9                                           	xor    ecx,ecx
  3b397a:	e8 81 30 11 00                                  	call   0x4c6a00
  3b397f:	c7 83 a0 04 00 00 01 00 00 00                   	mov    DWORD PTR [rbx+0x4a0],0x1
  3b3989:	45 84 e4                                        	test   r12b,r12b
  3b398c:	75 10                                           	jne    0x3b399e
  3b398e:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  3b3992:	e8 e9 47 64 00                                  	call   0x9f8180
  3b3997:	48 89 83 a8 04 00 00                            	mov    QWORD PTR [rbx+0x4a8],rax
  3b399e:	83 7d b8 00                                     	cmp    DWORD PTR [rbp-0x48],0x0
  3b39a2:	74 73                                           	je     0x3b3a17
  3b39a4:	48 b8 01 00 00 00 01 00 00 00                   	movabs rax,0x100000001
  3b39ae:	48 ba 00 00 10 00 00 00 10 00                   	movabs rdx,0x10000000100000
  3b39b8:	48 b9 20 00 00 00 20 00 00 00                   	movabs rcx,0x2000000020
  3b39c2:	c7 83 ac 01 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0x1ac],0x0
  3b39cc:	c7 83 bc 01 00 00 00 00 10 00                   	mov    DWORD PTR [rbx+0x1bc],0x100000
  3b39d6:	c7 83 9c 01 00 00 00 00 10 00                   	mov    DWORD PTR [rbx+0x19c],0x100000
  3b39e0:	c7 83 7c 01 00 00 20 00 00 00                   	mov    DWORD PTR [rbx+0x17c],0x20
  3b39ea:	c7 83 8c 01 00 00 20 00 00 00                   	mov    DWORD PTR [rbx+0x18c],0x20
  3b39f4:	48 89 83 a4 01 00 00                            	mov    QWORD PTR [rbx+0x1a4],rax
  3b39fb:	48 89 93 b4 01 00 00                            	mov    QWORD PTR [rbx+0x1b4],rdx
  3b3a02:	48 89 93 94 01 00 00                            	mov    QWORD PTR [rbx+0x194],rdx
  3b3a09:	48 89 8b 74 01 00 00                            	mov    QWORD PTR [rbx+0x174],rcx
  3b3a10:	48 89 8b 84 01 00 00                            	mov    QWORD PTR [rbx+0x184],rcx
  3b3a17:	48 8d 3d d2 b8 11 03                            	lea    rdi,[rip+0x311b8d2]        # 0x34cf2f0
  3b3a1e:	31 f6                                           	xor    esi,esi
  3b3a20:	45 31 e4                                        	xor    r12d,r12d
  3b3a23:	e8 e8 b5 38 00                                  	call   0x73f010
  3b3a28:	e9 71 fa ff ff                                  	jmp    0x3b349e
  3b3a2d:	e8 7e 9c 34 00                                  	call   0x6fd6b0
  3b3a32:	0f 0b                                           	ud2
  3b3a34:	90                                              	nop
  3b3a35:	90                                              	nop
  3b3a36:	90                                              	nop
  3b3a37:	90                                              	nop
  3b3a38:	90                                              	nop
  3b3a39:	90                                              	nop
  3b3a3a:	90                                              	nop
  3b3a3b:	90                                              	nop
  3b3a3c:	90                                              	nop
  3b3a3d:	90                                              	nop
  3b3a3e:	90                                              	nop
  3b3a3f:	90                                              	nop
  3b3a40:	55                                              	push   rbp
  3b3a41:	48 89 e5                                        	mov    rbp,rsp
  3b3a44:	41 57                                           	push   r15
  3b3a46:	41 56                                           	push   r14
  3b3a48:	53                                              	push   rbx
  3b3a49:	50                                              	push   rax
  3b3a4a:	49 89 ff                                        	mov    r15,rdi
  3b3a4d:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  3b3a56:	49 89 f6                                        	mov    r14,rsi
  3b3a59:	48 8d 35 37 b8 f9 00                            	lea    rsi,[rip+0xf9b837]        # 0x134f297
  3b3a60:	48 89 d3                                        	mov    rbx,rdx
  3b3a63:	31 d2                                           	xor    edx,edx
  3b3a65:	e8 76 69 86 00                                  	call   0xc1a3e0
  3b3a6a:	4c 89 ff                                        	mov    rdi,r15
  3b3a6d:	4c 89 f6                                        	mov    rsi,r14
  3b3a70:	48 89 da                                        	mov    rdx,rbx
  3b3a73:	48 83 c4 08                                     	add    rsp,0x8
  3b3a77:	5b                                              	pop    rbx
  3b3a78:	41 5e                                           	pop    r14
  3b3a7a:	41 5f                                           	pop    r15
  3b3a7c:	5d                                              	pop    rbp
  3b3a7d:	e9 4e 57 ea ff                                  	jmp    0x2591d0
  3b3a82:	90                                              	nop
  3b3a83:	90                                              	nop
  3b3a84:	90                                              	nop
  3b3a85:	90                                              	nop
  3b3a86:	90                                              	nop
  3b3a87:	90                                              	nop
  3b3a88:	90                                              	nop
  3b3a89:	90                                              	nop
  3b3a8a:	90                                              	nop
  3b3a8b:	90                                              	nop
  3b3a8c:	90                                              	nop
  3b3a8d:	90                                              	nop
  3b3a8e:	90                                              	nop
  3b3a8f:	90                                              	nop
  3b3a90:	55                                              	push   rbp
  3b3a91:	48 89 e5                                        	mov    rbp,rsp
  3b3a94:	41 57                                           	push   r15
  3b3a96:	41 56                                           	push   r14
  3b3a98:	41 55                                           	push   r13
  3b3a9a:	41 54                                           	push   r12
  3b3a9c:	53                                              	push   rbx
  3b3a9d:	48 83 ec 78                                     	sub    rsp,0x78
  3b3aa1:	48 8d 05 68 88 56 03                            	lea    rax,[rip+0x3568868]        # 0x391c310
  3b3aa8:	48 89 8d 68 ff ff ff                            	mov    QWORD PTR [rbp-0x98],rcx
  3b3aaf:	48 b9 0d 00 00 00 00 00 00 02                   	movabs rcx,0x20000000000000d
  3b3ab9:	4c 89 c3                                        	mov    rbx,r8
  3b3abc:	45 31 ed                                        	xor    r13d,r13d
  3b3abf:	48 ff c1                                        	inc    rcx
  3b3ac2:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  3b3ac5:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  3b3ac9:	89 75 a4                                        	mov    DWORD PTR [rbp-0x5c],esi
  3b3acc:	48 63 f6                                        	movsxd rsi,esi
  3b3acf:	48 89 4d 90                                     	mov    QWORD PTR [rbp-0x70],rcx
  3b3ad3:	89 55 a0                                        	mov    DWORD PTR [rbp-0x60],edx
  3b3ad6:	48 89 f0                                        	mov    rax,rsi
  3b3ad9:	48 89 75 a8                                     	mov    QWORD PTR [rbp-0x58],rsi
  3b3add:	48 c1 e6 04                                     	shl    rsi,0x4
  3b3ae1:	48 c1 e0 05                                     	shl    rax,0x5
  3b3ae5:	48 89 75 98                                     	mov    QWORD PTR [rbp-0x68],rsi
  3b3ae9:	49 8d 84 00 d8 00 00 00                         	lea    rax,[r8+rax*1+0xd8]
  3b3af1:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  3b3af5:	89 f8                                           	mov    eax,edi
  3b3af7:	48 89 85 70 ff ff ff                            	mov    QWORD PTR [rbp-0x90],rax
  3b3afe:	eb 44                                           	jmp    0x3b3b44
  3b3b00:	8b 75 a4                                        	mov    esi,DWORD PTR [rbp-0x5c]
  3b3b03:	4c 89 e7                                        	mov    rdi,r12
  3b3b06:	48 89 d9                                        	mov    rcx,rbx
  3b3b09:	e8 32 09 00 00                                  	call   0x3b4440
  3b3b0e:	42 ff 84 b3 c0 01 00 00                         	inc    DWORD PTR [rbx+r14*4+0x1c0]
  3b3b16:	48 8b 7d 88                                     	mov    rdi,QWORD PTR [rbp-0x78]
  3b3b1a:	41 c7 44 24 38 01 00 00 00                      	mov    DWORD PTR [r12+0x38],0x1
  3b3b23:	45 31 f6                                        	xor    r14d,r14d
  3b3b26:	31 f6                                           	xor    esi,esi
  3b3b28:	31 d2                                           	xor    edx,edx
  3b3b2a:	31 c9                                           	xor    ecx,ecx
  3b3b2c:	e8 6f 34 11 00                                  	call   0x4c6fa0
  3b3b31:	8b 55 a0                                        	mov    edx,DWORD PTR [rbp-0x60]
  3b3b34:	49 ff c5                                        	inc    r13
  3b3b37:	4c 39 ad 70 ff ff ff                            	cmp    QWORD PTR [rbp-0x90],r13
  3b3b3e:	0f 84 19 03 00 00                               	je     0x3b3e5d
  3b3b44:	48 8b 85 68 ff ff ff                            	mov    rax,QWORD PTR [rbp-0x98]
  3b3b4b:	48 c7 45 b8 00 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x0
  3b3b53:	48 8b 40 28                                     	mov    rax,QWORD PTR [rax+0x28]
  3b3b57:	4e 8b 24 e8                                     	mov    r12,QWORD PTR [rax+r13*8]
  3b3b5b:	49 8b 44 24 10                                  	mov    rax,QWORD PTR [r12+0x10]
  3b3b60:	48 8b 08                                        	mov    rcx,QWORD PTR [rax]
  3b3b63:	48 89 4d b8                                     	mov    QWORD PTR [rbp-0x48],rcx
  3b3b67:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  3b3b70:	83 fa 02                                        	cmp    edx,0x2
  3b3b73:	74 7b                                           	je     0x3b3bf0
  3b3b75:	83 fa 01                                        	cmp    edx,0x1
  3b3b78:	0f 85 d9 02 00 00                               	jne    0x3b3e57
  3b3b7e:	49 8b 4e 08                                     	mov    rcx,QWORD PTR [r14+0x8]
  3b3b82:	81 b9 d4 05 00 00 00 00 09 11                   	cmp    DWORD PTR [rcx+0x5d4],0x11090000
  3b3b8c:	77 10                                           	ja     0x3b3b9e
  3b3b8e:	81 b9 d8 05 00 00 00 00 00 08                   	cmp    DWORD PTR [rcx+0x5d8],0x8000000
  3b3b98:	0f 82 ae 01 00 00                               	jb     0x3b3d4c
  3b3b9e:	44 8b 78 20                                     	mov    r15d,DWORD PTR [rax+0x20]
  3b3ba2:	48 8d 75 c0                                     	lea    rsi,[rbp-0x40]
  3b3ba6:	48 ba 80 00 00 00 00 00 00 04                   	movabs rdx,0x400000000000080
  3b3bb0:	48 b9 0d 00 00 00 00 00 00 02                   	movabs rcx,0x20000000000000d
  3b3bba:	31 ff                                           	xor    edi,edi
  3b3bbc:	45 31 c0                                        	xor    r8d,r8d
  3b3bbf:	31 c0                                           	xor    eax,eax
  3b3bc1:	e8 5a 86 f0 ff                                  	call   0x2bc220
  3b3bc6:	4c 89 f7                                        	mov    rdi,r14
  3b3bc9:	44 89 fe                                        	mov    esi,r15d
  3b3bcc:	48 89 c2                                        	mov    rdx,rax
  3b3bcf:	48 8d 4d b0                                     	lea    rcx,[rbp-0x50]
  3b3bd3:	e8 a8 a5 37 00                                  	call   0x72e180
  3b3bd8:	85 c0                                           	test   eax,eax
  3b3bda:	75 70                                           	jne    0x3b3c4c
  3b3bdc:	e9 ad 01 00 00                                  	jmp    0x3b3d8e
  3b3be1:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b3bf0:	49 8b 4e 08                                     	mov    rcx,QWORD PTR [r14+0x8]
  3b3bf4:	81 b9 d4 05 00 00 00 00 09 11                   	cmp    DWORD PTR [rcx+0x5d4],0x11090000
  3b3bfe:	77 10                                           	ja     0x3b3c10
  3b3c00:	81 b9 d8 05 00 00 00 00 00 08                   	cmp    DWORD PTR [rcx+0x5d8],0x8000000
  3b3c0a:	0f 82 22 01 00 00                               	jb     0x3b3d32
  3b3c10:	48 8b 4d 90                                     	mov    rcx,QWORD PTR [rbp-0x70]
  3b3c14:	44 8b 78 20                                     	mov    r15d,DWORD PTR [rax+0x20]
  3b3c18:	48 8d 75 c0                                     	lea    rsi,[rbp-0x40]
  3b3c1c:	48 ba 80 00 00 00 00 00 00 04                   	movabs rdx,0x400000000000080
  3b3c26:	31 ff                                           	xor    edi,edi
  3b3c28:	45 31 c0                                        	xor    r8d,r8d
  3b3c2b:	31 c0                                           	xor    eax,eax
  3b3c2d:	e8 ee 85 f0 ff                                  	call   0x2bc220
  3b3c32:	4c 89 f7                                        	mov    rdi,r14
  3b3c35:	44 89 fe                                        	mov    esi,r15d
  3b3c38:	48 89 c2                                        	mov    rdx,rax
  3b3c3b:	48 8d 4d b0                                     	lea    rcx,[rbp-0x50]
  3b3c3f:	e8 5c a5 37 00                                  	call   0x72e1a0
  3b3c44:	85 c0                                           	test   eax,eax
  3b3c46:	0f 84 42 01 00 00                               	je     0x3b3d8e
  3b3c4c:	48 98                                           	cdqe
  3b3c4e:	49 c7 44 24 40 00 00 00 00                      	mov    QWORD PTR [r12+0x40],0x0
  3b3c57:	49 89 44 24 30                                  	mov    QWORD PTR [r12+0x30],rax
  3b3c5c:	31 c0                                           	xor    eax,eax
  3b3c5e:	48 c7 45 b8 00 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x0
  3b3c66:	48 8b 7d 88                                     	mov    rdi,QWORD PTR [rbp-0x78]
  3b3c6a:	4c 8b 75 a8                                     	mov    r14,QWORD PTR [rbp-0x58]
  3b3c6e:	49 89 44 24 08                                  	mov    QWORD PTR [r12+0x8],rax
  3b3c73:	31 f6                                           	xor    esi,esi
  3b3c75:	31 d2                                           	xor    edx,edx
  3b3c77:	31 c9                                           	xor    ecx,ecx
  3b3c79:	e8 82 2d 11 00                                  	call   0x4c6a00
  3b3c7e:	42 8b 84 b3 d0 01 00 00                         	mov    eax,DWORD PTR [rbx+r14*4+0x1d0]
  3b3c86:	8d 48 01                                        	lea    ecx,[rax+0x1]
  3b3c89:	42 89 8c b3 d0 01 00 00                         	mov    DWORD PTR [rbx+r14*4+0x1d0],ecx
  3b3c91:	41 89 44 24 04                                  	mov    DWORD PTR [r12+0x4],eax
  3b3c96:	42 8b 84 b3 70 01 00 00                         	mov    eax,DWORD PTR [rbx+r14*4+0x170]
  3b3c9e:	42 8b 8c b3 c0 01 00 00                         	mov    ecx,DWORD PTR [rbx+r14*4+0x1c0]
  3b3ca6:	85 c9                                           	test   ecx,ecx
  3b3ca8:	74 11                                           	je     0x3b3cbb
  3b3caa:	48 8b 55 b8                                     	mov    rdx,QWORD PTR [rbp-0x48]
  3b3cae:	48 85 d2                                        	test   rdx,rdx
  3b3cb1:	74 08                                           	je     0x3b3cbb
  3b3cb3:	39 c1                                           	cmp    ecx,eax
  3b3cb5:	0f 8e 45 fe ff ff                               	jle    0x3b3b00
  3b3cbb:	85 c0                                           	test   eax,eax
  3b3cbd:	49 c7 44 24 48 00 00 00 00                      	mov    QWORD PTR [r12+0x48],0x0
  3b3cc6:	0f 94 c2                                        	sete   dl
  3b3cc9:	39 c1                                           	cmp    ecx,eax
  3b3ccb:	49 8d 44 24 48                                  	lea    rax,[r12+0x48]
  3b3cd0:	0f 9c c1                                        	setl   cl
  3b3cd3:	08 d1                                           	or     cl,dl
  3b3cd5:	84 c9                                           	test   cl,cl
  3b3cd7:	74 27                                           	je     0x3b3d00
  3b3cd9:	48 8b 55 98                                     	mov    rdx,QWORD PTR [rbp-0x68]
  3b3cdd:	48 8b 4c 13 48                                  	mov    rcx,QWORD PTR [rbx+rdx*1+0x48]
  3b3ce2:	49 89 4c 24 50                                  	mov    QWORD PTR [r12+0x50],rcx
  3b3ce7:	4c 89 21                                        	mov    QWORD PTR [rcx],r12
  3b3cea:	48 89 44 13 48                                  	mov    QWORD PTR [rbx+rdx*1+0x48],rax
  3b3cef:	e9 1a fe ff ff                                  	jmp    0x3b3b0e
  3b3cf4:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b3d00:	48 8b 55 98                                     	mov    rdx,QWORD PTR [rbp-0x68]
  3b3d04:	48 8b 8c 13 88 00 00 00                         	mov    rcx,QWORD PTR [rbx+rdx*1+0x88]
  3b3d0c:	49 89 4c 24 50                                  	mov    QWORD PTR [r12+0x50],rcx
  3b3d11:	4c 89 21                                        	mov    QWORD PTR [rcx],r12
  3b3d14:	48 89 84 13 88 00 00 00                         	mov    QWORD PTR [rbx+rdx*1+0x88],rax
  3b3d1c:	41 c7 44 24 04 00 00 00 00                      	mov    DWORD PTR [r12+0x4],0x0
  3b3d25:	42 ff 8c b3 d0 01 00 00                         	dec    DWORD PTR [rbx+r14*4+0x1d0]
  3b3d2d:	e9 dc fd ff ff                                  	jmp    0x3b3b0e
  3b3d32:	44 8b 78 20                                     	mov    r15d,DWORD PTR [rax+0x20]
  3b3d36:	48 8b 4d 90                                     	mov    rcx,QWORD PTR [rbp-0x70]
  3b3d3a:	48 8d 75 c0                                     	lea    rsi,[rbp-0x40]
  3b3d3e:	48 ba 80 00 00 00 00 00 00 04                   	movabs rdx,0x400000000000080
  3b3d48:	31 ff                                           	xor    edi,edi
  3b3d4a:	eb 1e                                           	jmp    0x3b3d6a
  3b3d4c:	44 8b 78 20                                     	mov    r15d,DWORD PTR [rax+0x20]
  3b3d50:	31 ff                                           	xor    edi,edi
  3b3d52:	48 8d 75 c0                                     	lea    rsi,[rbp-0x40]
  3b3d56:	48 ba 80 00 00 00 00 00 00 04                   	movabs rdx,0x400000000000080
  3b3d60:	48 b9 0d 00 00 00 00 00 00 02                   	movabs rcx,0x20000000000000d
  3b3d6a:	45 31 c0                                        	xor    r8d,r8d
  3b3d6d:	31 c0                                           	xor    eax,eax
  3b3d6f:	e8 ac 84 f0 ff                                  	call   0x2bc220
  3b3d74:	4c 89 f7                                        	mov    rdi,r14
  3b3d77:	44 89 fe                                        	mov    esi,r15d
  3b3d7a:	48 89 c2                                        	mov    rdx,rax
  3b3d7d:	48 8d 4d b0                                     	lea    rcx,[rbp-0x50]
  3b3d81:	e8 4a 86 37 00                                  	call   0x72c3d0
  3b3d86:	85 c0                                           	test   eax,eax
  3b3d88:	0f 85 be fe ff ff                               	jne    0x3b3c4c
  3b3d8e:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  3b3d92:	8b 48 24                                        	mov    ecx,DWORD PTR [rax+0x24]
  3b3d95:	f6 c1 03                                        	test   cl,0x3
  3b3d98:	74 61                                           	je     0x3b3dfb
  3b3d9a:	49 89 44 24 40                                  	mov    QWORD PTR [r12+0x40],rax
  3b3d9f:	4c 8b 7d b0                                     	mov    r15,QWORD PTR [rbp-0x50]
  3b3da3:	4d 89 be a0 05 00 00                            	mov    QWORD PTR [r14+0x5a0],r15
  3b3daa:	49 8b 47 08                                     	mov    rax,QWORD PTR [r15+0x8]
  3b3dae:	49 8b 8e 40 01 00 00                            	mov    rcx,QWORD PTR [r14+0x140]
  3b3db5:	4c 8b 48 18                                     	mov    r9,QWORD PTR [rax+0x18]
  3b3db9:	48 8d 05 20 47 eb ff                            	lea    rax,[rip+0xffffffffffeb4720]        # 0x2684e0
  3b3dc0:	4c 29 c8                                        	sub    rax,r9
  3b3dc3:	48 c1 c8 03                                     	ror    rax,0x3
  3b3dc7:	48 83 f8 12                                     	cmp    rax,0x12
  3b3dcb:	77 60                                           	ja     0x3b3e2d
  3b3dcd:	be 69 91 08 80                                  	mov    esi,0x80089169
  3b3dd2:	4c 89 ff                                        	mov    rdi,r15
  3b3dd5:	48 8d 55 b8                                     	lea    rdx,[rbp-0x48]
  3b3dd9:	4d 89 f0                                        	mov    r8,r14
  3b3ddc:	41 ff d1                                        	call   r9
  3b3ddf:	49 c7 86 a0 05 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x5a0],0x0
  3b3dea:	85 c0                                           	test   eax,eax
  3b3dec:	0f 85 6a fe ff ff                               	jne    0x3b3c5c
  3b3df2:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  3b3df6:	e9 6b fe ff ff                                  	jmp    0x3b3c66
  3b3dfb:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  3b3e00:	f0 0f c1 48 28                                  	lock xadd DWORD PTR [rax+0x28],ecx
  3b3e05:	83 f9 01                                        	cmp    ecx,0x1
  3b3e08:	75 0c                                           	jne    0x3b3e16
  3b3e0a:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  3b3e0e:	4c 89 f6                                        	mov    rsi,r14
  3b3e11:	e8 6a 75 37 00                                  	call   0x72b380
  3b3e16:	49 c7 44 24 30 00 00 00 00                      	mov    QWORD PTR [r12+0x30],0x0
  3b3e1f:	49 c7 44 24 40 00 00 00 00                      	mov    QWORD PTR [r12+0x40],0x0
  3b3e28:	e9 2f fe ff ff                                  	jmp    0x3b3c5c
  3b3e2d:	48 8d 3d 6c 1e 70 01                            	lea    rdi,[rip+0x1701e6c]        # 0x1ab5ca0
  3b3e34:	4c 89 ce                                        	mov    rsi,r9
  3b3e37:	48 89 8d 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],rcx
  3b3e3e:	4c 89 4d 80                                     	mov    QWORD PTR [rbp-0x80],r9
  3b3e42:	e8 79 ba 09 00                                  	call   0x44f8c0
  3b3e47:	4c 8b 4d 80                                     	mov    r9,QWORD PTR [rbp-0x80]
  3b3e4b:	48 8b 8d 78 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0x88]
  3b3e52:	e9 76 ff ff ff                                  	jmp    0x3b3dcd
  3b3e57:	41 be 16 00 00 00                               	mov    r14d,0x16
  3b3e5d:	48 8d 05 ac 84 56 03                            	lea    rax,[rip+0x35684ac]        # 0x391c310
  3b3e64:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  3b3e67:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  3b3e6b:	75 12                                           	jne    0x3b3e7f
  3b3e6d:	44 89 f0                                        	mov    eax,r14d
  3b3e70:	48 83 c4 78                                     	add    rsp,0x78
  3b3e74:	5b                                              	pop    rbx
  3b3e75:	41 5c                                           	pop    r12
  3b3e77:	41 5d                                           	pop    r13
  3b3e79:	41 5e                                           	pop    r14
  3b3e7b:	41 5f                                           	pop    r15
  3b3e7d:	5d                                              	pop    rbp
  3b3e7e:	c3                                              	ret
  3b3e7f:	e8 2c 98 34 00                                  	call   0x6fd6b0
  3b3e84:	0f 0b                                           	ud2
  3b3e86:	90                                              	nop
  3b3e87:	90                                              	nop
  3b3e88:	90                                              	nop
  3b3e89:	90                                              	nop
  3b3e8a:	90                                              	nop
  3b3e8b:	90                                              	nop
  3b3e8c:	90                                              	nop
  3b3e8d:	90                                              	nop
  3b3e8e:	90                                              	nop
  3b3e8f:	90                                              	nop
  3b3e90:	55                                              	push   rbp
  3b3e91:	48 89 e5                                        	mov    rbp,rsp
  3b3e94:	53                                              	push   rbx
  3b3e95:	50                                              	push   rax
  3b3e96:	48 83 7f 28 00                                  	cmp    QWORD PTR [rdi+0x28],0x0
  3b3e9b:	48 89 fb                                        	mov    rbx,rdi
  3b3e9e:	74 1a                                           	je     0x3b3eba
  3b3ea0:	48 8d 3d 50 2b f5 00                            	lea    rdi,[rip+0xf52b50]        # 0x13069f7
  3b3ea7:	48 8d 35 d0 bc fb 00                            	lea    rsi,[rip+0xfbbcd0]        # 0x136fb7e
  3b3eae:	ba 35 0b 00 00                                  	mov    edx,0xb35
  3b3eb3:	31 c0                                           	xor    eax,eax
  3b3eb5:	e8 56 95 ea ff                                  	call   0x25d410
  3b3eba:	48 8b 43 40                                     	mov    rax,QWORD PTR [rbx+0x40]
  3b3ebe:	48 85 c0                                        	test   rax,rax
  3b3ec1:	74 29                                           	je     0x3b3eec
  3b3ec3:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  3b3ec8:	f0 0f c1 48 28                                  	lock xadd DWORD PTR [rax+0x28],ecx
  3b3ecd:	83 f9 01                                        	cmp    ecx,0x1
  3b3ed0:	75 12                                           	jne    0x3b3ee4
  3b3ed2:	48 8b 7b 40                                     	mov    rdi,QWORD PTR [rbx+0x40]
  3b3ed6:	65 48 8b 34 25 00 00 00 00                      	mov    rsi,QWORD PTR gs:0x0
  3b3edf:	e8 9c 74 37 00                                  	call   0x72b380
  3b3ee4:	48 c7 43 40 00 00 00 00                         	mov    QWORD PTR [rbx+0x40],0x0
  3b3eec:	48 8d 35 0d 1a 70 01                            	lea    rsi,[rip+0x1701a0d]        # 0x1ab5900
  3b3ef3:	48 89 df                                        	mov    rdi,rbx
  3b3ef6:	48 83 c4 08                                     	add    rsp,0x8
  3b3efa:	5b                                              	pop    rbx
  3b3efb:	5d                                              	pop    rbp
  3b3efc:	e9 ef 4e 85 00                                  	jmp    0xc08df0
  3b3f01:	90                                              	nop
  3b3f02:	90                                              	nop
  3b3f03:	90                                              	nop
  3b3f04:	90                                              	nop
  3b3f05:	90                                              	nop
  3b3f06:	90                                              	nop
  3b3f07:	90                                              	nop
  3b3f08:	90                                              	nop
  3b3f09:	90                                              	nop
  3b3f0a:	90                                              	nop
  3b3f0b:	90                                              	nop
  3b3f0c:	90                                              	nop
  3b3f0d:	90                                              	nop
  3b3f0e:	90                                              	nop
  3b3f0f:	90                                              	nop
  3b3f10:	55                                              	push   rbp
  3b3f11:	48 89 e5                                        	mov    rbp,rsp
  3b3f14:	41 56                                           	push   r14
  3b3f16:	53                                              	push   rbx
  3b3f17:	49 89 fe                                        	mov    r14,rdi
  3b3f1a:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  3b3f23:	48 89 f3                                        	mov    rbx,rsi
  3b3f26:	48 8d 35 10 40 fe 00                            	lea    rsi,[rip+0xfe4010]        # 0x1397f3d
  3b3f2d:	31 d2                                           	xor    edx,edx
  3b3f2f:	e8 ac 64 86 00                                  	call   0xc1a3e0
  3b3f34:	ba 3c 00 00 00                                  	mov    edx,0x3c
  3b3f39:	4c 89 f7                                        	mov    rdi,r14
  3b3f3c:	48 89 de                                        	mov    rsi,rbx
  3b3f3f:	5b                                              	pop    rbx
  3b3f40:	41 5e                                           	pop    r14
  3b3f42:	5d                                              	pop    rbp
  3b3f43:	e9 38 53 ea ff                                  	jmp    0x259280
  3b3f48:	90                                              	nop
  3b3f49:	90                                              	nop
  3b3f4a:	90                                              	nop
  3b3f4b:	90                                              	nop
  3b3f4c:	90                                              	nop
  3b3f4d:	90                                              	nop
  3b3f4e:	90                                              	nop
  3b3f4f:	90                                              	nop
  3b3f50:	55                                              	push   rbp
  3b3f51:	48 89 e5                                        	mov    rbp,rsp
  3b3f54:	41 57                                           	push   r15
  3b3f56:	41 56                                           	push   r14
  3b3f58:	41 55                                           	push   r13
  3b3f5a:	41 54                                           	push   r12
  3b3f5c:	53                                              	push   rbx
  3b3f5d:	48 83 ec 58                                     	sub    rsp,0x58
  3b3f61:	48 8d 1d a8 83 56 03                            	lea    rbx,[rip+0x35683a8]        # 0x391c310
  3b3f68:	48 89 55 88                                     	mov    QWORD PTR [rbp-0x78],rdx
  3b3f6c:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  3b3f6f:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  3b3f73:	8b 86 a0 05 00 00                               	mov    eax,DWORD PTR [rsi+0x5a0]
  3b3f79:	83 f8 60                                        	cmp    eax,0x60
  3b3f7c:	74 09                                           	je     0x3b3f87
  3b3f7e:	83 f8 05                                        	cmp    eax,0x5
  3b3f81:	0f 85 e3 01 00 00                               	jne    0x3b416a
  3b3f87:	45 85 c9                                        	test   r9d,r9d
  3b3f8a:	0f 84 da 01 00 00                               	je     0x3b416a
  3b3f90:	45 89 c7                                        	mov    r15d,r8d
  3b3f93:	48 89 7d 98                                     	mov    QWORD PTR [rbp-0x68],rdi
  3b3f97:	45 31 e4                                        	xor    r12d,r12d
  3b3f9a:	31 c0                                           	xor    eax,eax
  3b3f9c:	31 ff                                           	xor    edi,edi
  3b3f9e:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  3b3fa2:	eb 1e                                           	jmp    0x3b3fc2
  3b3fa4:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b3fb0:	41 89 c6                                        	mov    r14d,eax
  3b3fb3:	49 ff c4                                        	inc    r12
  3b3fb6:	44 89 f0                                        	mov    eax,r14d
  3b3fb9:	4d 39 e7                                        	cmp    r15,r12
  3b3fbc:	0f 84 94 01 00 00                               	je     0x3b4156
  3b3fc2:	46 8b 34 a1                                     	mov    r14d,DWORD PTR [rcx+r12*4]
  3b3fc6:	45 89 f5                                        	mov    r13d,r14d
  3b3fc9:	41 c1 fd 10                                     	sar    r13d,0x10
  3b3fcd:	41 81 e6 ff ff 00 00                            	and    r14d,0xffff
  3b3fd4:	40 0f 94 c6                                     	sete   sil
  3b3fd8:	41 83 fd 7f                                     	cmp    r13d,0x7f
  3b3fdc:	0f 97 c2                                        	seta   dl
  3b3fdf:	40 08 f2                                        	or     dl,sil
  3b3fe2:	75 cc                                           	jne    0x3b3fb0
  3b3fe4:	41 39 c6                                        	cmp    r14d,eax
  3b3fe7:	74 33                                           	je     0x3b401c
  3b3fe9:	85 ff                                           	test   edi,edi
  3b3feb:	74 09                                           	je     0x3b3ff6
  3b3fed:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  3b3ff1:	e8 ba 5e fe ff                                  	call   0x399eb0
  3b3ff6:	48 8b 7d 88                                     	mov    rdi,QWORD PTR [rbp-0x78]
  3b3ffa:	44 89 f6                                        	mov    esi,r14d
  3b3ffd:	ba 60 01 00 00                                  	mov    edx,0x160
  3b4002:	48 8d 4d b0                                     	lea    rcx,[rbp-0x50]
  3b4006:	e8 d5 5e fe ff                                  	call   0x399ee0
  3b400b:	48 85 c0                                        	test   rax,rax
  3b400e:	74 32                                           	je     0x3b4042
  3b4010:	48 8b 4d a0                                     	mov    rcx,QWORD PTR [rbp-0x60]
  3b4014:	48 89 c3                                        	mov    rbx,rax
  3b4017:	bf 01 00 00 00                                  	mov    edi,0x1
  3b401c:	0f bf 03                                        	movsx  eax,WORD PTR [rbx]
  3b401f:	41 39 c5                                        	cmp    r13d,eax
  3b4022:	7d 8f                                           	jge    0x3b3fb3
  3b4024:	48 89 7d a8                                     	mov    QWORD PTR [rbp-0x58],rdi
  3b4028:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  3b402c:	e8 ef 5d fe ff                                  	call   0x399e20
  3b4031:	85 c0                                           	test   eax,eax
  3b4033:	74 1d                                           	je     0x3b4052
  3b4035:	48 8b 4d a0                                     	mov    rcx,QWORD PTR [rbp-0x60]
  3b4039:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  3b403d:	e9 71 ff ff ff                                  	jmp    0x3b3fb3
  3b4042:	48 8b 4d a0                                     	mov    rcx,QWORD PTR [rbp-0x60]
  3b4046:	31 ff                                           	xor    edi,edi
  3b4048:	45 31 f6                                        	xor    r14d,r14d
  3b404b:	31 db                                           	xor    ebx,ebx
  3b404d:	e9 61 ff ff ff                                  	jmp    0x3b3fb3
  3b4052:	48 8b 43 28                                     	mov    rax,QWORD PTR [rbx+0x28]
  3b4056:	44 89 e9                                        	mov    ecx,r13d
  3b4059:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  3b405d:	48 8b 04 c8                                     	mov    rax,QWORD PTR [rax+rcx*8]
  3b4061:	48 8b 4d a0                                     	mov    rcx,QWORD PTR [rbp-0x60]
  3b4065:	48 85 c0                                        	test   rax,rax
  3b4068:	0f 84 45 ff ff ff                               	je     0x3b3fb3
  3b406e:	44 8b 68 30                                     	mov    r13d,DWORD PTR [rax+0x30]
  3b4072:	41 81 fd 60 00 02 80                            	cmp    r13d,0x80020060
  3b4079:	74 0d                                           	je     0x3b4088
  3b407b:	41 81 fd 05 00 02 80                            	cmp    r13d,0x80020005
  3b4082:	0f 85 2b ff ff ff                               	jne    0x3b3fb3
  3b4088:	48 8b 40 10                                     	mov    rax,QWORD PTR [rax+0x10]
  3b408c:	48 8d 75 c0                                     	lea    rsi,[rbp-0x40]
  3b4090:	48 ba 80 00 00 00 00 00 00 04                   	movabs rdx,0x400000000000080
  3b409a:	48 b9 0d 00 00 00 00 00 00 02                   	movabs rcx,0x20000000000000d
  3b40a4:	31 ff                                           	xor    edi,edi
  3b40a6:	45 31 c0                                        	xor    r8d,r8d
  3b40a9:	8b 40 20                                        	mov    eax,DWORD PTR [rax+0x20]
  3b40ac:	89 45 94                                        	mov    DWORD PTR [rbp-0x6c],eax
  3b40af:	31 c0                                           	xor    eax,eax
  3b40b1:	e8 6a 81 f0 ff                                  	call   0x2bc220
  3b40b6:	48 8b 7d 98                                     	mov    rdi,QWORD PTR [rbp-0x68]
  3b40ba:	8b 75 94                                        	mov    esi,DWORD PTR [rbp-0x6c]
  3b40bd:	48 89 c2                                        	mov    rdx,rax
  3b40c0:	48 8d 4d b8                                     	lea    rcx,[rbp-0x48]
  3b40c4:	e8 07 83 37 00                                  	call   0x72c3d0
  3b40c9:	85 c0                                           	test   eax,eax
  3b40cb:	0f 85 64 ff ff ff                               	jne    0x3b4035
  3b40d1:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  3b40d5:	e8 86 27 00 00                                  	call   0x3b6860
  3b40da:	48 85 c0                                        	test   rax,rax
  3b40dd:	75 29                                           	jne    0x3b4108
  3b40df:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  3b40e3:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  3b40e8:	f0 0f c1 48 28                                  	lock xadd DWORD PTR [rax+0x28],ecx
  3b40ed:	83 f9 01                                        	cmp    ecx,0x1
  3b40f0:	0f 85 3f ff ff ff                               	jne    0x3b4035
  3b40f6:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  3b40fa:	48 8b 75 98                                     	mov    rsi,QWORD PTR [rbp-0x68]
  3b40fe:	e8 7d 72 37 00                                  	call   0x72b380
  3b4103:	e9 2d ff ff ff                                  	jmp    0x3b4035
  3b4108:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  3b4111:	80 89 a8 03 00 00 01                            	or     BYTE PTR [rcx+0x3a8],0x1
  3b4118:	41 81 c5 00 00 fe 7f                            	add    r13d,0x7ffe0000
  3b411f:	be 01 00 00 00                                  	mov    esi,0x1
  3b4124:	48 89 c2                                        	mov    rdx,rax
  3b4127:	45 31 c0                                        	xor    r8d,r8d
  3b412a:	44 89 ef                                        	mov    edi,r13d
  3b412d:	e8 6e 65 1a 00                                  	call   0x55a6a0
  3b4132:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  3b4136:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  3b413b:	f0 0f c1 48 28                                  	lock xadd DWORD PTR [rax+0x28],ecx
  3b4140:	83 f9 01                                        	cmp    ecx,0x1
  3b4143:	75 0d                                           	jne    0x3b4152
  3b4145:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  3b4149:	48 8b 75 98                                     	mov    rsi,QWORD PTR [rbp-0x68]
  3b414d:	e8 2e 72 37 00                                  	call   0x72b380
  3b4152:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  3b4156:	48 8d 1d b3 81 56 03                            	lea    rbx,[rip+0x35681b3]        # 0x391c310
  3b415d:	85 ff                                           	test   edi,edi
  3b415f:	74 09                                           	je     0x3b416a
  3b4161:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  3b4165:	e8 46 5d fe ff                                  	call   0x399eb0
  3b416a:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  3b416d:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  3b4171:	75 0f                                           	jne    0x3b4182
  3b4173:	48 83 c4 58                                     	add    rsp,0x58
  3b4177:	5b                                              	pop    rbx
  3b4178:	41 5c                                           	pop    r12
  3b417a:	41 5d                                           	pop    r13
  3b417c:	41 5e                                           	pop    r14
  3b417e:	41 5f                                           	pop    r15
  3b4180:	5d                                              	pop    rbp
  3b4181:	c3                                              	ret
  3b4182:	e8 29 95 34 00                                  	call   0x6fd6b0
  3b4187:	0f 0b                                           	ud2
  3b4189:	90                                              	nop
  3b418a:	90                                              	nop
  3b418b:	90                                              	nop
  3b418c:	90                                              	nop
  3b418d:	90                                              	nop
  3b418e:	90                                              	nop
  3b418f:	90                                              	nop
  3b4190:	55                                              	push   rbp
  3b4191:	48 89 e5                                        	mov    rbp,rsp
  3b4194:	41 57                                           	push   r15
  3b4196:	41 56                                           	push   r14
  3b4198:	41 55                                           	push   r13
  3b419a:	41 54                                           	push   r12
  3b419c:	53                                              	push   rbx
  3b419d:	50                                              	push   rax
  3b419e:	4c 63 e6                                        	movsxd r12,esi
  3b41a1:	49 89 fe                                        	mov    r14,rdi
  3b41a4:	89 d3                                           	mov    ebx,edx
  3b41a6:	49 89 cf                                        	mov    r15,rcx
  3b41a9:	31 f6                                           	xor    esi,esi
  3b41ab:	31 d2                                           	xor    edx,edx
  3b41ad:	4c 89 e0                                        	mov    rax,r12
  3b41b0:	48 c1 e0 05                                     	shl    rax,0x5
  3b41b4:	48 8d bc 01 d8 00 00 00                         	lea    rdi,[rcx+rax*1+0xd8]
  3b41bc:	31 c9                                           	xor    ecx,ecx
  3b41be:	48 89 7d d0                                     	mov    QWORD PTR [rbp-0x30],rdi
  3b41c2:	e8 39 28 11 00                                  	call   0x4c6a00
  3b41c7:	41 83 7e 04 00                                  	cmp    DWORD PTR [r14+0x4],0x0
  3b41cc:	0f 84 7e 00 00 00                               	je     0x3b4250
  3b41d2:	4c 89 e0                                        	mov    rax,r12
  3b41d5:	4c 89 e6                                        	mov    rsi,r12
  3b41d8:	4c 89 fa                                        	mov    rdx,r15
  3b41db:	41 bd 03 00 00 00                               	mov    r13d,0x3
  3b41e1:	48 c1 e0 04                                     	shl    rax,0x4
  3b41e5:	49 8d 44 07 40                                  	lea    rax,[r15+rax*1+0x40]
  3b41ea:	49 89 c7                                        	mov    r15,rax
  3b41ed:	0f 1f 00                                        	nop    DWORD PTR [rax]
  3b41f0:	4d 8b 27                                        	mov    r12,QWORD PTR [r15]
  3b41f3:	4d 85 e4                                        	test   r12,r12
  3b41f6:	0f 84 35 01 00 00                               	je     0x3b4331
  3b41fc:	4d 8d 7c 24 48                                  	lea    r15,[r12+0x48]
  3b4201:	4d 39 e6                                        	cmp    r14,r12
  3b4204:	75 ea                                           	jne    0x3b41f0
  3b4206:	41 39 5c 24 38                                  	cmp    DWORD PTR [r12+0x38],ebx
  3b420b:	0f 85 20 01 00 00                               	jne    0x3b4331
  3b4211:	ff 8c b2 c0 01 00 00                            	dec    DWORD PTR [rdx+rsi*4+0x1c0]
  3b4218:	41 c7 44 24 38 04 00 00 00                      	mov    DWORD PTR [r12+0x38],0x4
  3b4221:	49 8b 4c 24 48                                  	mov    rcx,QWORD PTR [r12+0x48]
  3b4226:	48 85 c9                                        	test   rcx,rcx
  3b4229:	0f 84 b0 00 00 00                               	je     0x3b42df
  3b422f:	4c 39 79 50                                     	cmp    QWORD PTR [rcx+0x50],r15
  3b4233:	0f 85 48 01 00 00                               	jne    0x3b4381
  3b4239:	49 8b 44 24 50                                  	mov    rax,QWORD PTR [r12+0x50]
  3b423e:	4c 39 30                                        	cmp    QWORD PTR [rax],r14
  3b4241:	0f 85 0b 01 00 00                               	jne    0x3b4352
  3b4247:	48 89 41 50                                     	mov    QWORD PTR [rcx+0x50],rax
  3b424b:	e9 9d 00 00 00                                  	jmp    0x3b42ed
  3b4250:	4c 89 e0                                        	mov    rax,r12
  3b4253:	4c 89 e2                                        	mov    rdx,r12
  3b4256:	41 bd 03 00 00 00                               	mov    r13d,0x3
  3b425c:	48 c1 e0 04                                     	shl    rax,0x4
  3b4260:	4d 8b a4 07 80 00 00 00                         	mov    r12,QWORD PTR [r15+rax*1+0x80]
  3b4268:	4d 85 e4                                        	test   r12,r12
  3b426b:	0f 84 c0 00 00 00                               	je     0x3b4331
  3b4271:	49 8d 84 07 80 00 00 00                         	lea    rax,[r15+rax*1+0x80]
  3b4279:	eb 11                                           	jmp    0x3b428c
  3b427b:	0f 1f 44 00 00                                  	nop    DWORD PTR [rax+rax*1+0x0]
  3b4280:	49 89 cc                                        	mov    r12,rcx
  3b4283:	48 85 c9                                        	test   rcx,rcx
  3b4286:	0f 84 a5 00 00 00                               	je     0x3b4331
  3b428c:	49 8b 4c 24 48                                  	mov    rcx,QWORD PTR [r12+0x48]
  3b4291:	4d 39 e6                                        	cmp    r14,r12
  3b4294:	75 ea                                           	jne    0x3b4280
  3b4296:	41 39 5c 24 38                                  	cmp    DWORD PTR [r12+0x38],ebx
  3b429b:	75 e3                                           	jne    0x3b4280
  3b429d:	41 ff 8c 97 c0 01 00 00                         	dec    DWORD PTR [r15+rdx*4+0x1c0]
  3b42a5:	41 c7 44 24 38 04 00 00 00                      	mov    DWORD PTR [r12+0x38],0x4
  3b42ae:	49 8d 5c 24 48                                  	lea    rbx,[r12+0x48]
  3b42b3:	49 8b 4c 24 48                                  	mov    rcx,QWORD PTR [r12+0x48]
  3b42b8:	48 85 c9                                        	test   rcx,rcx
  3b42bb:	74 51                                           	je     0x3b430e
  3b42bd:	48 39 59 50                                     	cmp    QWORD PTR [rcx+0x50],rbx
  3b42c1:	0f 85 2f 01 00 00                               	jne    0x3b43f6
  3b42c7:	49 8b 44 24 50                                  	mov    rax,QWORD PTR [r12+0x50]
  3b42cc:	4c 39 30                                        	cmp    QWORD PTR [rax],r14
  3b42cf:	0f 85 e5 00 00 00                               	jne    0x3b43ba
  3b42d5:	49 83 c4 50                                     	add    r12,0x50
  3b42d9:	48 89 41 50                                     	mov    QWORD PTR [rcx+0x50],rax
  3b42dd:	eb 45                                           	jmp    0x3b4324
  3b42df:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b42e4:	4c 39 31                                        	cmp    QWORD PTR [rcx],r14
  3b42e7:	75 69                                           	jne    0x3b4352
  3b42e9:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  3b42ed:	49 8b 44 24 48                                  	mov    rax,QWORD PTR [r12+0x48]
  3b42f2:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b42f7:	45 31 ed                                        	xor    r13d,r13d
  3b42fa:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  3b42fd:	41 83 7c 24 04 00                               	cmp    DWORD PTR [r12+0x4],0x0
  3b4303:	7e 2c                                           	jle    0x3b4331
  3b4305:	ff 84 b2 60 01 00 00                            	inc    DWORD PTR [rdx+rsi*4+0x160]
  3b430c:	eb 23                                           	jmp    0x3b4331
  3b430e:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b4313:	4c 39 31                                        	cmp    QWORD PTR [rcx],r14
  3b4316:	0f 85 9e 00 00 00                               	jne    0x3b43ba
  3b431c:	49 83 c4 50                                     	add    r12,0x50
  3b4320:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  3b4324:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  3b4327:	49 8b 0c 24                                     	mov    rcx,QWORD PTR [r12]
  3b432b:	45 31 ed                                        	xor    r13d,r13d
  3b432e:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  3b4331:	48 8b 7d d0                                     	mov    rdi,QWORD PTR [rbp-0x30]
  3b4335:	31 f6                                           	xor    esi,esi
  3b4337:	31 d2                                           	xor    edx,edx
  3b4339:	31 c9                                           	xor    ecx,ecx
  3b433b:	e8 60 2c 11 00                                  	call   0x4c6fa0
  3b4340:	44 89 e8                                        	mov    eax,r13d
  3b4343:	48 83 c4 08                                     	add    rsp,0x8
  3b4347:	5b                                              	pop    rbx
  3b4348:	41 5c                                           	pop    r12
  3b434a:	41 5d                                           	pop    r13
  3b434c:	41 5e                                           	pop    r14
  3b434e:	41 5f                                           	pop    r15
  3b4350:	5d                                              	pop    rbp
  3b4351:	c3                                              	ret
  3b4352:	e8 f9 d5 43 00                                  	call   0x7f1950
  3b4357:	49 8b 54 24 50                                  	mov    rdx,QWORD PTR [r12+0x50]
  3b435c:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x3b4352
  3b4363:	4c 89 f6                                        	mov    rsi,r14
  3b4366:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  3b4369:	e8 52 dd 43 00                                  	call   0x7f20c0
  3b436e:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b4373:	48 8d 35 ea 77 f6 00                            	lea    rsi,[rip+0xf677ea]        # 0x131bb64
  3b437a:	bf 33 00 00 00                                  	mov    edi,0x33
  3b437f:	eb 66                                           	jmp    0x3b43e7
  3b4381:	e8 ca d5 43 00                                  	call   0x7f1950
  3b4386:	49 8b 54 24 48                                  	mov    rdx,QWORD PTR [r12+0x48]
  3b438b:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x3b4381
  3b4392:	4c 89 f6                                        	mov    rsi,r14
  3b4395:	4d 89 f8                                        	mov    r8,r15
  3b4398:	48 8b 4a 50                                     	mov    rcx,QWORD PTR [rdx+0x50]
  3b439c:	e8 df dd 43 00                                  	call   0x7f2180
  3b43a1:	49 8b 4c 24 48                                  	mov    rcx,QWORD PTR [r12+0x48]
  3b43a6:	48 8d 35 46 b3 fb 00                            	lea    rsi,[rip+0xfbb346]        # 0x136f6f3
  3b43ad:	bf 2f 00 00 00                                  	mov    edi,0x2f
  3b43b2:	4c 89 e2                                        	mov    rdx,r12
  3b43b5:	4d 89 f9                                        	mov    r9,r15
  3b43b8:	eb 73                                           	jmp    0x3b442d
  3b43ba:	e8 91 d5 43 00                                  	call   0x7f1950
  3b43bf:	49 8b 54 24 50                                  	mov    rdx,QWORD PTR [r12+0x50]
  3b43c4:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x3b43ba
  3b43cb:	4c 89 f6                                        	mov    rsi,r14
  3b43ce:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  3b43d1:	e8 ea dc 43 00                                  	call   0x7f20c0
  3b43d6:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b43db:	48 8d 35 82 77 f6 00                            	lea    rsi,[rip+0xf67782]        # 0x131bb64
  3b43e2:	bf 3b 00 00 00                                  	mov    edi,0x3b
  3b43e7:	4c 8b 01                                        	mov    r8,QWORD PTR [rcx]
  3b43ea:	4c 89 e2                                        	mov    rdx,r12
  3b43ed:	31 c0                                           	xor    eax,eax
  3b43ef:	e8 1c 66 8e 00                                  	call   0xc9aa10
  3b43f4:	0f 0b                                           	ud2
  3b43f6:	e8 55 d5 43 00                                  	call   0x7f1950
  3b43fb:	49 8b 54 24 48                                  	mov    rdx,QWORD PTR [r12+0x48]
  3b4400:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x3b43f6
  3b4407:	4c 89 f6                                        	mov    rsi,r14
  3b440a:	49 89 d8                                        	mov    r8,rbx
  3b440d:	48 8b 4a 50                                     	mov    rcx,QWORD PTR [rdx+0x50]
  3b4411:	e8 6a dd 43 00                                  	call   0x7f2180
  3b4416:	49 8b 4c 24 48                                  	mov    rcx,QWORD PTR [r12+0x48]
  3b441b:	48 8d 35 d1 b2 fb 00                            	lea    rsi,[rip+0xfbb2d1]        # 0x136f6f3
  3b4422:	bf 37 00 00 00                                  	mov    edi,0x37
  3b4427:	4c 89 e2                                        	mov    rdx,r12
  3b442a:	49 89 d9                                        	mov    r9,rbx
  3b442d:	4c 8b 41 50                                     	mov    r8,QWORD PTR [rcx+0x50]
  3b4431:	31 c0                                           	xor    eax,eax
  3b4433:	e8 d8 65 8e 00                                  	call   0xc9aa10
  3b4438:	0f 0b                                           	ud2
  3b443a:	90                                              	nop
  3b443b:	90                                              	nop
  3b443c:	90                                              	nop
  3b443d:	90                                              	nop
  3b443e:	90                                              	nop
  3b443f:	90                                              	nop
  3b4440:	55                                              	push   rbp
  3b4441:	48 89 e5                                        	mov    rbp,rsp
  3b4444:	53                                              	push   rbx
  3b4445:	50                                              	push   rax
  3b4446:	48 63 f6                                        	movsxd rsi,esi
  3b4449:	48 89 f0                                        	mov    rax,rsi
  3b444c:	4c 8b 84 f1 40 01 00 00                         	mov    r8,QWORD PTR [rcx+rsi*8+0x140]
  3b4454:	48 c1 e0 04                                     	shl    rax,0x4
  3b4458:	48 8b 5c 01 40                                  	mov    rbx,QWORD PTR [rcx+rax*1+0x40]
  3b445d:	49 39 d0                                        	cmp    r8,rdx
  3b4460:	76 56                                           	jbe    0x3b44b8
  3b4462:	48 85 db                                        	test   rbx,rbx
  3b4465:	0f 84 8a 00 00 00                               	je     0x3b44f5
  3b446b:	45 31 c9                                        	xor    r9d,r9d
  3b446e:	66 90                                           	xchg   ax,ax
  3b4470:	4c 8b 53 08                                     	mov    r10,QWORD PTR [rbx+0x8]
  3b4474:	4d 39 c2                                        	cmp    r10,r8
  3b4477:	41 0f 93 c3                                     	setae  r11b
  3b447b:	49 39 d2                                        	cmp    r10,rdx
  3b447e:	41 0f 96 c2                                     	setbe  r10b
  3b4482:	45 08 da                                        	or     r10b,r11b
  3b4485:	75 19                                           	jne    0x3b44a0
  3b4487:	44 8b 9c b1 d0 01 00 00                         	mov    r11d,DWORD PTR [rcx+rsi*4+0x1d0]
  3b448f:	44 8b 53 04                                     	mov    r10d,DWORD PTR [rbx+0x4]
  3b4493:	45 29 d3                                        	sub    r11d,r10d
  3b4496:	44 3b 9c b1 80 01 00 00                         	cmp    r11d,DWORD PTR [rcx+rsi*4+0x180]
  3b449e:	7c 79                                           	jl     0x3b4519
  3b44a0:	41 ff c1                                        	inc    r9d
  3b44a3:	44 3b 8c b1 70 01 00 00                         	cmp    r9d,DWORD PTR [rcx+rsi*4+0x170]
  3b44ab:	7d 48                                           	jge    0x3b44f5
  3b44ad:	48 8b 5b 48                                     	mov    rbx,QWORD PTR [rbx+0x48]
  3b44b1:	48 85 db                                        	test   rbx,rbx
  3b44b4:	75 ba                                           	jne    0x3b4470
  3b44b6:	eb 3d                                           	jmp    0x3b44f5
  3b44b8:	48 85 db                                        	test   rbx,rbx
  3b44bb:	74 38                                           	je     0x3b44f5
  3b44bd:	45 31 c0                                        	xor    r8d,r8d
  3b44c0:	48 39 53 08                                     	cmp    QWORD PTR [rbx+0x8],rdx
  3b44c4:	76 19                                           	jbe    0x3b44df
  3b44c6:	44 8b 94 b1 d0 01 00 00                         	mov    r10d,DWORD PTR [rcx+rsi*4+0x1d0]
  3b44ce:	44 8b 4b 04                                     	mov    r9d,DWORD PTR [rbx+0x4]
  3b44d2:	45 29 ca                                        	sub    r10d,r9d
  3b44d5:	44 3b 94 b1 80 01 00 00                         	cmp    r10d,DWORD PTR [rcx+rsi*4+0x180]
  3b44dd:	7c 74                                           	jl     0x3b4553
  3b44df:	41 ff c0                                        	inc    r8d
  3b44e2:	44 3b 84 b1 70 01 00 00                         	cmp    r8d,DWORD PTR [rcx+rsi*4+0x170]
  3b44ea:	7d 09                                           	jge    0x3b44f5
  3b44ec:	48 8b 5b 48                                     	mov    rbx,QWORD PTR [rbx+0x48]
  3b44f0:	48 85 db                                        	test   rbx,rbx
  3b44f3:	75 cb                                           	jne    0x3b44c0
  3b44f5:	48 c7 47 48 00 00 00 00                         	mov    QWORD PTR [rdi+0x48],0x0
  3b44fd:	48 8d 57 48                                     	lea    rdx,[rdi+0x48]
  3b4501:	48 8b 74 01 48                                  	mov    rsi,QWORD PTR [rcx+rax*1+0x48]
  3b4506:	48 89 77 50                                     	mov    QWORD PTR [rdi+0x50],rsi
  3b450a:	48 89 3e                                        	mov    QWORD PTR [rsi],rdi
  3b450d:	48 89 54 01 48                                  	mov    QWORD PTR [rcx+rax*1+0x48],rdx
  3b4512:	48 83 c4 08                                     	add    rsp,0x8
  3b4516:	5b                                              	pop    rbx
  3b4517:	5d                                              	pop    rbp
  3b4518:	c3                                              	ret
  3b4519:	44 89 57 04                                     	mov    DWORD PTR [rdi+0x4],r10d
  3b451d:	48 8b 43 50                                     	mov    rax,QWORD PTR [rbx+0x50]
  3b4521:	48 39 18                                        	cmp    QWORD PTR [rax],rbx
  3b4524:	74 3a                                           	je     0x3b4560
  3b4526:	e8 25 d4 43 00                                  	call   0x7f1950
  3b452b:	48 8b 53 50                                     	mov    rdx,QWORD PTR [rbx+0x50]
  3b452f:	48 8d 3d f0 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff0]        # 0x3b4526
  3b4536:	48 89 de                                        	mov    rsi,rbx
  3b4539:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  3b453c:	e8 7f db 43 00                                  	call   0x7f20c0
  3b4541:	48 8b 4b 50                                     	mov    rcx,QWORD PTR [rbx+0x50]
  3b4545:	48 8d 35 18 76 f6 00                            	lea    rsi,[rip+0xf67618]        # 0x131bb64
  3b454c:	bf 27 00 00 00                                  	mov    edi,0x27
  3b4551:	eb 51                                           	jmp    0x3b45a4
  3b4553:	44 89 4f 04                                     	mov    DWORD PTR [rdi+0x4],r9d
  3b4557:	48 8b 43 50                                     	mov    rax,QWORD PTR [rbx+0x50]
  3b455b:	48 39 18                                        	cmp    QWORD PTR [rax],rbx
  3b455e:	75 19                                           	jne    0x3b4579
  3b4560:	48 89 47 50                                     	mov    QWORD PTR [rdi+0x50],rax
  3b4564:	48 89 5f 48                                     	mov    QWORD PTR [rdi+0x48],rbx
  3b4568:	48 8d 4f 48                                     	lea    rcx,[rdi+0x48]
  3b456c:	48 8b 43 50                                     	mov    rax,QWORD PTR [rbx+0x50]
  3b4570:	48 89 38                                        	mov    QWORD PTR [rax],rdi
  3b4573:	48 89 4b 50                                     	mov    QWORD PTR [rbx+0x50],rcx
  3b4577:	eb 99                                           	jmp    0x3b4512
  3b4579:	e8 d2 d3 43 00                                  	call   0x7f1950
  3b457e:	48 8b 53 50                                     	mov    rdx,QWORD PTR [rbx+0x50]
  3b4582:	48 8d 3d f0 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff0]        # 0x3b4579
  3b4589:	48 89 de                                        	mov    rsi,rbx
  3b458c:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  3b458f:	e8 2c db 43 00                                  	call   0x7f20c0
  3b4594:	48 8b 4b 50                                     	mov    rcx,QWORD PTR [rbx+0x50]
  3b4598:	48 8d 35 c5 75 f6 00                            	lea    rsi,[rip+0xf675c5]        # 0x131bb64
  3b459f:	bf 2b 00 00 00                                  	mov    edi,0x2b
  3b45a4:	4c 8b 01                                        	mov    r8,QWORD PTR [rcx]
  3b45a7:	48 89 da                                        	mov    rdx,rbx
  3b45aa:	31 c0                                           	xor    eax,eax
  3b45ac:	e8 5f 64 8e 00                                  	call   0xc9aa10
  3b45b1:	0f 0b                                           	ud2
  3b45b3:	90                                              	nop
  3b45b4:	90                                              	nop
  3b45b5:	90                                              	nop
  3b45b6:	90                                              	nop
  3b45b7:	90                                              	nop
  3b45b8:	90                                              	nop
  3b45b9:	90                                              	nop
  3b45ba:	90                                              	nop
  3b45bb:	90                                              	nop
  3b45bc:	90                                              	nop
  3b45bd:	90                                              	nop
  3b45be:	90                                              	nop
  3b45bf:	90                                              	nop
  3b45c0:	55                                              	push   rbp
  3b45c1:	48 89 e5                                        	mov    rbp,rsp
  3b45c4:	41 57                                           	push   r15
  3b45c6:	41 56                                           	push   r14
  3b45c8:	41 55                                           	push   r13
  3b45ca:	41 54                                           	push   r12
  3b45cc:	53                                              	push   rbx
  3b45cd:	48 83 ec 28                                     	sub    rsp,0x28
  3b45d1:	81 fe 60 01 00 00                               	cmp    esi,0x160
  3b45d7:	0f 85 a4 02 00 00                               	jne    0x3b4881
  3b45dd:	48 0f bf 0f                                     	movsx  rcx,WORD PTR [rdi]
  3b45e1:	48 89 fb                                        	mov    rbx,rdi
  3b45e4:	48 89 4d c8                                     	mov    QWORD PTR [rbp-0x38],rcx
  3b45e8:	48 85 c9                                        	test   rcx,rcx
  3b45eb:	0f 8e 90 02 00 00                               	jle    0x3b4881
  3b45f1:	4c 8b 73 18                                     	mov    r14,QWORD PTR [rbx+0x18]
  3b45f5:	45 31 ff                                        	xor    r15d,r15d
  3b45f8:	48 89 5d b8                                     	mov    QWORD PTR [rbp-0x48],rbx
  3b45fc:	4c 89 75 c0                                     	mov    QWORD PTR [rbp-0x40],r14
  3b4600:	eb 49                                           	jmp    0x3b464b
  3b4602:	89 75 d0                                        	mov    DWORD PTR [rbp-0x30],esi
  3b4605:	48 8d 3d ce 13 fb 00                            	lea    rdi,[rip+0xfb13ce]        # 0x13659da
  3b460c:	48 8d 35 b8 94 f0 00                            	lea    rsi,[rip+0xf094b8]        # 0x12bdacb
  3b4613:	ba 74 15 00 00                                  	mov    edx,0x1574
  3b4618:	31 c0                                           	xor    eax,eax
  3b461a:	e8 f1 8d ea ff                                  	call   0x25d410
  3b461f:	8b 75 d0                                        	mov    esi,DWORD PTR [rbp-0x30]
  3b4622:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b4630:	4c 89 ef                                        	mov    rdi,r13
  3b4633:	44 89 e2                                        	mov    edx,r12d
  3b4636:	4c 89 f1                                        	mov    rcx,r14
  3b4639:	e8 52 fb ff ff                                  	call   0x3b4190
  3b463e:	49 ff c7                                        	inc    r15
  3b4641:	4c 3b 7d c8                                     	cmp    r15,QWORD PTR [rbp-0x38]
  3b4645:	0f 84 48 01 00 00                               	je     0x3b4793
  3b464b:	48 8b 43 28                                     	mov    rax,QWORD PTR [rbx+0x28]
  3b464f:	4e 8b 2c f8                                     	mov    r13,QWORD PTR [rax+r15*8]
  3b4653:	4d 85 ed                                        	test   r13,r13
  3b4656:	74 e6                                           	je     0x3b463e
  3b4658:	66 83 7d c8 01                                  	cmp    WORD PTR [rbp-0x38],0x1
  3b465d:	0f 85 dd 00 00 00                               	jne    0x3b4740
  3b4663:	4d 8b 65 20                                     	mov    r12,QWORD PTR [r13+0x20]
  3b4667:	41 8b 04 24                                     	mov    eax,DWORD PTR [r12]
  3b466b:	85 c0                                           	test   eax,eax
  3b466d:	74 cf                                           	je     0x3b463e
  3b466f:	45 31 ed                                        	xor    r13d,r13d
  3b4672:	4c 89 65 d0                                     	mov    QWORD PTR [rbp-0x30],r12
  3b4676:	eb 50                                           	jmp    0x3b46c8
  3b4678:	49 89 fe                                        	mov    r14,rdi
  3b467b:	89 f3                                           	mov    ebx,esi
  3b467d:	41 89 d4                                        	mov    r12d,edx
  3b4680:	48 8d 3d 53 13 fb 00                            	lea    rdi,[rip+0xfb1353]        # 0x13659da
  3b4687:	48 8d 35 3d 94 f0 00                            	lea    rsi,[rip+0xf0943d]        # 0x12bdacb
  3b468e:	ba 74 15 00 00                                  	mov    edx,0x1574
  3b4693:	31 c0                                           	xor    eax,eax
  3b4695:	e8 76 8d ea ff                                  	call   0x25d410
  3b469a:	44 89 e2                                        	mov    edx,r12d
  3b469d:	89 de                                           	mov    esi,ebx
  3b469f:	4c 89 f7                                        	mov    rdi,r14
  3b46a2:	4c 8b 65 d0                                     	mov    r12,QWORD PTR [rbp-0x30]
  3b46a6:	48 8b 5d b8                                     	mov    rbx,QWORD PTR [rbp-0x48]
  3b46aa:	4c 8b 75 c0                                     	mov    r14,QWORD PTR [rbp-0x40]
  3b46ae:	66 90                                           	xchg   ax,ax
  3b46b0:	4c 89 f1                                        	mov    rcx,r14
  3b46b3:	e8 d8 fa ff ff                                  	call   0x3b4190
  3b46b8:	41 8b 04 24                                     	mov    eax,DWORD PTR [r12]
  3b46bc:	41 ff c5                                        	inc    r13d
  3b46bf:	41 39 c5                                        	cmp    r13d,eax
  3b46c2:	0f 83 76 ff ff ff                               	jae    0x3b463e
  3b46c8:	48 8b 4b 28                                     	mov    rcx,QWORD PTR [rbx+0x28]
  3b46cc:	49 63 d5                                        	movsxd rdx,r13d
  3b46cf:	48 8b 3c d1                                     	mov    rdi,QWORD PTR [rcx+rdx*8]
  3b46d3:	48 85 ff                                        	test   rdi,rdi
  3b46d6:	74 e4                                           	je     0x3b46bc
  3b46d8:	8b 73 04                                        	mov    esi,DWORD PTR [rbx+0x4]
  3b46db:	8b 57 38                                        	mov    edx,DWORD PTR [rdi+0x38]
  3b46de:	83 fa 01                                        	cmp    edx,0x1
  3b46e1:	74 cd                                           	je     0x3b46b0
  3b46e3:	83 fa 02                                        	cmp    edx,0x2
  3b46e6:	75 d4                                           	jne    0x3b46bc
  3b46e8:	48 8b 47 28                                     	mov    rax,QWORD PTR [rdi+0x28]
  3b46ec:	48 85 c0                                        	test   rax,rax
  3b46ef:	74 87                                           	je     0x3b4678
  3b46f1:	80 78 48 00                                     	cmp    BYTE PTR [rax+0x48],0x0
  3b46f5:	74 06                                           	je     0x3b46fd
  3b46f7:	c6 40 48 00                                     	mov    BYTE PTR [rax+0x48],0x0
  3b46fb:	eb 2d                                           	jmp    0x3b472a
  3b46fd:	48 89 fb                                        	mov    rbx,rdi
  3b4700:	41 89 f6                                        	mov    r14d,esi
  3b4703:	48 89 c7                                        	mov    rdi,rax
  3b4706:	48 8d 35 43 13 70 01                            	lea    rsi,[rip+0x1701343]        # 0x1ab5a50
  3b470d:	41 89 d4                                        	mov    r12d,edx
  3b4710:	e8 db 46 85 00                                  	call   0xc08df0
  3b4715:	44 89 e2                                        	mov    edx,r12d
  3b4718:	44 89 f6                                        	mov    esi,r14d
  3b471b:	48 89 df                                        	mov    rdi,rbx
  3b471e:	4c 8b 65 d0                                     	mov    r12,QWORD PTR [rbp-0x30]
  3b4722:	4c 8b 75 c0                                     	mov    r14,QWORD PTR [rbp-0x40]
  3b4726:	48 8b 5d b8                                     	mov    rbx,QWORD PTR [rbp-0x48]
  3b472a:	48 c7 47 28 00 00 00 00                         	mov    QWORD PTR [rdi+0x28],0x0
  3b4732:	e9 79 ff ff ff                                  	jmp    0x3b46b0
  3b4737:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  3b4740:	8b 73 04                                        	mov    esi,DWORD PTR [rbx+0x4]
  3b4743:	45 8b 65 38                                     	mov    r12d,DWORD PTR [r13+0x38]
  3b4747:	41 83 fc 01                                     	cmp    r12d,0x1
  3b474b:	0f 84 df fe ff ff                               	je     0x3b4630
  3b4751:	41 83 fc 02                                     	cmp    r12d,0x2
  3b4755:	0f 85 e3 fe ff ff                               	jne    0x3b463e
  3b475b:	49 8b 7d 28                                     	mov    rdi,QWORD PTR [r13+0x28]
  3b475f:	48 85 ff                                        	test   rdi,rdi
  3b4762:	0f 84 9a fe ff ff                               	je     0x3b4602
  3b4768:	80 7f 48 00                                     	cmp    BYTE PTR [rdi+0x48],0x0
  3b476c:	74 06                                           	je     0x3b4774
  3b476e:	c6 47 48 00                                     	mov    BYTE PTR [rdi+0x48],0x0
  3b4772:	eb 12                                           	jmp    0x3b4786
  3b4774:	89 75 d0                                        	mov    DWORD PTR [rbp-0x30],esi
  3b4777:	48 8d 35 d2 12 70 01                            	lea    rsi,[rip+0x17012d2]        # 0x1ab5a50
  3b477e:	e8 6d 46 85 00                                  	call   0xc08df0
  3b4783:	8b 75 d0                                        	mov    esi,DWORD PTR [rbp-0x30]
  3b4786:	49 c7 45 28 00 00 00 00                         	mov    QWORD PTR [r13+0x28],0x0
  3b478e:	e9 9d fe ff ff                                  	jmp    0x3b4630
  3b4793:	4c 8d 2d 66 11 70 01                            	lea    r13,[rip+0x1701166]        # 0x1ab5900
  3b479a:	45 31 f6                                        	xor    r14d,r14d
  3b479d:	eb 2e                                           	jmp    0x3b47cd
  3b479f:	90                                              	nop
  3b47a0:	49 c7 44 24 40 00 00 00 00                      	mov    QWORD PTR [r12+0x40],0x0
  3b47a9:	4c 89 e7                                        	mov    rdi,r12
  3b47ac:	4c 89 ee                                        	mov    rsi,r13
  3b47af:	e8 3c 46 85 00                                  	call   0xc08df0
  3b47b4:	48 8b 43 28                                     	mov    rax,QWORD PTR [rbx+0x28]
  3b47b8:	4a c7 04 f0 00 00 00 00                         	mov    QWORD PTR [rax+r14*8],0x0
  3b47c0:	49 ff c6                                        	inc    r14
  3b47c3:	4c 39 75 c8                                     	cmp    QWORD PTR [rbp-0x38],r14
  3b47c7:	0f 84 b4 00 00 00                               	je     0x3b4881
  3b47cd:	48 8b 43 28                                     	mov    rax,QWORD PTR [rbx+0x28]
  3b47d1:	4e 8b 24 f0                                     	mov    r12,QWORD PTR [rax+r14*8]
  3b47d5:	4d 85 e4                                        	test   r12,r12
  3b47d8:	74 e6                                           	je     0x3b47c0
  3b47da:	4d 8b 7c 24 20                                  	mov    r15,QWORD PTR [r12+0x20]
  3b47df:	49 8b 7c 24 28                                  	mov    rdi,QWORD PTR [r12+0x28]
  3b47e4:	48 85 ff                                        	test   rdi,rdi
  3b47e7:	74 21                                           	je     0x3b480a
  3b47e9:	80 7f 48 00                                     	cmp    BYTE PTR [rdi+0x48],0x0
  3b47ed:	74 06                                           	je     0x3b47f5
  3b47ef:	c6 47 48 00                                     	mov    BYTE PTR [rdi+0x48],0x0
  3b47f3:	eb 0c                                           	jmp    0x3b4801
  3b47f5:	48 8d 35 54 12 70 01                            	lea    rsi,[rip+0x1701254]        # 0x1ab5a50
  3b47fc:	e8 ef 45 85 00                                  	call   0xc08df0
  3b4801:	49 c7 44 24 28 00 00 00 00                      	mov    QWORD PTR [r12+0x28],0x0
  3b480a:	0f b7 43 02                                     	movzx  eax,WORD PTR [rbx+0x2]
  3b480e:	66 83 f8 01                                     	cmp    ax,0x1
  3b4812:	74 7c                                           	je     0x3b4890
  3b4814:	49 83 c7 20                                     	add    r15,0x20
  3b4818:	ff c8                                           	dec    eax
  3b481a:	4c 89 ff                                        	mov    rdi,r15
  3b481d:	66 89 43 02                                     	mov    WORD PTR [rbx+0x2],ax
  3b4821:	e8 3a cf 83 00                                  	call   0xbf1760
  3b4826:	49 83 7c 24 28 00                               	cmp    QWORD PTR [r12+0x28],0x0
  3b482c:	74 1a                                           	je     0x3b4848
  3b482e:	48 8d 3d c2 21 f5 00                            	lea    rdi,[rip+0xf521c2]        # 0x13069f7
  3b4835:	48 8d 35 42 b3 fb 00                            	lea    rsi,[rip+0xfbb342]        # 0x136fb7e
  3b483c:	ba 35 0b 00 00                                  	mov    edx,0xb35
  3b4841:	31 c0                                           	xor    eax,eax
  3b4843:	e8 c8 8b ea ff                                  	call   0x25d410
  3b4848:	49 8b 44 24 40                                  	mov    rax,QWORD PTR [r12+0x40]
  3b484d:	48 85 c0                                        	test   rax,rax
  3b4850:	0f 84 53 ff ff ff                               	je     0x3b47a9
  3b4856:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  3b485b:	f0 0f c1 48 28                                  	lock xadd DWORD PTR [rax+0x28],ecx
  3b4860:	83 f9 01                                        	cmp    ecx,0x1
  3b4863:	0f 85 37 ff ff ff                               	jne    0x3b47a0
  3b4869:	49 8b 7c 24 40                                  	mov    rdi,QWORD PTR [r12+0x40]
  3b486e:	65 48 8b 34 25 00 00 00 00                      	mov    rsi,QWORD PTR gs:0x0
  3b4877:	e8 04 6b 37 00                                  	call   0x72b380
  3b487c:	e9 1f ff ff ff                                  	jmp    0x3b47a0
  3b4881:	48 83 c4 28                                     	add    rsp,0x28
  3b4885:	5b                                              	pop    rbx
  3b4886:	41 5c                                           	pop    r12
  3b4888:	41 5d                                           	pop    r13
  3b488a:	41 5e                                           	pop    r14
  3b488c:	41 5f                                           	pop    r15
  3b488e:	5d                                              	pop    rbp
  3b488f:	c3                                              	ret
  3b4890:	66 83 3b 01                                     	cmp    WORD PTR [rbx],0x1
  3b4894:	49 8b 44 24 18                                  	mov    rax,QWORD PTR [r12+0x18]
  3b4899:	4c 89 7d d0                                     	mov    QWORD PTR [rbp-0x30],r15
  3b489d:	48 89 45 c8                                     	mov    QWORD PTR [rbp-0x38],rax
  3b48a1:	0f 85 ae 00 00 00                               	jne    0x3b4955
  3b48a7:	41 8b 07                                        	mov    eax,DWORD PTR [r15]
  3b48aa:	85 c0                                           	test   eax,eax
  3b48ac:	0f 84 e7 00 00 00                               	je     0x3b4999
  3b48b2:	45 31 ff                                        	xor    r15d,r15d
  3b48b5:	eb 3e                                           	jmp    0x3b48f5
  3b48b7:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  3b48c0:	49 c7 45 40 00 00 00 00                         	mov    QWORD PTR [r13+0x40],0x0
  3b48c8:	4c 89 ef                                        	mov    rdi,r13
  3b48cb:	48 8d 35 2e 10 70 01                            	lea    rsi,[rip+0x170102e]        # 0x1ab5900
  3b48d2:	e8 19 45 85 00                                  	call   0xc08df0
  3b48d7:	48 8b 43 28                                     	mov    rax,QWORD PTR [rbx+0x28]
  3b48db:	4a c7 04 e0 00 00 00 00                         	mov    QWORD PTR [rax+r12*8],0x0
  3b48e3:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  3b48e7:	8b 00                                           	mov    eax,DWORD PTR [rax]
  3b48e9:	41 ff c7                                        	inc    r15d
  3b48ec:	41 39 c7                                        	cmp    r15d,eax
  3b48ef:	0f 83 a4 00 00 00                               	jae    0x3b4999
  3b48f5:	48 8b 4b 28                                     	mov    rcx,QWORD PTR [rbx+0x28]
  3b48f9:	4d 63 e7                                        	movsxd r12,r15d
  3b48fc:	4e 8b 2c e1                                     	mov    r13,QWORD PTR [rcx+r12*8]
  3b4900:	4d 85 ed                                        	test   r13,r13
  3b4903:	74 e4                                           	je     0x3b48e9
  3b4905:	49 83 7d 28 00                                  	cmp    QWORD PTR [r13+0x28],0x0
  3b490a:	74 1a                                           	je     0x3b4926
  3b490c:	48 8d 3d e4 20 f5 00                            	lea    rdi,[rip+0xf520e4]        # 0x13069f7
  3b4913:	48 8d 35 64 b2 fb 00                            	lea    rsi,[rip+0xfbb264]        # 0x136fb7e
  3b491a:	ba 35 0b 00 00                                  	mov    edx,0xb35
  3b491f:	31 c0                                           	xor    eax,eax
  3b4921:	e8 ea 8a ea ff                                  	call   0x25d410
  3b4926:	49 8b 45 40                                     	mov    rax,QWORD PTR [r13+0x40]
  3b492a:	48 85 c0                                        	test   rax,rax
  3b492d:	74 99                                           	je     0x3b48c8
  3b492f:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  3b4934:	f0 0f c1 48 28                                  	lock xadd DWORD PTR [rax+0x28],ecx
  3b4939:	83 f9 01                                        	cmp    ecx,0x1
  3b493c:	75 82                                           	jne    0x3b48c0
  3b493e:	49 8b 7d 40                                     	mov    rdi,QWORD PTR [r13+0x40]
  3b4942:	65 48 8b 34 25 00 00 00 00                      	mov    rsi,QWORD PTR gs:0x0
  3b494b:	e8 30 6a 37 00                                  	call   0x72b380
  3b4950:	e9 6b ff ff ff                                  	jmp    0x3b48c0
  3b4955:	49 8b 44 24 40                                  	mov    rax,QWORD PTR [r12+0x40]
  3b495a:	48 85 c0                                        	test   rax,rax
  3b495d:	74 2b                                           	je     0x3b498a
  3b495f:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  3b4964:	f0 0f c1 48 28                                  	lock xadd DWORD PTR [rax+0x28],ecx
  3b4969:	83 f9 01                                        	cmp    ecx,0x1
  3b496c:	75 13                                           	jne    0x3b4981
  3b496e:	49 8b 7c 24 40                                  	mov    rdi,QWORD PTR [r12+0x40]
  3b4973:	65 48 8b 34 25 00 00 00 00                      	mov    rsi,QWORD PTR gs:0x0
  3b497c:	e8 ff 69 37 00                                  	call   0x72b380
  3b4981:	49 c7 44 24 40 00 00 00 00                      	mov    QWORD PTR [r12+0x40],0x0
  3b498a:	48 8d 35 6f 0f 70 01                            	lea    rsi,[rip+0x1700f6f]        # 0x1ab5900
  3b4991:	4c 89 e7                                        	mov    rdi,r12
  3b4994:	e8 57 44 85 00                                  	call   0xc08df0
  3b4999:	4c 8b 7d c8                                     	mov    r15,QWORD PTR [rbp-0x38]
  3b499d:	49 8b 7f 10                                     	mov    rdi,QWORD PTR [r15+0x10]
  3b49a1:	e8 ca 4c ef ff                                  	call   0x2a9670
  3b49a6:	48 8d 35 33 10 70 01                            	lea    rsi,[rip+0x1701033]        # 0x1ab59e0
  3b49ad:	4c 89 ff                                        	mov    rdi,r15
  3b49b0:	e8 3b 44 85 00                                  	call   0xc08df0
  3b49b5:	48 8b 43 28                                     	mov    rax,QWORD PTR [rbx+0x28]
  3b49b9:	4a c7 04 f0 00 00 00 00                         	mov    QWORD PTR [rax+r14*8],0x0
  3b49c1:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  3b49c5:	8b 00                                           	mov    eax,DWORD PTR [rax]
  3b49c7:	83 f8 02                                        	cmp    eax,0x2
  3b49ca:	72 4c                                           	jb     0x3b4a18
  3b49cc:	4c 8d 3d 55 8e f2 00                            	lea    r15,[rip+0xf28e55]        # 0x12dd828
  3b49d3:	4c 8d 25 bc 69 fa 00                            	lea    r12,[rip+0xfa69bc]        # 0x135b396
  3b49da:	45 31 ed                                        	xor    r13d,r13d
  3b49dd:	eb 09                                           	jmp    0x3b49e8
  3b49df:	90                                              	nop
  3b49e0:	41 ff c5                                        	inc    r13d
  3b49e3:	41 39 c5                                        	cmp    r13d,eax
  3b49e6:	73 30                                           	jae    0x3b4a18
  3b49e8:	48 8b 4b 28                                     	mov    rcx,QWORD PTR [rbx+0x28]
  3b49ec:	49 63 d5                                        	movsxd rdx,r13d
  3b49ef:	4c 8b 0c d1                                     	mov    r9,QWORD PTR [rcx+rdx*8]
  3b49f3:	4d 85 c9                                        	test   r9,r9
  3b49f6:	74 e8                                           	je     0x3b49e0
  3b49f8:	4c 89 ff                                        	mov    rdi,r15
  3b49fb:	4c 89 e6                                        	mov    rsi,r12
  3b49fe:	ba df 15 00 00                                  	mov    edx,0x15df
  3b4a03:	44 89 e9                                        	mov    ecx,r13d
  3b4a06:	45 89 e8                                        	mov    r8d,r13d
  3b4a09:	31 c0                                           	xor    eax,eax
  3b4a0b:	e8 00 8a ea ff                                  	call   0x25d410
  3b4a10:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  3b4a14:	8b 00                                           	mov    eax,DWORD PTR [rax]
  3b4a16:	eb c8                                           	jmp    0x3b49e0
  3b4a18:	48 8b 7d d0                                     	mov    rdi,QWORD PTR [rbp-0x30]
  3b4a1c:	48 83 c7 20                                     	add    rdi,0x20
  3b4a20:	e8 3b cd 83 00                                  	call   0xbf1760
  3b4a25:	48 8b 7b 10                                     	mov    rdi,QWORD PTR [rbx+0x10]
  3b4a29:	48 8d 35 40 0f 70 01                            	lea    rsi,[rip+0x1700f40]        # 0x1ab5970
  3b4a30:	e8 bb 43 85 00                                  	call   0xc08df0
  3b4a35:	48 8b 7b 20                                     	mov    rdi,QWORD PTR [rbx+0x20]
  3b4a39:	48 8d 35 50 0e 70 01                            	lea    rsi,[rip+0x1700e50]        # 0x1ab5890
  3b4a40:	e8 ab 43 85 00                                  	call   0xc08df0
  3b4a45:	48 8b 7b 28                                     	mov    rdi,QWORD PTR [rbx+0x28]
  3b4a49:	4c 8d 35 00 10 70 01                            	lea    r14,[rip+0x1701000]        # 0x1ab5a50
  3b4a50:	4c 89 f6                                        	mov    rsi,r14
  3b4a53:	e8 98 43 85 00                                  	call   0xc08df0
  3b4a58:	48 89 df                                        	mov    rdi,rbx
  3b4a5b:	4c 89 f6                                        	mov    rsi,r14
  3b4a5e:	48 83 c4 28                                     	add    rsp,0x28
  3b4a62:	5b                                              	pop    rbx
  3b4a63:	41 5c                                           	pop    r12
  3b4a65:	41 5d                                           	pop    r13
  3b4a67:	41 5e                                           	pop    r14
  3b4a69:	41 5f                                           	pop    r15
  3b4a6b:	5d                                              	pop    rbp
  3b4a6c:	e9 7f 43 85 00                                  	jmp    0xc08df0
  3b4a71:	90                                              	nop
  3b4a72:	90                                              	nop
  3b4a73:	90                                              	nop
  3b4a74:	90                                              	nop
  3b4a75:	90                                              	nop
  3b4a76:	90                                              	nop
  3b4a77:	90                                              	nop
  3b4a78:	90                                              	nop
  3b4a79:	90                                              	nop
  3b4a7a:	90                                              	nop
  3b4a7b:	90                                              	nop
  3b4a7c:	90                                              	nop
  3b4a7d:	90                                              	nop
  3b4a7e:	90                                              	nop
  3b4a7f:	90                                              	nop
  3b4a80:	55                                              	push   rbp
  3b4a81:	48 89 e5                                        	mov    rbp,rsp
  3b4a84:	41 57                                           	push   r15
  3b4a86:	41 56                                           	push   r14
  3b4a88:	41 55                                           	push   r13
  3b4a8a:	41 54                                           	push   r12
  3b4a8c:	53                                              	push   rbx
  3b4a8d:	48 81 ec f8 00 00 00                            	sub    rsp,0xf8
  3b4a94:	c7 45 b4 00 00 00 00                            	mov    DWORD PTR [rbp-0x4c],0x0
  3b4a9b:	48 8d 45 b4                                     	lea    rax,[rbp-0x4c]
  3b4a9f:	be 4c 00 00 00                                  	mov    esi,0x4c
  3b4aa4:	ba 00 00 00 10                                  	mov    edx,0x10000000
  3b4aa9:	49 89 fd                                        	mov    r13,rdi
  3b4aac:	31 c9                                           	xor    ecx,ecx
  3b4aae:	65 48 8b 1c 25 00 00 00 00                      	mov    rbx,QWORD PTR gs:0x0
  3b4ab7:	4c 8b 7f 18                                     	mov    r15,QWORD PTR [rdi+0x18]
  3b4abb:	48 89 47 28                                     	mov    QWORD PTR [rdi+0x28],rax
  3b4abf:	31 ff                                           	xor    edi,edi
  3b4ac1:	e8 9a 19 57 00                                  	call   0x926460
  3b4ac6:	48 83 ec 08                                     	sub    rsp,0x8
  3b4aca:	48 8d 05 ff c5 ea ff                            	lea    rax,[rip+0xffffffffffeac5ff]        # 0x2610d0
  3b4ad1:	48 8d 35 67 ac f9 00                            	lea    rsi,[rip+0xf9ac67]        # 0x134f73f
  3b4ad8:	48 8d 15 a1 8f ea ff                            	lea    rdx,[rip+0xffffffffffea8fa1]        # 0x25da80
  3b4adf:	31 ff                                           	xor    edi,edi
  3b4ae1:	48 89 d9                                        	mov    rcx,rbx
  3b4ae4:	41 b8 19 27 00 00                               	mov    r8d,0x2719
  3b4aea:	49 89 d9                                        	mov    r9,rbx
  3b4aed:	50                                              	push   rax
  3b4aee:	e8 0d 95 38 00                                  	call   0x73e000
  3b4af3:	48 83 c4 10                                     	add    rsp,0x10
  3b4af7:	48 89 85 08 ff ff ff                            	mov    QWORD PTR [rbp-0xf8],rax
  3b4afe:	48 83 ec 08                                     	sub    rsp,0x8
  3b4b02:	48 8d 05 cf c5 ea ff                            	lea    rax,[rip+0xffffffffffeac5cf]        # 0x2610d8
  3b4b09:	48 8d 35 55 f9 ed 00                            	lea    rsi,[rip+0xedf955]        # 0x1294465
  3b4b10:	48 8d 15 71 8f ea ff                            	lea    rdx,[rip+0xffffffffffea8f71]        # 0x25da88
  3b4b17:	31 ff                                           	xor    edi,edi
  3b4b19:	48 89 d9                                        	mov    rcx,rbx
  3b4b1c:	41 b8 0b 00 00 00                               	mov    r8d,0xb
  3b4b22:	49 89 d9                                        	mov    r9,rbx
  3b4b25:	50                                              	push   rax
  3b4b26:	e8 d5 94 38 00                                  	call   0x73e000
  3b4b2b:	48 83 c4 10                                     	add    rsp,0x10
  3b4b2f:	48 89 df                                        	mov    rdi,rbx
  3b4b32:	31 f6                                           	xor    esi,esi
  3b4b34:	48 89 85 00 ff ff ff                            	mov    QWORD PTR [rbp-0x100],rax
  3b4b3b:	48 89 9d 60 ff ff ff                            	mov    QWORD PTR [rbp-0xa0],rbx
  3b4b42:	e8 11 08 eb ff                                  	call   0x265358
  3b4b47:	48 8d 3d 9a a7 11 03                            	lea    rdi,[rip+0x311a79a]        # 0x34cf2e8
  3b4b4e:	31 f6                                           	xor    esi,esi
  3b4b50:	31 d2                                           	xor    edx,edx
  3b4b52:	31 c9                                           	xor    ecx,ecx
  3b4b54:	e8 a7 1e 11 00                                  	call   0x4c6a00
  3b4b59:	41 83 bf a0 04 00 00 00                         	cmp    DWORD PTR [r15+0x4a0],0x0
  3b4b61:	79 38                                           	jns    0x3b4b9b
  3b4b63:	48 8d 3d 86 a7 11 03                            	lea    rdi,[rip+0x311a786]        # 0x34cf2f0
  3b4b6a:	48 8d 35 5f a7 11 03                            	lea    rsi,[rip+0x311a75f]        # 0x34cf2d0
  3b4b71:	31 d2                                           	xor    edx,edx
  3b4b73:	e8 08 9c 38 00                                  	call   0x73e780
  3b4b78:	85 c0                                           	test   eax,eax
  3b4b7a:	74 1f                                           	je     0x3b4b9b
  3b4b7c:	48 8d 3d 16 bc f9 00                            	lea    rdi,[rip+0xf9bc16]        # 0x1350799
  3b4b83:	48 8d 35 52 f7 fe 00                            	lea    rsi,[rip+0xfef752]        # 0x13a42dc
  3b4b8a:	ba 20 07 00 00                                  	mov    edx,0x720
  3b4b8f:	89 c1                                           	mov    ecx,eax
  3b4b91:	41 89 c0                                        	mov    r8d,eax
  3b4b94:	31 c0                                           	xor    eax,eax
  3b4b96:	e8 75 88 ea ff                                  	call   0x25d410
  3b4b9b:	48 8d 3d 46 a7 11 03                            	lea    rdi,[rip+0x311a746]        # 0x34cf2e8
  3b4ba2:	31 f6                                           	xor    esi,esi
  3b4ba4:	31 d2                                           	xor    edx,edx
  3b4ba6:	31 c9                                           	xor    ecx,ecx
  3b4ba8:	e8 f3 23 11 00                                  	call   0x4c6fa0
  3b4bad:	e8 1e 2d 75 00                                  	call   0xb078d0
  3b4bb2:	85 c0                                           	test   eax,eax
  3b4bb4:	74 08                                           	je     0x3b4bbe
  3b4bb6:	41 c7 45 20 00 00 00 00                         	mov    DWORD PTR [r13+0x20],0x0
  3b4bbe:	49 8d 4f 40                                     	lea    rcx,[r15+0x40]
  3b4bc2:	49 8d 87 d8 00 00 00                            	lea    rax,[r15+0xd8]
  3b4bc9:	49 8d 55 30                                     	lea    rdx,[r13+0x30]
  3b4bcd:	4c 89 6d d0                                     	mov    QWORD PTR [rbp-0x30],r13
  3b4bd1:	4c 89 7d c0                                     	mov    QWORD PTR [rbp-0x40],r15
  3b4bd5:	48 89 8d e8 fe ff ff                            	mov    QWORD PTR [rbp-0x118],rcx
  3b4bdc:	49 8d 8f 80 00 00 00                            	lea    rcx,[r15+0x80]
  3b4be3:	48 89 85 e0 fe ff ff                            	mov    QWORD PTR [rbp-0x120],rax
  3b4bea:	48 89 95 68 ff ff ff                            	mov    QWORD PTR [rbp-0x98],rdx
  3b4bf1:	48 89 8d 50 ff ff ff                            	mov    QWORD PTR [rbp-0xb0],rcx
  3b4bf8:	eb 2d                                           	jmp    0x3b4c27
  3b4bfa:	66 0f 1f 44 00 00                               	nop    WORD PTR [rax+rax*1+0x0]
  3b4c00:	48 8b bd 58 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xa8]
  3b4c07:	be 00 00 10 00                                  	mov    esi,0x100000
  3b4c0c:	31 d2                                           	xor    edx,edx
  3b4c0e:	31 c9                                           	xor    ecx,ecx
  3b4c10:	45 31 c0                                        	xor    r8d,r8d
  3b4c13:	45 31 c9                                        	xor    r9d,r9d
  3b4c16:	6a 00                                           	push   0x0
  3b4c18:	6a 00                                           	push   0x0
  3b4c1a:	e8 51 cb 83 00                                  	call   0xbf1770
  3b4c1f:	48 83 c4 10                                     	add    rsp,0x10
  3b4c23:	4c 8b 7d c0                                     	mov    r15,QWORD PTR [rbp-0x40]
  3b4c27:	e8 84 15 57 00                                  	call   0x9261b0
  3b4c2c:	bb 03 00 00 00                                  	mov    ebx,0x3
  3b4c31:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b4c40:	49 89 de                                        	mov    r14,rbx
  3b4c43:	31 f6                                           	xor    esi,esi
  3b4c45:	31 d2                                           	xor    edx,edx
  3b4c47:	31 c9                                           	xor    ecx,ecx
  3b4c49:	49 c1 e6 05                                     	shl    r14,0x5
  3b4c4d:	4c 03 b5 e0 fe ff ff                            	add    r14,QWORD PTR [rbp-0x120]
  3b4c54:	4c 89 f7                                        	mov    rdi,r14
  3b4c57:	e8 a4 1d 11 00                                  	call   0x4c6a00
  3b4c5c:	41 83 bc 9f c0 01 00 00 00                      	cmp    DWORD PTR [r15+rbx*4+0x1c0],0x0
  3b4c65:	41 bc 00 00 00 00                               	mov    r12d,0x0
  3b4c6b:	0f 84 6f 04 00 00                               	je     0x3b50e0
  3b4c71:	48 8b 85 e8 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x118]
  3b4c78:	49 89 df                                        	mov    r15,rbx
  3b4c7b:	49 c1 e7 04                                     	shl    r15,0x4
  3b4c7f:	4e 8b 24 38                                     	mov    r12,QWORD PTR [rax+r15*1]
  3b4c83:	4d 85 e4                                        	test   r12,r12
  3b4c86:	0f 84 a4 01 00 00                               	je     0x3b4e30
  3b4c8c:	4c 01 f8                                        	add    rax,r15
  3b4c8f:	48 89 45 b8                                     	mov    QWORD PTR [rbp-0x48],rax
  3b4c93:	eb 2d                                           	jmp    0x3b4cc2
  3b4c95:	48 8d 3d 4c a6 11 03                            	lea    rdi,[rip+0x311a64c]        # 0x34cf2e8
  3b4c9c:	31 f6                                           	xor    esi,esi
  3b4c9e:	31 d2                                           	xor    edx,edx
  3b4ca0:	31 c9                                           	xor    ecx,ecx
  3b4ca2:	e8 f9 22 11 00                                  	call   0x4c6fa0
  3b4ca7:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  3b4cb0:	4d 8b 64 24 48                                  	mov    r12,QWORD PTR [r12+0x48]
  3b4cb5:	4c 8b 6d d0                                     	mov    r13,QWORD PTR [rbp-0x30]
  3b4cb9:	4d 85 e4                                        	test   r12,r12
  3b4cbc:	0f 84 6e 01 00 00                               	je     0x3b4e30
  3b4cc2:	49 8b 44 24 18                                  	mov    rax,QWORD PTR [r12+0x18]
  3b4cc7:	48 8b 40 08                                     	mov    rax,QWORD PTR [rax+0x8]
  3b4ccb:	49 89 45 10                                     	mov    QWORD PTR [r13+0x10],rax
  3b4ccf:	41 8b 44 24 38                                  	mov    eax,DWORD PTR [r12+0x38]
  3b4cd4:	83 f8 02                                        	cmp    eax,0x2
  3b4cd7:	74 67                                           	je     0x3b4d40
  3b4cd9:	83 f8 01                                        	cmp    eax,0x1
  3b4cdc:	75 d2                                           	jne    0x3b4cb0
  3b4cde:	48 83 3d da bc 11 03 00                         	cmp    QWORD PTR [rip+0x311bcda],0x0        # 0x34d09c0
  3b4ce6:	0f 84 b6 00 00 00                               	je     0x3b4da2
  3b4cec:	48 8d 3d f5 a5 11 03                            	lea    rdi,[rip+0x311a5f5]        # 0x34cf2e8
  3b4cf3:	31 f6                                           	xor    esi,esi
  3b4cf5:	31 d2                                           	xor    edx,edx
  3b4cf7:	31 c9                                           	xor    ecx,ecx
  3b4cf9:	e8 02 1d 11 00                                  	call   0x4c6a00
  3b4cfe:	48 8b 05 bb bc 11 03                            	mov    rax,QWORD PTR [rip+0x311bcbb]        # 0x34d09c0
  3b4d05:	48 85 c0                                        	test   rax,rax
  3b4d08:	0f 84 82 00 00 00                               	je     0x3b4d90
  3b4d0e:	49 8b 4c 24 18                                  	mov    rcx,QWORD PTR [r12+0x18]
  3b4d13:	48 8b 49 08                                     	mov    rcx,QWORD PTR [rcx+0x8]
  3b4d17:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  3b4d20:	48 3b 08                                        	cmp    rcx,QWORD PTR [rax]
  3b4d23:	0f 84 6c ff ff ff                               	je     0x3b4c95
  3b4d29:	48 8b 40 08                                     	mov    rax,QWORD PTR [rax+0x8]
  3b4d2d:	48 85 c0                                        	test   rax,rax
  3b4d30:	75 ee                                           	jne    0x3b4d20
  3b4d32:	eb 5c                                           	jmp    0x3b4d90
  3b4d34:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b4d40:	4d 8b 6c 24 28                                  	mov    r13,QWORD PTR [r12+0x28]
  3b4d45:	4d 85 ed                                        	test   r13,r13
  3b4d48:	75 1a                                           	jne    0x3b4d64
  3b4d4a:	48 8d 3d 99 76 f4 00                            	lea    rdi,[rip+0xf47699]        # 0x12fc3ea
  3b4d51:	48 8d 35 84 f5 fe 00                            	lea    rsi,[rip+0xfef584]        # 0x13a42dc
  3b4d58:	ba 7f 07 00 00                                  	mov    edx,0x77f
  3b4d5d:	31 c0                                           	xor    eax,eax
  3b4d5f:	e8 ac 86 ea ff                                  	call   0x25d410
  3b4d64:	41 80 7d 4a 00                                  	cmp    BYTE PTR [r13+0x4a],0x0
  3b4d69:	0f 85 60 02 00 00                               	jne    0x3b4fcf
  3b4d6f:	41 80 7d 49 00                                  	cmp    BYTE PTR [r13+0x49],0x0
  3b4d74:	0f 85 36 ff ff ff                               	jne    0x3b4cb0
  3b4d7a:	b0 01                                           	mov    al,0x1
  3b4d7c:	e9 50 02 00 00                                  	jmp    0x3b4fd1
  3b4d81:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b4d90:	48 8d 3d 51 a5 11 03                            	lea    rdi,[rip+0x311a551]        # 0x34cf2e8
  3b4d97:	31 f6                                           	xor    esi,esi
  3b4d99:	31 d2                                           	xor    edx,edx
  3b4d9b:	31 c9                                           	xor    ecx,ecx
  3b4d9d:	e8 fe 21 11 00                                  	call   0x4c6fa0
  3b4da2:	48 8b 45 c0                                     	mov    rax,QWORD PTR [rbp-0x40]
  3b4da6:	83 bc 98 a0 01 00 00 00                         	cmp    DWORD PTR [rax+rbx*4+0x1a0],0x0
  3b4dae:	0f 84 8c 00 00 00                               	je     0x3b4e40
  3b4db4:	41 83 3c 24 01                                  	cmp    DWORD PTR [r12],0x1
  3b4db9:	0f 85 81 00 00 00                               	jne    0x3b4e40
  3b4dbf:	49 8b 44 24 10                                  	mov    rax,QWORD PTR [r12+0x10]
  3b4dc4:	48 8b 4d c0                                     	mov    rcx,QWORD PTR [rbp-0x40]
  3b4dc8:	4c 8b 6d d0                                     	mov    r13,QWORD PTR [rbp-0x30]
  3b4dcc:	48 8b 40 08                                     	mov    rax,QWORD PTR [rax+0x8]
  3b4dd0:	8b 8c 99 b0 01 00 00                            	mov    ecx,DWORD PTR [rcx+rbx*4+0x1b0]
  3b4dd7:	48 39 c8                                        	cmp    rax,rcx
  3b4dda:	0f 86 c6 00 00 00                               	jbe    0x3b4ea6
  3b4de0:	48 3d ff ff ff 7f                               	cmp    rax,0x7fffffff
  3b4de6:	0f 87 ba 00 00 00                               	ja     0x3b4ea6
  3b4dec:	48 8b 4d c0                                     	mov    rcx,QWORD PTR [rbp-0x40]
  3b4df0:	8b 8c 99 90 01 00 00                            	mov    ecx,DWORD PTR [rcx+rbx*4+0x190]
  3b4df7:	48 39 c8                                        	cmp    rax,rcx
  3b4dfa:	0f 86 a6 00 00 00                               	jbe    0x3b4ea6
  3b4e00:	4c 89 e7                                        	mov    rdi,r12
  3b4e03:	89 de                                           	mov    esi,ebx
  3b4e05:	4c 89 ea                                        	mov    rdx,r13
  3b4e08:	e8 a3 18 00 00                                  	call   0x3b66b0
  3b4e0d:	41 c7 44 24 38 02 00 00 00                      	mov    DWORD PTR [r12+0x38],0x2
  3b4e16:	4c 8b 7d c0                                     	mov    r15,QWORD PTR [rbp-0x40]
  3b4e1a:	49 8b 44 24 08                                  	mov    rax,QWORD PTR [r12+0x8]
  3b4e1f:	49 89 84 df 40 01 00 00                         	mov    QWORD PTR [r15+rbx*8+0x140],rax
  3b4e27:	e9 b4 02 00 00                                  	jmp    0x3b50e0
  3b4e2c:	0f 1f 40 00                                     	nop    DWORD PTR [rax+0x0]
  3b4e30:	4c 8b 7d c0                                     	mov    r15,QWORD PTR [rbp-0x40]
  3b4e34:	45 31 e4                                        	xor    r12d,r12d
  3b4e37:	e9 a4 02 00 00                                  	jmp    0x3b50e0
  3b4e3c:	0f 1f 40 00                                     	nop    DWORD PTR [rax+0x0]
  3b4e40:	49 8b 44 24 48                                  	mov    rax,QWORD PTR [r12+0x48]
  3b4e45:	48 85 c0                                        	test   rax,rax
  3b4e48:	74 23                                           	je     0x3b4e6d
  3b4e4a:	4d 8d 6c 24 48                                  	lea    r13,[r12+0x48]
  3b4e4f:	4c 39 68 50                                     	cmp    QWORD PTR [rax+0x50],r13
  3b4e53:	0f 85 06 0d 00 00                               	jne    0x3b5b5f
  3b4e59:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b4e5e:	4c 39 21                                        	cmp    QWORD PTR [rcx],r12
  3b4e61:	0f 85 90 0c 00 00                               	jne    0x3b5af7
  3b4e67:	48 89 48 50                                     	mov    QWORD PTR [rax+0x50],rcx
  3b4e6b:	eb 16                                           	jmp    0x3b4e83
  3b4e6d:	49 8b 44 24 50                                  	mov    rax,QWORD PTR [r12+0x50]
  3b4e72:	4c 39 20                                        	cmp    QWORD PTR [rax],r12
  3b4e75:	0f 85 7c 0c 00 00                               	jne    0x3b5af7
  3b4e7b:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  3b4e7f:	48 89 41 08                                     	mov    QWORD PTR [rcx+0x8],rax
  3b4e83:	49 8b 44 24 48                                  	mov    rax,QWORD PTR [r12+0x48]
  3b4e88:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b4e8d:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  3b4e90:	48 8b 4d c0                                     	mov    rcx,QWORD PTR [rbp-0x40]
  3b4e94:	41 c7 44 24 38 02 00 00 00                      	mov    DWORD PTR [r12+0x38],0x2
  3b4e9d:	ff 8c 99 c0 01 00 00                            	dec    DWORD PTR [rcx+rbx*4+0x1c0]
  3b4ea4:	eb 64                                           	jmp    0x3b4f0a
  3b4ea6:	49 8b 44 24 48                                  	mov    rax,QWORD PTR [r12+0x48]
  3b4eab:	48 85 c0                                        	test   rax,rax
  3b4eae:	74 23                                           	je     0x3b4ed3
  3b4eb0:	4d 8d 6c 24 48                                  	lea    r13,[r12+0x48]
  3b4eb5:	4c 39 68 50                                     	cmp    QWORD PTR [rax+0x50],r13
  3b4eb9:	0f 85 49 0d 00 00                               	jne    0x3b5c08
  3b4ebf:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b4ec4:	4c 39 21                                        	cmp    QWORD PTR [rcx],r12
  3b4ec7:	0f 85 09 0d 00 00                               	jne    0x3b5bd6
  3b4ecd:	48 89 48 50                                     	mov    QWORD PTR [rax+0x50],rcx
  3b4ed1:	eb 16                                           	jmp    0x3b4ee9
  3b4ed3:	49 8b 44 24 50                                  	mov    rax,QWORD PTR [r12+0x50]
  3b4ed8:	4c 39 20                                        	cmp    QWORD PTR [rax],r12
  3b4edb:	0f 85 f5 0c 00 00                               	jne    0x3b5bd6
  3b4ee1:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  3b4ee5:	48 89 41 08                                     	mov    QWORD PTR [rcx+0x8],rax
  3b4ee9:	49 8b 44 24 48                                  	mov    rax,QWORD PTR [r12+0x48]
  3b4eee:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b4ef3:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  3b4ef6:	48 8b 4d c0                                     	mov    rcx,QWORD PTR [rbp-0x40]
  3b4efa:	ff 8c 99 c0 01 00 00                            	dec    DWORD PTR [rcx+rbx*4+0x1c0]
  3b4f01:	41 c7 44 24 38 02 00 00 00                      	mov    DWORD PTR [r12+0x38],0x2
  3b4f0a:	49 8b 44 24 08                                  	mov    rax,QWORD PTR [r12+0x8]
  3b4f0f:	48 89 84 d9 40 01 00 00                         	mov    QWORD PTR [rcx+rbx*8+0x140],rax
  3b4f17:	48 8b 85 50 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xb0]
  3b4f1e:	4e 8b 2c 38                                     	mov    r13,QWORD PTR [rax+r15*1]
  3b4f22:	4d 85 ed                                        	test   r13,r13
  3b4f25:	0f 84 ab 01 00 00                               	je     0x3b50d6
  3b4f2b:	49 8b 45 48                                     	mov    rax,QWORD PTR [r13+0x48]
  3b4f2f:	49 8d 75 48                                     	lea    rsi,[r13+0x48]
  3b4f33:	48 85 c0                                        	test   rax,rax
  3b4f36:	74 1d                                           	je     0x3b4f55
  3b4f38:	48 39 70 50                                     	cmp    QWORD PTR [rax+0x50],rsi
  3b4f3c:	0f 85 53 0c 00 00                               	jne    0x3b5b95
  3b4f42:	49 8b 4d 50                                     	mov    rcx,QWORD PTR [r13+0x50]
  3b4f46:	4c 39 29                                        	cmp    QWORD PTR [rcx],r13
  3b4f49:	0f 85 da 0b 00 00                               	jne    0x3b5b29
  3b4f4f:	48 89 48 50                                     	mov    QWORD PTR [rax+0x50],rcx
  3b4f53:	eb 18                                           	jmp    0x3b4f6d
  3b4f55:	49 8b 45 50                                     	mov    rax,QWORD PTR [r13+0x50]
  3b4f59:	4c 39 28                                        	cmp    QWORD PTR [rax],r13
  3b4f5c:	0f 85 c7 0b 00 00                               	jne    0x3b5b29
  3b4f62:	4c 03 bd 50 ff ff ff                            	add    r15,QWORD PTR [rbp-0xb0]
  3b4f69:	49 89 47 08                                     	mov    QWORD PTR [r15+0x8],rax
  3b4f6d:	49 8b 45 48                                     	mov    rax,QWORD PTR [r13+0x48]
  3b4f71:	49 8b 4d 50                                     	mov    rcx,QWORD PTR [r13+0x50]
  3b4f75:	4c 8b 7d c0                                     	mov    r15,QWORD PTR [rbp-0x40]
  3b4f79:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  3b4f7c:	41 8b 84 9f d0 01 00 00                         	mov    eax,DWORD PTR [r15+rbx*4+0x1d0]
  3b4f84:	8d 48 01                                        	lea    ecx,[rax+0x1]
  3b4f87:	41 89 8c 9f d0 01 00 00                         	mov    DWORD PTR [r15+rbx*4+0x1d0],ecx
  3b4f8f:	41 89 45 04                                     	mov    DWORD PTR [r13+0x4],eax
  3b4f93:	49 8b 55 08                                     	mov    rdx,QWORD PTR [r13+0x8]
  3b4f97:	48 85 d2                                        	test   rdx,rdx
  3b4f9a:	74 0f                                           	je     0x3b4fab
  3b4f9c:	4c 89 ef                                        	mov    rdi,r13
  3b4f9f:	89 de                                           	mov    esi,ebx
  3b4fa1:	4c 89 f9                                        	mov    rcx,r15
  3b4fa4:	e8 97 f4 ff ff                                  	call   0x3b4440
  3b4fa9:	eb 1b                                           	jmp    0x3b4fc6
  3b4fab:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  3b4faf:	49 c7 45 48 00 00 00 00                         	mov    QWORD PTR [r13+0x48],0x0
  3b4fb7:	48 8b 41 08                                     	mov    rax,QWORD PTR [rcx+0x8]
  3b4fbb:	49 89 45 50                                     	mov    QWORD PTR [r13+0x50],rax
  3b4fbf:	4c 89 28                                        	mov    QWORD PTR [rax],r13
  3b4fc2:	48 89 71 08                                     	mov    QWORD PTR [rcx+0x8],rsi
  3b4fc6:	4c 8b 6d d0                                     	mov    r13,QWORD PTR [rbp-0x30]
  3b4fca:	e9 11 01 00 00                                  	jmp    0x3b50e0
  3b4fcf:	31 c0                                           	xor    eax,eax
  3b4fd1:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  3b4fd5:	41 c6 45 49 01                                  	mov    BYTE PTR [r13+0x49],0x1
  3b4fda:	48 8b b5 68 ff ff ff                            	mov    rsi,QWORD PTR [rbp-0x98]
  3b4fe1:	88 41 75                                        	mov    BYTE PTR [rcx+0x75],al
  3b4fe4:	49 8b 7c 24 28                                  	mov    rdi,QWORD PTR [r12+0x28]
  3b4fe9:	48 8b 41 18                                     	mov    rax,QWORD PTR [rcx+0x18]
  3b4fed:	8b 57 28                                        	mov    edx,DWORD PTR [rdi+0x28]
  3b4ff0:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  3b4ff4:	48 89 7d 90                                     	mov    QWORD PTR [rbp-0x70],rdi
  3b4ff8:	ff c2                                           	inc    edx
  3b4ffa:	89 57 28                                        	mov    DWORD PTR [rdi+0x28],edx
  3b4ffd:	89 51 70                                        	mov    DWORD PTR [rcx+0x70],edx
  3b5000:	ba 28 00 00 00                                  	mov    edx,0x28
  3b5005:	e8 d6 4b ea ff                                  	call   0x259be0
  3b500a:	48 8b 7d 90                                     	mov    rdi,QWORD PTR [rbp-0x70]
  3b500e:	48 8b 75 d0                                     	mov    rsi,QWORD PTR [rbp-0x30]
  3b5012:	4c 8b 45 88                                     	mov    r8,QWORD PTR [rbp-0x78]
  3b5016:	48 8d 47 30                                     	lea    rax,[rdi+0x30]
  3b501a:	48 89 46 60                                     	mov    QWORD PTR [rsi+0x60],rax
  3b501e:	48 8b 47 38                                     	mov    rax,QWORD PTR [rdi+0x38]
  3b5022:	41 8b 94 98 90 01 00 00                         	mov    edx,DWORD PTR [r8+rbx*4+0x190]
  3b502a:	48 89 c1                                        	mov    rcx,rax
  3b502d:	48 29 d1                                        	sub    rcx,rdx
  3b5030:	73 0e                                           	jae    0x3b5040
  3b5032:	48 89 46 38                                     	mov    QWORD PTR [rsi+0x38],rax
  3b5036:	48 c7 47 38 00 00 00 00                         	mov    QWORD PTR [rdi+0x38],0x0
  3b503e:	eb 27                                           	jmp    0x3b5067
  3b5040:	48 89 4f 38                                     	mov    QWORD PTR [rdi+0x38],rcx
  3b5044:	41 8b 84 98 90 01 00 00                         	mov    eax,DWORD PTR [r8+rbx*4+0x190]
  3b504c:	48 89 46 38                                     	mov    QWORD PTR [rsi+0x38],rax
  3b5050:	41 8b 84 98 90 01 00 00                         	mov    eax,DWORD PTR [r8+rbx*4+0x190]
  3b5058:	48 01 07                                        	add    QWORD PTR [rdi],rax
  3b505b:	41 8b 84 98 90 01 00 00                         	mov    eax,DWORD PTR [r8+rbx*4+0x190]
  3b5063:	48 01 47 10                                     	add    QWORD PTR [rdi+0x10],rax
  3b5067:	c6 46 74 00                                     	mov    BYTE PTR [rsi+0x74],0x0
  3b506b:	41 83 7d 4c 00                                  	cmp    DWORD PTR [r13+0x4c],0x0
  3b5070:	74 24                                           	je     0x3b5096
  3b5072:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b5080:	41 8b 45 30                                     	mov    eax,DWORD PTR [r13+0x30]
  3b5084:	41 8b 4d 28                                     	mov    ecx,DWORD PTR [r13+0x28]
  3b5088:	01 c1                                           	add    ecx,eax
  3b508a:	41 2b 4d 2c                                     	sub    ecx,DWORD PTR [r13+0x2c]
  3b508e:	f0 41 0f b1 4d 30                               	lock cmpxchg DWORD PTR [r13+0x30],ecx
  3b5094:	75 ea                                           	jne    0x3b5080
  3b5096:	49 83 7d 38 00                                  	cmp    QWORD PTR [r13+0x38],0x0
  3b509b:	74 07                                           	je     0x3b50a4
  3b509d:	41 83 7d 4c 00                                  	cmp    DWORD PTR [r13+0x4c],0x0
  3b50a2:	74 32                                           	je     0x3b50d6
  3b50a4:	49 8b 44 24 48                                  	mov    rax,QWORD PTR [r12+0x48]
  3b50a9:	4d 8d 6c 24 48                                  	lea    r13,[r12+0x48]
  3b50ae:	48 85 c0                                        	test   rax,rax
  3b50b1:	74 6b                                           	je     0x3b511e
  3b50b3:	4c 39 68 50                                     	cmp    QWORD PTR [rax+0x50],r13
  3b50b7:	0f 85 20 0c 00 00                               	jne    0x3b5cdd
  3b50bd:	49 8b 54 24 50                                  	mov    rdx,QWORD PTR [r12+0x50]
  3b50c2:	4c 39 22                                        	cmp    QWORD PTR [rdx],r12
  3b50c5:	0f 85 d6 0b 00 00                               	jne    0x3b5ca1
  3b50cb:	49 8d 4c 24 50                                  	lea    rcx,[r12+0x50]
  3b50d0:	48 89 50 50                                     	mov    QWORD PTR [rax+0x50],rdx
  3b50d4:	eb 63                                           	jmp    0x3b5139
  3b50d6:	4c 8b 6d d0                                     	mov    r13,QWORD PTR [rbp-0x30]
  3b50da:	4c 8b 7d c0                                     	mov    r15,QWORD PTR [rbp-0x40]
  3b50de:	66 90                                           	xchg   ax,ax
  3b50e0:	e8 eb 27 75 00                                  	call   0xb078d0
  3b50e5:	85 c0                                           	test   eax,eax
  3b50e7:	74 0f                                           	je     0x3b50f8
  3b50e9:	41 83 7d 20 00                                  	cmp    DWORD PTR [r13+0x20],0x0
  3b50ee:	74 08                                           	je     0x3b50f8
  3b50f0:	41 c7 45 20 00 00 00 00                         	mov    DWORD PTR [r13+0x20],0x0
  3b50f8:	4c 89 f7                                        	mov    rdi,r14
  3b50fb:	31 f6                                           	xor    esi,esi
  3b50fd:	31 d2                                           	xor    edx,edx
  3b50ff:	31 c9                                           	xor    ecx,ecx
  3b5101:	e8 9a 1e 11 00                                  	call   0x4c6fa0
  3b5106:	4d 85 e4                                        	test   r12,r12
  3b5109:	75 55                                           	jne    0x3b5160
  3b510b:	48 83 fb 02                                     	cmp    rbx,0x2
  3b510f:	48 8d 5b ff                                     	lea    rbx,[rbx-0x1]
  3b5113:	0f 83 27 fb ff ff                               	jae    0x3b4c40
  3b5119:	e9 12 03 00 00                                  	jmp    0x3b5430
  3b511e:	49 8b 44 24 50                                  	mov    rax,QWORD PTR [r12+0x50]
  3b5123:	4c 39 20                                        	cmp    QWORD PTR [rax],r12
  3b5126:	0f 85 75 0b 00 00                               	jne    0x3b5ca1
  3b512c:	48 8b 55 b8                                     	mov    rdx,QWORD PTR [rbp-0x48]
  3b5130:	49 8d 4c 24 50                                  	lea    rcx,[r12+0x50]
  3b5135:	48 89 42 08                                     	mov    QWORD PTR [rdx+0x8],rax
  3b5139:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  3b513d:	48 8b 09                                        	mov    rcx,QWORD PTR [rcx]
  3b5140:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  3b5143:	48 8b 4d c0                                     	mov    rcx,QWORD PTR [rbp-0x40]
  3b5147:	ff 8c 99 c0 01 00 00                            	dec    DWORD PTR [rcx+rbx*4+0x1c0]
  3b514e:	e9 c4 fd ff ff                                  	jmp    0x3b4f17
  3b5153:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b5160:	4d 8b 7c 24 20                                  	mov    r15,QWORD PTR [r12+0x20]
  3b5165:	be 00 00 08 00                                  	mov    esi,0x80000
  3b516a:	31 d2                                           	xor    edx,edx
  3b516c:	31 c9                                           	xor    ecx,ecx
  3b516e:	45 31 c0                                        	xor    r8d,r8d
  3b5171:	45 31 c9                                        	xor    r9d,r9d
  3b5174:	49 8d 5f 20                                     	lea    rbx,[r15+0x20]
  3b5178:	48 89 df                                        	mov    rdi,rbx
  3b517b:	6a 00                                           	push   0x0
  3b517d:	6a 00                                           	push   0x0
  3b517f:	e8 ec c5 83 00                                  	call   0xbf1770
  3b5184:	48 83 c4 10                                     	add    rsp,0x10
  3b5188:	41 83 7f 08 01                                  	cmp    DWORD PTR [r15+0x8],0x1
  3b518d:	75 08                                           	jne    0x3b5197
  3b518f:	41 c7 47 08 02 00 00 00                         	mov    DWORD PTR [r15+0x8],0x2
  3b5197:	be 00 00 10 00                                  	mov    esi,0x100000
  3b519c:	48 89 df                                        	mov    rdi,rbx
  3b519f:	31 d2                                           	xor    edx,edx
  3b51a1:	31 c9                                           	xor    ecx,ecx
  3b51a3:	45 31 c0                                        	xor    r8d,r8d
  3b51a6:	45 31 c9                                        	xor    r9d,r9d
  3b51a9:	6a 00                                           	push   0x0
  3b51ab:	6a 00                                           	push   0x0
  3b51ad:	e8 be c5 83 00                                  	call   0xbf1770
  3b51b2:	48 83 c4 10                                     	add    rsp,0x10
  3b51b6:	48 8d 3d 2b a1 11 03                            	lea    rdi,[rip+0x311a12b]        # 0x34cf2e8
  3b51bd:	31 f6                                           	xor    esi,esi
  3b51bf:	31 d2                                           	xor    edx,edx
  3b51c1:	31 c9                                           	xor    ecx,ecx
  3b51c3:	e8 38 18 11 00                                  	call   0x4c6a00
  3b51c8:	48 8b 45 c0                                     	mov    rax,QWORD PTR [rbp-0x40]
  3b51cc:	48 8b b0 b0 04 00 00                            	mov    rsi,QWORD PTR [rax+0x4b0]
  3b51d3:	48 85 f6                                        	test   rsi,rsi
  3b51d6:	74 0c                                           	je     0x3b51e4
  3b51d8:	48 8d 3d 11 a1 11 03                            	lea    rdi,[rip+0x311a111]        # 0x34cf2f0
  3b51df:	e8 9c 9d 38 00                                  	call   0x73ef80
  3b51e4:	48 8b 45 c0                                     	mov    rax,QWORD PTR [rbp-0x40]
  3b51e8:	48 89 9d 58 ff ff ff                            	mov    QWORD PTR [rbp-0xa8],rbx
  3b51ef:	48 8b b0 28 05 00 00                            	mov    rsi,QWORD PTR [rax+0x528]
  3b51f6:	48 85 f6                                        	test   rsi,rsi
  3b51f9:	74 0c                                           	je     0x3b5207
  3b51fb:	48 8d 3d ee a0 11 03                            	lea    rdi,[rip+0x311a0ee]        # 0x34cf2f0
  3b5202:	e8 79 9d 38 00                                  	call   0x73ef80
  3b5207:	48 8d 3d da a0 11 03                            	lea    rdi,[rip+0x311a0da]        # 0x34cf2e8
  3b520e:	31 f6                                           	xor    esi,esi
  3b5210:	31 d2                                           	xor    edx,edx
  3b5212:	31 c9                                           	xor    ecx,ecx
  3b5214:	e8 87 1d 11 00                                  	call   0x4c6fa0
  3b5219:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  3b5222:	48 c7 45 80 00 00 00 00                         	mov    QWORD PTR [rbp-0x80],0x0
  3b522a:	48 c7 85 78 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x88],0x0
  3b5235:	4d 8b 6c 24 18                                  	mov    r13,QWORD PTR [r12+0x18]
  3b523a:	49 8b 86 40 01 00 00                            	mov    rax,QWORD PTR [r14+0x140]
  3b5241:	49 8b 4e 08                                     	mov    rcx,QWORD PTR [r14+0x8]
  3b5245:	48 89 85 f0 fe ff ff                            	mov    QWORD PTR [rbp-0x110],rax
  3b524c:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  3b5250:	49 8b 75 08                                     	mov    rsi,QWORD PTR [r13+0x8]
  3b5254:	48 8b 91 00 02 00 00                            	mov    rdx,QWORD PTR [rcx+0x200]
  3b525b:	48 89 4d 90                                     	mov    QWORD PTR [rbp-0x70],rcx
  3b525f:	48 8b 8e 00 02 00 00                            	mov    rcx,QWORD PTR [rsi+0x200]
  3b5266:	49 89 86 90 03 00 00                            	mov    QWORD PTR [r14+0x390],rax
  3b526d:	48 89 55 b8                                     	mov    QWORD PTR [rbp-0x48],rdx
  3b5271:	49 8b 45 10                                     	mov    rax,QWORD PTR [r13+0x10]
  3b5275:	48 89 4d 88                                     	mov    QWORD PTR [rbp-0x78],rcx
  3b5279:	49 89 86 40 01 00 00                            	mov    QWORD PTR [r14+0x140],rax
  3b5280:	49 8b 44 24 10                                  	mov    rax,QWORD PTR [r12+0x10]
  3b5285:	49 89 86 d0 05 00 00                            	mov    QWORD PTR [r14+0x5d0],rax
  3b528c:	48 39 ca                                        	cmp    rdx,rcx
  3b528f:	74 35                                           	je     0x3b52c6
  3b5291:	48 8b 4d 90                                     	mov    rcx,QWORD PTR [rbp-0x70]
  3b5295:	48 8b 45 88                                     	mov    rax,QWORD PTR [rbp-0x78]
  3b5299:	4c 89 f7                                        	mov    rdi,r14
  3b529c:	48 8b 99 00 02 00 00                            	mov    rbx,QWORD PTR [rcx+0x200]
  3b52a3:	48 89 81 00 02 00 00                            	mov    QWORD PTR [rcx+0x200],rax
  3b52aa:	f0 83 80 e0 02 00 00 01                         	lock add DWORD PTR [rax+0x2e0],0x1
  3b52b2:	e8 89 9c 52 00                                  	call   0x8def40
  3b52b7:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  3b52bb:	48 39 5d b8                                     	cmp    QWORD PTR [rbp-0x48],rbx
  3b52bf:	74 05                                           	je     0x3b52c6
  3b52c1:	e8 da 0e f1 ff                                  	call   0x2c61a0
  3b52c6:	e8 05 26 75 00                                  	call   0xb078d0
  3b52cb:	85 c0                                           	test   eax,eax
  3b52cd:	74 20                                           	je     0x3b52ef
  3b52cf:	49 8b 44 24 10                                  	mov    rax,QWORD PTR [r12+0x10]
  3b52d4:	41 8b 3c 24                                     	mov    edi,DWORD PTR [r12]
  3b52d8:	49 8b 4d 00                                     	mov    rcx,QWORD PTR [r13+0x0]
  3b52dc:	49 8b 75 08                                     	mov    rsi,QWORD PTR [r13+0x8]
  3b52e0:	48 89 c2                                        	mov    rdx,rax
  3b52e3:	48 c1 fa 04                                     	sar    rdx,0x4
  3b52e7:	48 31 c2                                        	xor    rdx,rax
  3b52ea:	e8 61 f2 ce ff                                  	call   0xa4550
  3b52ef:	41 8b 7d 20                                     	mov    edi,DWORD PTR [r13+0x20]
  3b52f3:	e8 78 bc 23 00                                  	call   0x5f0f70
  3b52f8:	89 c7                                           	mov    edi,eax
  3b52fa:	41 8b 04 24                                     	mov    eax,DWORD PTR [r12]
  3b52fe:	4c 89 75 98                                     	mov    QWORD PTR [rbp-0x68],r14
  3b5302:	4c 89 6d a0                                     	mov    QWORD PTR [rbp-0x60],r13
  3b5306:	83 f8 02                                        	cmp    eax,0x2
  3b5309:	0f 84 8d 01 00 00                               	je     0x3b549c
  3b530f:	83 f8 01                                        	cmp    eax,0x1
  3b5312:	0f 85 f3 01 00 00                               	jne    0x3b550b
  3b5318:	65 4c 8b 2c 25 00 00 00 00                      	mov    r13,QWORD PTR gs:0x0
  3b5321:	49 8b 74 24 40                                  	mov    rsi,QWORD PTR [r12+0x40]
  3b5326:	48 85 f6                                        	test   rsi,rsi
  3b5329:	0f 84 e7 01 00 00                               	je     0x3b5516
  3b532f:	49 8b 5c 24 10                                  	mov    rbx,QWORD PTR [r12+0x10]
  3b5334:	89 7d cc                                        	mov    DWORD PTR [rbp-0x34],edi
  3b5337:	4c 89 ef                                        	mov    rdi,r13
  3b533a:	e8 11 c8 3f 00                                  	call   0x7b1b50
  3b533f:	4c 8b 43 08                                     	mov    r8,QWORD PTR [rbx+0x8]
  3b5343:	41 be 16 00 00 00                               	mov    r14d,0x16
  3b5349:	49 81 f8 ff ff ff 7f                            	cmp    r8,0x7fffffff
  3b5350:	0f 87 ad 01 00 00                               	ja     0x3b5503
  3b5356:	49 8b 7c 24 40                                  	mov    rdi,QWORD PTR [r12+0x40]
  3b535b:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  3b535e:	48 85 c9                                        	test   rcx,rcx
  3b5361:	79 11                                           	jns    0x3b5374
  3b5363:	48 8b 47 18                                     	mov    rax,QWORD PTR [rdi+0x18]
  3b5367:	83 b8 d4 01 00 00 04                            	cmp    DWORD PTR [rax+0x1d4],0x4
  3b536e:	0f 85 a2 02 00 00                               	jne    0x3b5616
  3b5374:	49 8b 44 24 28                                  	mov    rax,QWORD PTR [r12+0x28]
  3b5379:	48 85 c0                                        	test   rax,rax
  3b537c:	74 20                                           	je     0x3b539e
  3b537e:	44 8b 70 4c                                     	mov    r14d,DWORD PTR [rax+0x4c]
  3b5382:	45 85 f6                                        	test   r14d,r14d
  3b5385:	0f 85 78 01 00 00                               	jne    0x3b5503
  3b538b:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  3b538f:	48 8b 9d 68 ff ff ff                            	mov    rbx,QWORD PTR [rbp-0x98]
  3b5396:	48 8b 48 30                                     	mov    rcx,QWORD PTR [rax+0x30]
  3b539a:	4c 8b 40 38                                     	mov    r8,QWORD PTR [rax+0x38]
  3b539e:	48 8b 43 10                                     	mov    rax,QWORD PTR [rbx+0x10]
  3b53a2:	48 8d 95 40 ff ff ff                            	lea    rdx,[rbp-0xc0]
  3b53a9:	4c 89 eb                                        	mov    rbx,r13
  3b53ac:	48 89 95 10 ff ff ff                            	mov    QWORD PTR [rbp-0xf0],rdx
  3b53b3:	c7 85 18 ff ff ff 01 00 00 00                   	mov    DWORD PTR [rbp-0xe8],0x1
  3b53bd:	4c 89 85 28 ff ff ff                            	mov    QWORD PTR [rbp-0xd8],r8
  3b53c4:	48 c7 85 30 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xd0],0x0
  3b53cf:	4c 89 ad 38 ff ff ff                            	mov    QWORD PTR [rbp-0xc8],r13
  3b53d6:	48 89 8d 20 ff ff ff                            	mov    QWORD PTR [rbp-0xe0],rcx
  3b53dd:	4d 89 c5                                        	mov    r13,r8
  3b53e0:	48 89 85 40 ff ff ff                            	mov    QWORD PTR [rbp-0xc0],rax
  3b53e7:	4c 89 85 48 ff ff ff                            	mov    QWORD PTR [rbp-0xb8],r8
  3b53ee:	48 8b 47 08                                     	mov    rax,QWORD PTR [rdi+0x8]
  3b53f2:	48 8b 57 10                                     	mov    rdx,QWORD PTR [rdi+0x10]
  3b53f6:	4c 8b 30                                        	mov    r14,QWORD PTR [rax]
  3b53f9:	48 8d 05 b0 96 eb ff                            	lea    rax,[rip+0xffffffffffeb96b0]        # 0x26eab0
  3b5400:	4c 29 f0                                        	sub    rax,r14
  3b5403:	48 c1 c8 03                                     	ror    rax,0x3
  3b5407:	48 83 f8 14                                     	cmp    rax,0x14
  3b540b:	0f 87 79 06 00 00                               	ja     0x3b5a8a
  3b5411:	48 8d b5 10 ff ff ff                            	lea    rsi,[rbp-0xf0]
  3b5418:	b9 01 00 00 00                                  	mov    ecx,0x1
  3b541d:	49 89 d8                                        	mov    r8,rbx
  3b5420:	41 ff d6                                        	call   r14
  3b5423:	41 89 c6                                        	mov    r14d,eax
  3b5426:	e9 e2 01 00 00                                  	jmp    0x3b560d
  3b542b:	0f 1f 44 00 00                                  	nop    DWORD PTR [rax+rax*1+0x0]
  3b5430:	4c 8d 35 b1 9e 11 03                            	lea    r14,[rip+0x3119eb1]        # 0x34cf2e8
  3b5437:	49 c7 45 10 00 00 00 00                         	mov    QWORD PTR [r13+0x10],0x0
  3b543f:	31 f6                                           	xor    esi,esi
  3b5441:	31 d2                                           	xor    edx,edx
  3b5443:	31 c9                                           	xor    ecx,ecx
  3b5445:	4c 89 f7                                        	mov    rdi,r14
  3b5448:	e8 b3 15 11 00                                  	call   0x4c6a00
  3b544d:	48 8b 85 60 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xa0]
  3b5454:	48 8d 3d 95 9e 11 03                            	lea    rdi,[rip+0x3119e95]        # 0x34cf2f0
  3b545b:	48 8d 35 6e 9e 11 03                            	lea    rsi,[rip+0x3119e6e]        # 0x34cf2d0
  3b5462:	31 d2                                           	xor    edx,edx
  3b5464:	49 89 45 00                                     	mov    QWORD PTR [r13+0x0],rax
  3b5468:	e8 13 93 38 00                                  	call   0x73e780
  3b546d:	4c 89 f7                                        	mov    rdi,r14
  3b5470:	89 c3                                           	mov    ebx,eax
  3b5472:	49 c7 45 00 00 00 00 00                         	mov    QWORD PTR [r13+0x0],0x0
  3b547a:	31 f6                                           	xor    esi,esi
  3b547c:	31 d2                                           	xor    edx,edx
  3b547e:	31 c9                                           	xor    ecx,ecx
  3b5480:	e8 1b 1b 11 00                                  	call   0x4c6fa0
  3b5485:	83 7d b4 00                                     	cmp    DWORD PTR [rbp-0x4c],0x0
  3b5489:	0f 85 cb 07 00 00                               	jne    0x3b5c5a
  3b548f:	85 db                                           	test   ebx,ebx
  3b5491:	0f 84 90 f7 ff ff                               	je     0x3b4c27
  3b5497:	e9 a2 07 00 00                                  	jmp    0x3b5c3e
  3b549c:	65 4c 8b 2c 25 00 00 00 00                      	mov    r13,QWORD PTR gs:0x0
  3b54a5:	49 8b 74 24 40                                  	mov    rsi,QWORD PTR [r12+0x40]
  3b54aa:	48 85 f6                                        	test   rsi,rsi
  3b54ad:	74 67                                           	je     0x3b5516
  3b54af:	49 8b 5c 24 10                                  	mov    rbx,QWORD PTR [r12+0x10]
  3b54b4:	89 7d cc                                        	mov    DWORD PTR [rbp-0x34],edi
  3b54b7:	4c 89 ef                                        	mov    rdi,r13
  3b54ba:	e8 91 c6 3f 00                                  	call   0x7b1b50
  3b54bf:	4c 8b 43 08                                     	mov    r8,QWORD PTR [rbx+0x8]
  3b54c3:	41 be 16 00 00 00                               	mov    r14d,0x16
  3b54c9:	49 81 f8 ff ff ff 7f                            	cmp    r8,0x7fffffff
  3b54d0:	77 31                                           	ja     0x3b5503
  3b54d2:	49 8b 54 24 40                                  	mov    rdx,QWORD PTR [r12+0x40]
  3b54d7:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  3b54da:	48 85 c9                                        	test   rcx,rcx
  3b54dd:	79 11                                           	jns    0x3b54f0
  3b54df:	48 8b 42 18                                     	mov    rax,QWORD PTR [rdx+0x18]
  3b54e3:	83 b8 d4 01 00 00 04                            	cmp    DWORD PTR [rax+0x1d4],0x4
  3b54ea:	0f 85 3b 01 00 00                               	jne    0x3b562b
  3b54f0:	49 8b 44 24 28                                  	mov    rax,QWORD PTR [r12+0x28]
  3b54f5:	48 85 c0                                        	test   rax,rax
  3b54f8:	74 3c                                           	je     0x3b5536
  3b54fa:	44 8b 70 4c                                     	mov    r14d,DWORD PTR [rax+0x4c]
  3b54fe:	45 85 f6                                        	test   r14d,r14d
  3b5501:	74 20                                           	je     0x3b5523
  3b5503:	45 31 ed                                        	xor    r13d,r13d
  3b5506:	e9 45 01 00 00                                  	jmp    0x3b5650
  3b550b:	45 31 ed                                        	xor    r13d,r13d
  3b550e:	45 31 f6                                        	xor    r14d,r14d
  3b5511:	e9 3d 01 00 00                                  	jmp    0x3b5653
  3b5516:	45 8b 74 24 30                                  	mov    r14d,DWORD PTR [r12+0x30]
  3b551b:	45 31 ed                                        	xor    r13d,r13d
  3b551e:	e9 30 01 00 00                                  	jmp    0x3b5653
  3b5523:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  3b5527:	48 8b 9d 68 ff ff ff                            	mov    rbx,QWORD PTR [rbp-0x98]
  3b552e:	48 8b 48 30                                     	mov    rcx,QWORD PTR [rax+0x30]
  3b5532:	4c 8b 40 38                                     	mov    r8,QWORD PTR [rax+0x38]
  3b5536:	48 8b 43 10                                     	mov    rax,QWORD PTR [rbx+0x10]
  3b553a:	48 8d bd 40 ff ff ff                            	lea    rdi,[rbp-0xc0]
  3b5541:	48 be 00 00 00 00 01 00 00 00                   	movabs rsi,0x100000000
  3b554b:	4c 89 85 70 ff ff ff                            	mov    QWORD PTR [rbp-0x90],r8
  3b5552:	49 89 d6                                        	mov    r14,rdx
  3b5555:	48 89 bd 10 ff ff ff                            	mov    QWORD PTR [rbp-0xf0],rdi
  3b555c:	c7 85 18 ff ff ff 01 00 00 00                   	mov    DWORD PTR [rbp-0xe8],0x1
  3b5566:	4c 89 85 28 ff ff ff                            	mov    QWORD PTR [rbp-0xd8],r8
  3b556d:	48 89 b5 30 ff ff ff                            	mov    QWORD PTR [rbp-0xd0],rsi
  3b5574:	4c 89 ad 38 ff ff ff                            	mov    QWORD PTR [rbp-0xc8],r13
  3b557b:	48 89 8d 20 ff ff ff                            	mov    QWORD PTR [rbp-0xe0],rcx
  3b5582:	48 89 85 40 ff ff ff                            	mov    QWORD PTR [rbp-0xc0],rax
  3b5589:	4c 89 85 48 ff ff ff                            	mov    QWORD PTR [rbp-0xb8],r8
  3b5590:	48 8b 42 10                                     	mov    rax,QWORD PTR [rdx+0x10]
  3b5594:	48 89 85 f8 fe ff ff                            	mov    QWORD PTR [rbp-0x108],rax
  3b559b:	e8 b0 b9 23 00                                  	call   0x5f0f50
  3b55a0:	4c 89 f7                                        	mov    rdi,r14
  3b55a3:	89 c3                                           	mov    ebx,eax
  3b55a5:	4c 89 75 a8                                     	mov    QWORD PTR [rbp-0x58],r14
  3b55a9:	e8 42 77 13 00                                  	call   0x4eccf0
  3b55ae:	85 c0                                           	test   eax,eax
  3b55b0:	74 0d                                           	je     0x3b55bf
  3b55b2:	89 df                                           	mov    edi,ebx
  3b55b4:	81 cf 00 00 00 04                               	or     edi,0x4000000
  3b55ba:	e8 b1 b9 23 00                                  	call   0x5f0f70
  3b55bf:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  3b55c3:	48 8b 47 08                                     	mov    rax,QWORD PTR [rdi+0x8]
  3b55c7:	4c 8b 70 08                                     	mov    r14,QWORD PTR [rax+0x8]
  3b55cb:	48 8d 05 de 94 eb ff                            	lea    rax,[rip+0xffffffffffeb94de]        # 0x26eab0
  3b55d2:	4c 29 f0                                        	sub    rax,r14
  3b55d5:	48 c1 c8 03                                     	ror    rax,0x3
  3b55d9:	48 83 f8 14                                     	cmp    rax,0x14
  3b55dd:	0f 87 d1 04 00 00                               	ja     0x3b5ab4
  3b55e3:	48 8b 95 f8 fe ff ff                            	mov    rdx,QWORD PTR [rbp-0x108]
  3b55ea:	48 8d b5 10 ff ff ff                            	lea    rsi,[rbp-0xf0]
  3b55f1:	b9 01 00 00 00                                  	mov    ecx,0x1
  3b55f6:	4d 89 e8                                        	mov    r8,r13
  3b55f9:	41 ff d6                                        	call   r14
  3b55fc:	89 df                                           	mov    edi,ebx
  3b55fe:	41 89 c6                                        	mov    r14d,eax
  3b5601:	e8 6a b9 23 00                                  	call   0x5f0f70
  3b5606:	4c 8b ad 70 ff ff ff                            	mov    r13,QWORD PTR [rbp-0x90]
  3b560d:	4c 2b ad 28 ff ff ff                            	sub    r13,QWORD PTR [rbp-0xd8]
  3b5614:	eb 3a                                           	jmp    0x3b5650
  3b5616:	48 8d 3d d1 ec fe 00                            	lea    rdi,[rip+0xfeecd1]        # 0x13a42ee
  3b561d:	48 8d 35 7a ef fc 00                            	lea    rsi,[rip+0xfcef7a]        # 0x138459e
  3b5624:	ba 1d 04 00 00                                  	mov    edx,0x41d
  3b5629:	eb 13                                           	jmp    0x3b563e
  3b562b:	48 8d 3d bc ec fe 00                            	lea    rdi,[rip+0xfeecbc]        # 0x13a42ee
  3b5632:	48 8d 35 b8 97 ff 00                            	lea    rsi,[rip+0xff97b8]        # 0x13aedf1
  3b5639:	ba 5b 04 00 00                                  	mov    edx,0x45b
  3b563e:	31 c0                                           	xor    eax,eax
  3b5640:	e8 cb 7d ea ff                                  	call   0x25d410
  3b5645:	45 31 ed                                        	xor    r13d,r13d
  3b5648:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  3b5650:	8b 7d cc                                        	mov    edi,DWORD PTR [rbp-0x34]
  3b5653:	e8 18 b9 23 00                                  	call   0x5f0f70
  3b5658:	49 8b 5c 24 28                                  	mov    rbx,QWORD PTR [r12+0x28]
  3b565d:	48 85 db                                        	test   rbx,rbx
  3b5660:	74 37                                           	je     0x3b5699
  3b5662:	8b 43 4c                                        	mov    eax,DWORD PTR [rbx+0x4c]
  3b5665:	45 85 f6                                        	test   r14d,r14d
  3b5668:	0f 84 84 00 00 00                               	je     0x3b56f2
  3b566e:	85 c0                                           	test   eax,eax
  3b5670:	0f 85 5e 04 00 00                               	jne    0x3b5ad4
  3b5676:	83 7b 54 00                                     	cmp    DWORD PTR [rbx+0x54],0x0
  3b567a:	0f 85 54 04 00 00                               	jne    0x3b5ad4
  3b5680:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  3b5684:	8b 48 70                                        	mov    ecx,DWORD PTR [rax+0x70]
  3b5687:	31 c0                                           	xor    eax,eax
  3b5689:	f0 0f b1 4b 54                                  	lock cmpxchg DWORD PTR [rbx+0x54],ecx
  3b568e:	0f 84 3c 04 00 00                               	je     0x3b5ad0
  3b5694:	e9 3b 04 00 00                                  	jmp    0x3b5ad4
  3b5699:	45 85 f6                                        	test   r14d,r14d
  3b569c:	0f 84 75 01 00 00                               	je     0x3b5817
  3b56a2:	41 8d 86 00 00 02 80                            	lea    eax,[r14-0x7ffe0000]
  3b56a9:	48 98                                           	cdqe
  3b56ab:	49 89 44 24 30                                  	mov    QWORD PTR [r12+0x30],rax
  3b56b0:	41 83 fe 60                                     	cmp    r14d,0x60
  3b56b4:	74 0a                                           	je     0x3b56c0
  3b56b6:	41 83 fe 05                                     	cmp    r14d,0x5
  3b56ba:	0f 85 5c 01 00 00                               	jne    0x3b581c
  3b56c0:	41 83 3c 24 01                                  	cmp    DWORD PTR [r12],0x1
  3b56c5:	0f 85 51 01 00 00                               	jne    0x3b581c
  3b56cb:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  3b56cf:	49 8b 7c 24 40                                  	mov    rdi,QWORD PTR [r12+0x40]
  3b56d4:	48 8b 58 18                                     	mov    rbx,QWORD PTR [rax+0x18]
  3b56d8:	e8 83 11 00 00                                  	call   0x3b6860
  3b56dd:	48 85 c0                                        	test   rax,rax
  3b56e0:	0f 84 36 01 00 00                               	je     0x3b581c
  3b56e6:	44 89 b3 a0 05 00 00                            	mov    DWORD PTR [rbx+0x5a0],r14d
  3b56ed:	e9 2a 01 00 00                                  	jmp    0x3b581c
  3b56f2:	85 c0                                           	test   eax,eax
  3b56f4:	0f 85 da 03 00 00                               	jne    0x3b5ad4
  3b56fa:	f0 4c 01 6b 40                                  	lock add QWORD PTR [rbx+0x40],r13
  3b56ff:	90                                              	nop
  3b5700:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  3b5704:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  3b5709:	48 8b 40 60                                     	mov    rax,QWORD PTR [rax+0x60]
  3b570d:	f0 0f c1 08                                     	lock xadd DWORD PTR [rax],ecx
  3b5711:	4c 8b 75 98                                     	mov    r14,QWORD PTR [rbp-0x68]
  3b5715:	83 f9 01                                        	cmp    ecx,0x1
  3b5718:	0f 85 91 01 00 00                               	jne    0x3b58af
  3b571e:	4c 8b 75 d0                                     	mov    r14,QWORD PTR [rbp-0x30]
  3b5722:	41 c6 46 74 01                                  	mov    BYTE PTR [r14+0x74],0x1
  3b5727:	41 c7 44 24 38 03 00 00 00                      	mov    DWORD PTR [r12+0x38],0x3
  3b5730:	e8 9b 21 75 00                                  	call   0xb078d0
  3b5735:	85 c0                                           	test   eax,eax
  3b5737:	74 0f                                           	je     0x3b5748
  3b5739:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  3b573d:	4c 89 e7                                        	mov    rdi,r12
  3b5740:	4c 89 f6                                        	mov    rsi,r14
  3b5743:	e8 98 ee ce ff                                  	call   0xa45e0
  3b5748:	4d 8b 74 24 10                                  	mov    r14,QWORD PTR [r12+0x10]
  3b574d:	49 83 7e 18 00                                  	cmp    QWORD PTR [r14+0x18],0x0
  3b5752:	0f 84 ac 00 00 00                               	je     0x3b5804
  3b5758:	48 8b 4b 40                                     	mov    rcx,QWORD PTR [rbx+0x40]
  3b575c:	49 89 4c 24 30                                  	mov    QWORD PTR [r12+0x30],rcx
  3b5761:	8b 43 4c                                        	mov    eax,DWORD PTR [rbx+0x4c]
  3b5764:	85 c0                                           	test   eax,eax
  3b5766:	74 5e                                           	je     0x3b57c6
  3b5768:	48 85 c9                                        	test   rcx,rcx
  3b576b:	0f 84 bd 02 00 00                               	je     0x3b5a2e
  3b5771:	8b 4b 54                                        	mov    ecx,DWORD PTR [rbx+0x54]
  3b5774:	ff c9                                           	dec    ecx
  3b5776:	0f af 4b 50                                     	imul   ecx,DWORD PTR [rbx+0x50]
  3b577a:	48 89 4b 40                                     	mov    QWORD PTR [rbx+0x40],rcx
  3b577e:	4d 8b 44 24 30                                  	mov    r8,QWORD PTR [r12+0x30]
  3b5783:	49 39 c8                                        	cmp    r8,rcx
  3b5786:	74 3e                                           	je     0x3b57c6
  3b5788:	4c 8d 2d 28 81 f2 00                            	lea    r13,[rip+0xf28128]        # 0x12dd8b7
  3b578f:	48 8d 3d e6 80 f2 00                            	lea    rdi,[rip+0xf280e6]        # 0x12dd87c
  3b5796:	ba 0d 06 00 00                                  	mov    edx,0x60d
  3b579b:	31 c0                                           	xor    eax,eax
  3b579d:	4c 89 ee                                        	mov    rsi,r13
  3b57a0:	e8 6b 7c ea ff                                  	call   0x25d410
  3b57a5:	44 8b 43 50                                     	mov    r8d,DWORD PTR [rbx+0x50]
  3b57a9:	8b 4b 54                                        	mov    ecx,DWORD PTR [rbx+0x54]
  3b57ac:	48 8d 3d 18 46 fc 00                            	lea    rdi,[rip+0xfc4618]        # 0x1379dcb
  3b57b3:	4c 89 ee                                        	mov    rsi,r13
  3b57b6:	ba 0f 06 00 00                                  	mov    edx,0x60f
  3b57bb:	31 c0                                           	xor    eax,eax
  3b57bd:	e8 4e 7c ea ff                                  	call   0x25d410
  3b57c2:	48 8b 4b 40                                     	mov    rcx,QWORD PTR [rbx+0x40]
  3b57c6:	48 89 8d 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],rcx
  3b57cd:	41 8b 44 24 38                                  	mov    eax,DWORD PTR [r12+0x38]
  3b57d2:	48 8d 35 be 9a f9 00                            	lea    rsi,[rip+0xf99abe]        # 0x134f297
  3b57d9:	31 d2                                           	xor    edx,edx
  3b57db:	89 45 80                                        	mov    DWORD PTR [rbp-0x80],eax
  3b57de:	4d 8b 76 18                                     	mov    r14,QWORD PTR [r14+0x18]
  3b57e2:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  3b57eb:	e8 f0 4b 86 00                                  	call   0xc1a3e0
  3b57f0:	ba 10 00 00 00                                  	mov    edx,0x10
  3b57f5:	48 8d bd 78 ff ff ff                            	lea    rdi,[rbp-0x88]
  3b57fc:	4c 89 f6                                        	mov    rsi,r14
  3b57ff:	e8 cc 39 ea ff                                  	call   0x2591d0
  3b5804:	80 7b 48 00                                     	cmp    BYTE PTR [rbx+0x48],0x0
  3b5808:	0f 84 85 00 00 00                               	je     0x3b5893
  3b580e:	c6 43 48 00                                     	mov    BYTE PTR [rbx+0x48],0x0
  3b5812:	e9 8b 00 00 00                                  	jmp    0x3b58a2
  3b5817:	4d 89 6c 24 30                                  	mov    QWORD PTR [r12+0x30],r13
  3b581c:	41 c7 44 24 38 03 00 00 00                      	mov    DWORD PTR [r12+0x38],0x3
  3b5825:	e8 a6 20 75 00                                  	call   0xb078d0
  3b582a:	85 c0                                           	test   eax,eax
  3b582c:	74 10                                           	je     0x3b583e
  3b582e:	48 8b 75 d0                                     	mov    rsi,QWORD PTR [rbp-0x30]
  3b5832:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  3b5836:	4c 89 e7                                        	mov    rdi,r12
  3b5839:	e8 a2 ed ce ff                                  	call   0xa45e0
  3b583e:	49 8b 44 24 10                                  	mov    rax,QWORD PTR [r12+0x10]
  3b5843:	4c 8b 75 98                                     	mov    r14,QWORD PTR [rbp-0x68]
  3b5847:	48 83 78 18 00                                  	cmp    QWORD PTR [rax+0x18],0x0
  3b584c:	74 61                                           	je     0x3b58af
  3b584e:	49 8b 4c 24 30                                  	mov    rcx,QWORD PTR [r12+0x30]
  3b5853:	48 8d 35 3d 9a f9 00                            	lea    rsi,[rip+0xf99a3d]        # 0x134f297
  3b585a:	31 d2                                           	xor    edx,edx
  3b585c:	48 89 8d 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],rcx
  3b5863:	41 8b 4c 24 38                                  	mov    ecx,DWORD PTR [r12+0x38]
  3b5868:	89 4d 80                                        	mov    DWORD PTR [rbp-0x80],ecx
  3b586b:	48 8b 58 18                                     	mov    rbx,QWORD PTR [rax+0x18]
  3b586f:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  3b5878:	e8 63 4b 86 00                                  	call   0xc1a3e0
  3b587d:	ba 10 00 00 00                                  	mov    edx,0x10
  3b5882:	48 8d bd 78 ff ff ff                            	lea    rdi,[rbp-0x88]
  3b5889:	48 89 de                                        	mov    rsi,rbx
  3b588c:	e8 3f 39 ea ff                                  	call   0x2591d0
  3b5891:	eb 1c                                           	jmp    0x3b58af
  3b5893:	48 89 df                                        	mov    rdi,rbx
  3b5896:	48 8d 35 b3 01 70 01                            	lea    rsi,[rip+0x17001b3]        # 0x1ab5a50
  3b589d:	e8 4e 35 85 00                                  	call   0xc08df0
  3b58a2:	4c 8b 75 98                                     	mov    r14,QWORD PTR [rbp-0x68]
  3b58a6:	49 c7 44 24 28 00 00 00 00                      	mov    QWORD PTR [r12+0x28],0x0
  3b58af:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  3b58b3:	48 8b 4d 90                                     	mov    rcx,QWORD PTR [rbp-0x70]
  3b58b7:	4c 89 f7                                        	mov    rdi,r14
  3b58ba:	48 89 81 00 02 00 00                            	mov    QWORD PTR [rcx+0x200],rax
  3b58c1:	e8 7a 96 52 00                                  	call   0x8def40
  3b58c6:	48 8b 7d 88                                     	mov    rdi,QWORD PTR [rbp-0x78]
  3b58ca:	e8 d1 08 f1 ff                                  	call   0x2c61a0
  3b58cf:	48 8b 85 f0 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x110]
  3b58d6:	4c 8b 6d d0                                     	mov    r13,QWORD PTR [rbp-0x30]
  3b58da:	49 89 86 40 01 00 00                            	mov    QWORD PTR [r14+0x140],rax
  3b58e1:	49 c7 86 d0 05 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x5d0],0x0
  3b58ec:	41 83 7d 70 00                                  	cmp    DWORD PTR [r13+0x70],0x0
  3b58f1:	74 0b                                           	je     0x3b58fe
  3b58f3:	41 80 7d 74 00                                  	cmp    BYTE PTR [r13+0x74],0x0
  3b58f8:	0f 84 0f 01 00 00                               	je     0x3b5a0d
  3b58fe:	48 8b bd 58 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xa8]
  3b5905:	41 c7 45 70 00 00 00 00                         	mov    DWORD PTR [r13+0x70],0x0
  3b590d:	be 00 00 08 00                                  	mov    esi,0x80000
  3b5912:	31 d2                                           	xor    edx,edx
  3b5914:	31 c9                                           	xor    ecx,ecx
  3b5916:	45 31 c0                                        	xor    r8d,r8d
  3b5919:	45 31 c9                                        	xor    r9d,r9d
  3b591c:	6a 00                                           	push   0x0
  3b591e:	6a 00                                           	push   0x0
  3b5920:	e8 4b be 83 00                                  	call   0xbf1770
  3b5925:	48 83 c4 10                                     	add    rsp,0x10
  3b5929:	41 ff 4f 04                                     	dec    DWORD PTR [r15+0x4]
  3b592d:	41 c7 44 24 38 03 00 00 00                      	mov    DWORD PTR [r12+0x38],0x3
  3b5936:	49 8b 44 24 40                                  	mov    rax,QWORD PTR [r12+0x40]
  3b593b:	48 85 c0                                        	test   rax,rax
  3b593e:	74 29                                           	je     0x3b5969
  3b5940:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  3b5945:	f0 0f c1 48 28                                  	lock xadd DWORD PTR [rax+0x28],ecx
  3b594a:	83 f9 01                                        	cmp    ecx,0x1
  3b594d:	75 11                                           	jne    0x3b5960
  3b594f:	49 8b 7c 24 40                                  	mov    rdi,QWORD PTR [r12+0x40]
  3b5954:	48 8b b5 60 ff ff ff                            	mov    rsi,QWORD PTR [rbp-0xa0]
  3b595b:	e8 20 5a 37 00                                  	call   0x72b380
  3b5960:	49 c7 44 24 40 00 00 00 00                      	mov    QWORD PTR [r12+0x40],0x0
  3b5969:	41 83 7f 04 00                                  	cmp    DWORD PTR [r15+0x4],0x0
  3b596e:	0f 85 8c f2 ff ff                               	jne    0x3b4c00
  3b5974:	41 80 7f 0d 01                                  	cmp    BYTE PTR [r15+0xd],0x1
  3b5979:	b8 04 00 00 00                                  	mov    eax,0x4
  3b597e:	83 d8 00                                        	sbb    eax,0x0
  3b5981:	41 89 47 08                                     	mov    DWORD PTR [r15+0x8],eax
  3b5985:	49 8b 5f 50                                     	mov    rbx,QWORD PTR [r15+0x50]
  3b5989:	48 85 db                                        	test   rbx,rbx
  3b598c:	0f 84 6e f2 ff ff                               	je     0x3b4c00
  3b5992:	45 31 f6                                        	xor    r14d,r14d
  3b5995:	eb 2e                                           	jmp    0x3b59c5
  3b5997:	48 8b 3b                                        	mov    rdi,QWORD PTR [rbx]
  3b599a:	41 be 01 00 00 00                               	mov    r14d,0x1
  3b59a0:	e8 6b 0f 85 00                                  	call   0xc06910
  3b59a5:	48 8b 7b 10                                     	mov    rdi,QWORD PTR [rbx+0x10]
  3b59a9:	31 f6                                           	xor    esi,esi
  3b59ab:	31 d2                                           	xor    edx,edx
  3b59ad:	31 c9                                           	xor    ecx,ecx
  3b59af:	48 83 c7 18                                     	add    rdi,0x18
  3b59b3:	e8 e8 15 11 00                                  	call   0x4c6fa0
  3b59b8:	48 8b 5b 30                                     	mov    rbx,QWORD PTR [rbx+0x30]
  3b59bc:	48 85 db                                        	test   rbx,rbx
  3b59bf:	0f 84 3b f2 ff ff                               	je     0x3b4c00
  3b59c5:	41 8b 47 08                                     	mov    eax,DWORD PTR [r15+0x8]
  3b59c9:	31 f6                                           	xor    esi,esi
  3b59cb:	31 d2                                           	xor    edx,edx
  3b59cd:	31 c9                                           	xor    ecx,ecx
  3b59cf:	89 43 20                                        	mov    DWORD PTR [rbx+0x20],eax
  3b59d2:	48 8b 7b 10                                     	mov    rdi,QWORD PTR [rbx+0x10]
  3b59d6:	48 83 c7 18                                     	add    rdi,0x18
  3b59da:	e8 21 10 11 00                                  	call   0x4c6a00
  3b59df:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  3b59e2:	ff 08                                           	dec    DWORD PTR [rax]
  3b59e4:	48 8b 3b                                        	mov    rdi,QWORD PTR [rbx]
  3b59e7:	83 3f 00                                        	cmp    DWORD PTR [rdi],0x0
  3b59ea:	7f b9                                           	jg     0x3b59a5
  3b59ec:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  3b59f0:	48 85 c0                                        	test   rax,rax
  3b59f3:	74 ab                                           	je     0x3b59a0
  3b59f5:	ff 08                                           	dec    DWORD PTR [rax]
  3b59f7:	45 85 f6                                        	test   r14d,r14d
  3b59fa:	74 9b                                           	je     0x3b5997
  3b59fc:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  3b5a00:	41 be 01 00 00 00                               	mov    r14d,0x1
  3b5a06:	83 38 00                                        	cmp    DWORD PTR [rax],0x0
  3b5a09:	75 9a                                           	jne    0x3b59a5
  3b5a0b:	eb 8a                                           	jmp    0x3b5997
  3b5a0d:	41 80 7d 75 00                                  	cmp    BYTE PTR [r13+0x75],0x0
  3b5a12:	74 09                                           	je     0x3b5a1d
  3b5a14:	49 8b 44 24 28                                  	mov    rax,QWORD PTR [r12+0x28]
  3b5a19:	c6 40 49 00                                     	mov    BYTE PTR [rax+0x49],0x0
  3b5a1d:	4c 8b 7d c0                                     	mov    r15,QWORD PTR [rbp-0x40]
  3b5a21:	41 c7 45 70 00 00 00 00                         	mov    DWORD PTR [r13+0x70],0x0
  3b5a29:	e9 f9 f1 ff ff                                  	jmp    0x3b4c27
  3b5a2e:	05 00 00 02 80                                  	add    eax,0x80020000
  3b5a33:	48 98                                           	cdqe
  3b5a35:	48 89 85 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],rax
  3b5a3c:	44 8b 6b 4c                                     	mov    r13d,DWORD PTR [rbx+0x4c]
  3b5a40:	41 83 fd 60                                     	cmp    r13d,0x60
  3b5a44:	74 0a                                           	je     0x3b5a50
  3b5a46:	41 83 fd 05                                     	cmp    r13d,0x5
  3b5a4a:	0f 85 7d fd ff ff                               	jne    0x3b57cd
  3b5a50:	41 83 3c 24 01                                  	cmp    DWORD PTR [r12],0x1
  3b5a55:	0f 85 72 fd ff ff                               	jne    0x3b57cd
  3b5a5b:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  3b5a5f:	49 8b 7c 24 40                                  	mov    rdi,QWORD PTR [r12+0x40]
  3b5a64:	48 8b 40 18                                     	mov    rax,QWORD PTR [rax+0x18]
  3b5a68:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  3b5a6c:	e8 ef 0d 00 00                                  	call   0x3b6860
  3b5a71:	48 85 c0                                        	test   rax,rax
  3b5a74:	0f 84 53 fd ff ff                               	je     0x3b57cd
  3b5a7a:	48 8b 45 a0                                     	mov    rax,QWORD PTR [rbp-0x60]
  3b5a7e:	44 89 a8 a0 05 00 00                            	mov    DWORD PTR [rax+0x5a0],r13d
  3b5a85:	e9 43 fd ff ff                                  	jmp    0x3b57cd
  3b5a8a:	48 89 7d a8                                     	mov    QWORD PTR [rbp-0x58],rdi
  3b5a8e:	48 8d 3d 8b 01 70 01                            	lea    rdi,[rip+0x170018b]        # 0x1ab5c20
  3b5a95:	4c 89 f6                                        	mov    rsi,r14
  3b5a98:	48 89 95 70 ff ff ff                            	mov    QWORD PTR [rbp-0x90],rdx
  3b5a9f:	e8 1c 9e 09 00                                  	call   0x44f8c0
  3b5aa4:	48 8b 95 70 ff ff ff                            	mov    rdx,QWORD PTR [rbp-0x90]
  3b5aab:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  3b5aaf:	e9 5d f9 ff ff                                  	jmp    0x3b5411
  3b5ab4:	48 8d 3d 85 01 70 01                            	lea    rdi,[rip+0x1700185]        # 0x1ab5c40
  3b5abb:	4c 89 f6                                        	mov    rsi,r14
  3b5abe:	e8 fd 9d 09 00                                  	call   0x44f8c0
  3b5ac3:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  3b5ac7:	e9 17 fb ff ff                                  	jmp    0x3b55e3
  3b5acc:	0f 1f 40 00                                     	nop    DWORD PTR [rax+0x0]
  3b5ad0:	44 89 73 4c                                     	mov    DWORD PTR [rbx+0x4c],r14d
  3b5ad4:	8b 43 54                                        	mov    eax,DWORD PTR [rbx+0x54]
  3b5ad7:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  3b5adb:	8b 49 70                                        	mov    ecx,DWORD PTR [rcx+0x70]
  3b5ade:	39 c8                                           	cmp    eax,ecx
  3b5ae0:	0f 8e 1a fc ff ff                               	jle    0x3b5700
  3b5ae6:	45 85 f6                                        	test   r14d,r14d
  3b5ae9:	74 e9                                           	je     0x3b5ad4
  3b5aeb:	8b 43 54                                        	mov    eax,DWORD PTR [rbx+0x54]
  3b5aee:	f0 0f b1 4b 54                                  	lock cmpxchg DWORD PTR [rbx+0x54],ecx
  3b5af3:	74 db                                           	je     0x3b5ad0
  3b5af5:	eb dd                                           	jmp    0x3b5ad4
  3b5af7:	e8 54 be 43 00                                  	call   0x7f1950
  3b5afc:	49 8b 54 24 50                                  	mov    rdx,QWORD PTR [r12+0x50]
  3b5b01:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x3b5af7
  3b5b08:	4c 89 e6                                        	mov    rsi,r12
  3b5b0b:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  3b5b0e:	e8 ad c5 43 00                                  	call   0x7f20c0
  3b5b13:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b5b18:	48 8d 35 45 60 f6 00                            	lea    rsi,[rip+0xf66045]        # 0x131bb64
  3b5b1f:	bf 13 00 00 00                                  	mov    edi,0x13
  3b5b24:	e9 a5 01 00 00                                  	jmp    0x3b5cce
  3b5b29:	e8 22 be 43 00                                  	call   0x7f1950
  3b5b2e:	49 8b 55 50                                     	mov    rdx,QWORD PTR [r13+0x50]
  3b5b32:	48 8d 3d f0 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff0]        # 0x3b5b29
  3b5b39:	4c 89 ee                                        	mov    rsi,r13
  3b5b3c:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  3b5b3f:	e8 7c c5 43 00                                  	call   0x7f20c0
  3b5b44:	49 8b 4d 50                                     	mov    rcx,QWORD PTR [r13+0x50]
  3b5b48:	48 8d 35 15 60 f6 00                            	lea    rsi,[rip+0xf66015]        # 0x131bb64
  3b5b4f:	bf 23 00 00 00                                  	mov    edi,0x23
  3b5b54:	4c 89 ea                                        	mov    rdx,r13
  3b5b57:	4c 8b 01                                        	mov    r8,QWORD PTR [rcx]
  3b5b5a:	e9 75 01 00 00                                  	jmp    0x3b5cd4
  3b5b5f:	e8 ec bd 43 00                                  	call   0x7f1950
  3b5b64:	49 8b 54 24 48                                  	mov    rdx,QWORD PTR [r12+0x48]
  3b5b69:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x3b5b5f
  3b5b70:	4c 89 e6                                        	mov    rsi,r12
  3b5b73:	4d 89 e8                                        	mov    r8,r13
  3b5b76:	48 8b 4a 50                                     	mov    rcx,QWORD PTR [rdx+0x50]
  3b5b7a:	e8 01 c6 43 00                                  	call   0x7f2180
  3b5b7f:	49 8b 4c 24 48                                  	mov    rcx,QWORD PTR [r12+0x48]
  3b5b84:	48 8d 35 68 9b fb 00                            	lea    rsi,[rip+0xfb9b68]        # 0x136f6f3
  3b5b8b:	bf 0f 00 00 00                                  	mov    edi,0xf
  3b5b90:	e9 79 01 00 00                                  	jmp    0x3b5d0e
  3b5b95:	48 89 f3                                        	mov    rbx,rsi
  3b5b98:	e8 b3 bd 43 00                                  	call   0x7f1950
  3b5b9d:	49 8b 55 48                                     	mov    rdx,QWORD PTR [r13+0x48]
  3b5ba1:	48 8d 3d ed ff ff ff                            	lea    rdi,[rip+0xffffffffffffffed]        # 0x3b5b95
  3b5ba8:	4c 89 ee                                        	mov    rsi,r13
  3b5bab:	49 89 d8                                        	mov    r8,rbx
  3b5bae:	48 8b 4a 50                                     	mov    rcx,QWORD PTR [rdx+0x50]
  3b5bb2:	e8 c9 c5 43 00                                  	call   0x7f2180
  3b5bb7:	49 8b 4d 48                                     	mov    rcx,QWORD PTR [r13+0x48]
  3b5bbb:	48 8d 35 31 9b fb 00                            	lea    rsi,[rip+0xfb9b31]        # 0x136f6f3
  3b5bc2:	bf 1f 00 00 00                                  	mov    edi,0x1f
  3b5bc7:	4c 89 ea                                        	mov    rdx,r13
  3b5bca:	49 89 d9                                        	mov    r9,rbx
  3b5bcd:	4c 8b 41 50                                     	mov    r8,QWORD PTR [rcx+0x50]
  3b5bd1:	e9 42 01 00 00                                  	jmp    0x3b5d18
  3b5bd6:	e8 75 bd 43 00                                  	call   0x7f1950
  3b5bdb:	49 8b 54 24 50                                  	mov    rdx,QWORD PTR [r12+0x50]
  3b5be0:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x3b5bd6
  3b5be7:	4c 89 e6                                        	mov    rsi,r12
  3b5bea:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  3b5bed:	e8 ce c4 43 00                                  	call   0x7f20c0
  3b5bf2:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b5bf7:	48 8d 35 66 5f f6 00                            	lea    rsi,[rip+0xf65f66]        # 0x131bb64
  3b5bfe:	bf 0b 00 00 00                                  	mov    edi,0xb
  3b5c03:	e9 c6 00 00 00                                  	jmp    0x3b5cce
  3b5c08:	e8 43 bd 43 00                                  	call   0x7f1950
  3b5c0d:	49 8b 54 24 48                                  	mov    rdx,QWORD PTR [r12+0x48]
  3b5c12:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x3b5c08
  3b5c19:	4c 89 e6                                        	mov    rsi,r12
  3b5c1c:	4d 89 e8                                        	mov    r8,r13
  3b5c1f:	48 8b 4a 50                                     	mov    rcx,QWORD PTR [rdx+0x50]
  3b5c23:	e8 58 c5 43 00                                  	call   0x7f2180
  3b5c28:	49 8b 4c 24 48                                  	mov    rcx,QWORD PTR [r12+0x48]
  3b5c2d:	48 8d 35 bf 9a fb 00                            	lea    rsi,[rip+0xfb9abf]        # 0x136f6f3
  3b5c34:	bf 07 00 00 00                                  	mov    edi,0x7
  3b5c39:	e9 d0 00 00 00                                  	jmp    0x3b5d0e
  3b5c3e:	48 8d 3d c3 62 f6 00                            	lea    rdi,[rip+0xf662c3]        # 0x131bf08
  3b5c45:	48 8d 35 90 e6 fe 00                            	lea    rsi,[rip+0xfee690]        # 0x13a42dc
  3b5c4c:	ba 50 08 00 00                                  	mov    edx,0x850
  3b5c51:	89 d9                                           	mov    ecx,ebx
  3b5c53:	31 c0                                           	xor    eax,eax
  3b5c55:	e8 b6 77 ea ff                                  	call   0x25d410
  3b5c5a:	48 8d 3d de 9a f9 00                            	lea    rdi,[rip+0xf99ade]        # 0x134f73f
  3b5c61:	e8 7a 86 38 00                                  	call   0x73e2e0
  3b5c66:	48 85 c0                                        	test   rax,rax
  3b5c69:	74 0f                                           	je     0x3b5c7a
  3b5c6b:	48 8b b5 08 ff ff ff                            	mov    rsi,QWORD PTR [rbp-0xf8]
  3b5c72:	48 89 c7                                        	mov    rdi,rax
  3b5c75:	e8 06 84 38 00                                  	call   0x73e080
  3b5c7a:	48 8d 3d e4 e7 ed 00                            	lea    rdi,[rip+0xede7e4]        # 0x1294465
  3b5c81:	e8 5a 86 38 00                                  	call   0x73e2e0
  3b5c86:	48 85 c0                                        	test   rax,rax
  3b5c89:	74 0f                                           	je     0x3b5c9a
  3b5c8b:	48 8b b5 00 ff ff ff                            	mov    rsi,QWORD PTR [rbp-0x100]
  3b5c92:	48 89 c7                                        	mov    rdi,rax
  3b5c95:	e8 e6 83 38 00                                  	call   0x73e080
  3b5c9a:	e8 e1 00 57 00                                  	call   0x925d80
  3b5c9f:	0f 0b                                           	ud2
  3b5ca1:	e8 aa bc 43 00                                  	call   0x7f1950
  3b5ca6:	49 8b 54 24 50                                  	mov    rdx,QWORD PTR [r12+0x50]
  3b5cab:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x3b5ca1
  3b5cb2:	4c 89 e6                                        	mov    rsi,r12
  3b5cb5:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  3b5cb8:	e8 03 c4 43 00                                  	call   0x7f20c0
  3b5cbd:	49 8b 4c 24 50                                  	mov    rcx,QWORD PTR [r12+0x50]
  3b5cc2:	48 8d 35 9b 5e f6 00                            	lea    rsi,[rip+0xf65e9b]        # 0x131bb64
  3b5cc9:	bf 1b 00 00 00                                  	mov    edi,0x1b
  3b5cce:	4c 8b 01                                        	mov    r8,QWORD PTR [rcx]
  3b5cd1:	4c 89 e2                                        	mov    rdx,r12
  3b5cd4:	31 c0                                           	xor    eax,eax
  3b5cd6:	e8 35 4d 8e 00                                  	call   0xc9aa10
  3b5cdb:	0f 0b                                           	ud2
  3b5cdd:	e8 6e bc 43 00                                  	call   0x7f1950
  3b5ce2:	49 8b 54 24 48                                  	mov    rdx,QWORD PTR [r12+0x48]
  3b5ce7:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x3b5cdd
  3b5cee:	4c 89 e6                                        	mov    rsi,r12
  3b5cf1:	4d 89 e8                                        	mov    r8,r13
  3b5cf4:	48 8b 4a 50                                     	mov    rcx,QWORD PTR [rdx+0x50]
  3b5cf8:	e8 83 c4 43 00                                  	call   0x7f2180
  3b5cfd:	49 8b 4c 24 48                                  	mov    rcx,QWORD PTR [r12+0x48]
  3b5d02:	48 8d 35 ea 99 fb 00                            	lea    rsi,[rip+0xfb99ea]        # 0x136f6f3
  3b5d09:	bf 17 00 00 00                                  	mov    edi,0x17
  3b5d0e:	4c 8b 41 50                                     	mov    r8,QWORD PTR [rcx+0x50]
  3b5d12:	4c 89 e2                                        	mov    rdx,r12
  3b5d15:	4d 89 e9                                        	mov    r9,r13
  3b5d18:	31 c0                                           	xor    eax,eax
  3b5d1a:	e8 f1 4c 8e 00                                  	call   0xc9aa10
  3b5d1f:	0f 0b                                           	ud2
  3b5d21:	90                                              	nop
  3b5d22:	90                                              	nop
  3b5d23:	90                                              	nop
  3b5d24:	90                                              	nop
  3b5d25:	90                                              	nop
  3b5d26:	90                                              	nop
  3b5d27:	90                                              	nop
  3b5d28:	90                                              	nop
  3b5d29:	90                                              	nop
  3b5d2a:	90                                              	nop
  3b5d2b:	90                                              	nop
  3b5d2c:	90                                              	nop
  3b5d2d:	90                                              	nop
  3b5d2e:	90                                              	nop
  3b5d2f:	90                                              	nop
  3b5d30:	55                                              	push   rbp
  3b5d31:	48 89 e5                                        	mov    rbp,rsp
  3b5d34:	41 56                                           	push   r14
  3b5d36:	53                                              	push   rbx
  3b5d37:	4c 8d 35 aa 95 11 03                            	lea    r14,[rip+0x31195aa]        # 0x34cf2e8
  3b5d3e:	48 89 f3                                        	mov    rbx,rsi
  3b5d41:	31 f6                                           	xor    esi,esi
  3b5d43:	31 d2                                           	xor    edx,edx
  3b5d45:	31 c9                                           	xor    ecx,ecx
  3b5d47:	4c 89 f7                                        	mov    rdi,r14
  3b5d4a:	e8 b1 0c 11 00                                  	call   0x4c6a00
  3b5d4f:	48 8b 05 72 ac 11 03                            	mov    rax,QWORD PTR [rip+0x311ac72]        # 0x34d09c8
  3b5d56:	4c 89 f7                                        	mov    rdi,r14
  3b5d59:	31 f6                                           	xor    esi,esi
  3b5d5b:	31 d2                                           	xor    edx,edx
  3b5d5d:	48 89 18                                        	mov    QWORD PTR [rax],rbx
  3b5d60:	48 8b 48 08                                     	mov    rcx,QWORD PTR [rax+0x8]
  3b5d64:	48 89 0d 5d ac 11 03                            	mov    QWORD PTR [rip+0x311ac5d],rcx        # 0x34d09c8
  3b5d6b:	48 8b 0d 4e ac 11 03                            	mov    rcx,QWORD PTR [rip+0x311ac4e]        # 0x34d09c0
  3b5d72:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  3b5d76:	48 89 05 43 ac 11 03                            	mov    QWORD PTR [rip+0x311ac43],rax        # 0x34d09c0
  3b5d7d:	31 c9                                           	xor    ecx,ecx
  3b5d7f:	5b                                              	pop    rbx
  3b5d80:	41 5e                                           	pop    r14
  3b5d82:	5d                                              	pop    rbp
  3b5d83:	e9 18 12 11 00                                  	jmp    0x4c6fa0
  3b5d88:	90                                              	nop
  3b5d89:	90                                              	nop
  3b5d8a:	90                                              	nop
  3b5d8b:	90                                              	nop
  3b5d8c:	90                                              	nop
  3b5d8d:	90                                              	nop
  3b5d8e:	90                                              	nop
  3b5d8f:	90                                              	nop
  3b5d90:	55                                              	push   rbp
  3b5d91:	48 89 e5                                        	mov    rbp,rsp
  3b5d94:	41 57                                           	push   r15
  3b5d96:	41 56                                           	push   r14
  3b5d98:	53                                              	push   rbx
  3b5d99:	48 83 ec 18                                     	sub    rsp,0x18
  3b5d9d:	4c 8d 3d 6c 65 56 03                            	lea    r15,[rip+0x356656c]        # 0x391c310
  3b5da4:	48 89 f7                                        	mov    rdi,rsi
  3b5da7:	48 89 f3                                        	mov    rbx,rsi
  3b5daa:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  3b5dad:	48 89 45 e0                                     	mov    QWORD PTR [rbp-0x20],rax
  3b5db1:	e8 ca 23 64 00                                  	call   0x9f8180
  3b5db6:	48 8d 75 dc                                     	lea    rsi,[rbp-0x24]
  3b5dba:	48 89 df                                        	mov    rdi,rbx
  3b5dbd:	49 89 c6                                        	mov    r14,rax
  3b5dc0:	e8 fb 23 64 00                                  	call   0x9f81c0
  3b5dc5:	85 c0                                           	test   eax,eax
  3b5dc7:	75 26                                           	jne    0x3b5def
  3b5dc9:	8b 45 dc                                        	mov    eax,DWORD PTR [rbp-0x24]
  3b5dcc:	3d ff ff ff 00                                  	cmp    eax,0xffffff
  3b5dd1:	77 1c                                           	ja     0x3b5def
  3b5dd3:	3d ff ff 00 00                                  	cmp    eax,0xffff
  3b5dd8:	76 67                                           	jbe    0x3b5e41
  3b5dda:	25 00 00 ff 00                                  	and    eax,0xff0000
  3b5ddf:	3d 00 00 01 00                                  	cmp    eax,0x10000
  3b5de4:	75 09                                           	jne    0x3b5def
  3b5de6:	4c 8d 35 83 a0 11 03                            	lea    r14,[rip+0x311a083]        # 0x34cfe70
  3b5ded:	eb 07                                           	jmp    0x3b5df6
  3b5def:	4c 8d 35 d2 9a 11 03                            	lea    r14,[rip+0x3119ad2]        # 0x34cf8c8
  3b5df6:	49 39 9e c0 04 00 00                            	cmp    QWORD PTR [r14+0x4c0],rbx
  3b5dfd:	74 1d                                           	je     0x3b5e1c
  3b5dff:	49 39 9e 38 05 00 00                            	cmp    QWORD PTR [r14+0x538],rbx
  3b5e06:	74 2a                                           	je     0x3b5e32
  3b5e08:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  3b5e0b:	48 3b 45 e0                                     	cmp    rax,QWORD PTR [rbp-0x20]
  3b5e0f:	75 75                                           	jne    0x3b5e86
  3b5e11:	48 83 c4 18                                     	add    rsp,0x18
  3b5e15:	5b                                              	pop    rbx
  3b5e16:	41 5e                                           	pop    r14
  3b5e18:	41 5f                                           	pop    r15
  3b5e1a:	5d                                              	pop    rbp
  3b5e1b:	c3                                              	ret
  3b5e1c:	48 89 df                                        	mov    rdi,rbx
  3b5e1f:	be 80 00 00 00                                  	mov    esi,0x80
  3b5e24:	e8 87 6a f0 ff                                  	call   0x2bc8b0
  3b5e29:	49 39 9e 38 05 00 00                            	cmp    QWORD PTR [r14+0x538],rbx
  3b5e30:	75 d6                                           	jne    0x3b5e08
  3b5e32:	48 89 df                                        	mov    rdi,rbx
  3b5e35:	be 80 00 00 00                                  	mov    esi,0x80
  3b5e3a:	e8 71 6a f0 ff                                  	call   0x2bc8b0
  3b5e3f:	eb c7                                           	jmp    0x3b5e08
  3b5e41:	4c 39 35 80 99 11 03                            	cmp    QWORD PTR [rip+0x3119980],r14        # 0x34cf7c8
  3b5e48:	74 24                                           	je     0x3b5e6e
  3b5e4a:	4c 39 35 6f aa 11 03                            	cmp    QWORD PTR [rip+0x311aa6f],r14        # 0x34d08c0
  3b5e51:	74 27                                           	je     0x3b5e7a
  3b5e53:	83 3d 66 99 11 03 00                            	cmp    DWORD PTR [rip+0x3119966],0x0        # 0x34cf7c0
  3b5e5a:	48 8d 05 bf 94 11 03                            	lea    rax,[rip+0x31194bf]        # 0x34cf320
  3b5e61:	4c 8d 35 b0 a5 11 03                            	lea    r14,[rip+0x311a5b0]        # 0x34d0418
  3b5e68:	4c 0f 44 f0                                     	cmove  r14,rax
  3b5e6c:	eb 88                                           	jmp    0x3b5df6
  3b5e6e:	4c 8d 35 ab 94 11 03                            	lea    r14,[rip+0x31194ab]        # 0x34cf320
  3b5e75:	e9 7c ff ff ff                                  	jmp    0x3b5df6
  3b5e7a:	4c 8d 35 97 a5 11 03                            	lea    r14,[rip+0x311a597]        # 0x34d0418
  3b5e81:	e9 70 ff ff ff                                  	jmp    0x3b5df6
  3b5e86:	e8 25 78 34 00                                  	call   0x6fd6b0
  3b5e8b:	0f 0b                                           	ud2
  3b5e8d:	90                                              	nop
  3b5e8e:	90                                              	nop
  3b5e8f:	90                                              	nop
  3b5e90:	55                                              	push   rbp
  3b5e91:	48 89 e5                                        	mov    rbp,rsp
  3b5e94:	41 57                                           	push   r15
  3b5e96:	41 56                                           	push   r14
  3b5e98:	53                                              	push   rbx
  3b5e99:	48 83 ec 18                                     	sub    rsp,0x18
  3b5e9d:	4c 8d 3d 6c 64 56 03                            	lea    r15,[rip+0x356646c]        # 0x391c310
  3b5ea4:	48 89 f7                                        	mov    rdi,rsi
  3b5ea7:	48 89 f3                                        	mov    rbx,rsi
  3b5eaa:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  3b5ead:	48 89 45 e0                                     	mov    QWORD PTR [rbp-0x20],rax
  3b5eb1:	e8 ca 22 64 00                                  	call   0x9f8180
  3b5eb6:	48 8d 75 dc                                     	lea    rsi,[rbp-0x24]
  3b5eba:	48 89 df                                        	mov    rdi,rbx
  3b5ebd:	49 89 c6                                        	mov    r14,rax
  3b5ec0:	e8 fb 22 64 00                                  	call   0x9f81c0
  3b5ec5:	85 c0                                           	test   eax,eax
  3b5ec7:	75 2a                                           	jne    0x3b5ef3
  3b5ec9:	8b 45 dc                                        	mov    eax,DWORD PTR [rbp-0x24]
  3b5ecc:	3d ff ff ff 00                                  	cmp    eax,0xffffff
  3b5ed1:	77 20                                           	ja     0x3b5ef3
  3b5ed3:	3d ff ff 00 00                                  	cmp    eax,0xffff
  3b5ed8:	0f 86 eb 00 00 00                               	jbe    0x3b5fc9
  3b5ede:	25 00 00 ff 00                                  	and    eax,0xff0000
  3b5ee3:	3d 00 00 01 00                                  	cmp    eax,0x10000
  3b5ee8:	75 09                                           	jne    0x3b5ef3
  3b5eea:	4c 8d 35 7f 9f 11 03                            	lea    r14,[rip+0x3119f7f]        # 0x34cfe70
  3b5ef1:	eb 07                                           	jmp    0x3b5efa
  3b5ef3:	4c 8d 35 ce 99 11 03                            	lea    r14,[rip+0x31199ce]        # 0x34cf8c8
  3b5efa:	48 8d 3d e7 93 11 03                            	lea    rdi,[rip+0x31193e7]        # 0x34cf2e8
  3b5f01:	31 f6                                           	xor    esi,esi
  3b5f03:	31 d2                                           	xor    edx,edx
  3b5f05:	31 c9                                           	xor    ecx,ecx
  3b5f07:	e8 f4 0a 11 00                                  	call   0x4c6a00
  3b5f0c:	48 8b 0d ad aa 11 03                            	mov    rcx,QWORD PTR [rip+0x311aaad]        # 0x34d09c0
  3b5f13:	48 85 c9                                        	test   rcx,rcx
  3b5f16:	74 5b                                           	je     0x3b5f73
  3b5f18:	48 89 c8                                        	mov    rax,rcx
  3b5f1b:	0f 1f 44 00 00                                  	nop    DWORD PTR [rax+rax*1+0x0]
  3b5f20:	48 3b 18                                        	cmp    rbx,QWORD PTR [rax]
  3b5f23:	74 0b                                           	je     0x3b5f30
  3b5f25:	48 8b 40 08                                     	mov    rax,QWORD PTR [rax+0x8]
  3b5f29:	48 85 c0                                        	test   rax,rax
  3b5f2c:	75 f2                                           	jne    0x3b5f20
  3b5f2e:	eb 43                                           	jmp    0x3b5f73
  3b5f30:	48 39 c1                                        	cmp    rcx,rax
  3b5f33:	74 21                                           	je     0x3b5f56
  3b5f35:	66 66 2e 0f 1f 84 00 00 00 00 00                	data16 cs nop WORD PTR [rax+rax*1+0x0]
  3b5f40:	48 89 ca                                        	mov    rdx,rcx
  3b5f43:	48 8b 49 08                                     	mov    rcx,QWORD PTR [rcx+0x8]
  3b5f47:	48 39 c1                                        	cmp    rcx,rax
  3b5f4a:	75 f4                                           	jne    0x3b5f40
  3b5f4c:	48 8b 49 08                                     	mov    rcx,QWORD PTR [rcx+0x8]
  3b5f50:	48 89 4a 08                                     	mov    QWORD PTR [rdx+0x8],rcx
  3b5f54:	eb 0b                                           	jmp    0x3b5f61
  3b5f56:	48 8b 49 08                                     	mov    rcx,QWORD PTR [rcx+0x8]
  3b5f5a:	48 89 0d 5f aa 11 03                            	mov    QWORD PTR [rip+0x311aa5f],rcx        # 0x34d09c0
  3b5f61:	48 8b 0d 60 aa 11 03                            	mov    rcx,QWORD PTR [rip+0x311aa60]        # 0x34d09c8
  3b5f68:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  3b5f6c:	48 89 05 55 aa 11 03                            	mov    QWORD PTR [rip+0x311aa55],rax        # 0x34d09c8
  3b5f73:	49 8b b6 b0 04 00 00                            	mov    rsi,QWORD PTR [r14+0x4b0]
  3b5f7a:	48 85 f6                                        	test   rsi,rsi
  3b5f7d:	74 0c                                           	je     0x3b5f8b
  3b5f7f:	48 8d 3d 6a 93 11 03                            	lea    rdi,[rip+0x311936a]        # 0x34cf2f0
  3b5f86:	e8 f5 8f 38 00                                  	call   0x73ef80
  3b5f8b:	49 8b b6 28 05 00 00                            	mov    rsi,QWORD PTR [r14+0x528]
  3b5f92:	48 85 f6                                        	test   rsi,rsi
  3b5f95:	74 0c                                           	je     0x3b5fa3
  3b5f97:	48 8d 3d 52 93 11 03                            	lea    rdi,[rip+0x3119352]        # 0x34cf2f0
  3b5f9e:	e8 dd 8f 38 00                                  	call   0x73ef80
  3b5fa3:	48 8d 3d 3e 93 11 03                            	lea    rdi,[rip+0x311933e]        # 0x34cf2e8
  3b5faa:	31 f6                                           	xor    esi,esi
  3b5fac:	31 d2                                           	xor    edx,edx
  3b5fae:	31 c9                                           	xor    ecx,ecx
  3b5fb0:	e8 eb 0f 11 00                                  	call   0x4c6fa0
  3b5fb5:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  3b5fb8:	48 3b 45 e0                                     	cmp    rax,QWORD PTR [rbp-0x20]
  3b5fbc:	75 53                                           	jne    0x3b6011
  3b5fbe:	48 83 c4 18                                     	add    rsp,0x18
  3b5fc2:	5b                                              	pop    rbx
  3b5fc3:	41 5e                                           	pop    r14
  3b5fc5:	41 5f                                           	pop    r15
  3b5fc7:	5d                                              	pop    rbp
  3b5fc8:	c3                                              	ret
  3b5fc9:	4c 39 35 f8 97 11 03                            	cmp    QWORD PTR [rip+0x31197f8],r14        # 0x34cf7c8
  3b5fd0:	74 27                                           	je     0x3b5ff9
  3b5fd2:	4c 39 35 e7 a8 11 03                            	cmp    QWORD PTR [rip+0x311a8e7],r14        # 0x34d08c0
  3b5fd9:	74 2a                                           	je     0x3b6005
  3b5fdb:	83 3d de 97 11 03 00                            	cmp    DWORD PTR [rip+0x31197de],0x0        # 0x34cf7c0
  3b5fe2:	48 8d 05 37 93 11 03                            	lea    rax,[rip+0x3119337]        # 0x34cf320
  3b5fe9:	4c 8d 35 28 a4 11 03                            	lea    r14,[rip+0x311a428]        # 0x34d0418
  3b5ff0:	4c 0f 44 f0                                     	cmove  r14,rax
  3b5ff4:	e9 01 ff ff ff                                  	jmp    0x3b5efa
  3b5ff9:	4c 8d 35 20 93 11 03                            	lea    r14,[rip+0x3119320]        # 0x34cf320
  3b6000:	e9 f5 fe ff ff                                  	jmp    0x3b5efa
  3b6005:	4c 8d 35 0c a4 11 03                            	lea    r14,[rip+0x311a40c]        # 0x34d0418
  3b600c:	e9 e9 fe ff ff                                  	jmp    0x3b5efa
  3b6011:	e8 9a 76 34 00                                  	call   0x6fd6b0
  3b6016:	0f 0b                                           	ud2
  3b6018:	90                                              	nop
  3b6019:	90                                              	nop
  3b601a:	90                                              	nop
  3b601b:	90                                              	nop
  3b601c:	90                                              	nop
  3b601d:	90                                              	nop
  3b601e:	90                                              	nop
  3b601f:	90                                              	nop
  3b6020:	55                                              	push   rbp
  3b6021:	48 89 e5                                        	mov    rbp,rsp
  3b6024:	41 57                                           	push   r15
  3b6026:	41 56                                           	push   r14
  3b6028:	41 55                                           	push   r13
  3b602a:	41 54                                           	push   r12
  3b602c:	53                                              	push   rbx
  3b602d:	48 83 ec 18                                     	sub    rsp,0x18
  3b6031:	4c 8d 25 d8 62 56 03                            	lea    r12,[rip+0x35662d8]        # 0x391c310
  3b6038:	48 89 f7                                        	mov    rdi,rsi
  3b603b:	48 89 f3                                        	mov    rbx,rsi
  3b603e:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  3b6042:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  3b6046:	e8 35 21 64 00                                  	call   0x9f8180
  3b604b:	48 8d 75 cc                                     	lea    rsi,[rbp-0x34]
  3b604f:	48 89 df                                        	mov    rdi,rbx
  3b6052:	49 89 c6                                        	mov    r14,rax
  3b6055:	e8 66 21 64 00                                  	call   0x9f81c0
  3b605a:	85 c0                                           	test   eax,eax
  3b605c:	75 2a                                           	jne    0x3b6088
  3b605e:	8b                                              	.byte 0x8b
  3b605f:	45                                              	rex.RB
