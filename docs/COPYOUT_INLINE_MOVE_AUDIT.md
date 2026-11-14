# 13.60 处理器语料中的内联 kernel→userland 拷贝形状审计

**类别**：绕过 copy helper、在 handler 内直接用字符串指令 / 手写标度循环 / `stac` 保护区完成 kernel→user 搬运的形状。
**语料**：`results/kernel_handlers/asm/sys_*.asm`（145 个文件）+ `results/kernel_handlers/decompiled/sys_*.c`（145 个）。镜像基址 0xffffffff8a000000，RVA = VA − 0xffffffff8a000000。
**既有审计未覆盖的部分**：`docs/COPYOUT_TABLE_INDEX_AUDIT.md`、`docs/COPYOUT_PARTIAL_STACK_AUDIT.md` 只审了 helper 0xffffffff8ac191d0 的调用点，并以"sys_640 的表拷贝是无 `stac` 的内联 `rep movsq`，即 kernel-to-kernel"为由把 640 排除。本文件审的是被那次排除掩盖的整类。
**可达性口径**：`docs/SYSENT_PRESENCE_14_10.md`（14.10 实测，六参零、一连接一号）。
**证据等级**：**STATIC** = 从语料字节读出的；**INFERRED** = 由 STATIC 事实加体系结构约束推出的。本文件不含任何硬件实测；"14.10 可达"引自上述实测文档，不是本次测得。

---

## 中文摘要

1. **这一整类是干净的否定，不是"没查完"。** 语料里 `stac`（`0f 01 cb`）只有 **一个** 不同地址：file 偏移 `0x259235`，位于 copyout helper 0xffffffff8ac191d0 体内（sys_646.asm:15610）。全语料没有任何 handler 体内出现 `stac`，因此**不存在**"`stac` 保护的 handler 内拷贝区"这一形状——它在构造上就是空集。
2. **因为 SMAP 生效，内联 store 想落到用户地址必须先置 AC=1。** 既然 handler 体内零 `stac`，那些内联 `rep movs` 与标度 store 的目标只能是 kernel 栈 / kernel 全局 / kernel 对象槽位（INFERRED，前提是 `stac`/`clac` 的存在证明 SMAP 开启）。
3. **既有审计说"helper 体不在语料里"是错的。** copyout、copyin、bzero 三个 helper 的原始字节以"SUPPLEMENTAL ORIGINAL KERNEL HELPER BYTES"形式被追加在 9 个文件里，起址 `kernel_text.bin[0x258ff0]`、`[0x2591d0]`、`[0x259280]`；`0x8a9c0000 + 0x2591d0 = 0x8ac191d0`，与调用点的 VA 完全对上（STATIC）。因此 copyout 的参数方向从 INFERRED 升级为 STATIC：**rdi = kernel 源，rsi = 用户目标，rdx = 长度**。
4. **copyout 的越界防护只有一条地址范围检查**：`rsi+rdx` 不得进位、且 `<= 0x800000000000`；失败走 onfault（pcb_onfault = 0x259260）返回 0xe。目标地址还被 `and 0x7fffffffffff` 截断。它不校验源、不校验长度与目标对象的关系。
5. **sys_640 的排除成立，而且比原审计说的更强**：两处内联 `rep movsq` 的索引来自 `movslq (%r14)`，r14 = 全局 0xffffffff8e5b6a88 指向的 kernel 对象（sys_640.asm:3911/3929），基址 0xffffffff8e5b6a60（3930），长度 `0xb` 个 qword（3937）= 正好等于步长 0x58，目标 = `lea 0x10(...)`（3933）。语料里找不到任何让该索引或基址受 uap 影响的路径。附带的真实缺陷是**索引无符号性/上界校验**（未对表项数做 `cmp`），属 kernel 内 OOB 写，不是泄漏。
6. **17 个 AT&T 标度 store 归约为 3 个函数体，5 个不同地址**，全部在 PART-3 handler 区：字符串原地解混淆、kernel 链表枚举进调用者缓冲、kernel 全局表填充。唯一带"调用者给的缓冲 + 调用者给的计数"形状的是 `0x8b2dcdcf`（629 窗口），但它没有任何 `stac`，且在 145 个文件里**找不到调用者**，所以无法把它的 arg1 绑到 uap 上。
7. **420 条 Intel 方言标度 store 全部位于 deep 窗口（26 条）或 supplemental helper 段（394 条），PART-3 handler 区 0 条。** 它们的地址都是 6 位 RVA，而所有 PART-3 handler 指令都带 16 位 VA，这是可机械判定的分界。
8. **既有审计标为"memcpy-ish"的 0xffffffff8ac190b0 有 73 个调用点、体内字节不在语料中**，是本次唯一无法闭合的残余；抽样的 10 个调用点目标全是栈帧或 kernel 全局/对象。因为它没有 `stac`，它不可能是一条用户目标通路，但它也不可能安全地服务用户目标。
9. 结论：`provable kernel->user leaks in this class = 0`（见 Verdict 表）。

---

## 0. Verdict

| 项目 | 计数 |
|---|---|
| **provable kernel->user leaks in this class** | **0** |
| 语料文件数（asm / decompiled） | 145 / 145 |
| 指令级命中：`rep movs`（所有形式） | 49 处文本命中 / 17 个不同地址 |
| 指令级命中：`rep stos` | 18 / 2 个不同地址 |
| 指令级命中：`stac`（`0f 01 cb`） | 18 / 1 个不同地址（0x259235） |
| 指令级命中：`clac`（`0f 01 ca`） | 36 / 4 个不同地址 |
| 指令级命中：独立 `movsb`/`movsw`/`movsl`/`movsq`（非 `rep`） | 0 |
| 手写标度 store（AT&T，PART-3 区） | 17 / 5 个不同地址 / 3 个函数体（另有同体的 `movbe` 存储 1 处，见 F7） |
| 手写标度 store（Intel，deep+supplemental 区） | 420（deep 26 + supplemental 394），PART-3 区 0 |
| 落在 handler 可达区的不同内联搬运指令地址（字符串指令 + 标度 store） | 21 |
| 其中目标由 uap 派生的 | **0** |
| 其中长度由 uap 字段控制的 | **0** |
| 其中带 `stac` 保护的 | **0**（唯一的 `stac` 在 copyout helper 体内） |
| handler 体内出现 `stac` 的文件数 | 0 |
| 语料内可闭合的 helper 体 | 4 个中的 3 个（bzero、copyout、copyin 有体；memcpy-ish 0xac190b0 无体） |

---

## 1. Method

### 1.1 方言普查（必须先做，否则 grep 会在错误的分区里命中）

语料有三种反汇编方言，地址宽度不同，直接决定一条命中是否落在 handler 体里：

| 方言 | 形态 | 地址宽度 | 出现位置 |
|---|---|---|---|
| D1 | AT&T，`ffffffff8b47e086: 49 6b c6 68  imul $0x68,%r14,%rax` | 16 位 VA | PART-3 handler 体 |
| D2 | 小写 Intel，`ac897b: f3 48 a5  rep movs QWORD PTR [rdi],QWORD PTR [rsi]` | 6 位 RVA | deep 窗口（`sys_*_deep.asm`）与 supplemental helper 段 |
| D3 | 大写 Intel，`0x705e29: MOV ECX, 0x400000` | 6 位 RVA 带 `0x` | 少数文件的附加段（sys_533/534/535/536/563 等） |

判据（STATIC、可机械复核）：**所有 D1 行是 handler 体；D2/D3 行不是**。用 `/^\s*ffffffff8a[0-9a-f]{6}:/` 过滤 D1，结果是 0 条 Intel 形态命中、全部标度 store 命中 17 条，二者互不重叠。

### 1.2 指令普查（STATIC 计数）

对 `rep movs` / `rep stos` / `movsb` / `movsw` / `movsl` / `movsq` / `stac` / `clac` / 字节序列 `0f 01 cb` / `0f 01 ca` 全语料 grep，逐条记录 file:line、地址、指令字节：

- `rep movs` 49 条：`sys_558_deep` 6、`sys_640` 2、`sys_646/647/649/656` 各 4、`sys_650/651/652/654/655` 各 5。
- `rep stos` 18 条：9 个文件各 2（0x259024、0x25902e）。
- `stac` 18 条 / `clac` 36 条：9 个文件各 2 / 4，地址恒为 0x259235、0x259242、0x259260、0x25931a、0x259340。
- 独立 `movsb/movsw/movsl/movsq`（不带 `rep`）：**0 条**。先前把 `movsbl 0x14c(%r15),%eax` 一类的符号扩展 load 计入 `movsb` 的统计是口径错误，本文件已纠正。
- 唯一的 `stac` 编码是 `0f 01 cb`；唯一用 `pushf/popf` 改 AC 的可能通路不存在（`0x40000` 在语料里只出现为实现无关的常量，无 `pushfq`）。

### 1.3 候选分类规则

对每个候选站点记录四问：

- (a) 目标来自 uap 里的用户指针，还是 kernel 全局 / 栈 / 凭证对象？
- (b) 长度是常量、uap 字段，还是表/对象字段？
- (c) 源是栈帧、kernel 全局表，还是由 uap 或表指针到达的对象？
- (d) uap 取指到 store 之间有没有长度/索引的界检查，且其操作数顺序是否真的约束了被搬运的量？

分类前先做一次**结构性预判**：`stac` 在语料中只出现一次且位于 copyout helper 内 → 任何 handler 内联 store 的目标都不可能是用户地址（INFERRED，前提 SMAP 开启，由 `stac`/`clac` 的存在本身支持）。这一步把"逐点证明没有 uap 目标"降为"逐点证明形状"，成本可控。

### 1.4 可达性口径

按 `docs/SYSENT_PRESENCE_14_10.md` 的实测值对每个站点所属 syscall 打标；该号在 14.10 上不可达的站点一律标注并后置。注意 "kills" 不等于缺席，只等于"零参不可调用"。

---

## 2. 前置发现：三个 helper 的原始字节就在语料里

9 个文件（sys_646/647/649/650/651/652/654/655/656）的尾部有一段标注为 `; SUPPLEMENTAL ORIGINAL KERNEL HELPER BYTES; GNU objdump, not REA.` 的附加区（首次出现在 sys_646.asm:15540），内含 6 个 helper 的原始字节：

| 标注 | 起址 | 对应 helper VA | 有 `stac`？ |
|---|---|---|---|
| `zero` | `kernel_text.bin[0x258ff0:0x259032]` | 0xffffffff8ac18ff0 | 否 |
| `copyout` | `kernel_text.bin[0x2591d0:0x259280]` | 0xffffffff8ac191d0 | **是** |
| `copyin` | `kernel_text.bin[0x259280:0x259360]` | 0xffffffff8ac19280 | **是** |
| `credential_bit62` | `[0x608f90:0x608fa1]` | — | 否 |
| `credential_authid_allowlist` | `[0x6090d0:0x60910e]` | — | 否 |
| `module_query_gates` | `[0xacce10:0xacce84]` | — | 否 |

映射自洽性（STATIC）：`0x8a9c0000 + 0x258ff0 = 0x8ac18ff0`、`+0x2591d0 = 0x8ac191d0`、`+0x259280 = 0x8ac19280`——三者同时精确命中调用点标注的 0xffffffff8ac18ff0 / 0x8ac191d0 / 0x8ac19280，故 `kernel_text.bin` 的装载基址为 0xffffffff8a9c0000。**0xffffffff8ac190b0（memcpy-ish）不在这 6 个里，它的体不入语料。**

### 2.1 copyout（0x8ac191d0 = file 0x2591d0）逐段

```
sys_646.asm:15583 |   2591d0: 55                    push   rbp
sys_646.asm:15585 |   2591d4: 65 48 8b 04 25 20 00  mov    rax,QWORD PTR gs:0x20
sys_646.asm:15587 |   2591dd: 4c 8d 1d 7c 00 00 00  lea    r11,[rip+0x7c]        # 0x259260
sys_646.asm:15588 |   2591e4: 4c 89 98 08 01 00 00  mov    QWORD PTR [rax+0x108],r11
sys_646.asm:15589 |   2591eb: 48 85 d2              test   rdx,rdx
sys_646.asm:15590 |   2591ee: 74 55                 je     0x259245
sys_646.asm:15591 |   2591f0: 48 89 f0              mov    rax,rsi
sys_646.asm:15592 |   2591f3: 48 01 d0              add    rax,rdx
sys_646.asm:15593 |   2591f6: 72 68                 jb     0x259260
sys_646.asm:15594 |   2591f8: 48 b9 00 00 00 00 00  movabs rcx,0x800000000000
sys_646.asm:15596 |   259202: 48 39 c8              cmp    rax,rcx
sys_646.asm:15597 |   259205: 77 59                 ja     0x259260
sys_646.asm:15601 |   259214: 80 b8 91 05 00 00 00  cmp    BYTE PTR [rax+0x591],0x0
sys_646.asm:15602 |   25921b: 75 43                 jne    0x259260
sys_646.asm:15603 |   25921d: 48 b8 ff ff ff ff ff  movabs rax,0x7fffffffffff
sys_646.asm:15605 |   259227: 48 21 c6              and    rsi,rax
sys_646.asm:15606 |   25922a: 48 87 f7              xchg   rdi,rsi
sys_646.asm:15607 |   25922d: 48 89 d1              mov    rcx,rdx
sys_646.asm:15608 |   259230: 48 c1 e9 03           shr    rcx,0x3
sys_646.asm:15610 |   259235: 0f 01 cb              stac
sys_646.asm:15611 |   259238: f3 48 a5              rep movs QWORD PTR [rdi],QWORD PTR [rsi]
sys_646.asm:15612 |   25923b: 88 d1                 mov    cl,dl
sys_646.asm:15613 |   25923d: 80 e1 07              and    cl,0x7
sys_646.asm:15614 |   259240: f3 a4                 rep movs BYTE PTR [rdi],BYTE PTR [rsi]
sys_646.asm:15615 |   259242: 0f 01 ca              clac
sys_646.asm:15629 |   259260: 0f 01 ca              clac                     ; onfault
sys_646.asm:15632 |   25926c: 48 c7 82 08 01 00 00  mov    QWORD PTR [rdx+0x108],0x0
sys_646.asm:15634 |   259277: 48 c7 c0 0e 00 00 00  mov    rax,0xe
```

要点：

- `gs:0x20` 是每线程的 pcb 指针，`[pcb+0x108]` 被写入 0x259260 即 **pcb_onfault**；任何用户地址缺页会跳到 0x259260，`clac` 后清 onfault 并返回 0xe。返回 0 时同样清 onfault（15616-15619）。
- 长度 0 直接成功返回（15589-15590）。
- 唯一的越界防护是 `rsi+rdx` 的进位与 `<= 0x800000000000`；`and 0x7fffffffffff` 只是把目标截到 47 位规范地址。
- `cmp BYTE PTR [rax+0x591],0x0` 读 `[gs:0x0] -> [+0x8] -> [+0x591]`，非 0 则走 EFAULT（INFERRED：某个"禁止拷贝"线程/进程标志）。
- `xchg rdi,rsi` 确立了 ABI：跳转前 rdi = kernel 源、rsi = 用户目标；交换后 `rep movs [rdi],[rsi]` 的 rdi 才是用户目标。**方向由 helper 体直接证明（STATIC）**，不再依赖调用点推断。

### 2.2 copyin（0x8ac19280 = file 0x259280）

同形状，`stac` 在 0x25930d、`rep movs` 在 0x259310、`rep movs BYTE` 在 0x259318、`clac` 在 0x25931a 与 onfault 的 0x259340（sys_646.asm:15686-15713）。它是 helper 里的第二处也是最后一处 `stac`。

### 2.3 bzero（0x8ac18ff0 = file 0x258ff0）

```
sys_646.asm:15568 |   259024: f3 48 ab              rep stos QWORD PTR [rdi],rax
sys_646.asm:15571 |   25902e: f3 aa                 rep stos BYTE PTR [rdi],al
```
无 `stac`。开头还有一段把 `rdi+rsi` 与 `rsp`/`rbp+0x10` 比较的栈重叠判断（15552-15559），不涉及用户地址。

### 2.4 对既有审计的更正

`docs/COPYOUT_TABLE_INDEX_AUDIT.md` §2.2 写"helper 体不在语料里：`grep -n '^ffffffff8ac191d0 <'` 返回 0 命中"，并据此把方向定为 INFERRED。该 grep 以**符号标签**匹配，而 helper 体是以 **RVA + `; copyout` 注释**形式出现的（sys_646.asm:15575），所以标签匹配为 0 并不代表体不在。本文以 §2.1 的字节替代该推断，方向与越界防护均为 STATIC。既有文件未修改。

---

## 3. Findings

### F1 — 全语料唯一的 `stac` 在 copyout helper 体内；handler 体内不存在 `stac` 保护区（STATIC）

`stac` 命中 18 条，全部为地址 `0x259235`（`0f 01 cb`），分布在 9 个文件的 supplemental 段，每个文件 2 条（copyout 1 + copyin 1，后者地址 0x25930d）。分布文件：sys_646/647/649/650/651/652/654/655/656。PART-3 handler 区（D1，16 位 VA）`stac` 命中为 0。

结论：**"handler 用 `stac` 保护区直接搬用户内存"这一类在语料中是空集**——不是"没找到"，而是这条指令在 handler 体内一次都没出现。

### F2 — copyout 的方向与防护是 STATIC，不再是 INFERRED

见 §2.1。`xchg rdi,rsi`（0x25922a）确定的 ABI 与调用点完全一致：sys_618.asm:4369-4372 `mov $0x68,%edx; lea -0x98(%rbp),%rdi; mov %rbx,%rsi; call 0xffffffff8ac191d0`，其中 `%rbx = 0x10(%uap) + idx*0x68`（4362/4367），即 **rsi = 用户目标，rdi = 栈源**。两条独立证据（helper 体 + 调用点）同向。

### F3 — 618/620/624/628/637/642 共享体的界检查是"用户值比用户值"，真正的兜底在 copyout 里（STATIC）

```
sys_618.asm:4356 | ffffffff8b47e068: 48 8b 58 10          	mov    0x10(%rax),%rbx
sys_618.asm:4360 | ffffffff8b47e07c: 44 3b 70 08          	cmp    0x8(%rax),%r14d
sys_618.asm:4361 | ffffffff8b47e080: 0f 8d 3b fb ff ff    	jge    ffffffff8b47dbc1
sys_618.asm:4362 | ffffffff8b47e086: 49 6b c6 68          	imul   $0x68,%r14,%rax
sys_618.asm:4367 | ffffffff8b47e09c: 48 01 c3             	add    %rax,%rbx
sys_618.asm:4369 | ffffffff8b47e0a4: ba 68 00 00 00       	mov    $0x68,%edx
sys_618.asm:4372 | ffffffff8b47e0b3: e8 18 b1 79 ff       	call   ffffffff8ac191d0
```

`rax` 是 uap（`-0xb8(%rbp)` 处的保存副本），所以目标 = `uap->r[2]`，界 = `uap->r[1]`，索引 = 栈上的用户值。界与索引都来自用户，因此这条 `cmp/jge` **不构成对搬运量的证明**；真正的约束是 F2 的 `目标+长度 <= 0x800000000000` 与 onfault→EFAULT。实际上越界索引只会让 copyout 返回 0xe，不泄漏、不越写。这是"安全的实现、不安全的证明"，记录以备后续复核。

### F4 — sys_640 的两处内联 `rep movsq`：排除成立（STATIC）

```
sys_640.asm:3911 | ffffffff8b451389: 4c 8b 35 f8 56 16 03  mov    0x31656f8(%rip),%r14        # ffffffff8e5b6a88
sys_640.asm:3912 | ffffffff8b451390: 4d 85 f6              test   %r14,%r14
sys_640.asm:3927 | ffffffff8b4513c6: 49 6b c8 58           imul   $0x58,%r8,%rcx
sys_640.asm:3929 | ffffffff8b4513ce: 4d 63 0e              movslq (%r14),%r9
sys_640.asm:3930 | ffffffff8b4513d1: 4c 03 0d 88 56 16 03  add    0x3165688(%rip),%r9        # ffffffff8e5b6a60
sys_640.asm:3933 | ffffffff8b4513e1: 4a 8d 54 09 10        lea    0x10(%rcx,%r9,1),%rdx
sys_640.asm:3936 | ffffffff8b4513ea: 48 8d 75 90           lea    -0x70(%rbp),%rsi
sys_640.asm:3937 | ffffffff8b4513ee: b9 0b 00 00 00        mov    $0xb,%ecx
sys_640.asm:3939 | ffffffff8b4513f6: f3 48 a5              rep movsq (%rsi),(%rdi)
```

- 索引：`movslq (%r14)`，`r14` 由 3911 的 `mov 0x31656f8(%rip),%r14` 从全局 0xffffffff8e5b6a88 装入。**r14 不是 uap**：该全局在同一窗口内由 4100 的 `mov %r14,0x3165433(%rip)` 写入，写入者 r14 来自 4027-4032 的 `mov $0xc,%edi; mov $0x102,%edx; lea 0x216ab65(%rip),%rsi # ffffffff8d5bc080; call ffffffff8b5c8b50`（分配器）返回的堆对象，其索引字段由 4066 的 `mov %r15d,(%r14)` 写入，r15d 是尺寸派生的偏移。
- 基址：0xffffffff8e5b6a60（3930，`add` 立即数），stride 由 3927 的 `imul $0x58` 给出，**长度 0xb 个 qword = 0x58 字节 = 恰好一个槽位**（3937）。
- 目标：3933 的 `lea 0x10(%rcx,%r9,1)`，即表基址 + 字节偏移 + 槽内偏移 + 0x10。源：3936 的栈帧 `-0x70(%rbp)`。
- 语料内不存在让 r9 或基址受 uap 影响的路径；该窗口内 uap 从不参与这段地址算术。

**结论：640 的排除成立**，且理由比原审计的"没有 `stac`"更硬：即使有 `stac`，目标也是 kernel 表槽。第二处（sys_640.asm:4095，0x8b45163c）同形状，`movslq 0x0(%r13),%r9` 在 4085，栈源 `-0x88(%rbp)` 在 4092。

附带 STATIC 观察（非泄漏）：r9 是**有符号 32 位**读入后直接当字节偏移使用，语料内看不到对表容量的 `cmp`。若该字段可被外部写成任意值，这是 kernel 侧 OOB 写，方向为 kernel→kernel，不影响本类结论。另注 3921-3924 的 `cmp $0x4` 只约束槽内计数 `r8`（0..4），与 r9 无关。

### F5 — sys_558_deep 的 6 处 `rep movs`：全部是 kernel→kernel，且该窗口无函数标签（STATIC）

该文件整段是一个 deep 窗口（唯一符号为 `0000000000ac73c0 <.data>`，sys_558_deep.asm:7），没有任何 `handler_558_body` 标签，因此**无法**从本文件断言可达性；只能断言目标形状。

| file:line | 地址 | 目标 | 源 | 长度 |
|---|---|---|---|---|
| 1528 | `ac897b` | `lea rdi,[rbp-0x80]` 栈 | `r13`（取自 `[rbp-0x88]`） | `mov ecx,0xa` |
| 1581 | `ac8a66` | 反向写回上条那个 `r13` 指针 | 栈 | `0xa` |
| 2060 | `ac9125` | `r15`，每轮 +0x50 | `[rcx+0x198]` + `imul rsi,rbx,0x98` 的 kernel 记录数组 | `0xa` |
| 2241 | `ac93b0` | `[rbp-0x58]` | `[rbp-0x50]` + `rax*0x98` | `0xa` |
| 2279 | `ac9445` | `r15`（`mov rdi,r15`，0x1a 条之前为分配块） | `[rbp-0x50]` + `r12d*0x98`（2275） | `0xa` |
| 2485 | `ac9675` | `[rbx+0x198] + [rbx+0x104]*0x98 + 0x90`（kernel 数组槽，2472-2478） | `r12` = 函数第二实参；写入前先用 bzero helper `call 0x258ff0` 清零该槽（2480） | `0xa` |

无一例目标来自 uap；无一处带 `stac`。`ac9675` 的源是调用者给的指针，但目标固定为 kernel 数组槽，方向相反（kernel←caller），不是泄漏。

### F6 — 五文件共享的 `0x5613b5`：链表节点克隆，kernel→kernel（STATIC）

```
sys_650.asm:25634 |   56139b: e8 e0 a4 ed ff        call   0x43b880            ; 分配新节点
sys_650.asm:25638 |   5613a8: 48 8d 78 10           lea    rdi,[rax+0x10]      ; 新节点 +0x10
sys_650.asm:25639 |   5613ac: 48 8d 72 10           lea    rsi,[rdx+0x10]      ; 旧节点 +0x10
sys_650.asm:25640 |   5613b0: b9 0a 00 00 00        mov    ecx,0xa
sys_650.asm:25641 |   5613b5: f3 48 a5              rep movs QWORD PTR [rdi],QWORD PTR [rsi]
sys_650.asm:25653 |   5613df: 49 89 46 28           mov    QWORD PTR [r14+0x28],rax
sys_650.asm:25654 |   5613e3: 4c 89 70 68           mov    QWORD PTR [rax+0x68],r14
```
段后紧跟 `[+0x8]`/`[+0x28]` 的链表挂接。同址出现在 sys_651.asm:25641、sys_652.asm:25690、sys_654.asm:25612、sys_655.asm:25612（同一份体，文件内偏移略有差异）。目标为新分配节点的内嵌缓冲，源为旧节点，0x50 字节。

### F7 — 17 条 AT&T 标度 store 归约为 3 个函数体；无一以 uap 地址为目标（STATIC）

| file:line | 地址 / 指令字节 | 语义 | 目标来源 | 界 |
|---|---|---|---|---|
| sys_618.asm:5583（及 620/624/628/637/642 同址） | `ffffffff8b47efec: 46 88 1c 17  mov %r11b,(%rdi,%r10,1)` | 原地字符串解混淆循环 | **rdi = 该函数自己的第一实参**（`rdi+len` 的原地改写） | `cmp %r10,%rsi`（5571），rsi = 长度实参 |
| 同上 5585 | `ffffffff8b47eff2: 88 04 17  mov %al,(%rdi,%rdx,1)` | 收尾写回 | 同上 | 固定偏移 |
| sys_629.asm:3736 | `ffffffff8b2dcdcf: 49 89 04 d7  mov %rax,(%r15,%rdx,8)` | 遍历 kernel 链表填调用者缓冲 | **arg1 = r15** | `cmp %r12d,%r13d; jge`（3732-3733），r12d = `*(u32*)arg2`（3711） |
| sys_629.asm:3970 | `ffffffff8b2dd063: 48 89 0c d7  mov %rcx,(%rdi,%rdx,8)` | 同上，类型过滤 `cmpw $0x10,0x20(%rdx)` | `[rbp-0x40]`（保存的实参） | `cmp %ebx,%r13d; jge`（3966-3967） |
| sys_636.asm:5159（及 638/639 同址） | `ffffffff8b080030: 89 3c 11  mov %edi,(%rcx,%rdx,1)` | 启动期填 kernel 全局表 | **rdx = 全局 0xffffffff8e2d9f00**（5151），rcx = 0..0xff 计数器 | 固定 `cmp $0x100,%rcx`（5161） |
| sys_636.asm:5146（及 638/639 同址） | `ffffffff8b07fff7: 0f 38 f1 34 11  movbe %esi,(%rcx,%rdx,1)` | 同上，另一张表 | **rdx = 全局 0xffffffff8e2d9e00**（5140） | 固定 `cmp $0x100,%rcx`（5148） |

三个体都**没有 `stac`**。按 §1.3 的结构性预判，它们的 store 不可能落在用户地址；逐点的目标来源也印证了这一点。637/642/618 的 0x8b47f0ab 处还调用 memcpy-ish（见 F9），其 rsi 取自全局 `0xffffffff8e5b6e30` 指向的指针对表（4991/5645），是 kernel 表项。

### F8 — 唯一"调用者给缓冲 + 调用者给计数"的形状在 629 窗口，但其调用者不在语料内（STATIC）

`frame_candidate_91cd40`（0x8b2dcd40，sys_629.asm:3690）：

```
sys_629.asm:3711 | ffffffff8b2dcd73: 45 8b 26              mov    (%r14),%r12d        ; 计数 = *(u32*)arg2
sys_629.asm:3712 | ffffffff8b2dcd76: 48 8d 3d d3 9b 25 03  lea    0x3259bd3(%rip),%rdi # ffffffff8e536950
sys_629.asm:3721 | ffffffff8b2dcda0: 48 8b 09              mov    (%rcx),%rcx         ; 走 kernel 全局链表
sys_629.asm:3732 | ffffffff8b2dcdc3: 45 39 e5              cmp    %r12d,%r13d
sys_629.asm:3733 | ffffffff8b2dcdc6: 7d 0b                 jge    ffffffff8b2dcdd3
sys_629.asm:3734 | ffffffff8b2dcdc8: 48 8b 41 28           mov    0x28(%rcx),%rax
sys_629.asm:3736 | ffffffff8b2dcdcf: 49 89 04 d7           mov    %rax,(%r15,%rdx,8)  ; dest = arg1
sys_629.asm:3769 | ffffffff8b2dce2e: 45 39 ec              cmp    %r13d,%r12d
sys_629.asm:3770 | ffffffff8b2dce31: 45 0f 4d e5           cmovge %r13d,%r12d
sys_629.asm:3771 | ffffffff8b2dce35: 45 89 26              mov    %r12d,(%r14)        ; *arg2 = min(cap, filled)
sys_629.asm:3772 | ffffffff8b2dce38: 44 89 2b              mov    %r13d,(%rbx)        ; *arg3 = filled
```

- (a) 目标 = 第 1 实参，语料内**无法回溯**到 uap；(b) 长度 = `*arg2`（u32，调用者给的容量）；(c) 源 = kernel 链表头 0xffffffff8e536950 之后的节点 `[+0x28]`；(d) 有界检查 `index < *arg2`，且收尾把 `min(cap, filled)` 写回，所以写入量被容量约束。
- **决定性反证**：函数体自 0x8b2dcd40 到 0x8b2dce53 的 `ret` 之间没有 `stac`，也没有安装 onfault（无 `gs:0x20` 写入）。在 SMAP 生效的内核里，对用户地址做这条 store 会立刻 #PF；无 onfault 即 `trap_fatal`。因此 arg1 若是用户指针，这条路是"立即 panic"而不是"泄漏"。这也反过来说明 arg1 只可能是 kernel 指针。
- 附加 STATIC：`grep -c 'call\s\+ffffffff8b2dcd40'` 在 145 个文件里 **0 命中**——它的调用者在语料窗口之外。姊妹函数 0x8b2dce60（3769 起）同窗口同形状。

### F9 — memcpy-ish 0xffffffff8ac190b0：体不在语料里，73 个调用点，抽样 10 个全为 kernel→kernel（STATIC 抽样 + 结构性 INFERRED）

- 调用点 73，分布 25 个文件（sys_639 10、sys_638 7、sys_618/620/624/628/637/642 各 4、sys_640/636 各 3 等）。
- 抽样 10 个（sys_639:5399、sys_638:5486、sys_637:4993、sys_642:5233、sys_640:5684、sys_636:5364、sys_618:5647、sys_629:5728、sys_627:5221、sys_644:5539）：目标是栈帧（`lea -0x32(%rbp)`、`lea -0x220(%rbp)`）、kernel 全局（`lea ...(%rip) # ffffffff8e538440`、`ffffffff8e2d7a8a`）、或 kernel 对象字段（`0x38(%r14)`、`lea 0x470(%rbx)`）。源同理。**10/10 kernel→kernel**。
- 结构性结论：该 helper 在语料中没有任何 `stac`；它**不是** copyout 通路。这同时意味着若某个 handler 把用户地址喂给它，结果是 #PF 而不是复制。
- 残余：体内字节不入语料，无法排除它在自己的体内 `stac`（虽然按它与 copyout 并存的用法判断不会）。见 §5 排名第 1。

### F10 — 420 条 Intel 方言标度 store 全在 deep/supplemental 段，PART-3 区 0 条（STATIC）

按 `SUPPLEMENTAL ORIGINAL KERNEL HELPER BYTES` 标记行切分：deep 窗口 26 条、supplemental 段 394 条、其它 0 条。判据是地址宽度（全部 6 位 RVA）。段落内容为表初始化循环与 helper 体自身的字段写，无 handler 语义。

### F11 — decompiled/*.c 交叉核对（限定）

C 侧只用于确认形状与参数顺序（如 618 体的 `copyout(stack_rec, uap->buf + i*0x68, 0x68)` 形状），不作为地址/字节证据来源。凡本文引用的地址、字节、行号均取自 `.asm`。

---

## 4. Per-file table

145 个文件中 21 个有命中，124 个无命中（无 `rep movs`/`rep stos`/`stac`/`clac`，且无 PART-3 标度 store）。

| 文件 | rep movs | rep stos | stac/clac | 标度 store(AT&T) | 区域 | 结论 |
|---|---|---|---|---|---|---|
| sys_558_deep.asm | 6 | 0 | 0/0 | 0 | deep 窗口 (RVA) | kernel→kernel ×6（F5） |
| sys_640.asm | 2 | 0 | 0/0 | 0 | PART-3 (VA) | 表槽写（F4），排除成立 |
| sys_646.asm | 4 | 2 | 2/4 | 0 | PART-3 + supplemental | helper 体（§2） |
| sys_647.asm | 4 | 2 | 2/4 | 0 | 同上 | 同上 |
| sys_649.asm | 4 | 2 | 2/4 | 0 | 同上 | 同上 |
| sys_650.asm | 5 | 2 | 2/4 | 0 | 同上 | helper 体 + 0x5613b5 克隆 |
| sys_651.asm | 5 | 2 | 2/4 | 0 | 同上 | 同上 |
| sys_652.asm | 5 | 2 | 2/4 | 0 | 同上 | 同上 |
| sys_654.asm | 5 | 2 | 2/4 | 0 | 同上 | 同上 |
| sys_655.asm | 5 | 2 | 2/4 | 0 | 同上 | 同上 |
| sys_656.asm | 4 | 2 | 2/4 | 0 | 同上 | helper 体 |
| sys_618.asm | 0 | 0 | 0/0 | 2 | PART-3 | 解混淆循环（F7） |
| sys_620.asm | 0 | 0 | 0/0 | 2 | PART-3 | 同上（共享体） |
| sys_624.asm | 0 | 0 | 0/0 | 2 | PART-3 | 同上（共享体） |
| sys_628.asm | 0 | 0 | 0/0 | 2 | PART-3 | 同上（共享体） |
| sys_637.asm | 0 | 0 | 0/0 | 2 | PART-3 | 同上（共享体） |
| sys_642.asm | 0 | 0 | 0/0 | 2 | PART-3 | 同上（共享体） |
| sys_629.asm | 0 | 0 | 0/0 | 2 | PART-3 | 链表枚举（F8） |
| sys_636.asm | 0 | 0 | 0/0 | 1 | PART-3 | 全局表填充（F7） |
| sys_638.asm | 0 | 0 | 0/0 | 1 | PART-3 | 同上（共享体） |
| sys_639.asm | 0 | 0 | 0/0 | 1 | PART-3 | 同上（共享体） |

注：9 个含 supplemental 段的文件里，`rep movs` 的 4 条是 copyout 的 q/b 两条与 copyin 的 q/b 两条；650/651/652/654/655 的第 5 条是 `0x5613b5`。所有 18 条 `rep stos` 均为 bzero 体。

---

## 5. Ranked residual list

| 排名 | 站点 | 13.60 名 | 14.10 | 为什么排在这么前 | 下一步省钱的做法 |
|---|---|---|---|---|---|
| 1 | `0xffffffff8ac190b0`（73 调用点，体未入语料） | memcpy-ish | 多点，含 638/639（实测 0） | 唯一无法读体确认"无 `stac`"的搬运 helper；若它是第二条 copyout 通路，本类结论会缩到"除它之外" | 取 `kernel_text.bin[0x2590b0:0x2591d0]` 的字节，比对是否含 `0f 01 cb`；无体时改用它的 73 个调用点做目标来源全量分类（已抽 10/73） |
| 2 | `0xffffffff8b2dcdcf` / `0x8b2dd063` | 629 窗口 | 629 实测 -1（存在但拒零参） | 唯一"调用者给目标 + 调用者给容量"的形状；无 `stac` 使其不可能写用户地址，但一旦出现第二份带 `stac` 的副本就成立 | 找 0x8b2dcd40 的调用者（语料内 0 命中）；或在 14.10 上用 `SIG_IGN` + 非零参数跑 629，观察 buf/count 是否被写 |
| 3 | `0xffffffff8b4513ce` 的 r9（sys_640 表偏移） | 640 `set_uevt` | 640 实测 0（可达） | 可达性最高的一处地址算术；索引无上界比较。方向是 kernel 内 OOB 写，不是泄漏 | 在 14.10 上让 640 走到该分支（需要 scope/case 参数），观察是否 panic 而非错误返回 |
| 4 | `0xffffffff8b45163c`（640 第二处） | 同上 | 同上 | 同 F4，独立一处 | 同上 |
| 5 | `0xac9675`（558 deep 窗口） | 558 `namedobj_delete` | 558 实测 -1 | 目标为 kernel 数组槽，但源是调用者指针；若哪天目标改成调用者指针即成立 | 需要 558 的真实函数边界（当前窗口无标签）；先解决 §7 的窗口问题 |
| 6 | `0x8b47efec` 解混淆循环 | 618/620/624/628/637/642 共享体 | 618/628 实测 -1，620/624 实测 0/3377 | 原地改写第一实参，长度来自第二实参；若某调用点把用户地址当第一实参，就是内核在用户内存上做读写 | 对这 6 个文件的 0x8b47efa4 调用点逐个回溯 rdi |

---

## 6. 真正的内联泄漏会长什么样

用本文已建立的事实做反例构造，便于以后一眼识别：

1. handler 体内出现 `0f 01 cb`（在 `rep movs`/`mov` 循环之前），且该 `stac` 之后没有 `clac` 的对称配对——本文语料里这种形态 0 次。
2. 目标寄存器由 `mov 0xNN(%uap),%rXX` 直接装入，紧接着 `add idx*stride`，中间**没有** `cmp`/`jae` 对 idx 与对象容量的比较，也**没有** `目标+长度 <= 0x800000000000` 这类地址检查（copyout 的检查在 helper 里，绕过 helper 就绕过了它）。
3. 长度操作数是 `0xNN(%uap)` 而不是常量或表字段。
4. 无 onfault：copyout 靠 `[pcb+0x108] = 0x259260` 把缺页变成 EFAULT。内联路径若不装 onfault，坏指针是 panic 而非错误码，这本身也是一条判据——F8 的 `0x8b2dcd40` 就是靠这条被判为非用户目标。

---

## 7. Limits

- 语料是**固定窗口**，不是完整内核。deep 窗口（`sys_*_deep.asm`）连函数标签都没有（sys_558_deep.asm:7 只有 `<.data>`），所以可达性只能靠 syscall 号间接推断，不能从窗口内部证明。
- helper 体覆盖率 4 个中的 3 个。memcpy-ish 0xffffffff8ac190b0 无体，是 §5 排名第 1 的残余。
- "SMAP 生效"是 INFERRED（依据是 copyout/copyin 里的 `stac`/`clac` 与 onfault 设计），不是本文实测的 CR4 值。若 SMAP 实际关闭，F1/F8 的"不可能写用户地址"要降级为"没有证据表明写用户地址"。
- 73 个 memcpy-ish 调用点只抽样 10 个（14%），其余 63 个未逐点分类。
- decompiled C 只用于交叉确认形状，未做逐行比对。
- 14.10 的可达性引自 `docs/SYSENT_PRESENCE_14_10.md` 的既有实测；本文没有任何一行是在硬件上跑出来的。
