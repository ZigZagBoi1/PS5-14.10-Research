/* handler_566: recovered C pseudocode and analyst type overlays.
 * Source SHA256 22029bbda5344bf57db8e5fb34fdc2ab118c730a42f221802e4eae21fd57b088
 * Original load RVA 0x265de0; actual target RVA 0x603710.
 * REA 6.7.0 / Ghidra 12.1.4. No target code executed.
 * Tailcall pseudo-intrinsics preserve unknown ABI registers; not buildable source.
 */

/* Analyst-recovered, partial layouts for this dump; offset evidence is in .rea.asm.
 * Field names are descriptive hypotheses, not recovered debug symbols. */
#include <stdint.h>
#include <stddef.h>
typedef uint8_t undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef uint64_t undefined8;
typedef uint8_t byte;
typedef uint32_t uint;
typedef uint64_t ulong;
typedef void code(void);
struct recovered_thread;
struct recovered_process;
struct recovered_cred {
    uint8_t unknown_00[0x58];
    uint64_t authid;                   /* +0x58: exact caller identity comparison */
    uint64_t capabilities;             /* +0x60: masked in sys_587 */
    uint8_t unknown_68[0x18];
    uint64_t policy_flags;             /* +0x80: tested by target policy helper */
    uint8_t unknown_88[0x58];
};
struct recovered_pmc_context {
    uint8_t unknown_00[0x160];
    uint64_t event_select[6];          /* +0x160..0x188; even MSR bank */
    uint64_t counter_value[6];         /* +0x190..0x1b8; odd MSR bank */
};
struct recovered_thread {
    void *lock_object;                /* +0x000; unlock uses lock_object+0x18 */
    struct recovered_process *proc;    /* +0x008 */
    struct recovered_thread *next;     /* +0x010 */
    uint8_t unknown_18[0x128];
    struct recovered_cred *cred;       /* +0x140 */
    uint8_t unknown_148[0x238];
    uint32_t pmc_state;                /* +0x380; enabled and pending bits */
    uint8_t unknown_384[0x74];
    struct recovered_pmc_context *pmc; /* +0x3f8; broader PCB/MD object */
    uint32_t scheduling_state;         /* +0x400; running case ==4 */
    uint8_t unknown_404[4];
    uint64_t retval[2];                /* +0x408; second slot inferred ABI */
    uint8_t unknown_418[0x48];
    void *trap_frame;                  /* +0x460 */
    uint8_t unknown_468[0xbc];
    uint32_t cpu_id;                   /* +0x524 */
};
struct recovered_filedesc {
    uint8_t unknown_00[0x10];
    void *root_object;                 /* +0x10: compared to global root */
    uint8_t unknown_18[0x28];
    uint8_t lock[1];                   /* +0x40: opaque, extent unknown */
};
struct recovered_process {
    uint8_t unknown_00[0x10];
    struct recovered_thread *threads;  /* +0x010 */
    uint8_t unknown_18[0x28];
    struct recovered_cred *cred;       /* +0x040 */
    struct recovered_filedesc *fd;      /* +0x048 */
    uint8_t unknown_50[0x6c];
    uint32_t pid;                      /* +0x0bc */
    uint8_t unknown_c0[0x88];
    uint8_t lock[0xb8];                /* +0x148: padding extent only */
    void *vmspace;                     /* +0x200; map-like structure */
    uint8_t unknown_208[0x398];
    uint64_t image_range_start;        /* +0x5a0 */
    uint64_t image_range_end;          /* +0x5a8 */
    uint8_t unknown_5b0[0x14];
    uint32_t budget_id;                /* +0x5c4: semantic name tentative */
    uint8_t unknown_5c8[0xc];
    uint32_t compatibility_level;      /* +0x5d4 */
    uint8_t unknown_5d8[0x6a9];
    uint8_t extended_vm_query;         /* +0xc81 */
};
/* Syscall argument slots are eight bytes, even where only a low uint32 is read. */
struct selector_args { int32_t selector; uint32_t pad0; };
struct pmc_write_args {
    int32_t selector; uint32_t pad0;
    uint32_t index; uint32_t pad1;
    uint64_t value;
};
struct pmc_read_args {
    int32_t tid; uint32_t pad0;
    uint32_t index; uint32_t pad1;
    uint64_t *user_value;
};
struct vm_query_args {
    uint64_t address;
    uint32_t flags; uint32_t pad0;
    void *user_record;
    uint32_t user_size; uint32_t pad1;
};
struct budget_args { uint32_t id; uint32_t pad0; };
struct credential_query_args {
    int32_t pid; uint32_t pad0;
    void *user_record;
};
struct credential_query_record {
    uint64_t authid;                   /* copied from cred+0x58 */
    uint64_t capabilities;             /* copied from cred+0x60 */
    uint8_t remaining[0x78];           /* 0x88-byte total */
};
struct vm_query_record {
    uint64_t word00, word08, word10, word18;
    uint8_t flags;                     /* +0x20 */
    uint8_t name[0x20];                /* +0x21; explicit copy in slow path */
    uint8_t word41;
    uint8_t unknown42[6];              /* 0x48 bytes; meanings depend on helper */
};
struct vm_query_compact_record { uint64_t words[3]; }; /* 0x18 bytes */
/* REA's original decompiler text below retains its own generated parameter types.
 * Use these layouts as an offset/type overlay, not as assertions of original names.
 * local arrays/scalars split by Ghidra can belong to larger records (notably 0x88).
 * All Ghidra pseudocode is non-source and is not promised to compile. */


/* ANALYST SIGNATURE OVERLAY: int sys_566(struct recovered_thread *td, const struct pmc_write_args *uap); */

/* param_1 -> td; param_2 -> uap. plVar[0x70] is td+0x380,
 * plVar[0x7f] is td+0x3f8, and plVar[2] is td+0x10. */


/* ANALYST TYPED RECONSTRUCTION OF VALIDATED STATE OPERATIONS.
 * Full entry control flow is preserved in verbatim REA text below. */
/* Accepted iff uint32 subtraction wraps to >=0xfffffff9. */
int recovered_566_validate(uint32_t i) {
    return ((uint32_t)(i - 6) < UINT32_C(0xfffffff9)) ? 22 : 0;
}
/* Original selection/locking surrounds this operation. */
void recovered_566_thread_update(struct recovered_thread *t, uint32_t i, uint64_t v) {
    if (i == UINT32_MAX) {
        for (uint32_t j = 0; j < 6; ++j) t->pmc->counter_value[j] = v;
    } else t->pmc->counter_value[i] = v; /* validated i <= 5 */
    if (t->pmc_state == 1) apply_counter_state_at_0x602e80(t);
    else thread_unlock_at_0x4c7520((uint8_t *)t->lock_object + 0x18);
}


/* ===== PRIMARY IMPLEMENTATION: VERBATIM REA/GHIDRA OUTPUT ===== */


/* Primary RVA 0x603710; body 0x603710..0x603839, 0x603840..0x603887, 0x603890..0x6039c2
 * Evidence ev_8b4798d2230aabe4c24a67e9b3ce6e16b78633c1b5926c604669fd5464b2fb9b; generated signature undefined sys_566()
 * Warnings in the text are retained; halt_baddata may be an unmapped-call artifact.
 */

undefined8 sys_566(long param_1,int *param_2)

{
  uint uVar1;
  long lVar2;
  int iVar3;
  int iVar4;
  long lVar5;
  long *plVar6;
  undefined8 uVar7;
  
  uVar1 = param_2[2];
  if (uVar1 - 6 < 0xfffffff9) {
    return 0x16;
  }
  iVar4 = *param_2;
  uVar7 = *(undefined8 *)(param_2 + 4);
  if (iVar4 - 1U < 99999) {
    iVar3 = sub_00609020(*(undefined8 *)(param_1 + 0x140));
    if (iVar3 == 0) {
      return 3;
    }
    lVar5 = func_0x0053c170(iVar4);
    if (lVar5 == 0) {
      return 3;
    }
    iVar4 = sub_00609890(*(undefined8 *)(*(long *)(lVar5 + 0x10) + 0x140));
    if (iVar4 == 0) {
      uVar7 = 1;
      goto LAB_0060399f;
    }
  }
  else {
    lVar5 = *(long *)(param_1 + 8);
    if (iVar4 != 0) {
      plVar6 = (long *)func_0x00b92420(iVar4,*(undefined4 *)(lVar5 + 0xbc));
      if (plVar6 == (long *)0x0) {
        return 3;
      }
      lVar2 = plVar6[0x7f];
      func_0x004c78b0(plVar6,0,0x12ab551,0x254);
      if (uVar1 == 0xffffffff) {
        *(undefined8 *)(plVar6[0x7f] + 400) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x198) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1a0) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1a8) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1b0) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1b8) = uVar7;
        iVar4 = (int)plVar6[0x70];
      }
      else {
        *(undefined8 *)(lVar2 + 400 + (ulong)uVar1 * 8) = uVar7;
        iVar4 = (int)plVar6[0x70];
      }
      if (iVar4 == 1) {
        sub_00602e80(plVar6);
        uVar7 = 0;
      }
      else {
        uVar7 = 0;
        sub_004c7520(*plVar6 + 0x18,0,0,0);
      }
      goto LAB_0060399f;
    }
    func_0x004c6a00(lVar5 + 0x148,0,0,0);
  }
  plVar6 = *(long **)(lVar5 + 0x10);
  if (plVar6 == (long *)0x0) {
    uVar7 = 0;
  }
  else {
    do {
      lVar2 = plVar6[0x7f];
      func_0x004c78b0(plVar6,0,0x12ab551,0x26d);
      if (uVar1 == 0xffffffff) {
        *(undefined8 *)(plVar6[0x7f] + 400) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x198) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1a0) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1a8) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1b0) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1b8) = uVar7;
        if ((int)plVar6[0x70] != 1) goto LAB_006038f2;
LAB_00603840:
        sub_00602e80(plVar6);
      }
      else {
        *(undefined8 *)(lVar2 + 400 + (ulong)uVar1 * 8) = uVar7;
        if ((int)plVar6[0x70] == 1) goto LAB_00603840;
LAB_006038f2:
        sub_004c7520(*plVar6 + 0x18,0,0,0);
      }
      plVar6 = (long *)plVar6[2];
    } while (plVar6 != (long *)0x0);
    uVar7 = 0;
  }
LAB_0060399f:
  func_0x004c6fa0(lVar5 + 0x148,0,0,0);
  return uVar7;
}




/* Supporting function RVA 0x26d0a8; body 0x26d0a8..0x26d0ac
 * Evidence ev_cacb14c773958097224608dce8db8933e220ebdd69559b1e20a0429dbd5661b4; generated signature undefined sub_00609020()
 * Warnings in the text are retained; halt_baddata may be an unmapped-call artifact.
 */

bool sub_00609020(long param_1)

{
  return *(long *)(param_1 + 0x58) == 0x4800000000010003;
}




/* Supporting function RVA 0x609020; body 0x609020..0x609038
 * Evidence ev_f37c8b7b7e43ac4e495bfd1f32694fbc53971c02db97dedd189b3007d324ada8; generated signature undefined sub_00609020()
 * Warnings in the text are retained; halt_baddata may be an unmapped-call artifact.
 */

bool sub_00609020(long param_1)

{
  return *(long *)(param_1 + 0x58) == 0x4800000000010003;
}




/* Supporting function RVA 0x609890; body 0x609890..0x6098e8
 * Evidence ev_cf997376134556e69858d41a13607de35b3552543fc005ba69f6ad64519cf345; generated signature undefined sub_00609890()
 * Warnings in the text are retained; halt_baddata may be an unmapped-call artifact.
 */

undefined8 sub_00609890(long param_1)

{
  int iVar1;
  
  if ((*(ulong *)(param_1 + 0x80) & 0x1000000) == 0) {
    if ((*(ulong *)(param_1 + 0x80) & 0x2000000) != 0) {
      return 1;
    }
    iVar1 = func_0x005a4fe0();
    if (iVar1 == 1) {
      return 1;
    }
    if ((*(byte *)(param_1 + 0x83) & 1) == 0) {
      return 0;
    }
  }
  iVar1 = func_0x005a50c0();
  if (iVar1 != 1) {
    return 0;
  }
  return 1;
}




/* Supporting function RVA 0x602d40; body 0x602d40..0x602ddd
 * Evidence ev_777ffef07c7c967536b4db93320e5efe58e1a28c21bffe9e90d9ffc3b6b95cf2; generated signature undefined sub_00602d40()
 * Warnings in the text are retained; halt_baddata may be an unmapped-call artifact.
 */

void sub_00602d40(long *param_1)

{
  byte bVar1;
  long lVar2;
  long *in_GS_OFFSET;
  
  if ((int)param_1[0x80] == 4) {
    if (param_1 != (long *)*in_GS_OFFSET) {
      *(byte *)(param_1 + 0x70) = *(byte *)(param_1 + 0x70) | 2;
      sub_004c7520(*param_1 + 0x18,0,0,0);
      func_0x004c7190(0x3d0e908,0,0,0);
      func_0x0081e4d0(*(undefined4 *)((long)param_1 + 0x524),4);
      bVar1 = *(byte *)(param_1 + 0x70);
      while ((bVar1 & 6) != 0) {
        bVar1 = *(byte *)(param_1 + 0x70);
      }
      lVar2 = 0x3d0e908;
      goto LAB_00602dcf;
    }
    sub_00602830(param_1);
  }
  lVar2 = *param_1 + 0x18;
LAB_00602dcf:
  sub_004c7520(lVar2,0,0,0);
  return;
}




/* Supporting function RVA 0x602de0; body 0x602de0..0x602e7d
 * Evidence ev_cc04289dffa60dd0b78291d10a50b94ca694e92ceeba0ac9dfb74520951cd9a4; generated signature undefined sub_00602de0()
 * Warnings in the text are retained; halt_baddata may be an unmapped-call artifact.
 */

void sub_00602de0(long *param_1)

{
  byte bVar1;
  long lVar2;
  long *in_GS_OFFSET;
  
  if ((int)param_1[0x80] == 4) {
    if (param_1 != (long *)*in_GS_OFFSET) {
      *(byte *)(param_1 + 0x70) = *(byte *)(param_1 + 0x70) | 4;
      sub_004c7520(*param_1 + 0x18,0,0,0);
      func_0x004c7190(0x3d0e908,0,0,0);
      func_0x0081e4d0(*(undefined4 *)((long)param_1 + 0x524),5);
      bVar1 = *(byte *)(param_1 + 0x70);
      while ((bVar1 & 6) != 0) {
        bVar1 = *(byte *)(param_1 + 0x70);
      }
      lVar2 = 0x3d0e908;
      goto LAB_00602e6f;
    }
    sub_006029e0(param_1);
  }
  lVar2 = *param_1 + 0x18;
LAB_00602e6f:
  sub_004c7520(lVar2,0,0,0);
  return;
}




/* Supporting function RVA 0x602e80; body 0x602e80..0x602fd1
 * Evidence ev_7ffd3e988b2a2120ce48cb855526d900dd9302d395babb6457aef65704a91575; generated signature undefined sub_00602e80()
 * Warnings in the text are retained; halt_baddata may be an unmapped-call artifact.
 */

void sub_00602e80(long *param_1)

{
  byte bVar1;
  long lVar2;
  long *in_GS_OFFSET;
  
  if ((int)param_1[0x80] == 4) {
    if (param_1 != (long *)*in_GS_OFFSET) {
      *(byte *)(param_1 + 0x70) = *(byte *)(param_1 + 0x70) | 2;
      sub_004c7520(*param_1 + 0x18,0,0,0);
      func_0x004c7190(0x3d0e908,0,0,0);
      func_0x0081e4d0(*(undefined4 *)((long)param_1 + 0x524),6);
      bVar1 = *(byte *)(param_1 + 0x70);
      while ((bVar1 & 6) != 0) {
        bVar1 = *(byte *)(param_1 + 0x70);
      }
      lVar2 = 0x3d0e908;
      goto LAB_00602fc3;
    }
    wrmsr(0xc0010201,*(undefined8 *)(param_1[0x7f] + 400));
    wrmsr(0xc0010203,*(undefined8 *)(param_1[0x7f] + 0x198));
    wrmsr(0xc0010205,*(undefined8 *)(param_1[0x7f] + 0x1a0));
    wrmsr(0xc0010207,*(undefined8 *)(param_1[0x7f] + 0x1a8));
    wrmsr(0xc0010209,*(undefined8 *)(param_1[0x7f] + 0x1b0));
    wrmsr(0xc001020b,*(undefined8 *)(param_1[0x7f] + 0x1b8));
  }
  lVar2 = *param_1 + 0x18;
LAB_00602fc3:
  sub_004c7520(lVar2,0,0,0);
  return;
}




/* Supporting function RVA 0x602830; body 0x602830..0x602985
 * Evidence ev_410c05c32d0ec7d9a4b7820b7aa9ea80be82c4204bd63242e7c4fe0308d18673; generated signature undefined sub_00602830()
 * Warnings in the text are retained; halt_baddata may be an unmapped-call artifact.
 */

void sub_00602830(long param_1)

{
  wrmsr(0xc0010201,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 400));
  wrmsr(0xc0010203,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x198));
  wrmsr(0xc0010205,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x1a0));
  wrmsr(0xc0010207,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x1a8));
  wrmsr(0xc0010209,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x1b0));
  wrmsr(0xc001020b,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x1b8));
  wrmsr(0xc0010200,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x160));
  wrmsr(0xc0010202,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x168));
  wrmsr(0xc0010204,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x170));
  wrmsr(0xc0010206,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x178));
  wrmsr(0xc0010208,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x180));
  wrmsr(0xc001020a,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x188));
  return;
}




/* Supporting function RVA 0x6029e0; body 0x6029e0..0x602b41
 * Evidence ev_b49ab98fef4e9a8f7eb7dae4291a618ae622ab1a44e4f8a9f9357c124fe25e76; generated signature undefined sub_006029e0()
 * Warnings in the text are retained; halt_baddata may be an unmapped-call artifact.
 */

void sub_006029e0(long param_1)

{
  undefined8 uVar1;
  
  wrmsr(0xc0010200,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x160));
  wrmsr(0xc0010202,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x168));
  wrmsr(0xc0010204,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x170));
  wrmsr(0xc0010206,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x178));
  wrmsr(0xc0010208,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x180));
  wrmsr(0xc001020a,*(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x188));
  uVar1 = rdmsr(0xc0010201);
  *(undefined8 *)(*(long *)(param_1 + 0x3f8) + 400) = uVar1;
  uVar1 = rdmsr(0xc0010203);
  *(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x198) = uVar1;
  uVar1 = rdmsr(0xc0010205);
  *(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x1a0) = uVar1;
  uVar1 = rdmsr(0xc0010207);
  *(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x1a8) = uVar1;
  uVar1 = rdmsr(0xc0010209);
  *(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x1b0) = uVar1;
  uVar1 = rdmsr(0xc001020b);
  *(undefined8 *)(*(long *)(param_1 + 0x3f8) + 0x1b8) = uVar1;
  return;
}




/* ===== COMPLETE SUPPLIED WINDOW: NORMALIZED TRAMPOLINE PSEUDOCODE =====
 * Ghidra reports many unmapped destinations as halt_baddata(). That is a
 * decompiler artifact: each verified instruction is JMP rel32. The explicit
 * tailcall form below is analyst normalization of the REA assembly, with
 * target address calculated from the original bytes. It does not claim to
 * decompile unavailable destination bodies or infer their argument lists.
 * Offset-zero entry is this syscall. The remaining 511 entries are neighbors.
 */

/* file+0x000, RVA 0x265de0; ev_5617792a803d818f5f4a5c74a6fbc633c296f47af34e63e1faa3573b20bb85cf */
void trampoline_00265de0(void) { REA_TAILCALL_RVA(0x603710); }

/* file+0x008, RVA 0x265de8; ev_383826ccab055f3f935de2500ac3d19be21f0b090424b408a67ad22c5fb42f40 */
void trampoline_00265de8(void) { REA_TAILCALL_RVA(0x6039d0); }

/* file+0x010, RVA 0x265df0; ev_8b5dd4b879288fc122a3f23501d9f821424d69512f9e26345078bbcc054bf26e */
void trampoline_00265df0(void) { REA_TAILCALL_RVA(0xabac50); }

/* file+0x018, RVA 0x265df8; ev_76ea25a5ada651efb92c4b69978000171c17a5fe0dcc61b85aea388632038fd3 */
void trampoline_00265df8(void) { REA_TAILCALL_RVA(0x8fc610); }

/* file+0x020, RVA 0x265e00; ev_98736a3d03d36195a516784f936b792161411c6f8f98f41feed45145e9277537 */
void trampoline_00265e00(void) { REA_TAILCALL_RVA(0x4e1a70); }

/* file+0x028, RVA 0x265e08; ev_efa8692a6e9c16f11333028b24e67f2e944a894543ac6f2c19c27cb0bf7a4a99 */
void trampoline_00265e08(void) { REA_TAILCALL_RVA(0xabc5f0); }

/* file+0x030, RVA 0x265e10; ev_dabdcb541ceca71314834d2d7ab4b9b3c46f5f2db22380aa73fb2628c2c3dc8b */
void trampoline_00265e10(void) { REA_TAILCALL_RVA(0xa367e0); }

/* file+0x038, RVA 0x265e18; ev_d1f525ee3129c8a4ad352daa767b5b75cfc569dbf68972c407d2b066a5f86616 */
void trampoline_00265e18(void) { REA_TAILCALL_RVA(0xca0630); }

/* file+0x040, RVA 0x265e20; ev_597e0cbd10cc586b0c9ad6238db67a0909fd39b0289b5b6dcd6d8eb18eb992a2 */
void trampoline_00265e20(void) { REA_TAILCALL_RVA(0xa368e0); }

/* file+0x048, RVA 0x265e28; ev_c4109942ee68e80fae151b1edffee2384ff7bc3c4d73b62ff35054f5d32a289c */
void trampoline_00265e28(void) { REA_TAILCALL_RVA(0x72ecc0); }

/* file+0x050, RVA 0x265e30; ev_257d1d7794521f666262b1521f408c3f4b9196a300250d839255fecb561c3cbb */
void trampoline_00265e30(void) { REA_TAILCALL_RVA(0x4f7370); }

/* file+0x058, RVA 0x265e38; ev_f2c49384cb97de40881bbc07889cfeaf40a8847921fe154140904a7de3d390cd */
void trampoline_00265e38(void) { REA_TAILCALL_RVA(0xa36b00); }

/* file+0x060, RVA 0x265e40; ev_b9c280511e484a33bba5afdb5bb70bf33ce06be39907e4b72039a4bedefc1272 */
void trampoline_00265e40(void) { REA_TAILCALL_RVA(0xa36b90); }

/* file+0x068, RVA 0x265e48; ev_9093d82ce5854b9034d4f10045c0ebb7ce55843461b0eca46ea7d457aae631a1 */
void trampoline_00265e48(void) { REA_TAILCALL_RVA(0xabc710); }

/* file+0x070, RVA 0x265e50; ev_2816b732f0fef454b8aa0bd37115f5abd72469678d25b6d778429085b60de99a */
void trampoline_00265e50(void) { REA_TAILCALL_RVA(0x5a7f60); }

/* file+0x078, RVA 0x265e58; ev_770e256aee662cd771acf934689abeefc4307a1eb757a2a933606bf2fc845035 */
void trampoline_00265e58(void) { REA_TAILCALL_RVA(0xa36bc0); }

/* file+0x080, RVA 0x265e60; ev_2f10cba8e34f75d5ac6f6f54492b6bb83d763874ff0625fd1991f132739a95b0 */
void trampoline_00265e60(void) { REA_TAILCALL_RVA(0xabca10); }

/* file+0x088, RVA 0x265e68; ev_bab9dcaded8532eab81a7bea9d75244b3d8b21832a1f2d3597a9a4513b720db0 */
void trampoline_00265e68(void) { REA_TAILCALL_RVA(0xabcc00); }

/* file+0x090, RVA 0x265e70; ev_c753e26506e0b8513107059e9efc53d7f3531ae2e8982e4ec461bfc795cf22e6 */
void trampoline_00265e70(void) { REA_TAILCALL_RVA(0x438c90); }

/* file+0x098, RVA 0x265e78; ev_ac290194ac6cd87fdf648dbff5d22d77f2112633a89da065cf714a764cb9f3c9 */
void trampoline_00265e78(void) { REA_TAILCALL_RVA(0x8d2570); }

/* file+0x0a0, RVA 0x265e80; ev_71af1ed7dff3724f6192a9b22326373b14914e1f822b3b3a3ff26e68d1c925a6 */
void trampoline_00265e80(void) { REA_TAILCALL_RVA(0xabd0f0); }

/* file+0x0a8, RVA 0x265e88; ev_02301b94e7586d5bbd971396dddee058d61b115255a03a2e2bbde9c2236bc70d */
void trampoline_00265e88(void) { REA_TAILCALL_RVA(0xa37650); }

/* file+0x0b0, RVA 0x265e90; ev_fca97efe181dc3bf8e90a17892a4381296b30306b38ce3a9dd926fb2630e81aa */
void trampoline_00265e90(void) { REA_TAILCALL_RVA(0xabd430); }

/* file+0x0b8, RVA 0x265e98; ev_5ad21d951e9519613cf9ee4d4c8d658f43b4d532eaa7358b99beac689ffcb06e */
void trampoline_00265e98(void) { REA_TAILCALL_RVA(0x7dcd40); }

/* file+0x0c0, RVA 0x265ea0; ev_1f0991aff32537acc62b1569ba8603eae9c02b7736f03acaa4adbfc1eba6bdd8 */
void trampoline_00265ea0(void) { REA_TAILCALL_RVA(0x8d25a0); }

/* file+0x0c8, RVA 0x265ea8; ev_fb2d4e54fe45bd638b55145b497b13e93b6a273088a0190caf55db32288aa980 */
void trampoline_00265ea8(void) { REA_TAILCALL_RVA(0xabd4f0); }

/* file+0x0d0, RVA 0x265eb0; ev_fe2dfac522fbe82b7015bd8689bc55c2858a2ae907b2d392784ab83e1005109f */
void trampoline_00265eb0(void) { REA_TAILCALL_RVA(0x603c90); }

/* file+0x0d8, RVA 0x265eb8; ev_2f9bb31987d8f9950e65a633f405ed5cc79c54af580779c737b0e0d0491e52a7 */
void trampoline_00265eb8(void) { REA_TAILCALL_RVA(0x604cf0); }

/* file+0x0e0, RVA 0x265ec0; ev_7724fd06f065fd82fd0e2d26cfc83ca6fc7a61fe2555037b419d385c9251b765 */
void trampoline_00265ec0(void) { REA_TAILCALL_RVA(0x4a2850); }

/* file+0x0e8, RVA 0x265ec8; ev_bfb6277d9521c616e8de5efb7ab0ce45aaa4f01337cf4d8dda34fca26a2fcbd9 */
void trampoline_00265ec8(void) { REA_TAILCALL_RVA(0xabd540); }

/* file+0x0f0, RVA 0x265ed0; ev_8abd61310212a66ee7fffc7a555d7a2ed9282bd3d6b5a1303e276d232ee21fd0 */
void trampoline_00265ed0(void) { REA_TAILCALL_RVA(0x91c640); }

/* file+0x0f8, RVA 0x265ed8; ev_9c60e50cfe4a554f1caacb887b24ad9f1ad4b255d4c55f1ccc4bdeb1513143be */
void trampoline_00265ed8(void) { REA_TAILCALL_RVA(0x91cc70); }

/* file+0x100, RVA 0x265ee0; ev_94e250f3208879235eea4b468787a295a683a558491f964bfbcd318bc3091372 */
void trampoline_00265ee0(void) { REA_TAILCALL_RVA(0x438e30); }

/* file+0x108, RVA 0x265ee8; ev_b0b82678695f6ab73ce8861b5c632af4cb7262a44e85d653ff4ef249d8e9d10b */
void trampoline_00265ee8(void) { REA_TAILCALL_RVA(0x439070); }

/* file+0x110, RVA 0x265ef0; ev_69d307f8a8983141fdbae5e9ff1a9e14a55ed033c48541d9b1e2a16c93d04e81 */
void trampoline_00265ef0(void) { REA_TAILCALL_RVA(0x439150); }

/* file+0x118, RVA 0x265ef8; ev_344e003f74c2408ae339d15f5efe04578a58f70fbe8f11b62af792f5310ae403 */
void trampoline_00265ef8(void) { REA_TAILCALL_RVA(0x4393a0); }

/* file+0x120, RVA 0x265f00; ev_4b1ca9e206a8d5aa9bde5b434c38054a956ca7ed220b9283b2e0c253779b5a85 */
void trampoline_00265f00(void) { REA_TAILCALL_RVA(0x6be4d0); }

/* file+0x128, RVA 0x265f08; ev_930061c5bd3d56a066be26f0b3e4563c3aac739b068ef6622dea17eb242a4ed2 */
void trampoline_00265f08(void) { REA_TAILCALL_RVA(0xabd930); }

/* file+0x130, RVA 0x265f10; ev_d1170e018541f9e2c499217cb8583c69a7acdeb07e4b750af7e9cfa8de058194 */
void trampoline_00265f10(void) { REA_TAILCALL_RVA(0x6be5c0); }

/* file+0x138, RVA 0x265f18; ev_91c0751fccea417587657924be4026b0fb8f0eed2cb0d4789f8922bcf221c185 */
void trampoline_00265f18(void) { REA_TAILCALL_RVA(0x6be800); }

/* file+0x140, RVA 0x265f20; ev_f2b3433066aeb3aa3fdf74ef767ebfb15d6f53fa60af7f975224d5190975c570 */
void trampoline_00265f20(void) { REA_TAILCALL_RVA(0xa90e10); }

/* file+0x148, RVA 0x265f28; ev_9090e9c45fd819862cba2ac89cd3c73c446c2b455db61574953d62d91500fd56 */
void trampoline_00265f28(void) { REA_TAILCALL_RVA(0x4a2de0); }

/* file+0x150, RVA 0x265f30; ev_b8bf3bba1ac46efbe5d057be9f760fb196a6cc7cd8cd9f12ac1dfbca073c896b */
void trampoline_00265f30(void) { REA_TAILCALL_RVA(0xabdad0); }

/* file+0x158, RVA 0x265f38; ev_06378a6848819350ddcc20cb791da91d907629ea34d992343955bafe64e002b9 */
void trampoline_00265f38(void) { REA_TAILCALL_RVA(0xa37660); }

/* file+0x160, RVA 0x265f40; ev_0165fcc832ed534dcf89a13a4e32b7175145c97ca9f9dd03102a6818227f1e21 */
void trampoline_00265f40(void) { REA_TAILCALL_RVA(0xabe1c0); }

/* file+0x168, RVA 0x265f48; ev_4b84f5b76775251e86dac00f6309bcdd859182c9d0befd1010a411b9f1beab6a */
void trampoline_00265f48(void) { REA_TAILCALL_RVA(0xabe7b0); }

/* file+0x170, RVA 0x265f50; ev_9126d37972a6c96a8294b98ff4652607c429908d1fc6a5a9ffe6358b05a774c1 */
void trampoline_00265f50(void) { REA_TAILCALL_RVA(0x9f81f0); }

/* file+0x178, RVA 0x265f58; ev_21efe387cfc28dad90662d4bf0313ed9555251cbaec5b323c5319833af58d618 */
void trampoline_00265f58(void) { REA_TAILCALL_RVA(0xbe9510); }

/* file+0x180, RVA 0x265f60; ev_08dc47d76f8c663586037873aa416c3074bf4a2f3f78ded6c0b4f398782601ed */
void trampoline_00265f60(void) { REA_TAILCALL_RVA(0x9a7d10); }

/* file+0x188, RVA 0x265f68; ev_a90be405433673dfc4f63827591d35d0568a95ecf20cf7f00bd8bb9a381bacc0 */
void trampoline_00265f68(void) { REA_TAILCALL_RVA(0x9a9560); }

/* file+0x190, RVA 0x265f70; ev_4e4fa9389794acf72e3902ac2db24cdfa64f6aac8c19ac4277a0b1d41dbc3f74 */
void trampoline_00265f70(void) { REA_TAILCALL_RVA(0x9a9e10); }

/* file+0x198, RVA 0x265f78; ev_20c59410f91d73a78016bddceb8f743ef74d81970a5fd980886541d502e64d00 */
void trampoline_00265f78(void) { REA_TAILCALL_RVA(0x9a9f40); }

/* file+0x1a0, RVA 0x265f80; ev_1eeb3a6765b6ab28787b1ddd411d2cb49aabf3739dfc4e97554f002b7cacdcdb */
void trampoline_00265f80(void) { REA_TAILCALL_RVA(0x8fb440); }

/* file+0x1a8, RVA 0x265f88; ev_6c97c19f67106a556c6c5b5cdc7380eb5a45b6d0cda7ba21d6947b4d1235ccb0 */
void trampoline_00265f88(void) { REA_TAILCALL_RVA(0x4a31a0); }

/* file+0x1b0, RVA 0x265f90; ev_81a4f4212aaa4466055222677565eb2c985c8483bd8703aaf858fa1c77b997eb */
void trampoline_00265f90(void) { REA_TAILCALL_RVA(0xabe8b0); }

/* file+0x1b8, RVA 0x265f98; ev_084bff527ef4a39646d5196c812b33c0f148f2aeeaa82b585950b01b14a0ff93 */
void trampoline_00265f98(void) { REA_TAILCALL_RVA(0x9ab1f0); }

/* file+0x1c0, RVA 0x265fa0; ev_6dee6a45800de3ddf8e9063f07e15fa0f6e770376f66c89387c8fd1fa2806456 */
void trampoline_00265fa0(void) { REA_TAILCALL_RVA(0xabb980); }

/* file+0x1c8, RVA 0x265fa8; ev_28b569c8a25d12df9ba7e7774d6e2b3dd7af2caca56732e54e5d046790fd202a */
void trampoline_00265fa8(void) { REA_TAILCALL_RVA(0x6f92e0); }

/* file+0x1d0, RVA 0x265fb0; ev_8da950bfced75a0082e8f1616c320b0c037c12c863b265c5f8e56a3ff7b51bb3 */
void trampoline_00265fb0(void) { REA_TAILCALL_RVA(0x434da0); }

/* file+0x1d8, RVA 0x265fb8; ev_f04d227ee95d69753d0a375f8302f535c9b363313807baa16580d5b86275a51d */
void trampoline_00265fb8(void) { REA_TAILCALL_RVA(0x434db0); }

/* file+0x1e0, RVA 0x265fc0; ev_8c03fa804228a9567050bb0dd34a5e56f62b89b80a4a78773a54fcb8da999183 */
void trampoline_00265fc0(void) { REA_TAILCALL_RVA(0x434dc0); }

/* file+0x1e8, RVA 0x265fc8; ev_9086a44380935d4ddc1e72e9d168c5ad2196afb6eb1ba3c7b55007c3f3e8bda4 */
void trampoline_00265fc8(void) { REA_TAILCALL_RVA(0x437d90); }

/* file+0x1f0, RVA 0x265fd0; ev_847ccdef2f047338956d9ad215f9723af49223f0d61289b62930e7a1320438ac */
void trampoline_00265fd0(void) { REA_TAILCALL_RVA(0x438280); }

/* file+0x1f8, RVA 0x265fd8; ev_4deafef3933a2a35016f001f6237e530355f9777da81e654d46da30e32dcdb54 */
void trampoline_00265fd8(void) { REA_TAILCALL_RVA(0xae6690); }

/* file+0x200, RVA 0x265fe0; ev_3a524da37b12d0ef1a0f0a91b32765c0b65dcfadc6fc9e8ca38b4b6069ccd2ee */
void trampoline_00265fe0(void) { REA_TAILCALL_RVA(0xae6580); }

/* file+0x208, RVA 0x265fe8; ev_d2af33e8df5120e03fa1c1dcccf46f4abf430aa67c5f6c5e331e0e415c8bd9d3 */
void trampoline_00265fe8(void) { REA_TAILCALL_RVA(0x4490d0); }

/* file+0x210, RVA 0x265ff0; ev_ad2742a62a6f9ed794037c2c1c45ac8dbe600c3ee49153b145b62780be2af98a */
void trampoline_00265ff0(void) { REA_TAILCALL_RVA(0xa6dc0); }

/* file+0x218, RVA 0x265ff8; ev_b8907ecb2f80219bef85d3306e781fa42b543d9e6859dbda9c88d472f569c25e */
void trampoline_00265ff8(void) { REA_TAILCALL_RVA(0x44aa70); }

/* file+0x220, RVA 0x266000; ev_6bd9f09f4f1b599a9b908725404e9dc0ea3444b77173d4dc897c03370df30d7a */
void trampoline_00266000(void) { REA_TAILCALL_RVA(0x9b6110); }

/* file+0x228, RVA 0x266008; ev_6bbc159183c650415a8665ea60b2309897a28afbb438e6100aaa019aaa12d012 */
void trampoline_00266008(void) { REA_TAILCALL_RVA(0xa7670); }

/* file+0x230, RVA 0x266010; ev_4e91e007d2a8c58133df94c59ea0e1619ebf9b52903bcecdeabbe63866fec863 */
void trampoline_00266010(void) { REA_TAILCALL_RVA(0xa7850); }

/* file+0x238, RVA 0x266018; ev_955f218e8076eac2f51a200a4ac88bb79cee5050978bbf87caaade7515f3d1cb */
void trampoline_00266018(void) { REA_TAILCALL_RVA(0xa7880); }

/* file+0x240, RVA 0x266020; ev_8177533392d244eeacb934259f2a4c1ceb799151edaa87e3dfc6a7a86e8c423b */
void trampoline_00266020(void) { REA_TAILCALL_RVA(0x452040); }

/* file+0x248, RVA 0x266028; ev_263db49e8bd9339f8856c54c48c590b3aaa1810c1857217ccd2bce30f7692f63 */
void trampoline_00266028(void) { REA_TAILCALL_RVA(0x454cc0); }

/* file+0x250, RVA 0x266030; ev_b133f9a13ee76be7b921f2edcb63a1ad815fa9518600df8ace463d8c889a249c */
void trampoline_00266030(void) { REA_TAILCALL_RVA(0x457820); }

/* file+0x258, RVA 0x266038; ev_8a4497c5b3ce9c0477e739fe847ece965b83776f84b5d8e877944fbc1c495bfd */
void trampoline_00266038(void) { REA_TAILCALL_RVA(0x46df70); }

/* file+0x260, RVA 0x266040; ev_64d7e93469ad431593402890e9ab0b07fae948b75fe427530ad12cd9c36a2cff */
void trampoline_00266040(void) { REA_TAILCALL_RVA(0x46e080); }

/* file+0x268, RVA 0x266048; ev_28691bdd3c12577b68e88ad27986ddc60f93d0399798119fa266a4b25c4d684b */
void trampoline_00266048(void) { REA_TAILCALL_RVA(0x472990); }

/* file+0x270, RVA 0x266050; ev_0a2ad0c343b0527f20845abc7f5488d48c0d032699bbe90efec2574b61083c89 */
void trampoline_00266050(void) { REA_TAILCALL_RVA(0x4733b0); }

/* file+0x278, RVA 0x266058; ev_f7dbb3891b7b4397ee1aa6b11342fefc954415654acc3e01ed7d2551d8e4a993 */
void trampoline_00266058(void) { REA_TAILCALL_RVA(0x4738b0); }

/* file+0x280, RVA 0x266060; ev_eb8e119ed0c8024021882ed76ae341fd643e43bf05134942f6d4597d5f9605fb */
void trampoline_00266060(void) { REA_TAILCALL_RVA(0x474250); }

/* file+0x288, RVA 0x266068; ev_c90a648c13ad9fe6758b5046569c522c72ba7a6010430af3cfd663273c8589ab */
void trampoline_00266068(void) { REA_TAILCALL_RVA(0x474db0); }

/* file+0x290, RVA 0x266070; ev_7292705f5f757bd3a8d058a0943d2adc7fe418affd9ce7a0a6e0d942107cf5b8 */
void trampoline_00266070(void) { REA_TAILCALL_RVA(0x47cff0); }

/* file+0x298, RVA 0x266078; ev_f9769ebcfd002461934c3e2a241343a165224919006f0e76f1b83ee412734ea2 */
void trampoline_00266078(void) { REA_TAILCALL_RVA(0x21dff0); }

/* file+0x2a0, RVA 0x266080; ev_4cc357277894a90dec4deced0ac2228345764b1eb5f60ff2ca2781f905a8e22a */
void trampoline_00266080(void) { REA_TAILCALL_RVA(0x490300); }

/* file+0x2a8, RVA 0x266088; ev_76282cfc412f5eadcd0963f9712b0759948e536c468e174f42cc996bbc9bca68 */
void trampoline_00266088(void) { REA_TAILCALL_RVA(0x490db0); }

/* file+0x2b0, RVA 0x266090; ev_30bf0b4dc11ea39b886f61c8cc8b9e38d8b6dce68dbc07593f5ea600c64e5b38 */
void trampoline_00266090(void) { REA_TAILCALL_RVA(0x497fb0); }

/* file+0x2b8, RVA 0x266098; ev_a626d61814ac5d25caacb7c2292a377680378f9267ad6eadee76f2c358939def */
void trampoline_00266098(void) { REA_TAILCALL_RVA(0x497fe0); }

/* file+0x2c0, RVA 0x2660a0; ev_d62aa94656850c5c5045010190204f5a79d1eba487a4df6bf44b469b1b8022ce */
void trampoline_002660a0(void) { REA_TAILCALL_RVA(0x498630); }

/* file+0x2c8, RVA 0x2660a8; ev_4321ccdddcf8493b64b5112e809542a6e148e727a436c96daf4fad6da738b7f3 */
void trampoline_002660a8(void) { REA_TAILCALL_RVA(0x498640); }

/* file+0x2d0, RVA 0x2660b0; ev_586444d828fd0d38d20aaec62b74a27430cb2f3457bd189c26df7aad823adcff */
void trampoline_002660b0(void) { REA_TAILCALL_RVA(0x8f7bc0); }

/* file+0x2d8, RVA 0x2660b8; ev_964252c03271ae7cbd4ef739e53b1ee292fb9f15d284b2db592338d70003dd66 */
void trampoline_002660b8(void) { REA_TAILCALL_RVA(0x8f6800); }

/* file+0x2e0, RVA 0x2660c0; ev_1cded479875880557a28c86f5a1699384fd36cff43b7468f43053846362b227e */
void trampoline_002660c0(void) { REA_TAILCALL_RVA(0x8f7420); }

/* file+0x2e8, RVA 0x2660c8; ev_6bf48bdc113673af0d4ef15b2793d148c720d3c666723cf43f848f452ef7e873 */
void trampoline_002660c8(void) { REA_TAILCALL_RVA(0x8f9f80); }

/* file+0x2f0, RVA 0x2660d0; ev_74efce4fafad65beca8c7d101ebe28297997c8d73212580290fd609a681eeaf8 */
void trampoline_002660d0(void) { REA_TAILCALL_RVA(0x5df350); }

/* file+0x2f8, RVA 0x2660d8; ev_229a779caab19b6047264811c1caada70a01e20938cddcaffd6b5783aaf40051 */
void trampoline_002660d8(void) { REA_TAILCALL_RVA(0x5df820); }

/* file+0x300, RVA 0x2660e0; ev_d0a8f0a613688ac61d45b0a6d0bbc2f6f6991138aff09d9d8705d65567e1b337 */
void trampoline_002660e0(void) { REA_TAILCALL_RVA(0xa34ce0); }

/* file+0x308, RVA 0x2660e8; ev_3be549814fa7283b472ee1ee679b330e46b8bbdc7dd1097dd823a24198377f2d */
void trampoline_002660e8(void) { REA_TAILCALL_RVA(0x5e84a0); }

/* file+0x310, RVA 0x2660f0; ev_5ee1b79764a2d6fd48fd4b22a669486532d76685d275b3ca79426b8428d45855 */
void trampoline_002660f0(void) { REA_TAILCALL_RVA(0x8f81f0); }

/* file+0x318, RVA 0x2660f8; ev_b3b7c4e61d8dd8e88ac7aceec00a3936a5d075d0dd64f143878887f9ef4a3232 */
void trampoline_002660f8(void) { REA_TAILCALL_RVA(0x8f9410); }

/* file+0x320, RVA 0x266100; ev_f9e57eb6867003bffcebec0264203c868d07d0618dbb4803a1e961f2dcae1d44 */
void trampoline_00266100(void) { REA_TAILCALL_RVA(0x8fc3f0); }

/* file+0x328, RVA 0x266108; ev_64b23c14ffa8d79c4876ece0f6d97d9aa37f742eeded3210e67262c491133975 */
void trampoline_00266108(void) { REA_TAILCALL_RVA(0x8f6c90); }

/* file+0x330, RVA 0x266110; ev_dd4d7eef2f93ef1e701ed8d9dd596b4b7688e80475b35d128f48377b60e34c8f */
void trampoline_00266110(void) { REA_TAILCALL_RVA(0xcb1a10); }

/* file+0x338, RVA 0x266118; ev_5d1b3e51d8102b7e2b2ce869aefcbd4150b57204216158a69cd1df08eb54949c */
void trampoline_00266118(void) { REA_TAILCALL_RVA(0xab83a0); }

/* file+0x340, RVA 0x266120; ev_8c1b41a919a5cfaf7997d3cdd7ea9b0a30b793e09e5d4f551fdc30f84b5a58d9 */
void trampoline_00266120(void) { REA_TAILCALL_RVA(0xab83b0); }

/* file+0x348, RVA 0x266128; ev_834b9c907ca50476c64fe3a88b3d1537b0f64c26a592a1a3b7b5a25c511b5cf9 */
void trampoline_00266128(void) { REA_TAILCALL_RVA(0x8fa1c0); }

/* file+0x350, RVA 0x266130; ev_c7667b5e2d355f6b2eec14cab7f322987223dea1611629c56c40090aeb93b11f */
void trampoline_00266130(void) { REA_TAILCALL_RVA(0x8f7b40); }

/* file+0x358, RVA 0x266138; ev_303bdd74a041b71db41c2bfe5a4c5e4482da00d0658a53101042d926e4209b8e */
void trampoline_00266138(void) { REA_TAILCALL_RVA(0x4a0960); }

/* file+0x360, RVA 0x266140; ev_2afa8be4aef9f3cac4984579fbfe0f3baed486bda28b32022234cc3751ac1eed */
void trampoline_00266140(void) { REA_TAILCALL_RVA(0x729780); }

/* file+0x368, RVA 0x266148; ev_a50e4c0750f3ae938ef14ad1aaf9cd8673aa64f347784d120cd3e5654b49decd */
void trampoline_00266148(void) { REA_TAILCALL_RVA(0x729790); }

/* file+0x370, RVA 0x266150; ev_2ba8539405364894c7f4ce7e0ccaf2c6ec887d3615df917bbd5bf522b2b7bc84 */
void trampoline_00266150(void) { REA_TAILCALL_RVA(0x7297a0); }

/* file+0x378, RVA 0x266158; ev_b689ad8b441a32446366e9b7e887f8a80d50b90d68bc9c152facf6bb10c02ddf */
void trampoline_00266158(void) { REA_TAILCALL_RVA(0x6bb590); }

/* file+0x380, RVA 0x266160; ev_c9c3c67d0cb83ac7b2b247898c5173e91ea80c8da42ce1a0f007e8f33df77d38 */
void trampoline_00266160(void) { REA_TAILCALL_RVA(0xab8da0); }

/* file+0x388, RVA 0x266168; ev_f5a7f310f0bae076a78f3566b2be30beaa6c28078bc896c16998ec183fcd13c7 */
void trampoline_00266168(void) { REA_TAILCALL_RVA(0x8fa170); }

/* file+0x390, RVA 0x266170; ev_b437ecbf0ae88984a5f44e2aa6075d3bbe209c77d855484eff998efcc51102bd */
void trampoline_00266170(void) { REA_TAILCALL_RVA(0xb7f0c0); }

/* file+0x398, RVA 0x266178; ev_c1afdcb71ed06aa4bb2df5c6fdccc8e8bd6328d9c50aa3dabaf4dba7e107252b */
void trampoline_00266178(void) { REA_TAILCALL_RVA(0xb7f100); }

/* file+0x3a0, RVA 0x266180; ev_369667e3d1b5878f797c4e88fb7c5938128e1dcbb921a32910b1219da7a76d44 */
void trampoline_00266180(void) { REA_TAILCALL_RVA(0x8f9cf0); }

/* file+0x3a8, RVA 0x266188; ev_f2a97e35bcdc33513a1b3c906b8230a5908e9efe5353dc9a929965f75b9ba36a */
void trampoline_00266188(void) { REA_TAILCALL_RVA(0x8fa740); }

/* file+0x3b0, RVA 0x266190; ev_91a6488c5ade21f35f39148f65ebcb606ef6fe30415143a3756c92faa6cecbbf */
void trampoline_00266190(void) { REA_TAILCALL_RVA(0x552b70); }

/* file+0x3b8, RVA 0x266198; ev_675d21c886bc9014e5ae310601068ee59fe85744287e6ccc1eb72277136da537 */
void trampoline_00266198(void) { REA_TAILCALL_RVA(0x552bf0); }

/* file+0x3c0, RVA 0x2661a0; ev_05e0fdaa45846751ec7faecca3809e802671242bc5ebbc0579d32da247b7e0dc */
void trampoline_002661a0(void) { REA_TAILCALL_RVA(0x552c50); }

/* file+0x3c8, RVA 0x2661a8; ev_0ff7d411090c342259a52c402d004c341a42a8d90889443bab4caf270a052366 */
void trampoline_002661a8(void) { REA_TAILCALL_RVA(0x552c80); }

/* file+0x3d0, RVA 0x2661b0; ev_c567ce7c765bf7b6492fad101ea6094825df8cbc12464f15406a0c8b88bade7a */
void trampoline_002661b0(void) { REA_TAILCALL_RVA(0x552cb0); }

/* file+0x3d8, RVA 0x2661b8; ev_7a3c2f65380639946ee70a6990e28792bae24c9d90b7e92130fb7c57abb14f90 */
void trampoline_002661b8(void) { REA_TAILCALL_RVA(0x552ce0); }

/* file+0x3e0, RVA 0x2661c0; ev_6dd402045678f515612f12e7809366ddaff571920f0f490fff83f6a35e912f28 */
void trampoline_002661c0(void) { REA_TAILCALL_RVA(0xb7e800); }

/* file+0x3e8, RVA 0x2661c8; ev_e41443ae54d6134785844e4b66fcb2ea031d3ddc59653770a3b59d1388197f2b */
void trampoline_002661c8(void) { REA_TAILCALL_RVA(0xb7ebe0); }

/* file+0x3f0, RVA 0x2661d0; ev_78402ab4e10c4dabdf0220e28ffabb3626d8d2e0472c5ed5940d4d00d4b59ef9 */
void trampoline_002661d0(void) { REA_TAILCALL_RVA(0xb7ef70); }

/* file+0x3f8, RVA 0x2661d8; ev_d5a13fd1963e39fdf37710d9a646cbf6472769b9b1253bbb0309595150410a67 */
void trampoline_002661d8(void) { REA_TAILCALL_RVA(0xc06d30); }

/* file+0x400, RVA 0x2661e0; ev_b0046a852ba4f125cd5c9a5e834e0fc7d71402d22cb65aae430eac4745b28753 */
void trampoline_002661e0(void) { REA_TAILCALL_RVA(0x792690); }

/* file+0x408, RVA 0x2661e8; ev_6b87de440a32a2ede078608709a3d12a8539aad738409f24ff9b167f641e98c1 */
void trampoline_002661e8(void) { REA_TAILCALL_RVA(0x5e8b20); }

/* file+0x410, RVA 0x2661f0; ev_4008003ed02725231ba1938ffc3d9d106de99cf25320ad26a956214b085ed2cc */
void trampoline_002661f0(void) { REA_TAILCALL_RVA(0x552d10); }

/* file+0x418, RVA 0x2661f8; ev_d3f7bd4d47f621775131a34c16f21122e88ceffe53e018e2c42e2774442c45bd */
void trampoline_002661f8(void) { REA_TAILCALL_RVA(0xb7f160); }

/* file+0x420, RVA 0x266200; ev_eb9b5b069a47e7c344a898ea585492b6c3c0f2ef1745f40d764deabd46f53d90 */
void trampoline_00266200(void) { REA_TAILCALL_RVA(0x5de250); }

/* file+0x428, RVA 0x266208; ev_890a5e9773b6eb4c478b15fde0c6ec7fba5663250c36118ed7c0437ef5c1f187 */
void trampoline_00266208(void) { REA_TAILCALL_RVA(0xa54a30); }

/* file+0x430, RVA 0x266210; ev_c6d8079c07bd16aa63a086ad27308d408919770bb88b8fd6a0735e4fca801b71 */
void trampoline_00266210(void) { REA_TAILCALL_RVA(0xa54a40); }

/* file+0x438, RVA 0x266218; ev_1937b87c2ee43445c362bfcbfc5e234caf23f60e0c155ac1015ab0319e612a02 */
void trampoline_00266218(void) { REA_TAILCALL_RVA(0xa54a50); }

/* file+0x440, RVA 0x266220; ev_86a39a7a95b91c572025cecb0ecebfaed67dc4e8ee1753ff360b65c2537c21c9 */
void trampoline_00266220(void) { REA_TAILCALL_RVA(0xa54a60); }

/* file+0x448, RVA 0x266228; ev_b9aed4968cb661336c90e05d63ab275b7c3999feb9feedbb8fbbbe9ac48a718d */
void trampoline_00266228(void) { REA_TAILCALL_RVA(0xa54a80); }

/* file+0x450, RVA 0x266230; ev_2f3638ada04f3b898bb0134d3b262c524f19e9612cd54b6237027e7f830db196 */
void trampoline_00266230(void) { REA_TAILCALL_RVA(0xa54a90); }

/* file+0x458, RVA 0x266238; ev_8be4ebb52bb7f42f7ae8819477bdacfb5dd7f8a4a69b34d0e82b1676beb8b88b */
void trampoline_00266238(void) { REA_TAILCALL_RVA(0x8f9720); }

/* file+0x460, RVA 0x266240; ev_c973092bdc094431e7514b88190d7e469a092ae1816cf11432311b2475578ce4 */
void trampoline_00266240(void) { REA_TAILCALL_RVA(0xa54ab0); }

/* file+0x468, RVA 0x266248; ev_5b41bdf69faf72309850850612ded4a01786d025148ff3dec6ac7378166c42ce */
void trampoline_00266248(void) { REA_TAILCALL_RVA(0x8f64e0); }

/* file+0x470, RVA 0x266250; ev_2640a93b3ce8653d09eb090b1f6230787f9e034d7b760c96b3d547538dee5aeb */
void trampoline_00266250(void) { REA_TAILCALL_RVA(0x8f5ef0); }

/* file+0x478, RVA 0x266258; ev_76af850bd3788b9a8fe41dbf2438dca1db46ee4b04fa9f1ad9f49a517f25f23d */
void trampoline_00266258(void) { REA_TAILCALL_RVA(0xa54a20); }

/* file+0x480, RVA 0x266260; ev_9a1be69974cc1f664faf3971a3c7a3806beefc8d778a5de8abd754bedd73b74e */
void trampoline_00266260(void) { REA_TAILCALL_RVA(0xa54a70); }

/* file+0x488, RVA 0x266268; ev_407dd521120e587db335ff6d39acad0cfcd36a189ed940280631fb61204f0ccb */
void trampoline_00266268(void) { REA_TAILCALL_RVA(0xa54aa0); }

/* file+0x490, RVA 0x266270; ev_40746a0b93aec7839afd81d59457b4f3d09498e2433c22171aef0b499b6c8831 */
void trampoline_00266270(void) { REA_TAILCALL_RVA(0x6e54d0); }

/* file+0x498, RVA 0x266278; ev_e64de48c644f7a840219c853399623eb885f51dc52ae7d5c902792e6cabd7af3 */
void trampoline_00266278(void) { REA_TAILCALL_RVA(0xb7f4b0); }

/* file+0x4a0, RVA 0x266280; ev_2b63c7d8c3b52408e1bc070022da82a34eaf3813bde9a8d77bdc3241bebf3fa4 */
void trampoline_00266280(void) { REA_TAILCALL_RVA(0x83d660); }

/* file+0x4a8, RVA 0x266288; ev_fc3dc592ee8bb13fb359b0a95a078e4e6b0270ece4a9c1fea03d2e92a16cd88a */
void trampoline_00266288(void) { REA_TAILCALL_RVA(0x83d7c0); }

/* file+0x4b0, RVA 0x266290; ev_6f00647543e9e06075ddd224bd6f777ca28385de5acd9bc3f06fb2f290d723de */
void trampoline_00266290(void) { REA_TAILCALL_RVA(0x83dab0); }

/* file+0x4b8, RVA 0x266298; ev_0ce2c60da7c9bcdefd8872a5d263073ca33ddaeb2b3ddedf0c81bc8c019158cb */
void trampoline_00266298(void) { REA_TAILCALL_RVA(0x83de80); }

/* file+0x4c0, RVA 0x2662a0; ev_afe899e59dfec2690eb634a8f95172c9075b4291d3e71b4bd355fa248632d865 */
void trampoline_002662a0(void) { REA_TAILCALL_RVA(0x8f9c80); }

/* file+0x4c8, RVA 0x2662a8; ev_4d9e86ca8b421920a203eb20dc65df99d46584e458ccf1d1babb1c065edca21f */
void trampoline_002662a8(void) { REA_TAILCALL_RVA(0x8fa110); }

/* file+0x4d0, RVA 0x2662b0; ev_4fd19437105a55a762fae3b35c8d28bdb88edac0c1804dd85604042383d0c051 */
void trampoline_002662b0(void) { REA_TAILCALL_RVA(0x8f91b0); }

/* file+0x4d8, RVA 0x2662b8; ev_0900495d819f1c97494375d2c86e949c2282ed596f80da7dbc13ec4815e75288 */
void trampoline_002662b8(void) { REA_TAILCALL_RVA(0x8fa4f0); }

/* file+0x4e0, RVA 0x2662c0; ev_acb55346fe900693061b23d4b0647e69bba3c82086ca6f8dfe4a98108ccd0164 */
void trampoline_002662c0(void) { REA_TAILCALL_RVA(0x8f8090); }

/* file+0x4e8, RVA 0x2662c8; ev_69e519e2446a67e2692652a979fd80f94874838ee785f5751d10a52d991a1771 */
void trampoline_002662c8(void) { REA_TAILCALL_RVA(0x8fbb80); }

/* file+0x4f0, RVA 0x2662d0; ev_9f75d8d42fae7f84590d3ecec283571d5322dec1bdc90f32ce1da50efff3d78b */
void trampoline_002662d0(void) { REA_TAILCALL_RVA(0x8f7b80); }

/* file+0x4f8, RVA 0x2662d8; ev_91b607969856883e998de038a62803f27a09390c2c4392c931dd33ca8f08c28d */
void trampoline_002662d8(void) { REA_TAILCALL_RVA(0x8f7890); }

/* file+0x500, RVA 0x2662e0; ev_12f1b038ad33ffa602ca0240700860a0759309f260fa1416557bddded7653845 */
void trampoline_002662e0(void) { REA_TAILCALL_RVA(0x8fb8a0); }

/* file+0x508, RVA 0x2662e8; ev_12e0b7c7d06d906cf96d2d8f926c3d73b0eb55f7d402c6aac7ae972c2ae05670 */
void trampoline_002662e8(void) { REA_TAILCALL_RVA(0x8f8510); }

/* file+0x510, RVA 0x2662f0; ev_b94365078e18dea9a7e16a333f08a69bb792bc25703e1c62ffbe96a23ad9005c */
void trampoline_002662f0(void) { REA_TAILCALL_RVA(0x8f8800); }

/* file+0x518, RVA 0x2662f8; ev_d0e59169b88a68afdec4f16e469e97ff4592c2ec1eb950454e964c0fbc9b9489 */
void trampoline_002662f8(void) { REA_TAILCALL_RVA(0x49b080); }

/* file+0x520, RVA 0x266300; ev_05d4338129932a542e721f4d6cad3b965880c578a3f7877b376998250390abf7 */
void trampoline_00266300(void) { REA_TAILCALL_RVA(0x49b090); }

/* file+0x528, RVA 0x266308; ev_78cbc03bc9b3ee4c80742de069a9b5c034c064cdfc7fe09b19eea827165c9955 */
void trampoline_00266308(void) { REA_TAILCALL_RVA(0x55fa50); }

/* file+0x530, RVA 0x266310; ev_9096f7261dc4fffa736db9049715d06277a822f0fbadc3001e35146c0b7c1d23 */
void trampoline_00266310(void) { REA_TAILCALL_RVA(0xc34870); }

/* file+0x538, RVA 0x266318; ev_3447ab6f6a147b49d94d9048e5c22ffdb5f81f80090d88fba7a26997bacae7ad */
void trampoline_00266318(void) { REA_TAILCALL_RVA(0x7dccf0); }

/* file+0x540, RVA 0x266320; ev_9668b9bf4fa9400fddbfd76866f4aa2f6f5ccb3634227f2d47f73eb79be89a81 */
void trampoline_00266320(void) { REA_TAILCALL_RVA(0x7dcd00); }

/* file+0x548, RVA 0x266328; ev_8e104228ee03513d2ea3bd2e3545073725d0cdb2e46edd1049f2440457c361a7 */
void trampoline_00266328(void) { REA_TAILCALL_RVA(0x7dcd10); }

/* file+0x550, RVA 0x266330; ev_5ab922fe550718bbd42344df14c22212e627e3bc30b1d87c8447b08dddfdfb6a */
void trampoline_00266330(void) { REA_TAILCALL_RVA(0x7dcd20); }

/* file+0x558, RVA 0x266338; ev_fa766b1cb748031cb07490070502db3dd5220330210c7327de0766b42e0659aa */
void trampoline_00266338(void) { REA_TAILCALL_RVA(0x7dcd30); }

/* file+0x560, RVA 0x266340; ev_6df11549f01b3d85e1173c8c5fab59e8bea1ce192a3d0308aa6d069d55f7f865 */
void trampoline_00266340(void) { REA_TAILCALL_RVA(0x5a6c90); }

/* file+0x568, RVA 0x266348; ev_d76d0291e2b3962754d6b6da9a7c655362631e6025fc77db5602abbe70d92fe1 */
void trampoline_00266348(void) { REA_TAILCALL_RVA(0x5a7300); }

/* file+0x570, RVA 0x266350; ev_8c00e50ebbc0b8f2477c7db2ae31563ab9c41a21e523b2dc58946fa44ada7fca */
void trampoline_00266350(void) { REA_TAILCALL_RVA(0x5a7610); }

/* file+0x578, RVA 0x266358; ev_144a0609a7e4b1cbf79aa4f6efbf1322e29eafbcc22d15e48ba6d581a5ea40c9 */
void trampoline_00266358(void) { REA_TAILCALL_RVA(0x5a7900); }

/* file+0x580, RVA 0x266360; ev_4d89ebadac8ed8b46af3562a68c13298a7b215636ea89b146bb05b9b2f3f8efe */
void trampoline_00266360(void) { REA_TAILCALL_RVA(0xc9c830); }

/* file+0x588, RVA 0x266368; ev_7b5be175ebf1704a2ffe52f4e546ed2e806640b3be6e20c158bbcee39ed713f3 */
void trampoline_00266368(void) { REA_TAILCALL_RVA(0x5a7f00); }

/* file+0x590, RVA 0x266370; ev_b3f95382713fc33c40c8c22030d9f0ba3e6bb5ab3b1f239e6d72e5354704218a */
void trampoline_00266370(void) { REA_TAILCALL_RVA(0x5a8070); }

/* file+0x598, RVA 0x266378; ev_b007a682aaa438d530206a3d9b89586d18fccdafe3ebfa55c9a4e21fdd7df99c */
void trampoline_00266378(void) { REA_TAILCALL_RVA(0xbe8480); }

/* file+0x5a0, RVA 0x266380; ev_1fa2b1173f18e8b42185881c20ecd46994e8e93ee8a01f305eb531c1f3451e67 */
void trampoline_00266380(void) { REA_TAILCALL_RVA(0x49b0a0); }

/* file+0x5a8, RVA 0x266388; ev_17af925d0a37b28003f1a7b9d91933096116bca7f0f28f15b1d9c059eb07c981 */
void trampoline_00266388(void) { REA_TAILCALL_RVA(0x49b0c0); }

/* file+0x5b0, RVA 0x266390; ev_91eb5bf0d2d400b12aced3c06dc465cae881234fc1c10309f9cde2d3613c9afd */
void trampoline_00266390(void) { REA_TAILCALL_RVA(0x49b0d0); }

/* file+0x5b8, RVA 0x266398; ev_1070861a6385e7363011a177c2b8b63ddd0a4cab13d5d2ba62a5f645880c01ce */
void trampoline_00266398(void) { REA_TAILCALL_RVA(0x49b0e0); }

/* file+0x5c0, RVA 0x2663a0; ev_36dfeb8d0b9dad60259fbb73524d04ba0eb9331664c205ff92f56afa0d11b019 */
void trampoline_002663a0(void) { REA_TAILCALL_RVA(0x49b0f0); }

/* file+0x5c8, RVA 0x2663a8; ev_6b8a939a0c4ca6683f2d74cc333ebeff52ff9481483eca95d68519c3d89be817 */
void trampoline_002663a8(void) { REA_TAILCALL_RVA(0x530720); }

/* file+0x5d0, RVA 0x2663b0; ev_9b10eef7b23045ba6c36687e48b791963a0ff9a68764de3d86a2870a4aef273b */
void trampoline_002663b0(void) { REA_TAILCALL_RVA(0x531670); }

/* file+0x5d8, RVA 0x2663b8; ev_48caedbb43feea21870a0b7557c142fdf208f6ddf1a378941ca4a59206f8c198 */
void trampoline_002663b8(void) { REA_TAILCALL_RVA(0x8f96f0); }

/* file+0x5e0, RVA 0x2663c0; ev_d66104c3c28e3c89a85b920fcfc90a9e1d5c357cd1099e8240ff58bb7c457d88 */
void trampoline_002663c0(void) { REA_TAILCALL_RVA(0x531230); }

/* file+0x5e8, RVA 0x2663c8; ev_8d3c73f57d57ec1536431ee24894d5a639090edfbc085cf9cf7dd49756d6bdc2 */
void trampoline_002663c8(void) { REA_TAILCALL_RVA(0x802df0); }

/* file+0x5f0, RVA 0x2663d0; ev_f3d3fafd477f9293a2dca95dbcf6e27602284558c9305be816fa91bc486102af */
void trampoline_002663d0(void) { REA_TAILCALL_RVA(0xb7f140); }

/* file+0x5f8, RVA 0x2663d8; ev_f5bfbcfdbdb18a30d80848425c0047a9abf53cf7dd87675e64e5d204fa1f95b1 */
void trampoline_002663d8(void) { REA_TAILCALL_RVA(0xae35e0); }

/* file+0x600, RVA 0x2663e0; ev_f7bfc79c91d32af96d85d7b31df1792575ba0c3dec4abd7ad5af014086ac26b5 */
void trampoline_002663e0(void) { REA_TAILCALL_RVA(0x4eee20); }

/* file+0x608, RVA 0x2663e8; ev_b9abf8c7c484504101c3ea61aaf2d16686b2c38f3898d08aedbd5df7224f403b */
void trampoline_002663e8(void) { REA_TAILCALL_RVA(0x8fab10); }

/* file+0x610, RVA 0x2663f0; ev_44c2310c38da9b617ac2e1d1ca39ec38e8d16fdfbc525e67345bd3f560564c70 */
void trampoline_002663f0(void) { REA_TAILCALL_RVA(0x8fae30); }

/* file+0x618, RVA 0x2663f8; ev_8bb6db81465c6e3d979b6a74771c419c62d1d0c75f7aaa20d5292351bd7b7622 */
void trampoline_002663f8(void) { REA_TAILCALL_RVA(0x9c9220); }

/* file+0x620, RVA 0x266400; ev_6cb7987e1abe20ce62bfc0d23c705bf89a53df8478c876f8ee0a5c7fc7e49a4e */
void trampoline_00266400(void) { REA_TAILCALL_RVA(0x9c9100); }

/* file+0x628, RVA 0x266408; ev_c658ebb6c9f492b49a246aafdd448fb717857a03497fa80b91c5de16114a8b64 */
void trampoline_00266408(void) { REA_TAILCALL_RVA(0x642310); }

/* file+0x630, RVA 0x266410; ev_705a0da54b074058cbcde738b7851188791e292e92f77bdecb372626c335d621 */
void trampoline_00266410(void) { REA_TAILCALL_RVA(0x642820); }

/* file+0x638, RVA 0x266418; ev_be45ae836c664a4bd736fed71e1a99d6557e81873a18145a2532ffd37667a401 */
void trampoline_00266418(void) { REA_TAILCALL_RVA(0x6436e0); }

/* file+0x640, RVA 0x266420; ev_19ab1df574e27fdfc93b45b0d9109d0d817167948b215e9b32592d882167800e */
void trampoline_00266420(void) { REA_TAILCALL_RVA(0x6438d0); }

/* file+0x648, RVA 0x266428; ev_a19c508ba38dad17e51eb65f43c82d56c2262e5bfa69e545d80c227e62156d3d */
void trampoline_00266428(void) { REA_TAILCALL_RVA(0x643c60); }

/* file+0x650, RVA 0x266430; ev_134637598f2cd75181b92224d6a26fef5d5d9a2740693405fda80a68981e1726 */
void trampoline_00266430(void) { REA_TAILCALL_RVA(0x9f8290); }

/* file+0x658, RVA 0x266438; ev_633d3e671643ab07c15869b3f11ba141fd0bce50e2f0756b05509b413e20901c */
void trampoline_00266438(void) { REA_TAILCALL_RVA(0x9fbb70); }

/* file+0x660, RVA 0x266440; ev_e7cf7e1b5e2fe54e3e359b34358fb1761d3686e60a964c0f0bef7c231fd84c3a */
void trampoline_00266440(void) { REA_TAILCALL_RVA(0xa45280); }

/* file+0x668, RVA 0x266448; ev_a9d1dd06e3adf86f4f4d35ad6e7c7d375ee6b9a8cc0fc2fce3a409c4d2bb4178 */
void trampoline_00266448(void) { REA_TAILCALL_RVA(0xc87ca0); }

/* file+0x670, RVA 0x266450; ev_f30138477fba0388f6570967dd0ad14b8b16fdbc3a9278364f98d53f6de8cebc */
void trampoline_00266450(void) { REA_TAILCALL_RVA(0x9ff000); }

/* file+0x678, RVA 0x266458; ev_04d9a4a69f417dac99c6d75d273bb9bea9389739c25a994949d8ad68556f5e43 */
void trampoline_00266458(void) { REA_TAILCALL_RVA(0xa00780); }

/* file+0x680, RVA 0x266460; ev_59bfe6689cd2407cf9e033c4db10ea8a4d8bff08a650f1585e4809efbcd112ad */
void trampoline_00266460(void) { REA_TAILCALL_RVA(0xa007e0); }

/* file+0x688, RVA 0x266468; ev_9e9087b260a24cd1e30b17eca3b0709bd21a4473896ce8e1b65304729478fc3f */
void trampoline_00266468(void) { REA_TAILCALL_RVA(0xabe830); }

/* file+0x690, RVA 0x266470; ev_351da8d615c953c3c3bdba72b28242c60f183c4eff676a6a831feac7a36c04ba */
void trampoline_00266470(void) { REA_TAILCALL_RVA(0x9fcf30); }

/* file+0x698, RVA 0x266478; ev_919b7757b68b044325f4f3985ebc4bffad936e09f6d583b48809cfcc3fcd3d61 */
void trampoline_00266478(void) { REA_TAILCALL_RVA(0x5f0fc0); }

/* file+0x6a0, RVA 0x266480; ev_ec35d864c063384239ff10e15b70a91a9087b4e3c9838e01e3e0ab30ec579853 */
void trampoline_00266480(void) { REA_TAILCALL_RVA(0x8f73f0); }

/* file+0x6a8, RVA 0x266488; ev_c0e8e7e79c9860d58cb5f93b211cd9e45b9ddccc67bcb2726f7ff3de757d4bf5 */
void trampoline_00266488(void) { REA_TAILCALL_RVA(0x4f7250); }

/* file+0x6b0, RVA 0x266490; ev_325a45a277443aef0a01bc33b9ecbf1f8b23bc746ff42eb0cc588ee76d8a81b4 */
void trampoline_00266490(void) { REA_TAILCALL_RVA(0x9fdad0); }

/* file+0x6b8, RVA 0x266498; ev_4d33eab1793b96ffa7036b1707b09efd41bbf866ce6acf441ca75ec8af1b514e */
void trampoline_00266498(void) { REA_TAILCALL_RVA(0x9fddb0); }

/* file+0x6c0, RVA 0x2664a0; ev_114f5456e5f8b9b5164052394a2f669a7079b7dd065c6099b74ba66f999b15cc */
void trampoline_002664a0(void) { REA_TAILCALL_RVA(0x9fdf10); }

/* file+0x6c8, RVA 0x2664a8; ev_d23adc3942034c482f340b0f2e2a35b1238bad2f543b1eb4890f0c79853c29ec */
void trampoline_002664a8(void) { REA_TAILCALL_RVA(0x6444d0); }

/* file+0x6d0, RVA 0x2664b0; ev_de951251b1d949dfcd9beba54b2d7b87c2d06b2e155d5f3ab48317f5ecbfdba5 */
void trampoline_002664b0(void) { REA_TAILCALL_RVA(0x650fd0); }

/* file+0x6d8, RVA 0x2664b8; ev_3aab21628813fdee4e13c2e4a58db0b72dd734fc7971318ed30451cb7927213e */
void trampoline_002664b8(void) { REA_TAILCALL_RVA(0x9fea30); }

/* file+0x6e0, RVA 0x2664c0; ev_107528cdf9bfc43f6c1bbdf4d061b44e2e7abc20ba09f9d59fd30bac27f03153 */
void trampoline_002664c0(void) { REA_TAILCALL_RVA(0x4f7940); }

/* file+0x6e8, RVA 0x2664c8; ev_45ba05ad96bf8d73ff8f2002227ebffe713ac456ed4eca897e4735c475efbb6f */
void trampoline_002664c8(void) { REA_TAILCALL_RVA(0xab8ae0); }

/* file+0x6f0, RVA 0x2664d0; ev_5fe2ebab889e33e22077b2fbe43d8ca815a9d7cd7219c95565d88506e11fc3de */
void trampoline_002664d0(void) { REA_TAILCALL_RVA(0xabb660); }

/* file+0x6f8, RVA 0x2664d8; ev_1b653436719ad771d0f4bc28767da1052a5f673065dfbe98da8c16d9c4c64cfc */
void trampoline_002664d8(void) { REA_TAILCALL_RVA(0x9fe260); }

/* file+0x700, RVA 0x2664e0; ev_8f8baa9f4e8232acab354cf752d8e2c8c62463f9ffe3aa19b23069084b861760 */
void trampoline_002664e0(void) { REA_TAILCALL_RVA(0x9fe4e0); }

/* file+0x708, RVA 0x2664e8; ev_6ccc7e3752b9431b161cfcf2791073a7a4b8e6cee1b5ed32b97b9c7dac8e968d */
void trampoline_002664e8(void) { REA_TAILCALL_RVA(0x9fe630); }

/* file+0x710, RVA 0x2664f0; ev_e4180085fbd569aab9505566a6f74ffe0e526bb01a27d33fdb76a84fbea5c9b1 */
void trampoline_002664f0(void) { REA_TAILCALL_RVA(0x798330); }

/* file+0x718, RVA 0x2664f8; ev_af74aa1a874b0b086759cd52698271e9e427d23b981cc34da7f782e58c01d843 */
void trampoline_002664f8(void) { REA_TAILCALL_RVA(0xabd000); }

/* file+0x720, RVA 0x266500; ev_5e460dd4fa6d1ee8ae496bd4a4aa7435046a5e688959b81f7d5e17d42e9dabef */
void trampoline_00266500(void) { REA_TAILCALL_RVA(0xfc890); }

/* file+0x728, RVA 0x266508; ev_b6e2c30db382b84b3e42f79a723fa2f17aaee7d92f1dcf31038c6f167d476a4d */
void trampoline_00266508(void) { REA_TAILCALL_RVA(0x49f090); }

/* file+0x730, RVA 0x266510; ev_2deb094c5dd267812c2d20a519af38cc9b0403c13b9dcd03b1a85c39fe9a25b5 */
void trampoline_00266510(void) { REA_TAILCALL_RVA(0x49f200); }

/* file+0x738, RVA 0x266518; ev_4d8f93c415bd034f4f1bca6df76d977984f05070b9753b6d791bc69bcd2acf17 */
void trampoline_00266518(void) { REA_TAILCALL_RVA(0x4c0590); }

/* file+0x740, RVA 0x266520; ev_abc3d86efb0538e8cada7574a37ed0c2d793f7dff7ed8792ea679b0c0b71ce8b */
void trampoline_00266520(void) { REA_TAILCALL_RVA(0x4c05b0); }

/* file+0x748, RVA 0x266528; ev_a92a0b934a8912dc1fae3393d9c9cb992feea82a672c6123210bf7959b9c64b7 */
void trampoline_00266528(void) { REA_TAILCALL_RVA(0xa9430); }

/* file+0x750, RVA 0x266530; ev_1cf225b0e44e289c8d8e67ca773a57957efc8a11d4457d3e79c7e6119389648e */
void trampoline_00266530(void) { REA_TAILCALL_RVA(0x4ca350); }

/* file+0x758, RVA 0x266538; ev_594c5c8f2a1e0e7df849ea5df446b18d275443ec8a027debc699304e9b27b576 */
void trampoline_00266538(void) { REA_TAILCALL_RVA(0x4caa40); }

/* file+0x760, RVA 0x266540; ev_09efdcdb6d82165abeb5ddfba0893897c14bff9877f2c4123c701d808c209cb3 */
void trampoline_00266540(void) { REA_TAILCALL_RVA(0xaa510); }

/* file+0x768, RVA 0x266548; ev_e0075b684bc4497bf04db90c057069850cb08578e211d7473b30810b3fbadd89 */
void trampoline_00266548(void) { REA_TAILCALL_RVA(0x4d51d0); }

/* file+0x770, RVA 0x266550; ev_62d891c4dc8e0844d46f2afea838e3434e84678017e3051b5790425bf5e8421e */
void trampoline_00266550(void) { REA_TAILCALL_RVA(0x8111b0); }

/* file+0x778, RVA 0x266558; ev_120d801416d14ffe949cd0f00a408fe36d69bf99a4fd7c74ec9d926fdb576391 */
void trampoline_00266558(void) { REA_TAILCALL_RVA(0x1ae90); }

/* file+0x780, RVA 0x266560; ev_71706337407f4cec43b416409a024cd7e02ead92746d1f49cd583886824cf720 */
void trampoline_00266560(void) { REA_TAILCALL_RVA(0x4f0030); }

/* file+0x788, RVA 0x266568; ev_233e28fbf263fcc93772fa71940f6910c0d80cf14e4412786491cea2a98584a7 */
void trampoline_00266568(void) { REA_TAILCALL_RVA(0x4fbbd0); }

/* file+0x790, RVA 0x266570; ev_044de44531dc6dc7c0ed7a1a4ca9a4649afb06d19ea0fcdf5d95062e381210ab */
void trampoline_00266570(void) { REA_TAILCALL_RVA(0x50ced0); }

/* file+0x798, RVA 0x266578; ev_f04672760190464ef88390cc0b4c4c058a30685c18453543a275daff82941110 */
void trampoline_00266578(void) { REA_TAILCALL_RVA(0x50cee0); }

/* file+0x7a0, RVA 0x266580; ev_13cec78a48d7d0c2f2c9f7f227c68035151b61a08ee7cf06adef67485d01e198 */
void trampoline_00266580(void) { REA_TAILCALL_RVA(0x50cf30); }

/* file+0x7a8, RVA 0x266588; ev_7cfd599498114c66667ec19c2698a0a3b4fb35f83c9a2e658e1831a21bbf979d */
void trampoline_00266588(void) { REA_TAILCALL_RVA(0x50cf70); }

/* file+0x7b0, RVA 0x266590; ev_fe4183d0128d53a32405dcfa786475b67800564e2d11e03c2c275104ffcef284 */
void trampoline_00266590(void) { REA_TAILCALL_RVA(0x50cfb0); }

/* file+0x7b8, RVA 0x266598; ev_aa475cd5fc18883ba1984323b3f44ede253a7b3cbfb21711675c5043a84025eb */
void trampoline_00266598(void) { REA_TAILCALL_RVA(0x50cfe0); }

/* file+0x7c0, RVA 0x2665a0; ev_d06e23b3fc4b01c2048fd66a52e137d756efabf029d2a4176af4b757e9491cae */
void trampoline_002665a0(void) { REA_TAILCALL_RVA(0x51e4d0); }

/* file+0x7c8, RVA 0x2665a8; ev_92e526ce960b080a740cce3dc66c8c6c82e7f91bf9cad3b677362df524dfc53a */
void trampoline_002665a8(void) { REA_TAILCALL_RVA(0x51ef60); }

/* file+0x7d0, RVA 0x2665b0; ev_1397f018d596f8c3a600de6ce2cb6507ca3e37e941611960cd247c0337f6831c */
void trampoline_002665b0(void) { REA_TAILCALL_RVA(0x51f000); }

/* file+0x7d8, RVA 0x2665b8; ev_62ce3604723f4f5f60e45bf99e63044fd624b7cafe5aa5657b10782b36919363 */
void trampoline_002665b8(void) { REA_TAILCALL_RVA(0x51f0b0); }

/* file+0x7e0, RVA 0x2665c0; ev_7e0c1be47f16e0ac4f3f9277135ae8e9bfb302089cf0c9a92a4e93c58d01f64d */
void trampoline_002665c0(void) { REA_TAILCALL_RVA(0x51f2e0); }

/* file+0x7e8, RVA 0x2665c8; ev_d5baa2d8a4fa5ea3f45c002c9ba25c67055dde1ea23616c49d882f4363ef9742 */
void trampoline_002665c8(void) { REA_TAILCALL_RVA(0x51f670); }

/* file+0x7f0, RVA 0x2665d0; ev_57e72951acddf42d8a8948b32c7b508bcbcb0ea689d1f3013de7df7c3e032b10 */
void trampoline_002665d0(void) { REA_TAILCALL_RVA(0x51fee0); }

/* file+0x7f8, RVA 0x2665d8; ev_6ca0ec95a74c75bda177c9f1a4106c79f4fe4260345bc06fabd881110de29081 */
void trampoline_002665d8(void) { REA_TAILCALL_RVA(0x536400); }

/* file+0x800, RVA 0x2665e0; ev_ea1e9ea7f930410dd41cb15f91164ff2b8d0fee66eb2a487cd4b960011ba195e */
void trampoline_002665e0(void) { REA_TAILCALL_RVA(0x544ca0); }

/* file+0x808, RVA 0x2665e8; ev_2ff3c179cc1c15760af4ab4d504e0b903279b8e781de335abfc29ec2bec78f28 */
void trampoline_002665e8(void) { REA_TAILCALL_RVA(0x5468f0); }

/* file+0x810, RVA 0x2665f0; ev_64dc60c786fdf097f8cabe9a24dc65fa23c90bcec95b4c031ee9dd244a45c4ab */
void trampoline_002665f0(void) { REA_TAILCALL_RVA(0xb1630); }

/* file+0x818, RVA 0x2665f8; ev_048c91acd5230b5f168db1aa387eefe5dbef63685ce77d2cb1812ef6fac587f1 */
void trampoline_002665f8(void) { REA_TAILCALL_RVA(0xb1fb0); }

/* file+0x820, RVA 0x266600; ev_d5838d97d25d0404a9dd86ee3e4231336f7788593949509b36b36f988ce2e9c5 */
void trampoline_00266600(void) { REA_TAILCALL_RVA(0x55bf40); }

/* file+0x828, RVA 0x266608; ev_98298519c4811cd31175a09c0e6f76183ba2eff0e35d2636cd3920bedb6819fa */
void trampoline_00266608(void) { REA_TAILCALL_RVA(0x55c030); }

/* file+0x830, RVA 0x266610; ev_848181c24be9fbad1dabfd90c2c041026620367371dd04b3e5d37ee90811786d */
void trampoline_00266610(void) { REA_TAILCALL_RVA(0x55c050); }

/* file+0x838, RVA 0x266618; ev_27bee08c9b1193043039fdc8c47563f926ba90567be8e72ec64aea23ce8e0af3 */
void trampoline_00266618(void) { REA_TAILCALL_RVA(0x56e200); }

/* file+0x840, RVA 0x266620; ev_4ddec5f89d19a2cc23abba72f01134c5a02849938fe85cf449d4aa0db112fdfd */
void trampoline_00266620(void) { REA_TAILCALL_RVA(0x57f4a0); }

/* file+0x848, RVA 0x266628; ev_61a86c88edcf4f3b58f09ce33cc0242bc7e342f3ea8e4708eb2f0da99477b97c */
void trampoline_00266628(void) { REA_TAILCALL_RVA(0x9945e0); }

/* file+0x850, RVA 0x266630; ev_cc6a666cfae72670f185a2f5a2e11aa1f623b3b14d8253830e4c4991728f9d8c */
void trampoline_00266630(void) { REA_TAILCALL_RVA(0x585950); }

/* file+0x858, RVA 0x266638; ev_05908f766f9543e213de3110f4f87beefa1f41adfb69c03d9ca5cc10add84cb2 */
void trampoline_00266638(void) { REA_TAILCALL_RVA(0x599820); }

/* file+0x860, RVA 0x266640; ev_5812582b38fc8af5d25a5b508d3cbe99d69943de91ad69575d9cff0860c0e904 */
void trampoline_00266640(void) { REA_TAILCALL_RVA(0x59a3e0); }

/* file+0x868, RVA 0x266648; ev_b6dfa31fa28d6e952d6d88251b975351579a5eeee4126d1673887e7142d3aea6 */
void trampoline_00266648(void) { REA_TAILCALL_RVA(0x59a530); }

/* file+0x870, RVA 0x266650; ev_ed01ccff279d59b8a4f2cd89abdc3def4e0886751c4ad11c4373d297e53f5719 */
void trampoline_00266650(void) { REA_TAILCALL_RVA(0x59a700); }

/* file+0x878, RVA 0x266658; ev_6b61d4ab02cc3c006038b2b64d0af2b939c935d67b80f3dbbc2caac281eda47e */
void trampoline_00266658(void) { REA_TAILCALL_RVA(0x59a7d0); }

/* file+0x880, RVA 0x266660; ev_cbe1eaaed4df10cc75a9b79d07190dc1cbaac6c521c04126b1f06be1f227fce5 */
void trampoline_00266660(void) { REA_TAILCALL_RVA(0x59aa50); }

/* file+0x888, RVA 0x266668; ev_22869d48a04358186aa2865c19591d122a8833c51a1a6c062e08b52d5901ebab */
void trampoline_00266668(void) { REA_TAILCALL_RVA(0x59ab60); }

/* file+0x890, RVA 0x266670; ev_b3f47c80f36bc5674aa7d9bffd5ad953580c624320aa23715c13d58e2bbbb842 */
void trampoline_00266670(void) { REA_TAILCALL_RVA(0x59ac60); }

/* file+0x898, RVA 0x266678; ev_cad6533c2c3aa3c04be08021c96a2a6756e657bf2aa28c221eaf2708827cf704 */
void trampoline_00266678(void) { REA_TAILCALL_RVA(0x5dbed0); }

/* file+0x8a0, RVA 0x266680; ev_ad0615ee013e89c16455513c5466b5f2ce9ae1376854f36a087edd01303325e3 */
void trampoline_00266680(void) { REA_TAILCALL_RVA(0x5eb720); }

/* file+0x8a8, RVA 0x266688; ev_3ac30a55280113881ede59f9eb14be321e99a8899e373e25a71297aec62c0c94 */
void trampoline_00266688(void) { REA_TAILCALL_RVA(0x5ec030); }

/* file+0x8b0, RVA 0x266690; ev_987defa2f0bb2ce3edb76d5b3e216f95695d7830c9da627fb50c625ba35a78b8 */
void trampoline_00266690(void) { REA_TAILCALL_RVA(0x5ecad0); }

/* file+0x8b8, RVA 0x266698; ev_fd0223f8134aacf2ac72b1e40cd6d11fddb2ab96cac7c0edfe36ba0478df972f */
void trampoline_00266698(void) { REA_TAILCALL_RVA(0x5ed440); }

/* file+0x8c0, RVA 0x2666a0; ev_ea9aab6ed7c2177b8de74e2407b6ac95ce26591f235d2b35ba5c1c3f070dcc1a */
void trampoline_002666a0(void) { REA_TAILCALL_RVA(0x5edb30); }

/* file+0x8c8, RVA 0x2666a8; ev_4e7a5c2b6868f2facc6e32a97f1adc33bff9606e3b0549abe72f7dec1d5fac0f */
void trampoline_002666a8(void) { REA_TAILCALL_RVA(0x14e280); }

/* file+0x8d0, RVA 0x2666b0; ev_040ab764b2fe85d7c7c8b937470a33c89c72d7a411004c92472bd60f3a8af131 */
void trampoline_002666b0(void) { REA_TAILCALL_RVA(0x5f18b0); }

/* file+0x8d8, RVA 0x2666b8; ev_1a2303717b94c052d124628d4d6f2150e0ad3ac41a40208d858616d68b91f2bf */
void trampoline_002666b8(void) { REA_TAILCALL_RVA(0x5f2b30); }

/* file+0x8e0, RVA 0x2666c0; ev_1effd977ac09c6438a359cc7786cb726987597151c1d782ce40984b5ae347d38 */
void trampoline_002666c0(void) { REA_TAILCALL_RVA(0x5fd0c0); }

/* file+0x8e8, RVA 0x2666c8; ev_91b1c5f4db425b8637a904220ac09d930f499f112977c4daf8e27a3e9c9c0e65 */
void trampoline_002666c8(void) { REA_TAILCALL_RVA(0x600680); }

/* file+0x8f0, RVA 0x2666d0; ev_f36e256d259c52aadb70e5b35f2c3c991951e347c0f12ad45785bb5fdcec0b42 */
void trampoline_002666d0(void) { REA_TAILCALL_RVA(0x600f40); }

/* file+0x8f8, RVA 0x2666d8; ev_fe6c364e1dbfe14a8d2da6578824571634c20828e0c52592fb6ea11c1fc52c63 */
void trampoline_002666d8(void) { REA_TAILCALL_RVA(0xae64a0); }

/* file+0x900, RVA 0x2666e0; ev_2cb0e1269df922329ddbf52995b2c193a64491d2b2f8e13710d81df301619fc5 */
void trampoline_002666e0(void) { REA_TAILCALL_RVA(0x62daa0); }

/* file+0x908, RVA 0x2666e8; ev_be35578515bb7eac742cd9e0035c2ba71234bc1d6d7c03b70e67a8a1772c0aca */
void trampoline_002666e8(void) { REA_TAILCALL_RVA(0x6302d0); }

/* file+0x910, RVA 0x2666f0; ev_3fa43938021d371b600960971eba1e4b74f3ee855a2a88f6f5ac8636a1353528 */
void trampoline_002666f0(void) { REA_TAILCALL_RVA(0x634f10); }

/* file+0x918, RVA 0x2666f8; ev_61725172ce3a3b71fdf15035ca5f82ae5a0dc864dbb4502ef35cabcb9b82a8f0 */
void trampoline_002666f8(void) { REA_TAILCALL_RVA(0x63f520); }

/* file+0x920, RVA 0x266700; ev_bbc5354bad12fa280c5fa04713b475e194e2c49652b0dfc6a49a8536e95d7e8f */
void trampoline_00266700(void) { REA_TAILCALL_RVA(0x6579b0); }

/* file+0x928, RVA 0x266708; ev_5e41736513dfe69b25f14c42f50a2448440c79882a4bfacdc5c6be379555b1e6 */
void trampoline_00266708(void) { REA_TAILCALL_RVA(0xca7310); }

/* file+0x930, RVA 0x266710; ev_4e47c0f100e5651199007fa31cf68fffc4c18afcd709587fcf979ba3e2a068ac */
void trampoline_00266710(void) { REA_TAILCALL_RVA(0x662e70); }

/* file+0x938, RVA 0x266718; ev_02610441ba492ef0f06ffc9201d125589f7944ffc2bf9470c6767e40bd84ba26 */
void trampoline_00266718(void) { REA_TAILCALL_RVA(0x662e80); }

/* file+0x940, RVA 0x266720; ev_d735c205b1631f9982a50d6b3fbcc8161229f870f56b25afc11fa11773dc9ebf */
void trampoline_00266720(void) { REA_TAILCALL_RVA(0x678e10); }

/* file+0x948, RVA 0x266728; ev_67ba73450c68710572ab4dc3000e735d311c67e6c7c48da291828528cd261909 */
void trampoline_00266728(void) { REA_TAILCALL_RVA(0x678e60); }

/* file+0x950, RVA 0x266730; ev_c42aee078d3af653ceef9d5ba42dbd0580a0172676faaeba0d98c3630ced7c6f */
void trampoline_00266730(void) { REA_TAILCALL_RVA(0x678ec0); }

/* file+0x958, RVA 0x266738; ev_1c06028de82defe35d7465893ce4e09155e182b726cd9f5c302f5bd50c4d3d1b */
void trampoline_00266738(void) { REA_TAILCALL_RVA(0x678f60); }

/* file+0x960, RVA 0x266740; ev_ae1fec14813bea42fc2435ed6569d0e60e1565afbb3912f36ad156c4e3b77f47 */
void trampoline_00266740(void) { REA_TAILCALL_RVA(0x679190); }

/* file+0x968, RVA 0x266748; ev_94255a908116ee36481aaac6004eafebda085c4a77a34a53d6ddd345746895b1 */
void trampoline_00266748(void) { REA_TAILCALL_RVA(0x679360); }

/* file+0x970, RVA 0x266750; ev_8d81e7078427f73982b18f19c300e22fe199fffc885fd4813e4f0e22d36b2bc8 */
void trampoline_00266750(void) { REA_TAILCALL_RVA(0x679680); }

/* file+0x978, RVA 0x266758; ev_3120929bc86bc9c3ccc1ca4e5fe804edaef7dbe51b4d867f3b3ef8a7a04c34fa */
void trampoline_00266758(void) { REA_TAILCALL_RVA(0x33b90); }

/* file+0x980, RVA 0x266760; ev_b397484974a5ecaef9f5a21f35dbd0de86058364cb5537ff7703959013627049 */
void trampoline_00266760(void) { REA_TAILCALL_RVA(0x33ca0); }

/* file+0x988, RVA 0x266768; ev_dac1f160781168c151d90827c3bd04ca9c78911a06f356345605c478b0aeacef */
void trampoline_00266768(void) { REA_TAILCALL_RVA(0x33d20); }

/* file+0x990, RVA 0x266770; ev_cc1e236ccc1c36130834e2dcc91e1d9ec04379ce83ca6bac4e7400b34e2efe67 */
void trampoline_00266770(void) { REA_TAILCALL_RVA(0x3cf70); }

/* file+0x998, RVA 0x266778; ev_a61e892a0f424a1e514146f4493b20fa5077715499c97fa0f5c028c5368b33a8 */
void trampoline_00266778(void) { REA_TAILCALL_RVA(0x3d0e0); }

/* file+0x9a0, RVA 0x266780; ev_37f81d44aca1c24f753f5e2276abc8009e4080419e2689385d7de456d23b0b2f */
void trampoline_00266780(void) { REA_TAILCALL_RVA(0x3d660); }

/* file+0x9a8, RVA 0x266788; ev_87f44cf324ced33854ca5ef422011e0d07bbf5d6d56a4cc2b7aec26617a5ac6e */
void trampoline_00266788(void) { REA_TAILCALL_RVA(0x3e100); }

/* file+0x9b0, RVA 0x266790; ev_80764b5fbd1453cc36bcc31c1eec6dc2c4048255291e6834ec9c6db8ac7b226d */
void trampoline_00266790(void) { REA_TAILCALL_RVA(0x3e160); }

/* file+0x9b8, RVA 0x266798; ev_86530fac65279025ead11cf9f4f1335e1a5b275283b65f75ed12b2dd18a36097 */
void trampoline_00266798(void) { REA_TAILCALL_RVA(0x3e1c0); }

/* file+0x9c0, RVA 0x2667a0; ev_65285a1eda2995a3fe43af1a2ac18427e491362b0c75b0a2c5b85aa453a8214f */
void trampoline_002667a0(void) { REA_TAILCALL_RVA(0x3f070); }

/* file+0x9c8, RVA 0x2667a8; ev_f5297fe72a46b96af96e035fadf17f649c992be1cb0cbf18bc39821ff6a5ea1f */
void trampoline_002667a8(void) { REA_TAILCALL_RVA(0x3f0d0); }

/* file+0x9d0, RVA 0x2667b0; ev_947925cee29d865bf298c2b544bab1973e08b995d3c575da787f455f47e8f2b6 */
void trampoline_002667b0(void) { REA_TAILCALL_RVA(0x3f4b0); }

/* file+0x9d8, RVA 0x2667b8; ev_e784735a9b12221b96b29a23420eb764767968ac315f5d1cd3c00277a04ff569 */
void trampoline_002667b8(void) { REA_TAILCALL_RVA(0x3f510); }

/* file+0x9e0, RVA 0x2667c0; ev_29008f1918946d39d83889f1cfd0d20f44ce5b0fae5cf124e2d2f64e1cd6bd34 */
void trampoline_002667c0(void) { REA_TAILCALL_RVA(0x3f570); }

/* file+0x9e8, RVA 0x2667c8; ev_75ada8bea91130caeb8778fc47e1ef11c19290db56abf736aa6284cd1ab31aca */
void trampoline_002667c8(void) { REA_TAILCALL_RVA(0x3fbb0); }

/* file+0x9f0, RVA 0x2667d0; ev_314532e5f9a12a86c8c7f82bfd01b63ac331ad0cc2cd91fe1978d5fc223b0006 */
void trampoline_002667d0(void) { REA_TAILCALL_RVA(0x3ffc0); }

/* file+0x9f8, RVA 0x2667d8; ev_31615cfb3cecd95ec0e8a43f72973e359d7dde2140c34f1dc3416b1a9095ae58 */
void trampoline_002667d8(void) { REA_TAILCALL_RVA(0x40960); }

/* file+0xa00, RVA 0x2667e0; ev_b1eb9b999b21653dbae930bf22690e5588fa32b729a9aac98cd2dcefac1086c6 */
void trampoline_002667e0(void) { REA_TAILCALL_RVA(0x40b50); }

/* file+0xa08, RVA 0x2667e8; ev_8d9233f6524f942cc37b553ef47d73cad763a764e7d7ebb955abed2390f03bab */
void trampoline_002667e8(void) { REA_TAILCALL_RVA(0x40c30); }

/* file+0xa10, RVA 0x2667f0; ev_46c62bb8313900b85db69968cdafc1b87df10238a23166efac7466019fc578e7 */
void trampoline_002667f0(void) { REA_TAILCALL_RVA(0x41630); }

/* file+0xa18, RVA 0x2667f8; ev_97203b4a70e558a75e9b8c20df0e1c301e0beb6e84fb3020fc569bda43493b60 */
void trampoline_002667f8(void) { REA_TAILCALL_RVA(0x41750); }

/* file+0xa20, RVA 0x266800; ev_ea077c10bc36523a0221d7fea9caeffac59f0ba5ce8bb82fd5305b05c749e178 */
void trampoline_00266800(void) { REA_TAILCALL_RVA(0x41830); }

/* file+0xa28, RVA 0x266808; ev_1007891770a411afdaee87b5b8745deb26bfeea98135f3fccaa1cc49858fdafc */
void trampoline_00266808(void) { REA_TAILCALL_RVA(0x418c0); }

/* file+0xa30, RVA 0x266810; ev_7cb21d88e7c5463a555d386818015b675755195ac94a616a9459e3fc7d9a8331 */
void trampoline_00266810(void) { REA_TAILCALL_RVA(0x42060); }

/* file+0xa38, RVA 0x266818; ev_2a2be32e6c36a13be86f648c1def6c503696d8d5f87fff967d70c6fa2d4f0974 */
void trampoline_00266818(void) { REA_TAILCALL_RVA(0x424d0); }

/* file+0xa40, RVA 0x266820; ev_39d7b01f9db47ba68370dc66a6d4fee97f65038f2a0bf8e01034d1dc631a932e */
void trampoline_00266820(void) { REA_TAILCALL_RVA(0x425a0); }

/* file+0xa48, RVA 0x266828; ev_fe49b3d07f6faac78df2e8cefe487f268c1c2470c072a962f0f7174ce6930676 */
void trampoline_00266828(void) { REA_TAILCALL_RVA(0x42600); }

/* file+0xa50, RVA 0x266830; ev_5a551533354720b2c7a9c6f87881f9d7e464f610f5ac6cb25a0e03b4932cd123 */
void trampoline_00266830(void) { REA_TAILCALL_RVA(0x690030); }

/* file+0xa58, RVA 0x266838; ev_3c132229b734e6e6dd3e2692af820eb8f80485c18c75c435277cf4a5c976b776 */
void trampoline_00266838(void) { REA_TAILCALL_RVA(0x696cc0); }

/* file+0xa60, RVA 0x266840; ev_2d298c572e1b5511f6a9914e5996d66aeb5fd1abc9c3aefb3a276f1205959409 */
void trampoline_00266840(void) { REA_TAILCALL_RVA(0x6985d0); }

/* file+0xa68, RVA 0x266848; ev_0b613dfba55c098b62a8a76f56b54331d5bb36967001c5eb03832ad1f7c762df */
void trampoline_00266848(void) { REA_TAILCALL_RVA(0x6a2050); }

/* file+0xa70, RVA 0x266850; ev_6ea20b408ba809b5576c3a766c961dbf3fdb2132e10985865cc5f5d88ab35d50 */
void trampoline_00266850(void) { REA_TAILCALL_RVA(0x6a22b0); }

/* file+0xa78, RVA 0x266858; ev_3f3fee6b3feb77341e063466ce499385dd9eab3b6a0265c2a99807fea4726978 */
void trampoline_00266858(void) { REA_TAILCALL_RVA(0x6ae640); }

/* file+0xa80, RVA 0x266860; ev_10e77bd111d9ac774f77d20647d87b8f6535c7034d69ce05268884be0271c682 */
void trampoline_00266860(void) { REA_TAILCALL_RVA(0x6ae7f0); }

/* file+0xa88, RVA 0x266868; ev_d2c24fa0d60d1b6e2d402b2ed743f13c38e33e10f9741845ee13a0f6334fb208 */
void trampoline_00266868(void) { REA_TAILCALL_RVA(0x1813b0); }

/* file+0xa90, RVA 0x266870; ev_5ff8a6724732f4d3787432b63b0be59f661b8d046be22a535316c1f946f4814f */
void trampoline_00266870(void) { REA_TAILCALL_RVA(0x6befa0); }

/* file+0xa98, RVA 0x266878; ev_2b969010a4ca5e4ebaf11c5b97779f153c6622f35d28a3f858d8561762de2a38 */
void trampoline_00266878(void) { REA_TAILCALL_RVA(0x188040); }

/* file+0xaa0, RVA 0x266880; ev_cc6a9f2151674e24889d3ac6c51476fc6e0ea0cb9e3db9b11fcbd99c569443c6 */
void trampoline_00266880(void) { REA_TAILCALL_RVA(0x6d0b00); }

/* file+0xaa8, RVA 0x266888; ev_0650153055868e1d673335a43c7d6806c92f82c4128d44532fe43a28447ed2b8 */
void trampoline_00266888(void) { REA_TAILCALL_RVA(0x6d1100); }

/* file+0xab0, RVA 0x266890; ev_e9fe06c8a01e70613dc2fc758d45bfcb194661e922d16bac1de98d77c1de7a6a */
void trampoline_00266890(void) { REA_TAILCALL_RVA(0x6d1260); }

/* file+0xab8, RVA 0x266898; ev_fcca4aedcdf0f7f35b775708f026a80332a5aba383b9ebdf94a827a57edf33c0 */
void trampoline_00266898(void) { REA_TAILCALL_RVA(0x6d13e0); }

/* file+0xac0, RVA 0x2668a0; ev_e228a6e95e2755f03139b621688a369ea54b73cfeaaf83e0cc96256d399417c0 */
void trampoline_002668a0(void) { REA_TAILCALL_RVA(0x6d1520); }

/* file+0xac8, RVA 0x2668a8; ev_031ce0f14ac17c66ae07cad2e06ae2894ba8031580aa2ea62165cd1d19db9339 */
void trampoline_002668a8(void) { REA_TAILCALL_RVA(0x6d1640); }

/* file+0xad0, RVA 0x2668b0; ev_6a23afffe5ecb7c5d134c63a5ad37eddbdb09240112ebdab593dab204171b0f9 */
void trampoline_002668b0(void) { REA_TAILCALL_RVA(0x6d1720); }

/* file+0xad8, RVA 0x2668b8; ev_6eb69f629d03ee784cc6553662f4b76654b866865315d069a26bb1bed71b972c */
void trampoline_002668b8(void) { REA_TAILCALL_RVA(0x6dc660); }

/* file+0xae0, RVA 0x2668c0; ev_c120a0d0323bb25045f9a1d8c6dc2ff5d0120c4d1ddc349e5fea0c14b18dc657 */
void trampoline_002668c0(void) { REA_TAILCALL_RVA(0x6dc690); }

/* file+0xae8, RVA 0x2668c8; ev_6c94aa62761098db4eefe956caefe8360505abcebc8c09fcd1a70ff050912b61 */
void trampoline_002668c8(void) { REA_TAILCALL_RVA(0x6dc6a0); }

/* file+0xaf0, RVA 0x2668d0; ev_265e82de009a245df40b478518f753309c21b458e2b771a4ba52100a5d206f89 */
void trampoline_002668d0(void) { REA_TAILCALL_RVA(0x6e0920); }

/* file+0xaf8, RVA 0x2668d8; ev_e9af2c49876da894acb95529aea20bafef1f8d59c6268a4e8eb2a0d194a0793d */
void trampoline_002668d8(void) { REA_TAILCALL_RVA(0x6e1440); }

/* file+0xb00, RVA 0x2668e0; ev_d7b96b400a047d0ed12e257e5640a0c8cf62ba26a2f4f77cebf5f250ce8adf6b */
void trampoline_002668e0(void) { REA_TAILCALL_RVA(0x6e1450); }

/* file+0xb08, RVA 0x2668e8; ev_c658089d3e02c41f127471c83157c268f8e95ea9802d97c32cb7c64193ab9874 */
void trampoline_002668e8(void) { REA_TAILCALL_RVA(0x189a70); }

/* file+0xb10, RVA 0x2668f0; ev_0978e34a25f04ef0829cb60d2693eadd7a456ac55d29fb93c35810198130e3cd */
void trampoline_002668f0(void) { REA_TAILCALL_RVA(0x190aa0); }

/* file+0xb18, RVA 0x2668f8; ev_35fc5164a4de0f77c67166367f713bd308eafa79b8dff31ac4f547c63ee42b5b */
void trampoline_002668f8(void) { REA_TAILCALL_RVA(0x702970); }

/* file+0xb20, RVA 0x266900; ev_6bec001b3e31b281a3be652e7882a4f33bdaf5088817fa2585602e6f6669f134 */
void trampoline_00266900(void) { REA_TAILCALL_RVA(0x702d60); }

/* file+0xb28, RVA 0x266908; ev_49a44e5443eae2228a877e7ded31a3415258d501fad5041d4e84c053d47abc82 */
void trampoline_00266908(void) { REA_TAILCALL_RVA(0x706170); }

/* file+0xb30, RVA 0x266910; ev_b5bd3f47d639c498e4f5efeb9b60b93ec3096611f91392c2eb466a113a80a3df */
void trampoline_00266910(void) { REA_TAILCALL_RVA(0x7061f0); }

/* file+0xb38, RVA 0x266918; ev_1e1b8127f2603d5faee8df1eb04d59345f268c23159d606400e702ecdeea8239 */
void trampoline_00266918(void) { REA_TAILCALL_RVA(0x70ff00); }

/* file+0xb40, RVA 0x266920; ev_ece19b30190095f580ce88c183ad6de58ef9d7d0e7bb5e21bd205737247ad2ad */
void trampoline_00266920(void) { REA_TAILCALL_RVA(0x70ffb0); }

/* file+0xb48, RVA 0x266928; ev_81629b92fcb43dcb398898cab5d701df89501d264e6d76037f8e84fe5ef37b02 */
void trampoline_00266928(void) { REA_TAILCALL_RVA(0x7101c0); }

/* file+0xb50, RVA 0x266930; ev_11646d1df80b62fb6ffab37c94ac69d8d6993c0f908d7dc0aeb257db7c6684a8 */
void trampoline_00266930(void) { REA_TAILCALL_RVA(0x710320); }

/* file+0xb58, RVA 0x266938; ev_02e3ee489ff277c8c2de4c8b11ba8eb1ebc1d5ede756b95ec21b6ef49e746166 */
void trampoline_00266938(void) { REA_TAILCALL_RVA(0x712bb0); }

/* file+0xb60, RVA 0x266940; ev_192bc8d1c171c58aa52cef7c2f03120ede8c4de82b23e3b82fb6e3555f78ac31 */
void trampoline_00266940(void) { REA_TAILCALL_RVA(0x716360); }

/* file+0xb68, RVA 0x266948; ev_9651be8320bc86e367b580855cbb9f3bacfc34f866382918adb758522c43ba58 */
void trampoline_00266948(void) { REA_TAILCALL_RVA(0x72f970); }

/* file+0xb70, RVA 0x266950; ev_0508ff916c2c219ba236ab5ee3eab42d691a3cecbc237960a2efcd5d5fb284cd */
void trampoline_00266950(void) { REA_TAILCALL_RVA(0x72f990); }

/* file+0xb78, RVA 0x266958; ev_cb87c425a86e5c4083f01c4efd141eb1592da80c434a1671c291b4597a080c24 */
void trampoline_00266958(void) { REA_TAILCALL_RVA(0x72fa20); }

/* file+0xb80, RVA 0x266960; ev_4ba370d7f1e10b817a58291c491f49ca7ead3fb048f19e510a0deb4b6ca64206 */
void trampoline_00266960(void) { REA_TAILCALL_RVA(0x246e30); }

/* file+0xb88, RVA 0x266968; ev_0cb2ddf76691f5f82c726d6fccf136fe940e57a07d1d08ccf06fdf86bbca1ac1 */
void trampoline_00266968(void) { REA_TAILCALL_RVA(0x7647f0); }

/* file+0xb90, RVA 0x266970; ev_611adfa1d881c7bcd8e15248c3ad77c33e8f72317ceea30597c35666a6d525b2 */
void trampoline_00266970(void) { REA_TAILCALL_RVA(0x773710); }

/* file+0xb98, RVA 0x266978; ev_732e027f10445a313b2f5e4a0cdf95076c994a271543ad95e77977e98e01a551 */
void trampoline_00266978(void) { REA_TAILCALL_RVA(0x775950); }

/* file+0xba0, RVA 0x266980; ev_93d03cf85d8fd8647e1313ff5836e59d0a3d4a8d998cadc8e98a5dd1a5cd9836 */
void trampoline_00266980(void) { REA_TAILCALL_RVA(0x799e90); }

/* file+0xba8, RVA 0x266988; ev_862daa6e4db6302375e6564ef4946b32e1294eb041c10ef9adb0eafa6e079202 */
void trampoline_00266988(void) { REA_TAILCALL_RVA(0x7b31f0); }

/* file+0xbb0, RVA 0x266990; ev_0075b105431a338d475a2ed5626431928272e6877bb9a64209bceae6d575748a */
void trampoline_00266990(void) { REA_TAILCALL_RVA(0x7e23a0); }

/* file+0xbb8, RVA 0x266998; ev_fb2d65001d66949ab373849860497ce24ffe9e900ddcaedde9adcebd5fe1e7b6 */
void trampoline_00266998(void) { REA_TAILCALL_RVA(0x7e83e0); }

/* file+0xbc0, RVA 0x2669a0; ev_02fae05a0e92ef19ce4c50c806f64d12fb0a381536aa49b726a0df7e5efb875e */
void trampoline_002669a0(void) { REA_TAILCALL_RVA(0x7e8480); }

/* file+0xbc8, RVA 0x2669a8; ev_f99174893d4bdc01a1aaca43ad924d0a318ce591a1bb686020ca7aaf30e0aa57 */
void trampoline_002669a8(void) { REA_TAILCALL_RVA(0xc3b1b0); }

/* file+0xbd0, RVA 0x2669b0; ev_f0d96dc4a087d701eed6430f33f5f9c4baddf6f6c8e712baaaa88736d4141f14 */
void trampoline_002669b0(void) { REA_TAILCALL_RVA(0xc3c6e0); }

/* file+0xbd8, RVA 0x2669b8; ev_cd570b620d76a8a7b9db07e5e95a2d4dfd271f39932c17cf878cc5857a3e8507 */
void trampoline_002669b8(void) { REA_TAILCALL_RVA(0xc3c690); }

/* file+0xbe0, RVA 0x2669c0; ev_a9bfd577502a7aa2fe28a235b87cee2e3e425c380c7672eb24be1d58fa8d65a4 */
void trampoline_002669c0(void) { REA_TAILCALL_RVA(0xc3c730); }

/* file+0xbe8, RVA 0x2669c8; ev_a89ca0beb27e28aa5fbb1864cf83f3a096f7566bf0aee33ca94380093a7bc18d */
void trampoline_002669c8(void) { REA_TAILCALL_RVA(0x802220); }

/* file+0xbf0, RVA 0x2669d0; ev_df0170ac4e0e443ea3700c487374dd990e9788c6af71b70f46884eaaae0e3327 */
void trampoline_002669d0(void) { REA_TAILCALL_RVA(0x8024f0); }

/* file+0xbf8, RVA 0x2669d8; ev_9f1ae124865e0dc9bca03a3f7e623b6e5074628eb27cf14a4001f4e58b66b048 */
void trampoline_002669d8(void) { REA_TAILCALL_RVA(0x80c570); }

/* file+0xc00, RVA 0x2669e0; ev_52632b00b08bbaafe7e6c8812c94f32374abab4574f0c08c457e4d267802c321 */
void trampoline_002669e0(void) { REA_TAILCALL_RVA(0x82b300); }

/* file+0xc08, RVA 0x2669e8; ev_80ba43c91847856eec7a61e789f587e9bb004658d2381ec61e2cc336a7c0ee04 */
void trampoline_002669e8(void) { REA_TAILCALL_RVA(0x920ee0); }

/* file+0xc10, RVA 0x2669f0; ev_1a6ed07b2c592f3c20605baf18bf06bfaad5a6a5df2937d50a9b840ebc3cd60c */
void trampoline_002669f0(void) { REA_TAILCALL_RVA(0x920b90); }

/* file+0xc18, RVA 0x2669f8; ev_643b6fd30045ccc95021a2ae71a302f22a5900c17c4d0fe73929d92f19a39dda */
void trampoline_002669f8(void) { REA_TAILCALL_RVA(0x830810); }

/* file+0xc20, RVA 0x266a00; ev_560eaea7d124132325ddbadf95a3f32c5336e436a740ddf42d38f01af90ca587 */
void trampoline_00266a00(void) { REA_TAILCALL_RVA(0x830f00); }

/* file+0xc28, RVA 0x266a08; ev_accb7dc7bcc928dff617a18bfb202e86ea8e9060a99f8c45bb2a99b30ffaf306 */
void trampoline_00266a08(void) { REA_TAILCALL_RVA(0x8352b0); }

/* file+0xc30, RVA 0x266a10; ev_2d5a88799d06d9d5aaf99ba477e972f2f59609c641780d4d52052dcae756bac6 */
void trampoline_00266a10(void) { REA_TAILCALL_RVA(0x8352c0); }

/* file+0xc38, RVA 0x266a18; ev_758bf46963486f5b6943b7ff02a5e12acaf9eea8f0491bd1c003f5716b079bc9 */
void trampoline_00266a18(void) { REA_TAILCALL_RVA(0x8352d0); }

/* file+0xc40, RVA 0x266a20; ev_a4e978dc69c31fb28aef09f436a3da32cec0e1c66c9afa9f584df1176228006e */
void trampoline_00266a20(void) { REA_TAILCALL_RVA(0x8352f0); }

/* file+0xc48, RVA 0x266a28; ev_3e4f6fb56e5d11a56b07737bfb470950e8d953bf216079ce1c0cecf4c4e69b44 */
void trampoline_00266a28(void) { REA_TAILCALL_RVA(0x835440); }

/* file+0xc50, RVA 0x266a30; ev_b1c78994306d9a946a3a4ecd00999e2adfdf1168486efed884617655858e4776 */
void trampoline_00266a30(void) { REA_TAILCALL_RVA(0x835450); }

/* file+0xc58, RVA 0x266a38; ev_d9c6c73229016bc12a734a0da73049f65fab4c7a14a5f4aeeda3e1dad99a676f */
void trampoline_00266a38(void) { REA_TAILCALL_RVA(0x835490); }

/* file+0xc60, RVA 0x266a40; ev_9eaf5df13c55d918ac1d03db7eb9c9a2d34b7e7429d0ce2c7aa6f7c223d7f807 */
void trampoline_00266a40(void) { REA_TAILCALL_RVA(0x835ad0); }

/* file+0xc68, RVA 0x266a48; ev_e92a70dff5e270f84c9423316f279103c67b7d7a9d5283f92187b2b45372e136 */
void trampoline_00266a48(void) { REA_TAILCALL_RVA(0x850870); }

/* file+0xc70, RVA 0x266a50; ev_87d27901f39bc540be975a6cd663d3a236373f5a789a5600c730c611de984c2a */
void trampoline_00266a50(void) { REA_TAILCALL_RVA(0x8702f0); }

/* file+0xc78, RVA 0x266a58; ev_a3b47550da9ef977177c8a3ad7e93743dae48cf3aed28b9e413280e7916c4f76 */
void trampoline_00266a58(void) { REA_TAILCALL_RVA(0x8705d0); }

/* file+0xc80, RVA 0x266a60; ev_b14a8d5be7ca8cce0b9548c280b6752725487e912cda08a39bc775926a0e64e0 */
void trampoline_00266a60(void) { REA_TAILCALL_RVA(0x872af0); }

/* file+0xc88, RVA 0x266a68; ev_7d8b1abbec305fc24418768062423fa7fbd9777ed9392c5be16b7d1f5e320b64 */
void trampoline_00266a68(void) { REA_TAILCALL_RVA(0x873800); }

/* file+0xc90, RVA 0x266a70; ev_2fae32b8c554354b01472f6b66a9eaec54cb55177cd243e1e6b297f85707ea92 */
void trampoline_00266a70(void) { REA_TAILCALL_RVA(0x63a40); }

/* file+0xc98, RVA 0x266a78; ev_2cfb602e37206b25504c5f9f2877f2a4285384bba7fd7750e2fe7d636ba03554 */
void trampoline_00266a78(void) { REA_TAILCALL_RVA(0x66370); }

/* file+0xca0, RVA 0x266a80; ev_0ac9f452e1e47d31dd342dc91800ee3cf51d0e3e8674994a647359822af2e1d5 */
void trampoline_00266a80(void) { REA_TAILCALL_RVA(0xe6590); }

/* file+0xca8, RVA 0x266a88; ev_04ea4bff1f41a8d2dd4807ea36ac7a1a2e7fd19224b3e14d146674114d603dc4 */
void trampoline_00266a88(void) { REA_TAILCALL_RVA(0xe65a0); }

/* file+0xcb0, RVA 0x266a90; ev_bce673417bc8845f1c6c8a555cf1f6b494e0fa8a21c0a553eeabbda80e4064ed */
void trampoline_00266a90(void) { REA_TAILCALL_RVA(0xe6760); }

/* file+0xcb8, RVA 0x266a98; ev_c7879b203c1cbd671c53c048a90feaa04ae6e0a16b9f03747d21777108f046ab */
void trampoline_00266a98(void) { REA_TAILCALL_RVA(0xe6870); }

/* file+0xcc0, RVA 0x266aa0; ev_bc46698eb78bfa908b6128bde1a1bad930374c1828e21bd8a7e463496793b1ef */
void trampoline_00266aa0(void) { REA_TAILCALL_RVA(0xe7f90); }

/* file+0xcc8, RVA 0x266aa8; ev_5c234deab9c8dae3ba04939fa20ec82e83df69bce4c5c16a78bde5aff68a4f19 */
void trampoline_00266aa8(void) { REA_TAILCALL_RVA(0xe9fa0); }

/* file+0xcd0, RVA 0x266ab0; ev_d36b3f8abc724213b3ed79f9b5866e68cecab714b7956443052e125195f7534b */
void trampoline_00266ab0(void) { REA_TAILCALL_RVA(0xea670); }

/* file+0xcd8, RVA 0x266ab8; ev_2cfde3755ffcf224c08281222c91df27cc0d9aca6e14fb6a2e418795ffaa811c */
void trampoline_00266ab8(void) { REA_TAILCALL_RVA(0xea760); }

/* file+0xce0, RVA 0x266ac0; ev_39bd2a89d7a3ce0048c0bb2ae1a5eda122719e87312f9a01740de4f554d72597 */
void trampoline_00266ac0(void) { REA_TAILCALL_RVA(0xeb0a0); }

/* file+0xce8, RVA 0x266ac8; ev_07615e2a7ca6d9f698d9ed17be7c07384b8baa5f4711dfb9d7663e457afc71fa */
void trampoline_00266ac8(void) { REA_TAILCALL_RVA(0xeb190); }

/* file+0xcf0, RVA 0x266ad0; ev_4df207c521d43888a2ceda171d338a7d4c8ac8e071b728102278038a150e5587 */
void trampoline_00266ad0(void) { REA_TAILCALL_RVA(0xed000); }

/* file+0xcf8, RVA 0x266ad8; ev_051e245ed2255556e893b6d20fcc0823a673345c71f211183757eace64bc2a94 */
void trampoline_00266ad8(void) { REA_TAILCALL_RVA(0xed110); }

/* file+0xd00, RVA 0x266ae0; ev_ce47d08938dcbc53b0042aa3b4008d6895803d1862c579b620d6ed6f6baee1f7 */
void trampoline_00266ae0(void) { REA_TAILCALL_RVA(0x88a8a0); }

/* file+0xd08, RVA 0x266ae8; ev_2c4c943bcf973f61b14862809fc7903dcadc33911cd2438ad55dfe61c680828e */
void trampoline_00266ae8(void) { REA_TAILCALL_RVA(0x89cdf0); }

/* file+0xd10, RVA 0x266af0; ev_f350a3d3721a188e77ebb53156693dc28b455f1f1bacf3d7156ac11a03bbc4d4 */
void trampoline_00266af0(void) { REA_TAILCALL_RVA(0xeeb50); }

/* file+0xd18, RVA 0x266af8; ev_e97bc8db805e0d8a5b226dcf0c93d3e4ab25d10655220d88531511e18d5551d8 */
void trampoline_00266af8(void) { REA_TAILCALL_RVA(0x8cb250); }

/* file+0xd20, RVA 0x266b00; ev_980ebee3f6152f07796c8135825d5e0a6ba15b8613a983c5512279bb6fa752f6 */
void trampoline_00266b00(void) { REA_TAILCALL_RVA(0x8cb390); }

/* file+0xd28, RVA 0x266b08; ev_fd1514ed3fe292222156a9897572e2b752eb09e894e7ff42c5ecffd411516843 */
void trampoline_00266b08(void) { REA_TAILCALL_RVA(0x8d2f60); }

/* file+0xd30, RVA 0x266b10; ev_f118d530c029c35ced6a184097af3bdb39f654b56e6214f4edb2bf6e00c5be42 */
void trampoline_00266b10(void) { REA_TAILCALL_RVA(0x8d2f90); }

/* file+0xd38, RVA 0x266b18; ev_6547614b6f1815ee617aeabbe06acce11dc34345a484779fc5700bfd51baa4a8 */
void trampoline_00266b18(void) { REA_TAILCALL_RVA(0x8d8230); }

/* file+0xd40, RVA 0x266b20; ev_7c1b07d855337cb59b28f25c6d25474f561b83d6053dd26d32dfcc8cea5bc4d3 */
void trampoline_00266b20(void) { REA_TAILCALL_RVA(0x8d8de0); }

/* file+0xd48, RVA 0x266b28; ev_382af13a7302b1f12afb33c22dffed4267766be554e71251a527829226e74ca0 */
void trampoline_00266b28(void) { REA_TAILCALL_RVA(0x8d97b0); }

/* file+0xd50, RVA 0x266b30; ev_f868e13898009c024c065c466eb6a60d9fa1ca3249aef58203ffd1069bc618a0 */
void trampoline_00266b30(void) { REA_TAILCALL_RVA(0x8d9910); }

/* file+0xd58, RVA 0x266b38; ev_508667c4a11d4fcc7a96d930323525134295a4238990e8568c30b300a5121aca */
void trampoline_00266b38(void) { REA_TAILCALL_RVA(0x8da4c0); }

/* file+0xd60, RVA 0x266b40; ev_0c94d4d22ba95d6a0da3274cf7768cd2d8afc9b01e9ea585fd31c828c71a504d */
void trampoline_00266b40(void) { REA_TAILCALL_RVA(0x8da570); }

/* file+0xd68, RVA 0x266b48; ev_323d27a53d732dfc3330d17631de949d813367742ab5e6decb04e6ce10bb6a23 */
void trampoline_00266b48(void) { REA_TAILCALL_RVA(0x8da5b0); }

/* file+0xd70, RVA 0x266b50; ev_f2b89e50620a4113c85d5579e09459613b8a7231e9bb7c0ff2ee2282680e0af9 */
void trampoline_00266b50(void) { REA_TAILCALL_RVA(0x904c80); }

/* file+0xd78, RVA 0x266b58; ev_97788109533460b14b32f37a67e75a8ebc39b3e6bee2954e154a99214f584be1 */
void trampoline_00266b58(void) { REA_TAILCALL_RVA(0x904e60); }

/* file+0xd80, RVA 0x266b60; ev_40e8b0edbc1822e7d037eab68b49eb7dd1783e2facc1f194c9f7f1224b087f42 */
void trampoline_00266b60(void) { REA_TAILCALL_RVA(0x91d400); }

/* file+0xd88, RVA 0x266b68; ev_3c3552ca19d83961b81b948eff938583b814ad6558e085c7218cc7001af286db */
void trampoline_00266b68(void) { REA_TAILCALL_RVA(0x91d4a0); }

/* file+0xd90, RVA 0x266b70; ev_57eb4c63a0a22ce215b4436b027d1a105444097bc3ae3d5fd99dafb83ea59a33 */
void trampoline_00266b70(void) { REA_TAILCALL_RVA(0xa821d0); }

/* file+0xd98, RVA 0x266b78; ev_526efd00d47229ca348aff49a28b9febdaadf242aa6f0e48f1103957cf8a426d */
void trampoline_00266b78(void) { REA_TAILCALL_RVA(0xb42120); }

/* file+0xda0, RVA 0x266b80; ev_74a7635cce825719c71426ddedce4985fc1a0c5a83e1532612342515e541d618 */
void trampoline_00266b80(void) { REA_TAILCALL_RVA(0x964f30); }

/* file+0xda8, RVA 0x266b88; ev_0b56af5e9d40bbcc523b311eb2f73e070a67ac9ebab91bd2227616ceda9d6686 */
void trampoline_00266b88(void) { REA_TAILCALL_RVA(0x975f50); }

/* file+0xdb0, RVA 0x266b90; ev_3c20e3de8a57e4cabf8b31a9483047f06cd09b5b71a3c95b19afc2471c946c87 */
void trampoline_00266b90(void) { REA_TAILCALL_RVA(0x976200); }

/* file+0xdb8, RVA 0x266b98; ev_5c4bbc085b70b33bf6efe06ee3f25ec917088dc5237cc64b50bdcd790c463410 */
void trampoline_00266b98(void) { REA_TAILCALL_RVA(0x98c950); }

/* file+0xdc0, RVA 0x266ba0; ev_1f9af514b253b01f901d7cfb5eed250516237739b1b532832652456117fcc474 */
void trampoline_00266ba0(void) { REA_TAILCALL_RVA(0x98cc30); }

/* file+0xdc8, RVA 0x266ba8; ev_482f06c27153340d30f647934da55ba339906bd22758df48e4784f082afd9f14 */
void trampoline_00266ba8(void) { REA_TAILCALL_RVA(0x98cf30); }

/* file+0xdd0, RVA 0x266bb0; ev_98a160646ef919ae222d94d287cd89f481993ec8820a5389c326ccea8324f488 */
void trampoline_00266bb0(void) { REA_TAILCALL_RVA(0x98d6e0); }

/* file+0xdd8, RVA 0x266bb8; ev_53834f8b10c7635e27c0eb042b0fc2952994769d7c2f1c9400d95ab2ce5b769c */
void trampoline_00266bb8(void) { REA_TAILCALL_RVA(0x98e5d0); }

/* file+0xde0, RVA 0x266bc0; ev_aaddef5601e67bd49b4d3e622d95fd90489c06e665b5937064eb740fd240aa38 */
void trampoline_00266bc0(void) { REA_TAILCALL_RVA(0x98e700); }

/* file+0xde8, RVA 0x266bc8; ev_167a1a9011694808971c9ff63ba67d4cae0820297b89be83a0155e066b2b4306 */
void trampoline_00266bc8(void) { REA_TAILCALL_RVA(0x992170); }

/* file+0xdf0, RVA 0x266bd0; ev_d3b88a55810395af0d0ed14e9a31f01d5a2dbdb1b55d18af35e51d14562da8b1 */
void trampoline_00266bd0(void) { REA_TAILCALL_RVA(0x992240); }

/* file+0xdf8, RVA 0x266bd8; ev_3f75af667211e2d8e540691d10f3bbf681134cb6ec9e20adce86965c18d22721 */
void trampoline_00266bd8(void) { REA_TAILCALL_RVA(0xf5400); }

/* file+0xe00, RVA 0x266be0; ev_56ff781a8def7c5d5a6077366d4f2acfd64e0ee5acb62ea2a21cc407a9470d00 */
void trampoline_00266be0(void) { REA_TAILCALL_RVA(0x9a2320); }

/* file+0xe08, RVA 0x266be8; ev_5d34413a472ad44913e018fd14bb24cc8110bfea5c5fab6c1c4370918447a5a0 */
void trampoline_00266be8(void) { REA_TAILCALL_RVA(0x9a5720); }

/* file+0xe10, RVA 0x266bf0; ev_7f2bc6e9e363313da4b94f86d69fc65e8ce15fd6b72996b8eb4447753724ad46 */
void trampoline_00266bf0(void) { REA_TAILCALL_RVA(0x9ac9a0); }

/* file+0xe18, RVA 0x266bf8; ev_cc3dc8f399dd62c54a45b7883957319dad4c6906ac9b813b8e499eee05f275f1 */
void trampoline_00266bf8(void) { REA_TAILCALL_RVA(0x9aca20); }

/* file+0xe20, RVA 0x266c00; ev_bf79028dd32f9a3aecd31fb1995effbb13d7b1d3c1e705c1258ebd73e6865e88 */
void trampoline_00266c00(void) { REA_TAILCALL_RVA(0x1be640); }

/* file+0xe28, RVA 0x266c08; ev_fe5b924c62fec762e1733bc34aee255b89fb8280b37ed097fe9bd69db49a3e37 */
void trampoline_00266c08(void) { REA_TAILCALL_RVA(0x9bed20); }

/* file+0xe30, RVA 0x266c10; ev_ef5d7b4673ff37d4dec831f0bc16e1a2cab04192296e37f7bdcf8e56f5544822 */
void trampoline_00266c10(void) { REA_TAILCALL_RVA(0x9c6050); }

/* file+0xe38, RVA 0x266c18; ev_5e9312093fd4bdf372388e922fab88e982f266860a6811f25038a5d2f8823995 */
void trampoline_00266c18(void) { REA_TAILCALL_RVA(0x9c60d0); }

/* file+0xe40, RVA 0x266c20; ev_8e6dc25e56f3e164d487a9bc8906b5c20890b0d1caa6d3704f7543a5b7e71859 */
void trampoline_00266c20(void) { REA_TAILCALL_RVA(0x9c6280); }

/* file+0xe48, RVA 0x266c28; ev_41e7d7079056a546692d9079f2de0da6935c37650b925dad07ac01fb6c98c89e */
void trampoline_00266c28(void) { REA_TAILCALL_RVA(0x9c6310); }

/* file+0xe50, RVA 0x266c30; ev_58024a47f12a22fb9ff6072374a74966aaab3736da708b543a86a38dbb16a8e2 */
void trampoline_00266c30(void) { REA_TAILCALL_RVA(0x9c6490); }

/* file+0xe58, RVA 0x266c38; ev_c18f48633c9c7fc4f4ad3777f2d9488a592cc33823e5da44d7c82065fca79a63 */
void trampoline_00266c38(void) { REA_TAILCALL_RVA(0x9c65b0); }

/* file+0xe60, RVA 0x266c40; ev_62678f2efe4d3a901885cf56c3dc40c1d797bf0b88a8c6e869f02cd84e48f2f3 */
void trampoline_00266c40(void) { REA_TAILCALL_RVA(0x9c6890); }

/* file+0xe68, RVA 0x266c48; ev_2220a70e6e018d2fd9aa8b53201361575e4cfda0a842b727c366e6fc935e5224 */
void trampoline_00266c48(void) { REA_TAILCALL_RVA(0x9c9340); }

/* file+0xe70, RVA 0x266c50; ev_f2e585a8947df08446c0cf2e044d710808a1a0c0cd0484142d9978f9c337dc4e */
void trampoline_00266c50(void) { REA_TAILCALL_RVA(0x9c9360); }

/* file+0xe78, RVA 0x266c58; ev_14b7d3eebc84aee12f3c344b85f58ad97f1068109c0ef24eb256f76e35794211 */
void trampoline_00266c58(void) { REA_TAILCALL_RVA(0x9c9370); }

/* file+0xe80, RVA 0x266c60; ev_a250137cccf6b64efc3a19383dc26f8f8d2e69ba38cda1dc0a01cc7cdce73dea */
void trampoline_00266c60(void) { REA_TAILCALL_RVA(0x9c9380); }

/* file+0xe88, RVA 0x266c68; ev_7a6537f0afa41ab205515af298b4d6326435119c777fa657c61f331f8d7cd629 */
void trampoline_00266c68(void) { REA_TAILCALL_RVA(0x9dadb0); }

/* file+0xe90, RVA 0x266c70; ev_d7a97caf46ccd4849acf610eda004377b81ab6f48fa6f4a7e38a76dd2c412ca6 */
void trampoline_00266c70(void) { REA_TAILCALL_RVA(0x9dafa0); }

/* file+0xe98, RVA 0x266c78; ev_9db19b508ff0f1dd20473447aaba9306fd277ff212b932fcd419101f210af786 */
void trampoline_00266c78(void) { REA_TAILCALL_RVA(0x9dc860); }

/* file+0xea0, RVA 0x266c80; ev_51b5179d775ef8536adce96534b998a9f33db0e3ddd1115b1f88b4dfabc9aae4 */
void trampoline_00266c80(void) { REA_TAILCALL_RVA(0x9dcc40); }

/* file+0xea8, RVA 0x266c88; ev_877efe1974f6e42a1eb2c4b1f9aa5032c87f8516132e604402792672762f1632 */
void trampoline_00266c88(void) { REA_TAILCALL_RVA(0x9dce80); }

/* file+0xeb0, RVA 0x266c90; ev_5cb4e01c20856c1ab41fcd0cc1847419396536cdb3b98f1a41d454b58ce2255b */
void trampoline_00266c90(void) { REA_TAILCALL_RVA(0x9dd500); }

/* file+0xeb8, RVA 0x266c98; ev_01f90996cffaa31df8cdd456b7a1cf62f95013537ae8335af16b251c4b6be9bf */
void trampoline_00266c98(void) { REA_TAILCALL_RVA(0xcaacd0); }

/* file+0xec0, RVA 0x266ca0; ev_6762029a214a918b292d61d14b76beeaf90beb8630895c87a8a9d4131b3b753b */
void trampoline_00266ca0(void) { REA_TAILCALL_RVA(0x9dd7d0); }

/* file+0xec8, RVA 0x266ca8; ev_8113593603df52e68c7891f7ba64a5bbb1c329f4b8c50a2f6fcfea0f03bb21a9 */
void trampoline_00266ca8(void) { REA_TAILCALL_RVA(0x9dd990); }

/* file+0xed0, RVA 0x266cb0; ev_fa732a33f19d9e8bdfadf1cf186595d63534796df8a18d550798038c65728ffe */
void trampoline_00266cb0(void) { REA_TAILCALL_RVA(0x9ddba0); }

/* file+0xed8, RVA 0x266cb8; ev_891199045096857859426065c3edf6ba347ef02904e51e71e311356f7da4e20e */
void trampoline_00266cb8(void) { REA_TAILCALL_RVA(0x9ddc00); }

/* file+0xee0, RVA 0x266cc0; ev_48195daa010756a9d5edf86a50fc5a96e3ca15ab54299cd4bf405df5659b90d2 */
void trampoline_00266cc0(void) { REA_TAILCALL_RVA(0x9dde50); }

/* file+0xee8, RVA 0x266cc8; ev_7385da84180541489dbeb1ce2d65011761c910f8c11643ae0d549a7ec87a3810 */
void trampoline_00266cc8(void) { REA_TAILCALL_RVA(0x9ddeb0); }

/* file+0xef0, RVA 0x266cd0; ev_e78b1dbdf382c31f504e805f5823b90ac8abf7e8a9036607d3dac5d998b392f5 */
void trampoline_00266cd0(void) { REA_TAILCALL_RVA(0x9ddff0); }

/* file+0xef8, RVA 0x266cd8; ev_8dffe08cbdaffa63c21bc489f045e2c7abaea3c0d3a669675de55ab9e0fd5467 */
void trampoline_00266cd8(void) { REA_TAILCALL_RVA(0x9de070); }

/* file+0xf00, RVA 0x266ce0; ev_26d7006899695cd15879882e36ae0665462dc5664e8d3b158bd6baede970bb39 */
void trampoline_00266ce0(void) { REA_TAILCALL_RVA(0x9de0f0); }

/* file+0xf08, RVA 0x266ce8; ev_725401c8b87f9798788fe66ae7a58ddcf28e8d437e9b188dccee27ca88175adf */
void trampoline_00266ce8(void) { REA_TAILCALL_RVA(0x9e0b90); }

/* file+0xf10, RVA 0x266cf0; ev_6009f5593a7aec2c15a218f65f445350f0cf1f4c97c49449b931bad324f8841b */
void trampoline_00266cf0(void) { REA_TAILCALL_RVA(0x9e0cd0); }

/* file+0xf18, RVA 0x266cf8; ev_14cb4be080af8c10856a0f9228373d81916145cccf76a9072df1d54a46ada53f */
void trampoline_00266cf8(void) { REA_TAILCALL_RVA(0x9e0d70); }

/* file+0xf20, RVA 0x266d00; ev_531f2bb27dd103d66980d4a870f876715e91dce6f98e7733948b054fb0e2b47f */
void trampoline_00266d00(void) { REA_TAILCALL_RVA(0x9e0ef0); }

/* file+0xf28, RVA 0x266d08; ev_9d5e393467299b055bf138d47f082bcd36b7966a7568a87177155ef29748502d */
void trampoline_00266d08(void) { REA_TAILCALL_RVA(0x9e1050); }

/* file+0xf30, RVA 0x266d10; ev_bdc0c3ab5bf2d8cdeee10ff9c353dfbf9573f2623a21ab4cf7aaef889124baa8 */
void trampoline_00266d10(void) { REA_TAILCALL_RVA(0x9e1490); }

/* file+0xf38, RVA 0x266d18; ev_0333cb01e8fee3b4c82d5df641940c9d38f7b34eefe97f058582c5164b07bfee */
void trampoline_00266d18(void) { REA_TAILCALL_RVA(0xa065e0); }

/* file+0xf40, RVA 0x266d20; ev_7000e38c43828d71a94c2c9c5823533ea44fa754e1a9d8ad78f55e3b6bb444d9 */
void trampoline_00266d20(void) { REA_TAILCALL_RVA(0x101340); }

/* file+0xf48, RVA 0x266d28; ev_a77c6b14129598fd154595f0397b32898c2887755f24bd724c0c036072fb71e1 */
void trampoline_00266d28(void) { REA_TAILCALL_RVA(0xa32f30); }

/* file+0xf50, RVA 0x266d30; ev_642fcc0d2dc19107bcc0a1fb3ad893ff3f11d66a814365bfa028ed0c4afaf762 */
void trampoline_00266d30(void) { REA_TAILCALL_RVA(0xa336c0); }

/* file+0xf58, RVA 0x266d38; ev_891eacefa8be6354542a60d3105a91ac3b6e8eeb990797ff73c6a30bd9ad9dd7 */
void trampoline_00266d38(void) { REA_TAILCALL_RVA(0xa38c90); }

/* file+0xf60, RVA 0x266d40; ev_7b86984dcd39baef8533e1153128c057404054459aca3727bcb2745fbc3932a3 */
void trampoline_00266d40(void) { REA_TAILCALL_RVA(0xa6ab00); }

/* file+0xf68, RVA 0x266d48; ev_09d95c1a649a49c5802eab9ed3d9ca2a581757a58b161bd072fd839f90bfc27e */
void trampoline_00266d48(void) { REA_TAILCALL_RVA(0xa6abb0); }

/* file+0xf70, RVA 0x266d50; ev_3f69426cb08d4fdbfa85ea3c19f521b93f1d0371b67c4b0fe5f82ae5896fce82 */
void trampoline_00266d50(void) { REA_TAILCALL_RVA(0xa8ec10); }

/* file+0xf78, RVA 0x266d58; ev_41b6abb43b84dcd4f462c84b74b4de050784b8a70c50e4a5d47032ada0eae65f */
void trampoline_00266d58(void) { REA_TAILCALL_RVA(0xa8ee00); }

/* file+0xf80, RVA 0x266d60; ev_630c7550490604ef5015ce8c43c8b03e209631a473f112bfdfd4a360caf4f29c */
void trampoline_00266d60(void) { REA_TAILCALL_RVA(0xab17b0); }

/* file+0xf88, RVA 0x266d68; ev_7cfbc6317cb0e66bd88db818b24c2377343fed3137e622ea90456f0b15e24200 */
void trampoline_00266d68(void) { REA_TAILCALL_RVA(0xac07b0); }

/* file+0xf90, RVA 0x266d70; ev_7c2de2fb0e8fb6ec09d5a57cf3dc7a89b924412fae168ae1dfe2ce8c047dfc97 */
void trampoline_00266d70(void) { REA_TAILCALL_RVA(0xac2af0); }

/* file+0xf98, RVA 0x266d78; ev_ee20a4ea1316a20c37831a9a1c2e2ac589b21a05d15d67bac39d999ff73d9180 */
void trampoline_00266d78(void) { REA_TAILCALL_RVA(0x11a750); }

/* file+0xfa0, RVA 0x266d80; ev_17e440d9c68bb5f5cf7e117f55b6c7f287296e343042fe5254af97979b85373c */
void trampoline_00266d80(void) { REA_TAILCALL_RVA(0xae12a0); }

/* file+0xfa8, RVA 0x266d88; ev_6c9536e353b048a2bf8d8b2ee29723ea887247c116a19260031e9459e4f4456d */
void trampoline_00266d88(void) { REA_TAILCALL_RVA(0xae3400); }

/* file+0xfb0, RVA 0x266d90; ev_b4d5171290b9db611d7737dfecb19b7a2a960ecf3063949e848440bb9e2f8152 */
void trampoline_00266d90(void) { REA_TAILCALL_RVA(0xae3530); }

/* file+0xfb8, RVA 0x266d98; ev_3a3473afb0498b406c2a13a0945c6549a63a35567410f4189489b345db53d3ca */
void trampoline_00266d98(void) { REA_TAILCALL_RVA(0xae63c0); }

/* file+0xfc0, RVA 0x266da0; ev_4b9d94413c8f8add96e5c1b75e2ad52058187a16c583a68953b2900c872fefe0 */
void trampoline_00266da0(void) { REA_TAILCALL_RVA(0xb07ee0); }

/* file+0xfc8, RVA 0x266da8; ev_8a66cef6757b0ccccdff69f40b61fde5372c024a084481d9b613dfb810c0e4d3 */
void trampoline_00266da8(void) { REA_TAILCALL_RVA(0xb08190); }

/* file+0xfd0, RVA 0x266db0; ev_6af85e975e401aa788119000d4cbf9526212867797b15e30303f69a8a280e1e8 */
void trampoline_00266db0(void) { REA_TAILCALL_RVA(0xb08530); }

/* file+0xfd8, RVA 0x266db8; ev_53345b6e27c82ac731ae359c279305a95996a638377232d8afca2899cdc8a044 */
void trampoline_00266db8(void) { REA_TAILCALL_RVA(0xb08810); }

/* file+0xfe0, RVA 0x266dc0; ev_f5240a95a49d151a0c53b5c99b882503773b40ee910c17438dc41d76d4689430 */
void trampoline_00266dc0(void) { REA_TAILCALL_RVA(0xb096a0); }

/* file+0xfe8, RVA 0x266dc8; ev_34fd32009a627d6b8ebf0116dc6a3b81c6c0246111b0af1efdb9dbb728300c5d */
void trampoline_00266dc8(void) { REA_TAILCALL_RVA(0xb0b4f0); }

/* file+0xff0, RVA 0x266dd0; ev_d25f3e548cbb3d504c6a607f21c51f64733681e9fdf4ae6d1e278fb2ed786275 */
void trampoline_00266dd0(void) { REA_TAILCALL_RVA(0x1ef0f0); }

/* file+0xff8, RVA 0x266dd8; ev_ecbf7c5bd00f93b0efe3cf1a132b3e3cb5f43485e637ad081720a67e63c99257 */
void trampoline_00266dd8(void) { REA_TAILCALL_RVA(0x1f0060); }

