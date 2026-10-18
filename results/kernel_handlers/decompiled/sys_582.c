/* handler_582: recovered C pseudocode and analyst type overlays.
 * Source SHA256 c22afc5c7cc3a6c3a1387f51b7dfa46b1ee55bb4b399853fd85ca6e05596c78e
 * Original load RVA 0x265760; actual target RVA 0x5620e0.
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


/* ANALYST SIGNATURE OVERLAY: int nosys_impl(struct recovered_thread *td); */


/* ANALYST TYPED RECONSTRUCTION; helper names describe inferred roles.
 * Exact RVA 0x5620e0 control flow, apart from compiler canary boilerplate. */
int recovered_nosys(struct recovered_thread *td) {
    uint8_t siginfo[0x70] = {0};
    process_lock_at_0x4c6a00(td->proc->lock);
    *(uint32_t *)(siginfo + 0x10) = 12;
    *(uint32_t *)(siginfo + 0x18) = 0x10006;
    signal_helper_at_0x560540(td->proc, td, 12, siginfo);
    process_unlock_at_0x4c6fa0(td->proc->lock);
    return 78;
}


/* ===== PRIMARY IMPLEMENTATION: VERBATIM REA/GHIDRA OUTPUT ===== */


/* Primary RVA 0x5620e0; body 0x5620e0..0x562187
 * Evidence ev_2658f48f8239cba056b76e092f6c8ff2fd755f66f67fe2b407957e058aade6cd; generated signature undefined processEntry nosys_impl()
 * Warnings in the text are retained; halt_baddata may be an unmapped-call artifact.
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 processEntry nosys_impl(void)

{
  code *pcVar1;
  long lVar2;
  long in_RDI;
  undefined1 local_a0 [16];
  undefined4 local_90;
  undefined4 local_88;
  long local_30;
  
  local_30 = _DAT_0391c310;
  lVar2 = *(long *)(in_RDI + 8) + 0x148;
  func_0x004c6a00(lVar2,0,0,0);
  func_0x00258ff0(local_a0,0x70);
  local_90 = 0xc;
  local_88 = 0x10006;
  func_0x00560540(*(undefined8 *)(in_RDI + 8));
  func_0x004c6fa0(lVar2,0,0,0);
  if (_DAT_0391c310 == local_30) {
    return 0x4e;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== COMPLETE SUPPLIED WINDOW: NORMALIZED TRAMPOLINE PSEUDOCODE =====
 * Ghidra reports many unmapped destinations as halt_baddata(). That is a
 * decompiler artifact: each verified instruction is JMP rel32. The explicit
 * tailcall form below is analyst normalization of the REA assembly, with
 * target address calculated from the original bytes. It does not claim to
 * decompile unavailable destination bodies or infer their argument lists.
 * Offset-zero entry is this syscall. The remaining 511 entries are neighbors.
 */

/* file+0x000, RVA 0x265760; ev_e92085eadeac8e7ca153ee0c0f49b1713e3f01f15dc16eadf735f2b06307b9e0 */
void trampoline_00265760(void) { REA_TAILCALL_RVA(0x5620e0); }

/* file+0x008, RVA 0x265768; ev_9074af6b7e1bf94a2c60d13320aeca82671b2dbf9264faf91c8da60d6353ef8e */
void trampoline_00265768(void) { REA_TAILCALL_RVA(0x3b6020); }

/* file+0x010, RVA 0x265770; ev_d8ce2cf5ddb7f2f22564ff70a99b2478fec6de4603c5dbab5edb37a56341450c */
void trampoline_00265770(void) { REA_TAILCALL_RVA(0x3b6240); }

/* file+0x018, RVA 0x265778; ev_89ca9d6a6289c134791f6ff8f46c5eeae899b428e66e46e426741220e01b6eb7 */
void trampoline_00265778(void) { REA_TAILCALL_RVA(0x3c1e10); }

/* file+0x020, RVA 0x265780; ev_232e3671278b7d86d1a663bed481aa55a51b80e25caeef4228653bb1e6f42066 */
void trampoline_00265780(void) { REA_TAILCALL_RVA(0x3c2240); }

/* file+0x028, RVA 0x265788; ev_ed1dce5648c6c01dd1106268b10bfc36fa79895d1955f5a12b78f850cbc010e1 */
void trampoline_00265788(void) { REA_TAILCALL_RVA(0x12f7e0); }

/* file+0x030, RVA 0x265790; ev_28a25352a34a9e96ef90fbe576d5e218fb86b32d9e01907fbddf690380f669cd */
void trampoline_00265790(void) { REA_TAILCALL_RVA(0x3ce150); }

/* file+0x038, RVA 0x265798; ev_72b5f4a9f287ed3b399f6cee3a0b4cca5044d8acb62aeb134fe7cf5ace9cf0c6 */
void trampoline_00265798(void) { REA_TAILCALL_RVA(0x3d52b0); }

/* file+0x040, RVA 0x2657a0; ev_00610a4e46cc51b9a0bc7ed987b685bd23c10130940583036c09eaea7fdad383 */
void trampoline_002657a0(void) { REA_TAILCALL_RVA(0x3e5aa0); }

/* file+0x048, RVA 0x2657a8; ev_6d9a753b8c4e8a25fa0ff1e62bacd2c42ceb679020f1cac63c33b33a91725f4a */
void trampoline_002657a8(void) { REA_TAILCALL_RVA(0x3e5ad0); }

/* file+0x050, RVA 0x2657b0; ev_50bac01de1cc7ccf6b621adaa1b487db7b77d7e857101def5ab85bcb97aa8548 */
void trampoline_002657b0(void) { REA_TAILCALL_RVA(0x3e5af0); }

/* file+0x058, RVA 0x2657b8; ev_4ff51b1e3613f06661533bff14406529a09eb00bf903169d4ea66a3d584746dd */
void trampoline_002657b8(void) { REA_TAILCALL_RVA(0x3ec340); }

/* file+0x060, RVA 0x2657c0; ev_2764dd3a184060277b8b12b038a73d3bd60e2650775093524d0c062902c75414 */
void trampoline_002657c0(void) { REA_TAILCALL_RVA(0x3f05c0); }

/* file+0x068, RVA 0x2657c8; ev_b8e4e469ba4170d6b55b345dfdfb1581ce6141d208e6619175ba91cad77d546d */
void trampoline_002657c8(void) { REA_TAILCALL_RVA(0x3f2810); }

/* file+0x070, RVA 0x2657d0; ev_d9359f6900ac36f9ef5e1f3c4f6dc6eb272ca56b1aafb9f63a59153c6e5ac0e2 */
void trampoline_002657d0(void) { REA_TAILCALL_RVA(0x3f2b60); }

/* file+0x078, RVA 0x2657d8; ev_fd677fd8080a959ad3693477adffb42a1cd818b34e76bf44ba87398db0cb1968 */
void trampoline_002657d8(void) { REA_TAILCALL_RVA(0x50ce20); }

/* file+0x080, RVA 0x2657e0; ev_37a21de58dd785c2394d86e8ee5fe5721d3bf5a27853ea5c2169bdb007f5f4bc */
void trampoline_002657e0(void) { REA_TAILCALL_RVA(0x3f3f90); }

/* file+0x088, RVA 0x2657e8; ev_3dbed447f555f41200425b2594ddcfa9b09c745604168772c1afc45e14e4b051 */
void trampoline_002657e8(void) { REA_TAILCALL_RVA(0x409790); }

/* file+0x090, RVA 0x2657f0; ev_e2d20361e6fdfdcd4d0cf97641f025b0e901995c76a1ff1a973c3c4017e52a22 */
void trampoline_002657f0(void) { REA_TAILCALL_RVA(0xbe7240); }

/* file+0x098, RVA 0x2657f8; ev_44c6a294fc44a5e668125191f2a268c907be028e308a5a7975466da8ffce75f0 */
void trampoline_002657f8(void) { REA_TAILCALL_RVA(0xcb1390); }

/* file+0x0a0, RVA 0x265800; ev_bb490750128888dff9254b9b782f8aeef7fcee69c3b71356e548dcbec88ae4b3 */
void trampoline_00265800(void) { REA_TAILCALL_RVA(0x4ec000); }

/* file+0x0a8, RVA 0x265808; ev_412fb701ad4a40bf2e9cba9aeadf416688d97d703fe8773fd99e42b4b6f5e173 */
void trampoline_00265808(void) { REA_TAILCALL_RVA(0x4ec560); }

/* file+0x0b0, RVA 0x265810; ev_23e8738ec05e26aa6662143787fd7fe68a464bdc9ae8459279026428120f7733 */
void trampoline_00265810(void) { REA_TAILCALL_RVA(0x8f6e00); }

/* file+0x0b8, RVA 0x265818; ev_012785a1d85f5acaaee28f820968b4a3df33848d70b6400c7f1d02c7c288fc05 */
void trampoline_00265818(void) { REA_TAILCALL_RVA(0x72bf00); }

/* file+0x0c0, RVA 0x265820; ev_2bec6084e9c1c2aa4e2fd82d0f8e50db4a47e6e78b24f76cf67f7702b000184e */
void trampoline_00265820(void) { REA_TAILCALL_RVA(0xbe8290); }

/* file+0x0c8, RVA 0x265828; ev_cfb42585584209440c11fced8538c41bfe0289f21273c17e4be30edff68bf6b5 */
void trampoline_00265828(void) { REA_TAILCALL_RVA(0x8f8550); }

/* file+0x0d0, RVA 0x265830; ev_31e60e31e57c7f6722372cabd9996527fe6510612047b2f711bce4ab2a129122 */
void trampoline_00265830(void) { REA_TAILCALL_RVA(0x8f6b20); }

/* file+0x0d8, RVA 0x265838; ev_0af698da830b64ad7518c08cb820c1a033297c79fbc0350a379a9ce2b25f1d7b */
void trampoline_00265838(void) { REA_TAILCALL_RVA(0x8f9b40); }

/* file+0x0e0, RVA 0x265840; ev_df25b717b600f9d8666341fbbcf3251f7544568ccb67d57abc0d55e5230283ab */
void trampoline_00265840(void) { REA_TAILCALL_RVA(0x5329e0); }

/* file+0x0e8, RVA 0x265848; ev_8294c3b67ba9c29dcec7d93df89f3ef57fbf2434440aed30bd5df6a8cb8db929 */
void trampoline_00265848(void) { REA_TAILCALL_RVA(0x5321e0); }

/* file+0x0f0, RVA 0x265850; ev_3a37ffa4d4ec51c7495cf844f2aeb5febc5dee82f79f0694da15ac0276b41165 */
void trampoline_00265850(void) { REA_TAILCALL_RVA(0x5328d0); }

/* file+0x0f8, RVA 0x265858; ev_239591f0da8ccbe062d63c5c40a76897d633bf1260a32bf43841628d6b5b64f2 */
void trampoline_00265858(void) { REA_TAILCALL_RVA(0x531080); }

/* file+0x100, RVA 0x265860; ev_76fdf937818922bce9d9e73aed19b941e0410fa873c017a4ec08e31213d0f222 */
void trampoline_00265860(void) { REA_TAILCALL_RVA(0x533310); }

/* file+0x108, RVA 0x265868; ev_340839838e99173ecf445ffa9d9309155565b70614e986efe6d407b259498fd6 */
void trampoline_00265868(void) { REA_TAILCALL_RVA(0x533030); }

/* file+0x110, RVA 0x265870; ev_98ef3f4147eea7c49d8261e52ce53ec2982b602c9b0768847462a9b192679ce3 */
void trampoline_00265870(void) { REA_TAILCALL_RVA(0x8f8be0); }

/* file+0x118, RVA 0x265878; ev_7bba069dcde5a52d7a9c923caf2ae69dfbd31bafe8777101253e8ff84ede1c67 */
void trampoline_00265878(void) { REA_TAILCALL_RVA(0x8f95b0); }

/* file+0x120, RVA 0x265880; ev_913065e94beac7b90e6a51c2ffa21aa89d65241519714d38b1fc1cf10bfc4112 */
void trampoline_00265880(void) { REA_TAILCALL_RVA(0x8f9760); }

/* file+0x128, RVA 0x265888; ev_4e26ddac2d219c51a3b790915c0570a97ce83781c9064ff8e55ad55a4fc2abb8 */
void trampoline_00265888(void) { REA_TAILCALL_RVA(0x8f5d20); }

/* file+0x130, RVA 0x265890; ev_fd29020300bd244e1edce4adcc769b3ad803edc4c4cdc006a9f175de9671b0aa */
void trampoline_00265890(void) { REA_TAILCALL_RVA(0x55f5b0); }

/* file+0x138, RVA 0x265898; ev_dcb1e7b5b9fc0db976f0173a206902fd5317288d9bab59ff78d406c25cd2071d */
void trampoline_00265898(void) { REA_TAILCALL_RVA(0x729d80); }

/* file+0x140, RVA 0x2658a0; ev_565d12cbf446e153f4b981e0710b2908327f3e5a261f16add7354a01fb5073dd */
void trampoline_002658a0(void) { REA_TAILCALL_RVA(0x802d90); }

/* file+0x148, RVA 0x2658a8; ev_ad423e6a68ae54a136303f1ead48f7ed49611fc048963413e49a8891f7cacadc */
void trampoline_002658a8(void) { REA_TAILCALL_RVA(0x45e4d0); }

/* file+0x150, RVA 0x2658b0; ev_b86f11c34b308c27ac0a4bdffe2989abfa64898f7a46f59ec30833e70b58f1e2 */
void trampoline_002658b0(void) { REA_TAILCALL_RVA(0x55f400); }

/* file+0x158, RVA 0x2658b8; ev_6b9a6ddc77030251b2d5c7681649637fb915dc9fba0d9ef8d080d130608102d8 */
void trampoline_002658b8(void) { REA_TAILCALL_RVA(0x4ecf40); }

/* file+0x160, RVA 0x2658c0; ev_df6809fd8fba416214b7b808b0cf826c6c33d45e9ac2724ca036ad60d0f16a09 */
void trampoline_002658c0(void) { REA_TAILCALL_RVA(0x7e4810); }

/* file+0x168, RVA 0x2658c8; ev_fefbbb3be8bbd1f906fc7e68752189b317cb4e8386c95fb170befeb79057637f */
void trampoline_002658c8(void) { REA_TAILCALL_RVA(0x8fc490); }

/* file+0x170, RVA 0x2658d0; ev_5dd230e7f62501d4dc4c7106cbcb033ca6fe29e9934ad03db76a0dc8f9a90c9f */
void trampoline_002658d0(void) { REA_TAILCALL_RVA(0x6e2dc0); }

/* file+0x178, RVA 0x2658d8; ev_def82242ae0e9f337c27c1d6c9e481f8b244f8aacd6bd29e330aacff7d5c2804 */
void trampoline_002658d8(void) { REA_TAILCALL_RVA(0xab8af0); }

/* file+0x180, RVA 0x2658e0; ev_3ee3220244ada631bc9c3aaba150880b3135f13b9e02397dfd9ebd8ee8d886ff */
void trampoline_002658e0(void) { REA_TAILCALL_RVA(0xab8bb0); }

/* file+0x188, RVA 0x2658e8; ev_6cc51d0e7c39f5b21ae5cc0b7cd60e7c50dba66e6e2b2515d027de3042b0aa7a */
void trampoline_002658e8(void) { REA_TAILCALL_RVA(0xab8d20); }

/* file+0x190, RVA 0x2658f0; ev_f39d74ea16d228d392a0d70410f0bbda4cb8daf50b986cfc77d5a9dfc6463787 */
void trampoline_002658f0(void) { REA_TAILCALL_RVA(0xab8e00); }

/* file+0x198, RVA 0x2658f8; ev_f869111cad9511b96b42f17674b546bf2281cdb53d4652ea4fd5cc4bc44acb13 */
void trampoline_002658f8(void) { REA_TAILCALL_RVA(0xab8ec0); }

/* file+0x1a0, RVA 0x265900; ev_1010e5f792bad48bf4b6db23dc275150f7e7c0427c5c502a129bc293970bc156 */
void trampoline_00265900(void) { REA_TAILCALL_RVA(0x6bccc0); }

/* file+0x1a8, RVA 0x265908; ev_19e71e3893c42ad9fba326abe76f7b8732cb3b83e31e440adfe4452467311e0f */
void trampoline_00265908(void) { REA_TAILCALL_RVA(0x6bca20); }

/* file+0x1b0, RVA 0x265910; ev_a3edcfb71be0e3c760712afc471d352b96bbf8300f816dee82a832bdd6da5a92 */
void trampoline_00265910(void) { REA_TAILCALL_RVA(0x7299f0); }

/* file+0x1b8, RVA 0x265918; ev_a3407a6d9f4cdb2afe7c17d2db068237238ac1634ef90fd2bf0f9e2e7b4b5de9 */
void trampoline_00265918(void) { REA_TAILCALL_RVA(0x729a40); }

/* file+0x1c0, RVA 0x265920; ev_c0a70d027cbb681e3310f6d432af5f8766d44f98fea63f4efe61508052c1e875 */
void trampoline_00265920(void) { REA_TAILCALL_RVA(0x729dc0); }

/* file+0x1c8, RVA 0x265928; ev_aeffa6ca1e2b8cc51a7ce0b3fa762b78d6c564da1ae373f19e7a975b9aa9ed49 */
void trampoline_00265928(void) { REA_TAILCALL_RVA(0x4ee4b0); }

/* file+0x1d0, RVA 0x265930; ev_3cf99574b8b1d3aefad0fba954304dac35f8eb61c5b00ee97e44aced33d92e4f */
void trampoline_00265930(void) { REA_TAILCALL_RVA(0x8fb430); }

/* file+0x1d8, RVA 0x265938; ev_99b0efcac2f2519552c5bbcf716b54986eb1d58e8f33e1696d6aa0070c1af0d5 */
void trampoline_00265938(void) { REA_TAILCALL_RVA(0x49ff80); }

/* file+0x1e0, RVA 0x265940; ev_d8d968be5c2596499373fefb5914c39f98e9f647cbec08496c4c18754cf1164d */
void trampoline_00265940(void) { REA_TAILCALL_RVA(0x52f8f0); }

/* file+0x1e8, RVA 0x265948; ev_a3d3b41862af69058d5869ac8e55e5a4076dfce0dff1c31a7ee3d52fee889c2b */
void trampoline_00265948(void) { REA_TAILCALL_RVA(0x531260); }

/* file+0x1f0, RVA 0x265950; ev_7bcccadfc8cf99be916917664cefcbeab1e75a6a055882ca5f5c6f6218fd12e0 */
void trampoline_00265950(void) { REA_TAILCALL_RVA(0x52fce0); }

/* file+0x1f8, RVA 0x265958; ev_07c82620e6122eb8454a53bcc78808a18b4cde97e71117b243125916b79934dc */
void trampoline_00265958(void) { REA_TAILCALL_RVA(0x49fcf0); }

/* file+0x200, RVA 0x265960; ev_800ae0cf8200ab2c4b7ccf5c8366aef72c11b75aebdd6f22d0b94ffc05a0768b */
void trampoline_00265960(void) { REA_TAILCALL_RVA(0x52fd00); }

/* file+0x208, RVA 0x265968; ev_4800183a926c7e59c04ebebb8313436b07fe5122e00cfea2b3471e8dd3163a75 */
void trampoline_00265968(void) { REA_TAILCALL_RVA(0x52fe00); }

/* file+0x210, RVA 0x265970; ev_861c38fb561ae9af6ba432628538a7dce26218d62b4f4edf1e56d554480377cd */
void trampoline_00265970(void) { REA_TAILCALL_RVA(0x530480); }

/* file+0x218, RVA 0x265978; ev_5274561d310a40a0ad2f1be0ea41b7d51bd10bb95f2def598a02411077b2d014 */
void trampoline_00265978(void) { REA_TAILCALL_RVA(0x532bc0); }

/* file+0x220, RVA 0x265980; ev_49576506704afced15484bf88a42420071f10d71a492fd6fd4eacbdd7112b110 */
void trampoline_00265980(void) { REA_TAILCALL_RVA(0x5307d0); }

/* file+0x228, RVA 0x265988; ev_1cd470f9ecaae0a27bd42648f874b291573114f3b04cf87825333c68b58cebc6 */
void trampoline_00265988(void) { REA_TAILCALL_RVA(0x52fae0); }

/* file+0x230, RVA 0x265990; ev_c876efaa9fcdd91e59b2cbda59129a47d81044e2e1005258400deef8d8bcb34a */
void trampoline_00265990(void) { REA_TAILCALL_RVA(0x72c140); }

/* file+0x238, RVA 0x265998; ev_ac27ac619a6b12da8b5041663341089d964528f0178018bb62eda6940bc9a215 */
void trampoline_00265998(void) { REA_TAILCALL_RVA(0x6bc800); }

/* file+0x240, RVA 0x2659a0; ev_8a72d96f4655b5e6975b37eeae674ad54cc717044fb72812972bdfff828011e2 */
void trampoline_002659a0(void) { REA_TAILCALL_RVA(0x4a1ba0); }

/* file+0x248, RVA 0x2659a8; ev_e92ea051b341555c0c4643b07eaeb74642db76acbec15a0d369ecfb56abb6718 */
void trampoline_002659a8(void) { REA_TAILCALL_RVA(0x532cd0); }

/* file+0x250, RVA 0x2659b0; ev_03dd5e642afbb6e106d1d14c059dff6d3fa148cb275a74e45605907d63b790d2 */
void trampoline_002659b0(void) { REA_TAILCALL_RVA(0x4ec2c0); }

/* file+0x258, RVA 0x2659b8; ev_4f9e385548af081084e5643b01f8ee23154cb00f35bbb4f871440b940ed3f28f */
void trampoline_002659b8(void) { REA_TAILCALL_RVA(0x4ec8e0); }

/* file+0x260, RVA 0x2659c0; ev_606d38ed6782365af5be5c0ea4e957dee202e2317b49517f974e6382d39d0625 */
void trampoline_002659c0(void) { REA_TAILCALL_RVA(0x6bc8d0); }

/* file+0x268, RVA 0x2659c8; ev_bceb3dcf3e802b0375c7a925f8dd0c3170b18192353ce506f922cc0265052e9f */
void trampoline_002659c8(void) { REA_TAILCALL_RVA(0x8f9d40); }

/* file+0x270, RVA 0x2659d0; ev_cfd02f676c3cdb2374f748ed82cef7016248e28537559dad882c883874447eeb */
void trampoline_002659d0(void) { REA_TAILCALL_RVA(0x52fe70); }

/* file+0x278, RVA 0x2659d8; ev_5418b6e333cc45fe1e243d23f7d31b2848f71b2342af8d7678239f08fdfe5ace */
void trampoline_002659d8(void) { REA_TAILCALL_RVA(0x8fb450); }

/* file+0x280, RVA 0x2659e0; ev_d6ebd35a15d662f83878c852067263d612b4cd8efb751066903e22549b17e8a6 */
void trampoline_002659e0(void) { REA_TAILCALL_RVA(0x72e590); }

/* file+0x288, RVA 0x2659e8; ev_00eff0d27cf1f12bddfe227e8ddb1fc1a0e28fc1a53d2fe2c92b673188e822f0 */
void trampoline_002659e8(void) { REA_TAILCALL_RVA(0x531b30); }

/* file+0x290, RVA 0x2659f0; ev_f2b924b656e6c16b364a79047ff2c95dda8d40286609a8f9d5a1893fd728fddd */
void trampoline_002659f0(void) { REA_TAILCALL_RVA(0x532af0); }

/* file+0x298, RVA 0x2659f8; ev_8d42ba1978aed1302a3d18d5c69f81e7b0092f303fff75f10d55f04af348da5a */
void trampoline_002659f8(void) { REA_TAILCALL_RVA(0x531720); }

/* file+0x2a0, RVA 0x265a00; ev_dd3e4679e76638724c30cf0f358cea5477b2128900ed808330c1f5e4f0cecaf9 */
void trampoline_00265a00(void) { REA_TAILCALL_RVA(0x8fb8e0); }

/* file+0x2a8, RVA 0x265a08; ev_bdf2351cd989a3d02d373735bf6418d4d734648a32050f47e31301f70840e992 */
void trampoline_00265a08(void) { REA_TAILCALL_RVA(0x8fbbc0); }

/* file+0x2b0, RVA 0x265a10; ev_8b8bbcd7ca69ae7559e2673ebae3094935d82bff7c2c2252e1cb50a0cedec0dc */
void trampoline_00265a10(void) { REA_TAILCALL_RVA(0x8fa310); }

/* file+0x2b8, RVA 0x265a18; ev_823961d41ac6512603d1974d738d5285b4a4b36a5db30e4d2bcd9489837fb980 */
void trampoline_00265a18(void) { REA_TAILCALL_RVA(0x47b030); }

/* file+0x2c0, RVA 0x265a20; ev_d8797c8cfc5d2076514a28ad49565e4338d16d47eb461bf5a4ba5f635485462b */
void trampoline_00265a20(void) { REA_TAILCALL_RVA(0x8f8e20); }

/* file+0x2c8, RVA 0x265a28; ev_4f4a3231ecd5c3111bdb4edc911b56e7f464b59d6040ac4584278441a0122573 */
void trampoline_00265a28(void) { REA_TAILCALL_RVA(0x72c150); }

/* file+0x2d0, RVA 0x265a30; ev_d8c04825fba6e7482c9e18afa75e379ad400f16d6b35fc2f6e3bf96230c1d963 */
void trampoline_00265a30(void) { REA_TAILCALL_RVA(0x8f9260); }

/* file+0x2d8, RVA 0x265a38; ev_6651126b51adfa38687af1eb9431c22c5beb131263ee30d9014318ca6e287db7 */
void trampoline_00265a38(void) { REA_TAILCALL_RVA(0x8f9310); }

/* file+0x2e0, RVA 0x265a40; ev_07dd486f6ffe96b8796a5a25331cc5a03f3ec307d688ff8a243a1f568dcea8dd */
void trampoline_00265a40(void) { REA_TAILCALL_RVA(0x72c3e0); }

/* file+0x2e8, RVA 0x265a48; ev_2b06cd04f47163268dfaacf9de3ec25b45ca3cf00fc4a78ee25689b6c4bb4707 */
void trampoline_00265a48(void) { REA_TAILCALL_RVA(0x4a13e0); }

/* file+0x2f0, RVA 0x265a50; ev_ab3091451954995abaa54220470a8ed895ea39fc5a6faf3b266dd07074c2ec98 */
void trampoline_00265a50(void) { REA_TAILCALL_RVA(0x4a0c30); }

/* file+0x2f8, RVA 0x265a58; ev_0c6189ee93b79076f5806747c30e6deeed3c6d4e287742b1ef00e212f2c637c3 */
void trampoline_00265a58(void) { REA_TAILCALL_RVA(0x8fbbe0); }

/* file+0x300, RVA 0x265a60; ev_90a3ebb1d7ef5211c9a3988a8b2270061c8bae906e1a9188e998fdfee5c7ee81 */
void trampoline_00265a60(void) { REA_TAILCALL_RVA(0x5581e0); }

/* file+0x308, RVA 0x265a68; ev_0ee78e08e65d5ff41bbce7913eb7df8d5b997dde4f9eaa16fa9a7a0b84d62fed */
void trampoline_00265a68(void) { REA_TAILCALL_RVA(0xab9450); }

/* file+0x310, RVA 0x265a70; ev_27f5d9d9cbb3bc3abdb55df99dca585189b00149c15d32f8b263dddaf7e68ad7 */
void trampoline_00265a70(void) { REA_TAILCALL_RVA(0xab9710); }

/* file+0x318, RVA 0x265a78; ev_3bf42a305e89a37a2783049077f812a15a409d29932f8e255cde626ec329b179 */
void trampoline_00265a78(void) { REA_TAILCALL_RVA(0x8fa8e0); }

/* file+0x320, RVA 0x265a80; ev_b307c0f5da1ff1f707632ddd0270fc80a623599c19fb45f5a572024b67d7e8c3 */
void trampoline_00265a80(void) { REA_TAILCALL_RVA(0x4ee550); }

/* file+0x328, RVA 0x265a88; ev_36264ebdee5b32829545f092c7de999e341a04eec30938081685558282108d23 */
void trampoline_00265a88(void) { REA_TAILCALL_RVA(0x8fc810); }

/* file+0x330, RVA 0x265a90; ev_76fcc8d8da8936148b6534131527e442fe1c4efb352c19d1b1cac82b5538c1eb */
void trampoline_00265a90(void) { REA_TAILCALL_RVA(0x8fc820); }

/* file+0x338, RVA 0x265a98; ev_c6d10a15e2a358caa7ff5ef174d4361fc7900157a9fee571c7df80f3add0aa7f */
void trampoline_00265a98(void) { REA_TAILCALL_RVA(0x6bb670); }

/* file+0x340, RVA 0x265aa0; ev_675117347a2b779f967147fb68e4a6064884c2b58a27a20b74f1a6b325b70c49 */
void trampoline_00265aa0(void) { REA_TAILCALL_RVA(0x6bbd20); }

/* file+0x348, RVA 0x265aa8; ev_7ce7765b855c79b1d353b0c714a6391769bcf08e173544646fbe35d79130d6fb */
void trampoline_00265aa8(void) { REA_TAILCALL_RVA(0x6bc030); }

/* file+0x350, RVA 0x265ab0; ev_5b4c088d7718feda4810845b280cfe7fb5eb09e72642a3de863c1d590a8ed3f5 */
void trampoline_00265ab0(void) { REA_TAILCALL_RVA(0x6bd570); }

/* file+0x358, RVA 0x265ab8; ev_b30e3423c0e22184177876751c61ee857acde8697b9110778dec1bcabcbef0c5 */
void trampoline_00265ab8(void) { REA_TAILCALL_RVA(0x6bdfa0); }

/* file+0x360, RVA 0x265ac0; ev_46e654a69ebae0f797b5733a6f18981d9d056758a005476c35c44e00f2db12d6 */
void trampoline_00265ac0(void) { REA_TAILCALL_RVA(0x6bdfb0); }

/* file+0x368, RVA 0x265ac8; ev_13528d26e5f185efc992a6899af44a4462d26530a0aea5a1bf7a9aabf22f5259 */
void trampoline_00265ac8(void) { REA_TAILCALL_RVA(0x6be1d0); }

/* file+0x370, RVA 0x265ad0; ev_15a5d93121ccdb0f3e00d874bdadbd7e413ef5dc9ffe66f769406f0ba5c9cfc9 */
void trampoline_00265ad0(void) { REA_TAILCALL_RVA(0x6be370); }

/* file+0x378, RVA 0x265ad8; ev_65ae3e81b60c3e25dff671d5e45f2954e25f1e8de9bab3c170920df32ed3f926 */
void trampoline_00265ad8(void) { REA_TAILCALL_RVA(0x6bc4e0); }

/* file+0x380, RVA 0x265ae0; ev_fc4566112cfc58866c3c586122d18a7efc9d358b74f61875c3226470a1aa2fed */
void trampoline_00265ae0(void) { REA_TAILCALL_RVA(0xcb1ab0); }

/* file+0x388, RVA 0x265ae8; ev_cacd09384dbdb385f0f6ba97736236e3b5fb0b035be2985511a861c0b99316d1 */
void trampoline_00265ae8(void) { REA_TAILCALL_RVA(0x8fc390); }

/* file+0x390, RVA 0x265af0; ev_bb79f04cce0e84ddf4b568af8722e40cb44573db7e597202f9c7463cd8351738 */
void trampoline_00265af0(void) { REA_TAILCALL_RVA(0x4ec4e0); }

/* file+0x398, RVA 0x265af8; ev_dbb18caeefda78745acf83cd70135c830f88ceb52663c7fad7196dfa90878f2b */
void trampoline_00265af8(void) { REA_TAILCALL_RVA(0x4ecc70); }

/* file+0x3a0, RVA 0x265b00; ev_b6be72e3781c3ba6aac5dad1bdedf80e8b8a79cd856ce680f0b66c9a4185c50c */
void trampoline_00265b00(void) { REA_TAILCALL_RVA(0xb7e960); }

/* file+0x3a8, RVA 0x265b08; ev_7650e381bc9d4612ebdbead34b1987d735098bafce9f33db20a53bc5080b8051 */
void trampoline_00265b08(void) { REA_TAILCALL_RVA(0xab9580); }

/* file+0x3b0, RVA 0x265b10; ev_342be591791e10b144c3f6c968b49e0e3dd517b70a9b58dfa09b62263f38d923 */
void trampoline_00265b10(void) { REA_TAILCALL_RVA(0xab9690); }

/* file+0x3b8, RVA 0x265b18; ev_01bab16ebf80570ebf306e7c6bd0c6aa84369081912f010723159bea1901d591 */
void trampoline_00265b18(void) { REA_TAILCALL_RVA(0x5a3a60); }

/* file+0x3c0, RVA 0x265b20; ev_9c42da966452bbeafa931073a25b93fc1e83fd62330a5d2a33ecf70553e6a8fa */
void trampoline_00265b20(void) { REA_TAILCALL_RVA(0x5a3b50); }

/* file+0x3c8, RVA 0x265b28; ev_a8d9c7f62f1ebf6bf606afec9eff2b13830ee5646f8c79e7a7f9ed89155a43dc */
void trampoline_00265b28(void) { REA_TAILCALL_RVA(0x5a3c60); }

/* file+0x3d0, RVA 0x265b30; ev_c2f5daf499772fd7ac7d3e756157e7e2beaa56b1c8c548b98272621081db5a01 */
void trampoline_00265b30(void) { REA_TAILCALL_RVA(0x5a3d80); }

/* file+0x3d8, RVA 0x265b38; ev_32975a0dbb9038431e0f8ceefaf05c2e972d1e13173defffc3e2071a8586fb1d */
void trampoline_00265b38(void) { REA_TAILCALL_RVA(0x5a3e70); }

/* file+0x3e0, RVA 0x265b40; ev_ae5d9dd4c76bc108eb288b1f33da6da31bebea5dbf494c9abb5105361e241725 */
void trampoline_00265b40(void) { REA_TAILCALL_RVA(0x5a3e90); }

/* file+0x3e8, RVA 0x265b48; ev_590120d535c4ced62c3557dec61e66b60b485f138a599fc30fc34498209be887 */
void trampoline_00265b48(void) { REA_TAILCALL_RVA(0x5a3ef0); }

/* file+0x3f0, RVA 0x265b50; ev_70c75910bb6e5014b7cbfd9f715f0ee4e6720b8544b031b9eb94b8d1d6c792c0 */
void trampoline_00265b50(void) { REA_TAILCALL_RVA(0x5a3f50); }

/* file+0x3f8, RVA 0x265b58; ev_6e3f0aae637cbc38fac90e903d4a3c9f94681abc17dea7181d13d76f5845e19d */
void trampoline_00265b58(void) { REA_TAILCALL_RVA(0x55ddc0); }

/* file+0x400, RVA 0x265b60; ev_b54890adaf3a01f835e9c2aea4cdd29bbbcc66513b5e8a661adf62c0adf7e03b */
void trampoline_00265b60(void) { REA_TAILCALL_RVA(0x55ed70); }

/* file+0x408, RVA 0x265b68; ev_3cd532e54c61db1b25afb61a694694a95f4e11027c687dcd9b6816ba78138dab */
void trampoline_00265b68(void) { REA_TAILCALL_RVA(0x55ec90); }

/* file+0x410, RVA 0x265b70; ev_d995283fac767ca28461fb443c952faa41f3f8ae3435931fd07a6c80ccaa7e59 */
void trampoline_00265b70(void) { REA_TAILCALL_RVA(0x55e550); }

/* file+0x418, RVA 0x265b78; ev_f59ffd3b8d968bb964a636759b0b6d66117a6dbd828d92d3dbaa2d4afadbe832 */
void trampoline_00265b78(void) { REA_TAILCALL_RVA(0x55e680); }

/* file+0x420, RVA 0x265b80; ev_97c04bb9ff4e54c9779eb233317565f8814373ce0e13d1f812b8e8ce47bd6c08 */
void trampoline_00265b80(void) { REA_TAILCALL_RVA(0xabbd80); }

/* file+0x428, RVA 0x265b88; ev_1d9079268614cd36d4012fe69ef6eec1959a113af027a60ec4d2bd3350038cf2 */
void trampoline_00265b88(void) { REA_TAILCALL_RVA(0x8340e0); }

/* file+0x430, RVA 0x265b90; ev_383a2776c5e30a1ac75c2acc293923598f4a0b0927551ee05d7354c1e746900f */
void trampoline_00265b90(void) { REA_TAILCALL_RVA(0x8f6120); }

/* file+0x438, RVA 0x265b98; ev_b6eda18d385b64ed718338b49df83dade2eba0e5d418910bf607c8828d2b3592 */
void trampoline_00265b98(void) { REA_TAILCALL_RVA(0xc42f00); }

/* file+0x440, RVA 0x265ba0; ev_bd7d33b716dcc6578123dd88c50dfa453f4a82849f6be5cd0d5529d5f8803511 */
void trampoline_00265ba0(void) { REA_TAILCALL_RVA(0xc43010); }

/* file+0x448, RVA 0x265ba8; ev_ece091bba5eb1301a6c2209e9dcb02fdb18d7064778287c77950e9175569e030 */
void trampoline_00265ba8(void) { REA_TAILCALL_RVA(0xc43170); }

/* file+0x450, RVA 0x265bb0; ev_9c712c443cef1abd06e558ab857416fa035bae7580e405b8faee3185db5b9ec8 */
void trampoline_00265bb0(void) { REA_TAILCALL_RVA(0xc434a0); }

/* file+0x458, RVA 0x265bb8; ev_a420ee575a482f0e1716b4c982bb795c88ada40f5b165bdf0d937fd4a99cef5b */
void trampoline_00265bb8(void) { REA_TAILCALL_RVA(0xc42760); }

/* file+0x460, RVA 0x265bc0; ev_4880f48e8b3563a642e76a99ec5703799482552faa2f2b0e2cc3763412a73e47 */
void trampoline_00265bc0(void) { REA_TAILCALL_RVA(0xc42b90); }

/* file+0x468, RVA 0x265bc8; ev_37d24cc7f4063b8babb86e717b6d482131231fe39d62282b29dbee2f5940f513 */
void trampoline_00265bc8(void) { REA_TAILCALL_RVA(0xc42bc0); }

/* file+0x470, RVA 0x265bd0; ev_14d5a3d79a7126efb5f3d41bbbc0e68c2539e4b7adda0df8ef6f5c9ff21a0f85 */
void trampoline_00265bd0(void) { REA_TAILCALL_RVA(0xc434c0); }

/* file+0x478, RVA 0x265bd8; ev_cf3af2efed6662d8af664bb8970c79e3ddecbfa0f31dd07004f531eee677cbe0 */
void trampoline_00265bd8(void) { REA_TAILCALL_RVA(0xc43620); }

/* file+0x480, RVA 0x265be0; ev_c70961ff1dcb60ea0be22c7ab4531ac5f882a3f7833bb3768225f5964e2d0ab5 */
void trampoline_00265be0(void) { REA_TAILCALL_RVA(0x55d0c0); }

/* file+0x488, RVA 0x265be8; ev_fe9312150a7ce6697a3c900d64a9e51f88f574b55b9e8681a4d91d768621ba2c */
void trampoline_00265be8(void) { REA_TAILCALL_RVA(0xa07280); }

/* file+0x490, RVA 0x265bf0; ev_e0b1f7a7c981fc5d9dcafe81c16edb2fe3ea9d95843b28518234ac66ab0a5a23 */
void trampoline_00265bf0(void) { REA_TAILCALL_RVA(0xc37860); }

/* file+0x498, RVA 0x265bf8; ev_4d6c15d226c40b4e32f661631591436ef57f3a9aeaac7244353faf652c355e29 */
void trampoline_00265bf8(void) { REA_TAILCALL_RVA(0xc37970); }

/* file+0x4a0, RVA 0x265c00; ev_b23069cdbcf7e6c4756165834f33c17485fe042361d2518e183035958f6f3df7 */
void trampoline_00265c00(void) { REA_TAILCALL_RVA(0xc37a20); }

/* file+0x4a8, RVA 0x265c08; ev_fac06441cdba810fe9209d63468a4831a4fe9adcb1da76cdad5856e3d9c5760e */
void trampoline_00265c08(void) { REA_TAILCALL_RVA(0x55deb0); }

/* file+0x4b0, RVA 0x265c10; ev_f081331950cb6f1bd3a57daf853865d25b13a2e1c4fefaf41cb391e565d20cf8 */
void trampoline_00265c10(void) { REA_TAILCALL_RVA(0x437cf0); }

/* file+0x4b8, RVA 0x265c18; ev_058d536b2ae4b0a4324784a40903672e17df37517c83fc5a0e984985522601f8 */
void trampoline_00265c18(void) { REA_TAILCALL_RVA(0x4383f0); }

/* file+0x4c0, RVA 0x265c20; ev_18225aeee56fa88adf88f08d8d0dfd524c801e9971c90c44354b5a67fd398472 */
void trampoline_00265c20(void) { REA_TAILCALL_RVA(0x4383c0); }

/* file+0x4c8, RVA 0x265c28; ev_dd8342063867a4ea69ae1f13acba0c8d678a071ad1e4b07d7fafd65bb5be79ab */
void trampoline_00265c28(void) { REA_TAILCALL_RVA(0x438560); }

/* file+0x4d0, RVA 0x265c30; ev_e828e40605ee2bba46a423a358f6a15081cb2a5d3aea6b4ddacba53902a8b76f */
void trampoline_00265c30(void) { REA_TAILCALL_RVA(0xc433f0); }

/* file+0x4d8, RVA 0x265c38; ev_ae6dae16c42a04fd9b82f78f650e58bb563880f1cc242b489fce00092d411ec9 */
void trampoline_00265c38(void) { REA_TAILCALL_RVA(0x4388c0); }

/* file+0x4e0, RVA 0x265c40; ev_af8397497301481e4d955c5e7a72257407d854872e524c225af8153a3be8763e */
void trampoline_00265c40(void) { REA_TAILCALL_RVA(0x438ab0); }

/* file+0x4e8, RVA 0x265c48; ev_2bfb31ecbd4f13ae8a39676a6e1cdf19137262addd87c4f0d8b8df0d6007ef1d */
void trampoline_00265c48(void) { REA_TAILCALL_RVA(0x552c20); }

/* file+0x4f0, RVA 0x265c50; ev_6ea830efd8c81247f2dbb39df1e11de6a24f8dd6ec273863fbcc0faf546557ef */
void trampoline_00265c50(void) { REA_TAILCALL_RVA(0x437de0); }

/* file+0x4f8, RVA 0x265c58; ev_0b977cae979849c2dc11ac499664a40aec4bb8cebfc0a8ab1940b6332ce352d1 */
void trampoline_00265c58(void) { REA_TAILCALL_RVA(0x55fc20); }

/* file+0x500, RVA 0x265c60; ev_42144550e663936588b9bc108e5f3ec4ea638c0028d23cf9b4cba38b7b44942b */
void trampoline_00265c60(void) { REA_TAILCALL_RVA(0x438b60); }

/* file+0x508, RVA 0x265c68; ev_1464eb04b518770c04e89f95e9b780d4763d9b786f43e01ab56f7fc3bf808a82 */
void trampoline_00265c68(void) { REA_TAILCALL_RVA(0x4a0400); }

/* file+0x510, RVA 0x265c70; ev_7dd1c1a184798d3a41cef657df13296c45711e3a55e368400e7df5695e88861c */
void trampoline_00265c70(void) { REA_TAILCALL_RVA(0x4ec120); }

/* file+0x518, RVA 0x265c78; ev_75c1bf6540a2590beaff6b20c39cb65f1d04c9b3e8f8f5f478349b1e29552f5a */
void trampoline_00265c78(void) { REA_TAILCALL_RVA(0x4ec740); }

/* file+0x520, RVA 0x265c80; ev_ffd0ab6f5d80c7a5999b2ae0e00ec09f262eab8c84f162fe81d330b062a1e905 */
void trampoline_00265c80(void) { REA_TAILCALL_RVA(0xab83c0); }

/* file+0x528, RVA 0x265c88; ev_dd3996923f8dfbd303a4f00db84f02e857f6f4d874aa8ea3193f67e94e706083 */
void trampoline_00265c88(void) { REA_TAILCALL_RVA(0x8f8ab0); }

/* file+0x530, RVA 0x265c90; ev_8cab634f96a33cce4da4dc8c221bb6dd8866c6d0ecdc24b779924b847c8ea7c3 */
void trampoline_00265c90(void) { REA_TAILCALL_RVA(0x8fafa0); }

/* file+0x538, RVA 0x265c98; ev_91a792a59e712d99e852aae86e030dc84e21dc888b04e6d7755aacf12d63e12b */
void trampoline_00265c98(void) { REA_TAILCALL_RVA(0x4ecf20); }

/* file+0x540, RVA 0x265ca0; ev_f821044ca27f26ea21e816c9eb83b4e965310d928e144b753feef8c3c7ddb6a6 */
void trampoline_00265ca0(void) { REA_TAILCALL_RVA(0x4386f0); }

/* file+0x548, RVA 0x265ca8; ev_f824c355aa10d711f9edcd263a1f504264c50a99aee6f976613a076399aa6e0e */
void trampoline_00265ca8(void) { REA_TAILCALL_RVA(0x80d740); }

/* file+0x550, RVA 0x265cb0; ev_9fb2215ffd4c3f424bafc8fad11107594b8ee47f59025e8216bd8b2ac66b2783 */
void trampoline_00265cb0(void) { REA_TAILCALL_RVA(0x80dbd0); }

/* file+0x558, RVA 0x265cb8; ev_e0fdca6c8e6a7ffaa0eca34fe24c7a7892038629033068f5685504f21d633dfe */
void trampoline_00265cb8(void) { REA_TAILCALL_RVA(0x83d830); }

/* file+0x560, RVA 0x265cc0; ev_ff6a7ef6a9aaff14f3c5c00d0d5087ae7a3d7d6127675b48d5095ef5b6845ee8 */
void trampoline_00265cc0(void) { REA_TAILCALL_RVA(0x83de60); }

/* file+0x568, RVA 0x265cc8; ev_ba232a02aba383fca92791890cf14f420ed1f26579ba9fde1d0da50e5390c8c3 */
void trampoline_00265cc8(void) { REA_TAILCALL_RVA(0x83e320); }

/* file+0x570, RVA 0x265cd0; ev_0397fecef4fff4ba2cdc5b69a3fcffaa67bbf4838959e5390a6169dd196e418f */
void trampoline_00265cd0(void) { REA_TAILCALL_RVA(0x8f6e50); }

/* file+0x578, RVA 0x265cd8; ev_f0fb863eeef6e1f39fb655ed995522aa63de188602c99ed7a8b028daeb4eb933 */
void trampoline_00265cd8(void) { REA_TAILCALL_RVA(0x49b0b0); }

/* file+0x580, RVA 0x265ce0; ev_933b61f2e4add58513eace2fba84a47ff276471435ff385068482b874b59bd70 */
void trampoline_00265ce0(void) { REA_TAILCALL_RVA(0x4ed3c0); }

/* file+0x588, RVA 0x265ce8; ev_5ab7cdaf7318fc98e26b35d971aeb2cb79905b0b91bd881c5bafb6267c93c7bb */
void trampoline_00265ce8(void) { REA_TAILCALL_RVA(0xaf0040); }

/* file+0x590, RVA 0x265cf0; ev_9904544988ab816655fd1124178c21c2c375f4d4ba11dbb5cf14b6f45810d3a6 */
void trampoline_00265cf0(void) { REA_TAILCALL_RVA(0x705880); }

/* file+0x598, RVA 0x265cf8; ev_dfcb6f37587d39df9e8b425ee2bac0ecaab1401f270a2b9399b8bec918aa65c2 */
void trampoline_00265cf8(void) { REA_TAILCALL_RVA(0x705c60); }

/* file+0x5a0, RVA 0x265d00; ev_e12f023ed77e240228e2e8fbd182731f91ebd5e7f053a83bb32005bfeb948553 */
void trampoline_00265d00(void) { REA_TAILCALL_RVA(0x4f65f0); }

/* file+0x5a8, RVA 0x265d08; ev_8dd8f36f8f1bc7ad5c3a77a47c77b00cce25a4ac998b1d94ece70e2b83d17267 */
void trampoline_00265d08(void) { REA_TAILCALL_RVA(0x4f6a70); }

/* file+0x5b0, RVA 0x265d10; ev_84cf08705fedb406bb943f094bea2ffaf9586b9d81c010c8d9848e5fe88d7745 */
void trampoline_00265d10(void) { REA_TAILCALL_RVA(0xbafa80); }

/* file+0x5b8, RVA 0x265d18; ev_b46b53daee3292f54e917beaabe480e7050e72084ca74230a91e515631bdbe2d */
void trampoline_00265d18(void) { REA_TAILCALL_RVA(0xbafcf0); }

/* file+0x5c0, RVA 0x265d20; ev_9330a72f9c7ef8243d5377341f1ce8501a03a26b1cc018d48b4b8c94d4798b47 */
void trampoline_00265d20(void) { REA_TAILCALL_RVA(0xbb0330); }

/* file+0x5c8, RVA 0x265d28; ev_b74d0817b1c8a358e5420e0beb7d7f2932c89684cf603e26fc0fa0c626f6e03c */
void trampoline_00265d28(void) { REA_TAILCALL_RVA(0xbb0490); }

/* file+0x5d0, RVA 0x265d30; ev_33db51cd2aa5a05f0f4729872bf973250d94166486c51e83fe20277cd6ae4ca4 */
void trampoline_00265d30(void) { REA_TAILCALL_RVA(0xbafe50); }

/* file+0x5d8, RVA 0x265d38; ev_c9dbe3076b7425681f0c4dd384443a9360c19ddd2abff378e5518bc07a819a67 */
void trampoline_00265d38(void) { REA_TAILCALL_RVA(0xbb0030); }

/* file+0x5e0, RVA 0x265d40; ev_f1c3adc967c1e2eb5d89e5cd7015eeda50d8d3bc852132799a283cc438f9e7a6 */
void trampoline_00265d40(void) { REA_TAILCALL_RVA(0xbb0150); }

/* file+0x5e8, RVA 0x265d48; ev_1ed9c4c99bb0abae4eabc12b584dc971de1ce25233d18964b4f18e1e28daa230 */
void trampoline_00265d48(void) { REA_TAILCALL_RVA(0xbb01d0); }

/* file+0x5f0, RVA 0x265d50; ev_0db2cf47e5e1e54bc8696e5e70c6a549137f65c603c9f3ba938a8e27f5075678 */
void trampoline_00265d50(void) { REA_TAILCALL_RVA(0xbb0280); }

/* file+0x5f8, RVA 0x265d58; ev_ad79683ca05c060cc451c6d434dcf7ea4543c5a530dd2afbf6b5db2000df7030 */
void trampoline_00265d58(void) { REA_TAILCALL_RVA(0xaba540); }

/* file+0x600, RVA 0x265d60; ev_8c6853862e8f0706aa0529bb6ffc888dd15abee4cb88135c35c9bc7b3699ec1e */
void trampoline_00265d60(void) { REA_TAILCALL_RVA(0xabbe60); }

/* file+0x608, RVA 0x265d68; ev_90b8e5d1a94e3e79fdf4be462d2f99c8e3f80d5a1a3f463a652f64f5938d9d4c */
void trampoline_00265d68(void) { REA_TAILCALL_RVA(0xc16020); }

/* file+0x610, RVA 0x265d70; ev_1e872aad864f4a84c1a3a85ee0a5ece6ed5cb432a780cd265c78f90be9ca6413 */
void trampoline_00265d70(void) { REA_TAILCALL_RVA(0xc16270); }

/* file+0x618, RVA 0x265d78; ev_183bfc0d0ec5ed7f458b0087433ae429976f36b4e9f0bfca4fd7309c8601100b */
void trampoline_00265d78(void) { REA_TAILCALL_RVA(0xc16720); }

/* file+0x620, RVA 0x265d80; ev_3c8202bd08018dcef6472bf05c3964b1cf5ddf8c743e8592c9c6978aee581bab */
void trampoline_00265d80(void) { REA_TAILCALL_RVA(0xc16880); }

/* file+0x628, RVA 0x265d88; ev_51359079b311e406d8a854ae0f64ffa137966759520cc254477070a36fd4f4f8 */
void trampoline_00265d88(void) { REA_TAILCALL_RVA(0xc163d0); }

/* file+0x630, RVA 0x265d90; ev_ca1e7e39f115fa58dfa9febce2b68f9f1aedf3d465a74c4727e7245c73e58e63 */
void trampoline_00265d90(void) { REA_TAILCALL_RVA(0xc164f0); }

/* file+0x638, RVA 0x265d98; ev_0c114c47e17760cd94ed0c290f83288c2866724f49819399fff487b9b2919502 */
void trampoline_00265d98(void) { REA_TAILCALL_RVA(0xc165d0); }

/* file+0x640, RVA 0x265da0; ev_406e606fd527de8cbf70f0f999bad7e77b22fe105f5be0a6759e2fdf402a8cbc */
void trampoline_00265da0(void) { REA_TAILCALL_RVA(0xc16660); }

/* file+0x648, RVA 0x265da8; ev_075985b391904a1b0f1fc781075244d1a2d80209ff53b85544ed16e83dcffff5 */
void trampoline_00265da8(void) { REA_TAILCALL_RVA(0xac7240); }

/* file+0x650, RVA 0x265db0; ev_d521abc1487ab6738d2ba676967a1f95e7be8e5b3ad19cdf6dacf5c8b93d7f9b */
void trampoline_00265db0(void) { REA_TAILCALL_RVA(0xac73c0); }

/* file+0x658, RVA 0x265db8; ev_f29a643112d26182b607820dd517ec51225c7fe4dfe88b81759ff64f2363b000 */
void trampoline_00265db8(void) { REA_TAILCALL_RVA(0xabc510); }

/* file+0x660, RVA 0x265dc0; ev_a47fc8b0e81d153d9a047de87271158e632b462f4b20273884e5f54676de5b9b */
void trampoline_00265dc0(void) { REA_TAILCALL_RVA(0x4f5e60); }

/* file+0x668, RVA 0x265dc8; ev_1bbdda1f36bb604ef0f3d913b4dc37a5d8e393e926ebded19ce19410c3ede713 */
void trampoline_00265dc8(void) { REA_TAILCALL_RVA(0x602fe0); }

/* file+0x670, RVA 0x265dd0; ev_6a9ea7e104a3571ccdaa56e9498aba502866891f23e2ba6d5477a33b90398c22 */
void trampoline_00265dd0(void) { REA_TAILCALL_RVA(0x603260); }

/* file+0x678, RVA 0x265dd8; ev_7db3e394328312bbd456916a2e6b39870c6131402bd7874f1aadfdb7b4fdb67d */
void trampoline_00265dd8(void) { REA_TAILCALL_RVA(0x6034e0); }

/* file+0x680, RVA 0x265de0; ev_5617792a803d818f5f4a5c74a6fbc633c296f47af34e63e1faa3573b20bb85cf */
void trampoline_00265de0(void) { REA_TAILCALL_RVA(0x603710); }

/* file+0x688, RVA 0x265de8; ev_383826ccab055f3f935de2500ac3d19be21f0b090424b408a67ad22c5fb42f40 */
void trampoline_00265de8(void) { REA_TAILCALL_RVA(0x6039d0); }

/* file+0x690, RVA 0x265df0; ev_8b5dd4b879288fc122a3f23501d9f821424d69512f9e26345078bbcc054bf26e */
void trampoline_00265df0(void) { REA_TAILCALL_RVA(0xabac50); }

/* file+0x698, RVA 0x265df8; ev_76ea25a5ada651efb92c4b69978000171c17a5fe0dcc61b85aea388632038fd3 */
void trampoline_00265df8(void) { REA_TAILCALL_RVA(0x8fc610); }

/* file+0x6a0, RVA 0x265e00; ev_98736a3d03d36195a516784f936b792161411c6f8f98f41feed45145e9277537 */
void trampoline_00265e00(void) { REA_TAILCALL_RVA(0x4e1a70); }

/* file+0x6a8, RVA 0x265e08; ev_efa8692a6e9c16f11333028b24e67f2e944a894543ac6f2c19c27cb0bf7a4a99 */
void trampoline_00265e08(void) { REA_TAILCALL_RVA(0xabc5f0); }

/* file+0x6b0, RVA 0x265e10; ev_dabdcb541ceca71314834d2d7ab4b9b3c46f5f2db22380aa73fb2628c2c3dc8b */
void trampoline_00265e10(void) { REA_TAILCALL_RVA(0xa367e0); }

/* file+0x6b8, RVA 0x265e18; ev_d1f525ee3129c8a4ad352daa767b5b75cfc569dbf68972c407d2b066a5f86616 */
void trampoline_00265e18(void) { REA_TAILCALL_RVA(0xca0630); }

/* file+0x6c0, RVA 0x265e20; ev_597e0cbd10cc586b0c9ad6238db67a0909fd39b0289b5b6dcd6d8eb18eb992a2 */
void trampoline_00265e20(void) { REA_TAILCALL_RVA(0xa368e0); }

/* file+0x6c8, RVA 0x265e28; ev_c4109942ee68e80fae151b1edffee2384ff7bc3c4d73b62ff35054f5d32a289c */
void trampoline_00265e28(void) { REA_TAILCALL_RVA(0x72ecc0); }

/* file+0x6d0, RVA 0x265e30; ev_257d1d7794521f666262b1521f408c3f4b9196a300250d839255fecb561c3cbb */
void trampoline_00265e30(void) { REA_TAILCALL_RVA(0x4f7370); }

/* file+0x6d8, RVA 0x265e38; ev_f2c49384cb97de40881bbc07889cfeaf40a8847921fe154140904a7de3d390cd */
void trampoline_00265e38(void) { REA_TAILCALL_RVA(0xa36b00); }

/* file+0x6e0, RVA 0x265e40; ev_b9c280511e484a33bba5afdb5bb70bf33ce06be39907e4b72039a4bedefc1272 */
void trampoline_00265e40(void) { REA_TAILCALL_RVA(0xa36b90); }

/* file+0x6e8, RVA 0x265e48; ev_9093d82ce5854b9034d4f10045c0ebb7ce55843461b0eca46ea7d457aae631a1 */
void trampoline_00265e48(void) { REA_TAILCALL_RVA(0xabc710); }

/* file+0x6f0, RVA 0x265e50; ev_2816b732f0fef454b8aa0bd37115f5abd72469678d25b6d778429085b60de99a */
void trampoline_00265e50(void) { REA_TAILCALL_RVA(0x5a7f60); }

/* file+0x6f8, RVA 0x265e58; ev_770e256aee662cd771acf934689abeefc4307a1eb757a2a933606bf2fc845035 */
void trampoline_00265e58(void) { REA_TAILCALL_RVA(0xa36bc0); }

/* file+0x700, RVA 0x265e60; ev_2f10cba8e34f75d5ac6f6f54492b6bb83d763874ff0625fd1991f132739a95b0 */
void trampoline_00265e60(void) { REA_TAILCALL_RVA(0xabca10); }

/* file+0x708, RVA 0x265e68; ev_bab9dcaded8532eab81a7bea9d75244b3d8b21832a1f2d3597a9a4513b720db0 */
void trampoline_00265e68(void) { REA_TAILCALL_RVA(0xabcc00); }

/* file+0x710, RVA 0x265e70; ev_c753e26506e0b8513107059e9efc53d7f3531ae2e8982e4ec461bfc795cf22e6 */
void trampoline_00265e70(void) { REA_TAILCALL_RVA(0x438c90); }

/* file+0x718, RVA 0x265e78; ev_ac290194ac6cd87fdf648dbff5d22d77f2112633a89da065cf714a764cb9f3c9 */
void trampoline_00265e78(void) { REA_TAILCALL_RVA(0x8d2570); }

/* file+0x720, RVA 0x265e80; ev_71af1ed7dff3724f6192a9b22326373b14914e1f822b3b3a3ff26e68d1c925a6 */
void trampoline_00265e80(void) { REA_TAILCALL_RVA(0xabd0f0); }

/* file+0x728, RVA 0x265e88; ev_02301b94e7586d5bbd971396dddee058d61b115255a03a2e2bbde9c2236bc70d */
void trampoline_00265e88(void) { REA_TAILCALL_RVA(0xa37650); }

/* file+0x730, RVA 0x265e90; ev_fca97efe181dc3bf8e90a17892a4381296b30306b38ce3a9dd926fb2630e81aa */
void trampoline_00265e90(void) { REA_TAILCALL_RVA(0xabd430); }

/* file+0x738, RVA 0x265e98; ev_5ad21d951e9519613cf9ee4d4c8d658f43b4d532eaa7358b99beac689ffcb06e */
void trampoline_00265e98(void) { REA_TAILCALL_RVA(0x7dcd40); }

/* file+0x740, RVA 0x265ea0; ev_1f0991aff32537acc62b1569ba8603eae9c02b7736f03acaa4adbfc1eba6bdd8 */
void trampoline_00265ea0(void) { REA_TAILCALL_RVA(0x8d25a0); }

/* file+0x748, RVA 0x265ea8; ev_fb2d4e54fe45bd638b55145b497b13e93b6a273088a0190caf55db32288aa980 */
void trampoline_00265ea8(void) { REA_TAILCALL_RVA(0xabd4f0); }

/* file+0x750, RVA 0x265eb0; ev_fe2dfac522fbe82b7015bd8689bc55c2858a2ae907b2d392784ab83e1005109f */
void trampoline_00265eb0(void) { REA_TAILCALL_RVA(0x603c90); }

/* file+0x758, RVA 0x265eb8; ev_2f9bb31987d8f9950e65a633f405ed5cc79c54af580779c737b0e0d0491e52a7 */
void trampoline_00265eb8(void) { REA_TAILCALL_RVA(0x604cf0); }

/* file+0x760, RVA 0x265ec0; ev_7724fd06f065fd82fd0e2d26cfc83ca6fc7a61fe2555037b419d385c9251b765 */
void trampoline_00265ec0(void) { REA_TAILCALL_RVA(0x4a2850); }

/* file+0x768, RVA 0x265ec8; ev_bfb6277d9521c616e8de5efb7ab0ce45aaa4f01337cf4d8dda34fca26a2fcbd9 */
void trampoline_00265ec8(void) { REA_TAILCALL_RVA(0xabd540); }

/* file+0x770, RVA 0x265ed0; ev_8abd61310212a66ee7fffc7a555d7a2ed9282bd3d6b5a1303e276d232ee21fd0 */
void trampoline_00265ed0(void) { REA_TAILCALL_RVA(0x91c640); }

/* file+0x778, RVA 0x265ed8; ev_9c60e50cfe4a554f1caacb887b24ad9f1ad4b255d4c55f1ccc4bdeb1513143be */
void trampoline_00265ed8(void) { REA_TAILCALL_RVA(0x91cc70); }

/* file+0x780, RVA 0x265ee0; ev_94e250f3208879235eea4b468787a295a683a558491f964bfbcd318bc3091372 */
void trampoline_00265ee0(void) { REA_TAILCALL_RVA(0x438e30); }

/* file+0x788, RVA 0x265ee8; ev_b0b82678695f6ab73ce8861b5c632af4cb7262a44e85d653ff4ef249d8e9d10b */
void trampoline_00265ee8(void) { REA_TAILCALL_RVA(0x439070); }

/* file+0x790, RVA 0x265ef0; ev_69d307f8a8983141fdbae5e9ff1a9e14a55ed033c48541d9b1e2a16c93d04e81 */
void trampoline_00265ef0(void) { REA_TAILCALL_RVA(0x439150); }

/* file+0x798, RVA 0x265ef8; ev_344e003f74c2408ae339d15f5efe04578a58f70fbe8f11b62af792f5310ae403 */
void trampoline_00265ef8(void) { REA_TAILCALL_RVA(0x4393a0); }

/* file+0x7a0, RVA 0x265f00; ev_4b1ca9e206a8d5aa9bde5b434c38054a956ca7ed220b9283b2e0c253779b5a85 */
void trampoline_00265f00(void) { REA_TAILCALL_RVA(0x6be4d0); }

/* file+0x7a8, RVA 0x265f08; ev_930061c5bd3d56a066be26f0b3e4563c3aac739b068ef6622dea17eb242a4ed2 */
void trampoline_00265f08(void) { REA_TAILCALL_RVA(0xabd930); }

/* file+0x7b0, RVA 0x265f10; ev_d1170e018541f9e2c499217cb8583c69a7acdeb07e4b750af7e9cfa8de058194 */
void trampoline_00265f10(void) { REA_TAILCALL_RVA(0x6be5c0); }

/* file+0x7b8, RVA 0x265f18; ev_91c0751fccea417587657924be4026b0fb8f0eed2cb0d4789f8922bcf221c185 */
void trampoline_00265f18(void) { REA_TAILCALL_RVA(0x6be800); }

/* file+0x7c0, RVA 0x265f20; ev_f2b3433066aeb3aa3fdf74ef767ebfb15d6f53fa60af7f975224d5190975c570 */
void trampoline_00265f20(void) { REA_TAILCALL_RVA(0xa90e10); }

/* file+0x7c8, RVA 0x265f28; ev_9090e9c45fd819862cba2ac89cd3c73c446c2b455db61574953d62d91500fd56 */
void trampoline_00265f28(void) { REA_TAILCALL_RVA(0x4a2de0); }

/* file+0x7d0, RVA 0x265f30; ev_b8bf3bba1ac46efbe5d057be9f760fb196a6cc7cd8cd9f12ac1dfbca073c896b */
void trampoline_00265f30(void) { REA_TAILCALL_RVA(0xabdad0); }

/* file+0x7d8, RVA 0x265f38; ev_06378a6848819350ddcc20cb791da91d907629ea34d992343955bafe64e002b9 */
void trampoline_00265f38(void) { REA_TAILCALL_RVA(0xa37660); }

/* file+0x7e0, RVA 0x265f40; ev_0165fcc832ed534dcf89a13a4e32b7175145c97ca9f9dd03102a6818227f1e21 */
void trampoline_00265f40(void) { REA_TAILCALL_RVA(0xabe1c0); }

/* file+0x7e8, RVA 0x265f48; ev_4b84f5b76775251e86dac00f6309bcdd859182c9d0befd1010a411b9f1beab6a */
void trampoline_00265f48(void) { REA_TAILCALL_RVA(0xabe7b0); }

/* file+0x7f0, RVA 0x265f50; ev_9126d37972a6c96a8294b98ff4652607c429908d1fc6a5a9ffe6358b05a774c1 */
void trampoline_00265f50(void) { REA_TAILCALL_RVA(0x9f81f0); }

/* file+0x7f8, RVA 0x265f58; ev_21efe387cfc28dad90662d4bf0313ed9555251cbaec5b323c5319833af58d618 */
void trampoline_00265f58(void) { REA_TAILCALL_RVA(0xbe9510); }

/* file+0x800, RVA 0x265f60; ev_08dc47d76f8c663586037873aa416c3074bf4a2f3f78ded6c0b4f398782601ed */
void trampoline_00265f60(void) { REA_TAILCALL_RVA(0x9a7d10); }

/* file+0x808, RVA 0x265f68; ev_a90be405433673dfc4f63827591d35d0568a95ecf20cf7f00bd8bb9a381bacc0 */
void trampoline_00265f68(void) { REA_TAILCALL_RVA(0x9a9560); }

/* file+0x810, RVA 0x265f70; ev_4e4fa9389794acf72e3902ac2db24cdfa64f6aac8c19ac4277a0b1d41dbc3f74 */
void trampoline_00265f70(void) { REA_TAILCALL_RVA(0x9a9e10); }

/* file+0x818, RVA 0x265f78; ev_20c59410f91d73a78016bddceb8f743ef74d81970a5fd980886541d502e64d00 */
void trampoline_00265f78(void) { REA_TAILCALL_RVA(0x9a9f40); }

/* file+0x820, RVA 0x265f80; ev_1eeb3a6765b6ab28787b1ddd411d2cb49aabf3739dfc4e97554f002b7cacdcdb */
void trampoline_00265f80(void) { REA_TAILCALL_RVA(0x8fb440); }

/* file+0x828, RVA 0x265f88; ev_6c97c19f67106a556c6c5b5cdc7380eb5a45b6d0cda7ba21d6947b4d1235ccb0 */
void trampoline_00265f88(void) { REA_TAILCALL_RVA(0x4a31a0); }

/* file+0x830, RVA 0x265f90; ev_81a4f4212aaa4466055222677565eb2c985c8483bd8703aaf858fa1c77b997eb */
void trampoline_00265f90(void) { REA_TAILCALL_RVA(0xabe8b0); }

/* file+0x838, RVA 0x265f98; ev_084bff527ef4a39646d5196c812b33c0f148f2aeeaa82b585950b01b14a0ff93 */
void trampoline_00265f98(void) { REA_TAILCALL_RVA(0x9ab1f0); }

/* file+0x840, RVA 0x265fa0; ev_6dee6a45800de3ddf8e9063f07e15fa0f6e770376f66c89387c8fd1fa2806456 */
void trampoline_00265fa0(void) { REA_TAILCALL_RVA(0xabb980); }

/* file+0x848, RVA 0x265fa8; ev_28b569c8a25d12df9ba7e7774d6e2b3dd7af2caca56732e54e5d046790fd202a */
void trampoline_00265fa8(void) { REA_TAILCALL_RVA(0x6f92e0); }

/* file+0x850, RVA 0x265fb0; ev_8da950bfced75a0082e8f1616c320b0c037c12c863b265c5f8e56a3ff7b51bb3 */
void trampoline_00265fb0(void) { REA_TAILCALL_RVA(0x434da0); }

/* file+0x858, RVA 0x265fb8; ev_f04d227ee95d69753d0a375f8302f535c9b363313807baa16580d5b86275a51d */
void trampoline_00265fb8(void) { REA_TAILCALL_RVA(0x434db0); }

/* file+0x860, RVA 0x265fc0; ev_8c03fa804228a9567050bb0dd34a5e56f62b89b80a4a78773a54fcb8da999183 */
void trampoline_00265fc0(void) { REA_TAILCALL_RVA(0x434dc0); }

/* file+0x868, RVA 0x265fc8; ev_9086a44380935d4ddc1e72e9d168c5ad2196afb6eb1ba3c7b55007c3f3e8bda4 */
void trampoline_00265fc8(void) { REA_TAILCALL_RVA(0x437d90); }

/* file+0x870, RVA 0x265fd0; ev_847ccdef2f047338956d9ad215f9723af49223f0d61289b62930e7a1320438ac */
void trampoline_00265fd0(void) { REA_TAILCALL_RVA(0x438280); }

/* file+0x878, RVA 0x265fd8; ev_4deafef3933a2a35016f001f6237e530355f9777da81e654d46da30e32dcdb54 */
void trampoline_00265fd8(void) { REA_TAILCALL_RVA(0xae6690); }

/* file+0x880, RVA 0x265fe0; ev_3a524da37b12d0ef1a0f0a91b32765c0b65dcfadc6fc9e8ca38b4b6069ccd2ee */
void trampoline_00265fe0(void) { REA_TAILCALL_RVA(0xae6580); }

/* file+0x888, RVA 0x265fe8; ev_d2af33e8df5120e03fa1c1dcccf46f4abf430aa67c5f6c5e331e0e415c8bd9d3 */
void trampoline_00265fe8(void) { REA_TAILCALL_RVA(0x4490d0); }

/* file+0x890, RVA 0x265ff0; ev_ad2742a62a6f9ed794037c2c1c45ac8dbe600c3ee49153b145b62780be2af98a */
void trampoline_00265ff0(void) { REA_TAILCALL_RVA(0xa6dc0); }

/* file+0x898, RVA 0x265ff8; ev_b8907ecb2f80219bef85d3306e781fa42b543d9e6859dbda9c88d472f569c25e */
void trampoline_00265ff8(void) { REA_TAILCALL_RVA(0x44aa70); }

/* file+0x8a0, RVA 0x266000; ev_6bd9f09f4f1b599a9b908725404e9dc0ea3444b77173d4dc897c03370df30d7a */
void trampoline_00266000(void) { REA_TAILCALL_RVA(0x9b6110); }

/* file+0x8a8, RVA 0x266008; ev_6bbc159183c650415a8665ea60b2309897a28afbb438e6100aaa019aaa12d012 */
void trampoline_00266008(void) { REA_TAILCALL_RVA(0xa7670); }

/* file+0x8b0, RVA 0x266010; ev_4e91e007d2a8c58133df94c59ea0e1619ebf9b52903bcecdeabbe63866fec863 */
void trampoline_00266010(void) { REA_TAILCALL_RVA(0xa7850); }

/* file+0x8b8, RVA 0x266018; ev_955f218e8076eac2f51a200a4ac88bb79cee5050978bbf87caaade7515f3d1cb */
void trampoline_00266018(void) { REA_TAILCALL_RVA(0xa7880); }

/* file+0x8c0, RVA 0x266020; ev_8177533392d244eeacb934259f2a4c1ceb799151edaa87e3dfc6a7a86e8c423b */
void trampoline_00266020(void) { REA_TAILCALL_RVA(0x452040); }

/* file+0x8c8, RVA 0x266028; ev_263db49e8bd9339f8856c54c48c590b3aaa1810c1857217ccd2bce30f7692f63 */
void trampoline_00266028(void) { REA_TAILCALL_RVA(0x454cc0); }

/* file+0x8d0, RVA 0x266030; ev_b133f9a13ee76be7b921f2edcb63a1ad815fa9518600df8ace463d8c889a249c */
void trampoline_00266030(void) { REA_TAILCALL_RVA(0x457820); }

/* file+0x8d8, RVA 0x266038; ev_8a4497c5b3ce9c0477e739fe847ece965b83776f84b5d8e877944fbc1c495bfd */
void trampoline_00266038(void) { REA_TAILCALL_RVA(0x46df70); }

/* file+0x8e0, RVA 0x266040; ev_64d7e93469ad431593402890e9ab0b07fae948b75fe427530ad12cd9c36a2cff */
void trampoline_00266040(void) { REA_TAILCALL_RVA(0x46e080); }

/* file+0x8e8, RVA 0x266048; ev_28691bdd3c12577b68e88ad27986ddc60f93d0399798119fa266a4b25c4d684b */
void trampoline_00266048(void) { REA_TAILCALL_RVA(0x472990); }

/* file+0x8f0, RVA 0x266050; ev_0a2ad0c343b0527f20845abc7f5488d48c0d032699bbe90efec2574b61083c89 */
void trampoline_00266050(void) { REA_TAILCALL_RVA(0x4733b0); }

/* file+0x8f8, RVA 0x266058; ev_f7dbb3891b7b4397ee1aa6b11342fefc954415654acc3e01ed7d2551d8e4a993 */
void trampoline_00266058(void) { REA_TAILCALL_RVA(0x4738b0); }

/* file+0x900, RVA 0x266060; ev_eb8e119ed0c8024021882ed76ae341fd643e43bf05134942f6d4597d5f9605fb */
void trampoline_00266060(void) { REA_TAILCALL_RVA(0x474250); }

/* file+0x908, RVA 0x266068; ev_c90a648c13ad9fe6758b5046569c522c72ba7a6010430af3cfd663273c8589ab */
void trampoline_00266068(void) { REA_TAILCALL_RVA(0x474db0); }

/* file+0x910, RVA 0x266070; ev_7292705f5f757bd3a8d058a0943d2adc7fe418affd9ce7a0a6e0d942107cf5b8 */
void trampoline_00266070(void) { REA_TAILCALL_RVA(0x47cff0); }

/* file+0x918, RVA 0x266078; ev_f9769ebcfd002461934c3e2a241343a165224919006f0e76f1b83ee412734ea2 */
void trampoline_00266078(void) { REA_TAILCALL_RVA(0x21dff0); }

/* file+0x920, RVA 0x266080; ev_4cc357277894a90dec4deced0ac2228345764b1eb5f60ff2ca2781f905a8e22a */
void trampoline_00266080(void) { REA_TAILCALL_RVA(0x490300); }

/* file+0x928, RVA 0x266088; ev_76282cfc412f5eadcd0963f9712b0759948e536c468e174f42cc996bbc9bca68 */
void trampoline_00266088(void) { REA_TAILCALL_RVA(0x490db0); }

/* file+0x930, RVA 0x266090; ev_30bf0b4dc11ea39b886f61c8cc8b9e38d8b6dce68dbc07593f5ea600c64e5b38 */
void trampoline_00266090(void) { REA_TAILCALL_RVA(0x497fb0); }

/* file+0x938, RVA 0x266098; ev_a626d61814ac5d25caacb7c2292a377680378f9267ad6eadee76f2c358939def */
void trampoline_00266098(void) { REA_TAILCALL_RVA(0x497fe0); }

/* file+0x940, RVA 0x2660a0; ev_d62aa94656850c5c5045010190204f5a79d1eba487a4df6bf44b469b1b8022ce */
void trampoline_002660a0(void) { REA_TAILCALL_RVA(0x498630); }

/* file+0x948, RVA 0x2660a8; ev_4321ccdddcf8493b64b5112e809542a6e148e727a436c96daf4fad6da738b7f3 */
void trampoline_002660a8(void) { REA_TAILCALL_RVA(0x498640); }

/* file+0x950, RVA 0x2660b0; ev_586444d828fd0d38d20aaec62b74a27430cb2f3457bd189c26df7aad823adcff */
void trampoline_002660b0(void) { REA_TAILCALL_RVA(0x8f7bc0); }

/* file+0x958, RVA 0x2660b8; ev_964252c03271ae7cbd4ef739e53b1ee292fb9f15d284b2db592338d70003dd66 */
void trampoline_002660b8(void) { REA_TAILCALL_RVA(0x8f6800); }

/* file+0x960, RVA 0x2660c0; ev_1cded479875880557a28c86f5a1699384fd36cff43b7468f43053846362b227e */
void trampoline_002660c0(void) { REA_TAILCALL_RVA(0x8f7420); }

/* file+0x968, RVA 0x2660c8; ev_6bf48bdc113673af0d4ef15b2793d148c720d3c666723cf43f848f452ef7e873 */
void trampoline_002660c8(void) { REA_TAILCALL_RVA(0x8f9f80); }

/* file+0x970, RVA 0x2660d0; ev_74efce4fafad65beca8c7d101ebe28297997c8d73212580290fd609a681eeaf8 */
void trampoline_002660d0(void) { REA_TAILCALL_RVA(0x5df350); }

/* file+0x978, RVA 0x2660d8; ev_229a779caab19b6047264811c1caada70a01e20938cddcaffd6b5783aaf40051 */
void trampoline_002660d8(void) { REA_TAILCALL_RVA(0x5df820); }

/* file+0x980, RVA 0x2660e0; ev_d0a8f0a613688ac61d45b0a6d0bbc2f6f6991138aff09d9d8705d65567e1b337 */
void trampoline_002660e0(void) { REA_TAILCALL_RVA(0xa34ce0); }

/* file+0x988, RVA 0x2660e8; ev_3be549814fa7283b472ee1ee679b330e46b8bbdc7dd1097dd823a24198377f2d */
void trampoline_002660e8(void) { REA_TAILCALL_RVA(0x5e84a0); }

/* file+0x990, RVA 0x2660f0; ev_5ee1b79764a2d6fd48fd4b22a669486532d76685d275b3ca79426b8428d45855 */
void trampoline_002660f0(void) { REA_TAILCALL_RVA(0x8f81f0); }

/* file+0x998, RVA 0x2660f8; ev_b3b7c4e61d8dd8e88ac7aceec00a3936a5d075d0dd64f143878887f9ef4a3232 */
void trampoline_002660f8(void) { REA_TAILCALL_RVA(0x8f9410); }

/* file+0x9a0, RVA 0x266100; ev_f9e57eb6867003bffcebec0264203c868d07d0618dbb4803a1e961f2dcae1d44 */
void trampoline_00266100(void) { REA_TAILCALL_RVA(0x8fc3f0); }

/* file+0x9a8, RVA 0x266108; ev_64b23c14ffa8d79c4876ece0f6d97d9aa37f742eeded3210e67262c491133975 */
void trampoline_00266108(void) { REA_TAILCALL_RVA(0x8f6c90); }

/* file+0x9b0, RVA 0x266110; ev_dd4d7eef2f93ef1e701ed8d9dd596b4b7688e80475b35d128f48377b60e34c8f */
void trampoline_00266110(void) { REA_TAILCALL_RVA(0xcb1a10); }

/* file+0x9b8, RVA 0x266118; ev_5d1b3e51d8102b7e2b2ce869aefcbd4150b57204216158a69cd1df08eb54949c */
void trampoline_00266118(void) { REA_TAILCALL_RVA(0xab83a0); }

/* file+0x9c0, RVA 0x266120; ev_8c1b41a919a5cfaf7997d3cdd7ea9b0a30b793e09e5d4f551fdc30f84b5a58d9 */
void trampoline_00266120(void) { REA_TAILCALL_RVA(0xab83b0); }

/* file+0x9c8, RVA 0x266128; ev_834b9c907ca50476c64fe3a88b3d1537b0f64c26a592a1a3b7b5a25c511b5cf9 */
void trampoline_00266128(void) { REA_TAILCALL_RVA(0x8fa1c0); }

/* file+0x9d0, RVA 0x266130; ev_c7667b5e2d355f6b2eec14cab7f322987223dea1611629c56c40090aeb93b11f */
void trampoline_00266130(void) { REA_TAILCALL_RVA(0x8f7b40); }

/* file+0x9d8, RVA 0x266138; ev_303bdd74a041b71db41c2bfe5a4c5e4482da00d0658a53101042d926e4209b8e */
void trampoline_00266138(void) { REA_TAILCALL_RVA(0x4a0960); }

/* file+0x9e0, RVA 0x266140; ev_2afa8be4aef9f3cac4984579fbfe0f3baed486bda28b32022234cc3751ac1eed */
void trampoline_00266140(void) { REA_TAILCALL_RVA(0x729780); }

/* file+0x9e8, RVA 0x266148; ev_a50e4c0750f3ae938ef14ad1aaf9cd8673aa64f347784d120cd3e5654b49decd */
void trampoline_00266148(void) { REA_TAILCALL_RVA(0x729790); }

/* file+0x9f0, RVA 0x266150; ev_2ba8539405364894c7f4ce7e0ccaf2c6ec887d3615df917bbd5bf522b2b7bc84 */
void trampoline_00266150(void) { REA_TAILCALL_RVA(0x7297a0); }

/* file+0x9f8, RVA 0x266158; ev_b689ad8b441a32446366e9b7e887f8a80d50b90d68bc9c152facf6bb10c02ddf */
void trampoline_00266158(void) { REA_TAILCALL_RVA(0x6bb590); }

/* file+0xa00, RVA 0x266160; ev_c9c3c67d0cb83ac7b2b247898c5173e91ea80c8da42ce1a0f007e8f33df77d38 */
void trampoline_00266160(void) { REA_TAILCALL_RVA(0xab8da0); }

/* file+0xa08, RVA 0x266168; ev_f5a7f310f0bae076a78f3566b2be30beaa6c28078bc896c16998ec183fcd13c7 */
void trampoline_00266168(void) { REA_TAILCALL_RVA(0x8fa170); }

/* file+0xa10, RVA 0x266170; ev_b437ecbf0ae88984a5f44e2aa6075d3bbe209c77d855484eff998efcc51102bd */
void trampoline_00266170(void) { REA_TAILCALL_RVA(0xb7f0c0); }

/* file+0xa18, RVA 0x266178; ev_c1afdcb71ed06aa4bb2df5c6fdccc8e8bd6328d9c50aa3dabaf4dba7e107252b */
void trampoline_00266178(void) { REA_TAILCALL_RVA(0xb7f100); }

/* file+0xa20, RVA 0x266180; ev_369667e3d1b5878f797c4e88fb7c5938128e1dcbb921a32910b1219da7a76d44 */
void trampoline_00266180(void) { REA_TAILCALL_RVA(0x8f9cf0); }

/* file+0xa28, RVA 0x266188; ev_f2a97e35bcdc33513a1b3c906b8230a5908e9efe5353dc9a929965f75b9ba36a */
void trampoline_00266188(void) { REA_TAILCALL_RVA(0x8fa740); }

/* file+0xa30, RVA 0x266190; ev_91a6488c5ade21f35f39148f65ebcb606ef6fe30415143a3756c92faa6cecbbf */
void trampoline_00266190(void) { REA_TAILCALL_RVA(0x552b70); }

/* file+0xa38, RVA 0x266198; ev_675d21c886bc9014e5ae310601068ee59fe85744287e6ccc1eb72277136da537 */
void trampoline_00266198(void) { REA_TAILCALL_RVA(0x552bf0); }

/* file+0xa40, RVA 0x2661a0; ev_05e0fdaa45846751ec7faecca3809e802671242bc5ebbc0579d32da247b7e0dc */
void trampoline_002661a0(void) { REA_TAILCALL_RVA(0x552c50); }

/* file+0xa48, RVA 0x2661a8; ev_0ff7d411090c342259a52c402d004c341a42a8d90889443bab4caf270a052366 */
void trampoline_002661a8(void) { REA_TAILCALL_RVA(0x552c80); }

/* file+0xa50, RVA 0x2661b0; ev_c567ce7c765bf7b6492fad101ea6094825df8cbc12464f15406a0c8b88bade7a */
void trampoline_002661b0(void) { REA_TAILCALL_RVA(0x552cb0); }

/* file+0xa58, RVA 0x2661b8; ev_7a3c2f65380639946ee70a6990e28792bae24c9d90b7e92130fb7c57abb14f90 */
void trampoline_002661b8(void) { REA_TAILCALL_RVA(0x552ce0); }

/* file+0xa60, RVA 0x2661c0; ev_6dd402045678f515612f12e7809366ddaff571920f0f490fff83f6a35e912f28 */
void trampoline_002661c0(void) { REA_TAILCALL_RVA(0xb7e800); }

/* file+0xa68, RVA 0x2661c8; ev_e41443ae54d6134785844e4b66fcb2ea031d3ddc59653770a3b59d1388197f2b */
void trampoline_002661c8(void) { REA_TAILCALL_RVA(0xb7ebe0); }

/* file+0xa70, RVA 0x2661d0; ev_78402ab4e10c4dabdf0220e28ffabb3626d8d2e0472c5ed5940d4d00d4b59ef9 */
void trampoline_002661d0(void) { REA_TAILCALL_RVA(0xb7ef70); }

/* file+0xa78, RVA 0x2661d8; ev_d5a13fd1963e39fdf37710d9a646cbf6472769b9b1253bbb0309595150410a67 */
void trampoline_002661d8(void) { REA_TAILCALL_RVA(0xc06d30); }

/* file+0xa80, RVA 0x2661e0; ev_b0046a852ba4f125cd5c9a5e834e0fc7d71402d22cb65aae430eac4745b28753 */
void trampoline_002661e0(void) { REA_TAILCALL_RVA(0x792690); }

/* file+0xa88, RVA 0x2661e8; ev_6b87de440a32a2ede078608709a3d12a8539aad738409f24ff9b167f641e98c1 */
void trampoline_002661e8(void) { REA_TAILCALL_RVA(0x5e8b20); }

/* file+0xa90, RVA 0x2661f0; ev_4008003ed02725231ba1938ffc3d9d106de99cf25320ad26a956214b085ed2cc */
void trampoline_002661f0(void) { REA_TAILCALL_RVA(0x552d10); }

/* file+0xa98, RVA 0x2661f8; ev_d3f7bd4d47f621775131a34c16f21122e88ceffe53e018e2c42e2774442c45bd */
void trampoline_002661f8(void) { REA_TAILCALL_RVA(0xb7f160); }

/* file+0xaa0, RVA 0x266200; ev_eb9b5b069a47e7c344a898ea585492b6c3c0f2ef1745f40d764deabd46f53d90 */
void trampoline_00266200(void) { REA_TAILCALL_RVA(0x5de250); }

/* file+0xaa8, RVA 0x266208; ev_890a5e9773b6eb4c478b15fde0c6ec7fba5663250c36118ed7c0437ef5c1f187 */
void trampoline_00266208(void) { REA_TAILCALL_RVA(0xa54a30); }

/* file+0xab0, RVA 0x266210; ev_c6d8079c07bd16aa63a086ad27308d408919770bb88b8fd6a0735e4fca801b71 */
void trampoline_00266210(void) { REA_TAILCALL_RVA(0xa54a40); }

/* file+0xab8, RVA 0x266218; ev_1937b87c2ee43445c362bfcbfc5e234caf23f60e0c155ac1015ab0319e612a02 */
void trampoline_00266218(void) { REA_TAILCALL_RVA(0xa54a50); }

/* file+0xac0, RVA 0x266220; ev_86a39a7a95b91c572025cecb0ecebfaed67dc4e8ee1753ff360b65c2537c21c9 */
void trampoline_00266220(void) { REA_TAILCALL_RVA(0xa54a60); }

/* file+0xac8, RVA 0x266228; ev_b9aed4968cb661336c90e05d63ab275b7c3999feb9feedbb8fbbbe9ac48a718d */
void trampoline_00266228(void) { REA_TAILCALL_RVA(0xa54a80); }

/* file+0xad0, RVA 0x266230; ev_2f3638ada04f3b898bb0134d3b262c524f19e9612cd54b6237027e7f830db196 */
void trampoline_00266230(void) { REA_TAILCALL_RVA(0xa54a90); }

/* file+0xad8, RVA 0x266238; ev_8be4ebb52bb7f42f7ae8819477bdacfb5dd7f8a4a69b34d0e82b1676beb8b88b */
void trampoline_00266238(void) { REA_TAILCALL_RVA(0x8f9720); }

/* file+0xae0, RVA 0x266240; ev_c973092bdc094431e7514b88190d7e469a092ae1816cf11432311b2475578ce4 */
void trampoline_00266240(void) { REA_TAILCALL_RVA(0xa54ab0); }

/* file+0xae8, RVA 0x266248; ev_5b41bdf69faf72309850850612ded4a01786d025148ff3dec6ac7378166c42ce */
void trampoline_00266248(void) { REA_TAILCALL_RVA(0x8f64e0); }

/* file+0xaf0, RVA 0x266250; ev_2640a93b3ce8653d09eb090b1f6230787f9e034d7b760c96b3d547538dee5aeb */
void trampoline_00266250(void) { REA_TAILCALL_RVA(0x8f5ef0); }

/* file+0xaf8, RVA 0x266258; ev_76af850bd3788b9a8fe41dbf2438dca1db46ee4b04fa9f1ad9f49a517f25f23d */
void trampoline_00266258(void) { REA_TAILCALL_RVA(0xa54a20); }

/* file+0xb00, RVA 0x266260; ev_9a1be69974cc1f664faf3971a3c7a3806beefc8d778a5de8abd754bedd73b74e */
void trampoline_00266260(void) { REA_TAILCALL_RVA(0xa54a70); }

/* file+0xb08, RVA 0x266268; ev_407dd521120e587db335ff6d39acad0cfcd36a189ed940280631fb61204f0ccb */
void trampoline_00266268(void) { REA_TAILCALL_RVA(0xa54aa0); }

/* file+0xb10, RVA 0x266270; ev_40746a0b93aec7839afd81d59457b4f3d09498e2433c22171aef0b499b6c8831 */
void trampoline_00266270(void) { REA_TAILCALL_RVA(0x6e54d0); }

/* file+0xb18, RVA 0x266278; ev_e64de48c644f7a840219c853399623eb885f51dc52ae7d5c902792e6cabd7af3 */
void trampoline_00266278(void) { REA_TAILCALL_RVA(0xb7f4b0); }

/* file+0xb20, RVA 0x266280; ev_2b63c7d8c3b52408e1bc070022da82a34eaf3813bde9a8d77bdc3241bebf3fa4 */
void trampoline_00266280(void) { REA_TAILCALL_RVA(0x83d660); }

/* file+0xb28, RVA 0x266288; ev_fc3dc592ee8bb13fb359b0a95a078e4e6b0270ece4a9c1fea03d2e92a16cd88a */
void trampoline_00266288(void) { REA_TAILCALL_RVA(0x83d7c0); }

/* file+0xb30, RVA 0x266290; ev_6f00647543e9e06075ddd224bd6f777ca28385de5acd9bc3f06fb2f290d723de */
void trampoline_00266290(void) { REA_TAILCALL_RVA(0x83dab0); }

/* file+0xb38, RVA 0x266298; ev_0ce2c60da7c9bcdefd8872a5d263073ca33ddaeb2b3ddedf0c81bc8c019158cb */
void trampoline_00266298(void) { REA_TAILCALL_RVA(0x83de80); }

/* file+0xb40, RVA 0x2662a0; ev_afe899e59dfec2690eb634a8f95172c9075b4291d3e71b4bd355fa248632d865 */
void trampoline_002662a0(void) { REA_TAILCALL_RVA(0x8f9c80); }

/* file+0xb48, RVA 0x2662a8; ev_4d9e86ca8b421920a203eb20dc65df99d46584e458ccf1d1babb1c065edca21f */
void trampoline_002662a8(void) { REA_TAILCALL_RVA(0x8fa110); }

/* file+0xb50, RVA 0x2662b0; ev_4fd19437105a55a762fae3b35c8d28bdb88edac0c1804dd85604042383d0c051 */
void trampoline_002662b0(void) { REA_TAILCALL_RVA(0x8f91b0); }

/* file+0xb58, RVA 0x2662b8; ev_0900495d819f1c97494375d2c86e949c2282ed596f80da7dbc13ec4815e75288 */
void trampoline_002662b8(void) { REA_TAILCALL_RVA(0x8fa4f0); }

/* file+0xb60, RVA 0x2662c0; ev_acb55346fe900693061b23d4b0647e69bba3c82086ca6f8dfe4a98108ccd0164 */
void trampoline_002662c0(void) { REA_TAILCALL_RVA(0x8f8090); }

/* file+0xb68, RVA 0x2662c8; ev_69e519e2446a67e2692652a979fd80f94874838ee785f5751d10a52d991a1771 */
void trampoline_002662c8(void) { REA_TAILCALL_RVA(0x8fbb80); }

/* file+0xb70, RVA 0x2662d0; ev_9f75d8d42fae7f84590d3ecec283571d5322dec1bdc90f32ce1da50efff3d78b */
void trampoline_002662d0(void) { REA_TAILCALL_RVA(0x8f7b80); }

/* file+0xb78, RVA 0x2662d8; ev_91b607969856883e998de038a62803f27a09390c2c4392c931dd33ca8f08c28d */
void trampoline_002662d8(void) { REA_TAILCALL_RVA(0x8f7890); }

/* file+0xb80, RVA 0x2662e0; ev_12f1b038ad33ffa602ca0240700860a0759309f260fa1416557bddded7653845 */
void trampoline_002662e0(void) { REA_TAILCALL_RVA(0x8fb8a0); }

/* file+0xb88, RVA 0x2662e8; ev_12e0b7c7d06d906cf96d2d8f926c3d73b0eb55f7d402c6aac7ae972c2ae05670 */
void trampoline_002662e8(void) { REA_TAILCALL_RVA(0x8f8510); }

/* file+0xb90, RVA 0x2662f0; ev_b94365078e18dea9a7e16a333f08a69bb792bc25703e1c62ffbe96a23ad9005c */
void trampoline_002662f0(void) { REA_TAILCALL_RVA(0x8f8800); }

/* file+0xb98, RVA 0x2662f8; ev_d0e59169b88a68afdec4f16e469e97ff4592c2ec1eb950454e964c0fbc9b9489 */
void trampoline_002662f8(void) { REA_TAILCALL_RVA(0x49b080); }

/* file+0xba0, RVA 0x266300; ev_05d4338129932a542e721f4d6cad3b965880c578a3f7877b376998250390abf7 */
void trampoline_00266300(void) { REA_TAILCALL_RVA(0x49b090); }

/* file+0xba8, RVA 0x266308; ev_78cbc03bc9b3ee4c80742de069a9b5c034c064cdfc7fe09b19eea827165c9955 */
void trampoline_00266308(void) { REA_TAILCALL_RVA(0x55fa50); }

/* file+0xbb0, RVA 0x266310; ev_9096f7261dc4fffa736db9049715d06277a822f0fbadc3001e35146c0b7c1d23 */
void trampoline_00266310(void) { REA_TAILCALL_RVA(0xc34870); }

/* file+0xbb8, RVA 0x266318; ev_3447ab6f6a147b49d94d9048e5c22ffdb5f81f80090d88fba7a26997bacae7ad */
void trampoline_00266318(void) { REA_TAILCALL_RVA(0x7dccf0); }

/* file+0xbc0, RVA 0x266320; ev_9668b9bf4fa9400fddbfd76866f4aa2f6f5ccb3634227f2d47f73eb79be89a81 */
void trampoline_00266320(void) { REA_TAILCALL_RVA(0x7dcd00); }

/* file+0xbc8, RVA 0x266328; ev_8e104228ee03513d2ea3bd2e3545073725d0cdb2e46edd1049f2440457c361a7 */
void trampoline_00266328(void) { REA_TAILCALL_RVA(0x7dcd10); }

/* file+0xbd0, RVA 0x266330; ev_5ab922fe550718bbd42344df14c22212e627e3bc30b1d87c8447b08dddfdfb6a */
void trampoline_00266330(void) { REA_TAILCALL_RVA(0x7dcd20); }

/* file+0xbd8, RVA 0x266338; ev_fa766b1cb748031cb07490070502db3dd5220330210c7327de0766b42e0659aa */
void trampoline_00266338(void) { REA_TAILCALL_RVA(0x7dcd30); }

/* file+0xbe0, RVA 0x266340; ev_6df11549f01b3d85e1173c8c5fab59e8bea1ce192a3d0308aa6d069d55f7f865 */
void trampoline_00266340(void) { REA_TAILCALL_RVA(0x5a6c90); }

/* file+0xbe8, RVA 0x266348; ev_d76d0291e2b3962754d6b6da9a7c655362631e6025fc77db5602abbe70d92fe1 */
void trampoline_00266348(void) { REA_TAILCALL_RVA(0x5a7300); }

/* file+0xbf0, RVA 0x266350; ev_8c00e50ebbc0b8f2477c7db2ae31563ab9c41a21e523b2dc58946fa44ada7fca */
void trampoline_00266350(void) { REA_TAILCALL_RVA(0x5a7610); }

/* file+0xbf8, RVA 0x266358; ev_144a0609a7e4b1cbf79aa4f6efbf1322e29eafbcc22d15e48ba6d581a5ea40c9 */
void trampoline_00266358(void) { REA_TAILCALL_RVA(0x5a7900); }

/* file+0xc00, RVA 0x266360; ev_4d89ebadac8ed8b46af3562a68c13298a7b215636ea89b146bb05b9b2f3f8efe */
void trampoline_00266360(void) { REA_TAILCALL_RVA(0xc9c830); }

/* file+0xc08, RVA 0x266368; ev_7b5be175ebf1704a2ffe52f4e546ed2e806640b3be6e20c158bbcee39ed713f3 */
void trampoline_00266368(void) { REA_TAILCALL_RVA(0x5a7f00); }

/* file+0xc10, RVA 0x266370; ev_b3f95382713fc33c40c8c22030d9f0ba3e6bb5ab3b1f239e6d72e5354704218a */
void trampoline_00266370(void) { REA_TAILCALL_RVA(0x5a8070); }

/* file+0xc18, RVA 0x266378; ev_b007a682aaa438d530206a3d9b89586d18fccdafe3ebfa55c9a4e21fdd7df99c */
void trampoline_00266378(void) { REA_TAILCALL_RVA(0xbe8480); }

/* file+0xc20, RVA 0x266380; ev_1fa2b1173f18e8b42185881c20ecd46994e8e93ee8a01f305eb531c1f3451e67 */
void trampoline_00266380(void) { REA_TAILCALL_RVA(0x49b0a0); }

/* file+0xc28, RVA 0x266388; ev_17af925d0a37b28003f1a7b9d91933096116bca7f0f28f15b1d9c059eb07c981 */
void trampoline_00266388(void) { REA_TAILCALL_RVA(0x49b0c0); }

/* file+0xc30, RVA 0x266390; ev_91eb5bf0d2d400b12aced3c06dc465cae881234fc1c10309f9cde2d3613c9afd */
void trampoline_00266390(void) { REA_TAILCALL_RVA(0x49b0d0); }

/* file+0xc38, RVA 0x266398; ev_1070861a6385e7363011a177c2b8b63ddd0a4cab13d5d2ba62a5f645880c01ce */
void trampoline_00266398(void) { REA_TAILCALL_RVA(0x49b0e0); }

/* file+0xc40, RVA 0x2663a0; ev_36dfeb8d0b9dad60259fbb73524d04ba0eb9331664c205ff92f56afa0d11b019 */
void trampoline_002663a0(void) { REA_TAILCALL_RVA(0x49b0f0); }

/* file+0xc48, RVA 0x2663a8; ev_6b8a939a0c4ca6683f2d74cc333ebeff52ff9481483eca95d68519c3d89be817 */
void trampoline_002663a8(void) { REA_TAILCALL_RVA(0x530720); }

/* file+0xc50, RVA 0x2663b0; ev_9b10eef7b23045ba6c36687e48b791963a0ff9a68764de3d86a2870a4aef273b */
void trampoline_002663b0(void) { REA_TAILCALL_RVA(0x531670); }

/* file+0xc58, RVA 0x2663b8; ev_48caedbb43feea21870a0b7557c142fdf208f6ddf1a378941ca4a59206f8c198 */
void trampoline_002663b8(void) { REA_TAILCALL_RVA(0x8f96f0); }

/* file+0xc60, RVA 0x2663c0; ev_d66104c3c28e3c89a85b920fcfc90a9e1d5c357cd1099e8240ff58bb7c457d88 */
void trampoline_002663c0(void) { REA_TAILCALL_RVA(0x531230); }

/* file+0xc68, RVA 0x2663c8; ev_8d3c73f57d57ec1536431ee24894d5a639090edfbc085cf9cf7dd49756d6bdc2 */
void trampoline_002663c8(void) { REA_TAILCALL_RVA(0x802df0); }

/* file+0xc70, RVA 0x2663d0; ev_f3d3fafd477f9293a2dca95dbcf6e27602284558c9305be816fa91bc486102af */
void trampoline_002663d0(void) { REA_TAILCALL_RVA(0xb7f140); }

/* file+0xc78, RVA 0x2663d8; ev_f5bfbcfdbdb18a30d80848425c0047a9abf53cf7dd87675e64e5d204fa1f95b1 */
void trampoline_002663d8(void) { REA_TAILCALL_RVA(0xae35e0); }

/* file+0xc80, RVA 0x2663e0; ev_f7bfc79c91d32af96d85d7b31df1792575ba0c3dec4abd7ad5af014086ac26b5 */
void trampoline_002663e0(void) { REA_TAILCALL_RVA(0x4eee20); }

/* file+0xc88, RVA 0x2663e8; ev_b9abf8c7c484504101c3ea61aaf2d16686b2c38f3898d08aedbd5df7224f403b */
void trampoline_002663e8(void) { REA_TAILCALL_RVA(0x8fab10); }

/* file+0xc90, RVA 0x2663f0; ev_44c2310c38da9b617ac2e1d1ca39ec38e8d16fdfbc525e67345bd3f560564c70 */
void trampoline_002663f0(void) { REA_TAILCALL_RVA(0x8fae30); }

/* file+0xc98, RVA 0x2663f8; ev_8bb6db81465c6e3d979b6a74771c419c62d1d0c75f7aaa20d5292351bd7b7622 */
void trampoline_002663f8(void) { REA_TAILCALL_RVA(0x9c9220); }

/* file+0xca0, RVA 0x266400; ev_6cb7987e1abe20ce62bfc0d23c705bf89a53df8478c876f8ee0a5c7fc7e49a4e */
void trampoline_00266400(void) { REA_TAILCALL_RVA(0x9c9100); }

/* file+0xca8, RVA 0x266408; ev_c658ebb6c9f492b49a246aafdd448fb717857a03497fa80b91c5de16114a8b64 */
void trampoline_00266408(void) { REA_TAILCALL_RVA(0x642310); }

/* file+0xcb0, RVA 0x266410; ev_705a0da54b074058cbcde738b7851188791e292e92f77bdecb372626c335d621 */
void trampoline_00266410(void) { REA_TAILCALL_RVA(0x642820); }

/* file+0xcb8, RVA 0x266418; ev_be45ae836c664a4bd736fed71e1a99d6557e81873a18145a2532ffd37667a401 */
void trampoline_00266418(void) { REA_TAILCALL_RVA(0x6436e0); }

/* file+0xcc0, RVA 0x266420; ev_19ab1df574e27fdfc93b45b0d9109d0d817167948b215e9b32592d882167800e */
void trampoline_00266420(void) { REA_TAILCALL_RVA(0x6438d0); }

/* file+0xcc8, RVA 0x266428; ev_a19c508ba38dad17e51eb65f43c82d56c2262e5bfa69e545d80c227e62156d3d */
void trampoline_00266428(void) { REA_TAILCALL_RVA(0x643c60); }

/* file+0xcd0, RVA 0x266430; ev_134637598f2cd75181b92224d6a26fef5d5d9a2740693405fda80a68981e1726 */
void trampoline_00266430(void) { REA_TAILCALL_RVA(0x9f8290); }

/* file+0xcd8, RVA 0x266438; ev_633d3e671643ab07c15869b3f11ba141fd0bce50e2f0756b05509b413e20901c */
void trampoline_00266438(void) { REA_TAILCALL_RVA(0x9fbb70); }

/* file+0xce0, RVA 0x266440; ev_e7cf7e1b5e2fe54e3e359b34358fb1761d3686e60a964c0f0bef7c231fd84c3a */
void trampoline_00266440(void) { REA_TAILCALL_RVA(0xa45280); }

/* file+0xce8, RVA 0x266448; ev_a9d1dd06e3adf86f4f4d35ad6e7c7d375ee6b9a8cc0fc2fce3a409c4d2bb4178 */
void trampoline_00266448(void) { REA_TAILCALL_RVA(0xc87ca0); }

/* file+0xcf0, RVA 0x266450; ev_f30138477fba0388f6570967dd0ad14b8b16fdbc3a9278364f98d53f6de8cebc */
void trampoline_00266450(void) { REA_TAILCALL_RVA(0x9ff000); }

/* file+0xcf8, RVA 0x266458; ev_04d9a4a69f417dac99c6d75d273bb9bea9389739c25a994949d8ad68556f5e43 */
void trampoline_00266458(void) { REA_TAILCALL_RVA(0xa00780); }

/* file+0xd00, RVA 0x266460; ev_59bfe6689cd2407cf9e033c4db10ea8a4d8bff08a650f1585e4809efbcd112ad */
void trampoline_00266460(void) { REA_TAILCALL_RVA(0xa007e0); }

/* file+0xd08, RVA 0x266468; ev_9e9087b260a24cd1e30b17eca3b0709bd21a4473896ce8e1b65304729478fc3f */
void trampoline_00266468(void) { REA_TAILCALL_RVA(0xabe830); }

/* file+0xd10, RVA 0x266470; ev_351da8d615c953c3c3bdba72b28242c60f183c4eff676a6a831feac7a36c04ba */
void trampoline_00266470(void) { REA_TAILCALL_RVA(0x9fcf30); }

/* file+0xd18, RVA 0x266478; ev_919b7757b68b044325f4f3985ebc4bffad936e09f6d583b48809cfcc3fcd3d61 */
void trampoline_00266478(void) { REA_TAILCALL_RVA(0x5f0fc0); }

/* file+0xd20, RVA 0x266480; ev_ec35d864c063384239ff10e15b70a91a9087b4e3c9838e01e3e0ab30ec579853 */
void trampoline_00266480(void) { REA_TAILCALL_RVA(0x8f73f0); }

/* file+0xd28, RVA 0x266488; ev_c0e8e7e79c9860d58cb5f93b211cd9e45b9ddccc67bcb2726f7ff3de757d4bf5 */
void trampoline_00266488(void) { REA_TAILCALL_RVA(0x4f7250); }

/* file+0xd30, RVA 0x266490; ev_325a45a277443aef0a01bc33b9ecbf1f8b23bc746ff42eb0cc588ee76d8a81b4 */
void trampoline_00266490(void) { REA_TAILCALL_RVA(0x9fdad0); }

/* file+0xd38, RVA 0x266498; ev_4d33eab1793b96ffa7036b1707b09efd41bbf866ce6acf441ca75ec8af1b514e */
void trampoline_00266498(void) { REA_TAILCALL_RVA(0x9fddb0); }

/* file+0xd40, RVA 0x2664a0; ev_114f5456e5f8b9b5164052394a2f669a7079b7dd065c6099b74ba66f999b15cc */
void trampoline_002664a0(void) { REA_TAILCALL_RVA(0x9fdf10); }

/* file+0xd48, RVA 0x2664a8; ev_d23adc3942034c482f340b0f2e2a35b1238bad2f543b1eb4890f0c79853c29ec */
void trampoline_002664a8(void) { REA_TAILCALL_RVA(0x6444d0); }

/* file+0xd50, RVA 0x2664b0; ev_de951251b1d949dfcd9beba54b2d7b87c2d06b2e155d5f3ab48317f5ecbfdba5 */
void trampoline_002664b0(void) { REA_TAILCALL_RVA(0x650fd0); }

/* file+0xd58, RVA 0x2664b8; ev_3aab21628813fdee4e13c2e4a58db0b72dd734fc7971318ed30451cb7927213e */
void trampoline_002664b8(void) { REA_TAILCALL_RVA(0x9fea30); }

/* file+0xd60, RVA 0x2664c0; ev_107528cdf9bfc43f6c1bbdf4d061b44e2e7abc20ba09f9d59fd30bac27f03153 */
void trampoline_002664c0(void) { REA_TAILCALL_RVA(0x4f7940); }

/* file+0xd68, RVA 0x2664c8; ev_45ba05ad96bf8d73ff8f2002227ebffe713ac456ed4eca897e4735c475efbb6f */
void trampoline_002664c8(void) { REA_TAILCALL_RVA(0xab8ae0); }

/* file+0xd70, RVA 0x2664d0; ev_5fe2ebab889e33e22077b2fbe43d8ca815a9d7cd7219c95565d88506e11fc3de */
void trampoline_002664d0(void) { REA_TAILCALL_RVA(0xabb660); }

/* file+0xd78, RVA 0x2664d8; ev_1b653436719ad771d0f4bc28767da1052a5f673065dfbe98da8c16d9c4c64cfc */
void trampoline_002664d8(void) { REA_TAILCALL_RVA(0x9fe260); }

/* file+0xd80, RVA 0x2664e0; ev_8f8baa9f4e8232acab354cf752d8e2c8c62463f9ffe3aa19b23069084b861760 */
void trampoline_002664e0(void) { REA_TAILCALL_RVA(0x9fe4e0); }

/* file+0xd88, RVA 0x2664e8; ev_6ccc7e3752b9431b161cfcf2791073a7a4b8e6cee1b5ed32b97b9c7dac8e968d */
void trampoline_002664e8(void) { REA_TAILCALL_RVA(0x9fe630); }

/* file+0xd90, RVA 0x2664f0; ev_e4180085fbd569aab9505566a6f74ffe0e526bb01a27d33fdb76a84fbea5c9b1 */
void trampoline_002664f0(void) { REA_TAILCALL_RVA(0x798330); }

/* file+0xd98, RVA 0x2664f8; ev_af74aa1a874b0b086759cd52698271e9e427d23b981cc34da7f782e58c01d843 */
void trampoline_002664f8(void) { REA_TAILCALL_RVA(0xabd000); }

/* file+0xda0, RVA 0x266500; ev_5e460dd4fa6d1ee8ae496bd4a4aa7435046a5e688959b81f7d5e17d42e9dabef */
void trampoline_00266500(void) { REA_TAILCALL_RVA(0xfc890); }

/* file+0xda8, RVA 0x266508; ev_b6e2c30db382b84b3e42f79a723fa2f17aaee7d92f1dcf31038c6f167d476a4d */
void trampoline_00266508(void) { REA_TAILCALL_RVA(0x49f090); }

/* file+0xdb0, RVA 0x266510; ev_2deb094c5dd267812c2d20a519af38cc9b0403c13b9dcd03b1a85c39fe9a25b5 */
void trampoline_00266510(void) { REA_TAILCALL_RVA(0x49f200); }

/* file+0xdb8, RVA 0x266518; ev_4d8f93c415bd034f4f1bca6df76d977984f05070b9753b6d791bc69bcd2acf17 */
void trampoline_00266518(void) { REA_TAILCALL_RVA(0x4c0590); }

/* file+0xdc0, RVA 0x266520; ev_abc3d86efb0538e8cada7574a37ed0c2d793f7dff7ed8792ea679b0c0b71ce8b */
void trampoline_00266520(void) { REA_TAILCALL_RVA(0x4c05b0); }

/* file+0xdc8, RVA 0x266528; ev_a92a0b934a8912dc1fae3393d9c9cb992feea82a672c6123210bf7959b9c64b7 */
void trampoline_00266528(void) { REA_TAILCALL_RVA(0xa9430); }

/* file+0xdd0, RVA 0x266530; ev_1cf225b0e44e289c8d8e67ca773a57957efc8a11d4457d3e79c7e6119389648e */
void trampoline_00266530(void) { REA_TAILCALL_RVA(0x4ca350); }

/* file+0xdd8, RVA 0x266538; ev_594c5c8f2a1e0e7df849ea5df446b18d275443ec8a027debc699304e9b27b576 */
void trampoline_00266538(void) { REA_TAILCALL_RVA(0x4caa40); }

/* file+0xde0, RVA 0x266540; ev_09efdcdb6d82165abeb5ddfba0893897c14bff9877f2c4123c701d808c209cb3 */
void trampoline_00266540(void) { REA_TAILCALL_RVA(0xaa510); }

/* file+0xde8, RVA 0x266548; ev_e0075b684bc4497bf04db90c057069850cb08578e211d7473b30810b3fbadd89 */
void trampoline_00266548(void) { REA_TAILCALL_RVA(0x4d51d0); }

/* file+0xdf0, RVA 0x266550; ev_62d891c4dc8e0844d46f2afea838e3434e84678017e3051b5790425bf5e8421e */
void trampoline_00266550(void) { REA_TAILCALL_RVA(0x8111b0); }

/* file+0xdf8, RVA 0x266558; ev_120d801416d14ffe949cd0f00a408fe36d69bf99a4fd7c74ec9d926fdb576391 */
void trampoline_00266558(void) { REA_TAILCALL_RVA(0x1ae90); }

/* file+0xe00, RVA 0x266560; ev_71706337407f4cec43b416409a024cd7e02ead92746d1f49cd583886824cf720 */
void trampoline_00266560(void) { REA_TAILCALL_RVA(0x4f0030); }

/* file+0xe08, RVA 0x266568; ev_233e28fbf263fcc93772fa71940f6910c0d80cf14e4412786491cea2a98584a7 */
void trampoline_00266568(void) { REA_TAILCALL_RVA(0x4fbbd0); }

/* file+0xe10, RVA 0x266570; ev_044de44531dc6dc7c0ed7a1a4ca9a4649afb06d19ea0fcdf5d95062e381210ab */
void trampoline_00266570(void) { REA_TAILCALL_RVA(0x50ced0); }

/* file+0xe18, RVA 0x266578; ev_f04672760190464ef88390cc0b4c4c058a30685c18453543a275daff82941110 */
void trampoline_00266578(void) { REA_TAILCALL_RVA(0x50cee0); }

/* file+0xe20, RVA 0x266580; ev_13cec78a48d7d0c2f2c9f7f227c68035151b61a08ee7cf06adef67485d01e198 */
void trampoline_00266580(void) { REA_TAILCALL_RVA(0x50cf30); }

/* file+0xe28, RVA 0x266588; ev_7cfd599498114c66667ec19c2698a0a3b4fb35f83c9a2e658e1831a21bbf979d */
void trampoline_00266588(void) { REA_TAILCALL_RVA(0x50cf70); }

/* file+0xe30, RVA 0x266590; ev_fe4183d0128d53a32405dcfa786475b67800564e2d11e03c2c275104ffcef284 */
void trampoline_00266590(void) { REA_TAILCALL_RVA(0x50cfb0); }

/* file+0xe38, RVA 0x266598; ev_aa475cd5fc18883ba1984323b3f44ede253a7b3cbfb21711675c5043a84025eb */
void trampoline_00266598(void) { REA_TAILCALL_RVA(0x50cfe0); }

/* file+0xe40, RVA 0x2665a0; ev_d06e23b3fc4b01c2048fd66a52e137d756efabf029d2a4176af4b757e9491cae */
void trampoline_002665a0(void) { REA_TAILCALL_RVA(0x51e4d0); }

/* file+0xe48, RVA 0x2665a8; ev_92e526ce960b080a740cce3dc66c8c6c82e7f91bf9cad3b677362df524dfc53a */
void trampoline_002665a8(void) { REA_TAILCALL_RVA(0x51ef60); }

/* file+0xe50, RVA 0x2665b0; ev_1397f018d596f8c3a600de6ce2cb6507ca3e37e941611960cd247c0337f6831c */
void trampoline_002665b0(void) { REA_TAILCALL_RVA(0x51f000); }

/* file+0xe58, RVA 0x2665b8; ev_62ce3604723f4f5f60e45bf99e63044fd624b7cafe5aa5657b10782b36919363 */
void trampoline_002665b8(void) { REA_TAILCALL_RVA(0x51f0b0); }

/* file+0xe60, RVA 0x2665c0; ev_7e0c1be47f16e0ac4f3f9277135ae8e9bfb302089cf0c9a92a4e93c58d01f64d */
void trampoline_002665c0(void) { REA_TAILCALL_RVA(0x51f2e0); }

/* file+0xe68, RVA 0x2665c8; ev_d5baa2d8a4fa5ea3f45c002c9ba25c67055dde1ea23616c49d882f4363ef9742 */
void trampoline_002665c8(void) { REA_TAILCALL_RVA(0x51f670); }

/* file+0xe70, RVA 0x2665d0; ev_57e72951acddf42d8a8948b32c7b508bcbcb0ea689d1f3013de7df7c3e032b10 */
void trampoline_002665d0(void) { REA_TAILCALL_RVA(0x51fee0); }

/* file+0xe78, RVA 0x2665d8; ev_6ca0ec95a74c75bda177c9f1a4106c79f4fe4260345bc06fabd881110de29081 */
void trampoline_002665d8(void) { REA_TAILCALL_RVA(0x536400); }

/* file+0xe80, RVA 0x2665e0; ev_ea1e9ea7f930410dd41cb15f91164ff2b8d0fee66eb2a487cd4b960011ba195e */
void trampoline_002665e0(void) { REA_TAILCALL_RVA(0x544ca0); }

/* file+0xe88, RVA 0x2665e8; ev_2ff3c179cc1c15760af4ab4d504e0b903279b8e781de335abfc29ec2bec78f28 */
void trampoline_002665e8(void) { REA_TAILCALL_RVA(0x5468f0); }

/* file+0xe90, RVA 0x2665f0; ev_64dc60c786fdf097f8cabe9a24dc65fa23c90bcec95b4c031ee9dd244a45c4ab */
void trampoline_002665f0(void) { REA_TAILCALL_RVA(0xb1630); }

/* file+0xe98, RVA 0x2665f8; ev_048c91acd5230b5f168db1aa387eefe5dbef63685ce77d2cb1812ef6fac587f1 */
void trampoline_002665f8(void) { REA_TAILCALL_RVA(0xb1fb0); }

/* file+0xea0, RVA 0x266600; ev_d5838d97d25d0404a9dd86ee3e4231336f7788593949509b36b36f988ce2e9c5 */
void trampoline_00266600(void) { REA_TAILCALL_RVA(0x55bf40); }

/* file+0xea8, RVA 0x266608; ev_98298519c4811cd31175a09c0e6f76183ba2eff0e35d2636cd3920bedb6819fa */
void trampoline_00266608(void) { REA_TAILCALL_RVA(0x55c030); }

/* file+0xeb0, RVA 0x266610; ev_848181c24be9fbad1dabfd90c2c041026620367371dd04b3e5d37ee90811786d */
void trampoline_00266610(void) { REA_TAILCALL_RVA(0x55c050); }

/* file+0xeb8, RVA 0x266618; ev_27bee08c9b1193043039fdc8c47563f926ba90567be8e72ec64aea23ce8e0af3 */
void trampoline_00266618(void) { REA_TAILCALL_RVA(0x56e200); }

/* file+0xec0, RVA 0x266620; ev_4ddec5f89d19a2cc23abba72f01134c5a02849938fe85cf449d4aa0db112fdfd */
void trampoline_00266620(void) { REA_TAILCALL_RVA(0x57f4a0); }

/* file+0xec8, RVA 0x266628; ev_61a86c88edcf4f3b58f09ce33cc0242bc7e342f3ea8e4708eb2f0da99477b97c */
void trampoline_00266628(void) { REA_TAILCALL_RVA(0x9945e0); }

/* file+0xed0, RVA 0x266630; ev_cc6a666cfae72670f185a2f5a2e11aa1f623b3b14d8253830e4c4991728f9d8c */
void trampoline_00266630(void) { REA_TAILCALL_RVA(0x585950); }

/* file+0xed8, RVA 0x266638; ev_05908f766f9543e213de3110f4f87beefa1f41adfb69c03d9ca5cc10add84cb2 */
void trampoline_00266638(void) { REA_TAILCALL_RVA(0x599820); }

/* file+0xee0, RVA 0x266640; ev_5812582b38fc8af5d25a5b508d3cbe99d69943de91ad69575d9cff0860c0e904 */
void trampoline_00266640(void) { REA_TAILCALL_RVA(0x59a3e0); }

/* file+0xee8, RVA 0x266648; ev_b6dfa31fa28d6e952d6d88251b975351579a5eeee4126d1673887e7142d3aea6 */
void trampoline_00266648(void) { REA_TAILCALL_RVA(0x59a530); }

/* file+0xef0, RVA 0x266650; ev_ed01ccff279d59b8a4f2cd89abdc3def4e0886751c4ad11c4373d297e53f5719 */
void trampoline_00266650(void) { REA_TAILCALL_RVA(0x59a700); }

/* file+0xef8, RVA 0x266658; ev_6b61d4ab02cc3c006038b2b64d0af2b939c935d67b80f3dbbc2caac281eda47e */
void trampoline_00266658(void) { REA_TAILCALL_RVA(0x59a7d0); }

/* file+0xf00, RVA 0x266660; ev_cbe1eaaed4df10cc75a9b79d07190dc1cbaac6c521c04126b1f06be1f227fce5 */
void trampoline_00266660(void) { REA_TAILCALL_RVA(0x59aa50); }

/* file+0xf08, RVA 0x266668; ev_22869d48a04358186aa2865c19591d122a8833c51a1a6c062e08b52d5901ebab */
void trampoline_00266668(void) { REA_TAILCALL_RVA(0x59ab60); }

/* file+0xf10, RVA 0x266670; ev_b3f47c80f36bc5674aa7d9bffd5ad953580c624320aa23715c13d58e2bbbb842 */
void trampoline_00266670(void) { REA_TAILCALL_RVA(0x59ac60); }

/* file+0xf18, RVA 0x266678; ev_cad6533c2c3aa3c04be08021c96a2a6756e657bf2aa28c221eaf2708827cf704 */
void trampoline_00266678(void) { REA_TAILCALL_RVA(0x5dbed0); }

/* file+0xf20, RVA 0x266680; ev_ad0615ee013e89c16455513c5466b5f2ce9ae1376854f36a087edd01303325e3 */
void trampoline_00266680(void) { REA_TAILCALL_RVA(0x5eb720); }

/* file+0xf28, RVA 0x266688; ev_3ac30a55280113881ede59f9eb14be321e99a8899e373e25a71297aec62c0c94 */
void trampoline_00266688(void) { REA_TAILCALL_RVA(0x5ec030); }

/* file+0xf30, RVA 0x266690; ev_987defa2f0bb2ce3edb76d5b3e216f95695d7830c9da627fb50c625ba35a78b8 */
void trampoline_00266690(void) { REA_TAILCALL_RVA(0x5ecad0); }

/* file+0xf38, RVA 0x266698; ev_fd0223f8134aacf2ac72b1e40cd6d11fddb2ab96cac7c0edfe36ba0478df972f */
void trampoline_00266698(void) { REA_TAILCALL_RVA(0x5ed440); }

/* file+0xf40, RVA 0x2666a0; ev_ea9aab6ed7c2177b8de74e2407b6ac95ce26591f235d2b35ba5c1c3f070dcc1a */
void trampoline_002666a0(void) { REA_TAILCALL_RVA(0x5edb30); }

/* file+0xf48, RVA 0x2666a8; ev_4e7a5c2b6868f2facc6e32a97f1adc33bff9606e3b0549abe72f7dec1d5fac0f */
void trampoline_002666a8(void) { REA_TAILCALL_RVA(0x14e280); }

/* file+0xf50, RVA 0x2666b0; ev_040ab764b2fe85d7c7c8b937470a33c89c72d7a411004c92472bd60f3a8af131 */
void trampoline_002666b0(void) { REA_TAILCALL_RVA(0x5f18b0); }

/* file+0xf58, RVA 0x2666b8; ev_1a2303717b94c052d124628d4d6f2150e0ad3ac41a40208d858616d68b91f2bf */
void trampoline_002666b8(void) { REA_TAILCALL_RVA(0x5f2b30); }

/* file+0xf60, RVA 0x2666c0; ev_1effd977ac09c6438a359cc7786cb726987597151c1d782ce40984b5ae347d38 */
void trampoline_002666c0(void) { REA_TAILCALL_RVA(0x5fd0c0); }

/* file+0xf68, RVA 0x2666c8; ev_91b1c5f4db425b8637a904220ac09d930f499f112977c4daf8e27a3e9c9c0e65 */
void trampoline_002666c8(void) { REA_TAILCALL_RVA(0x600680); }

/* file+0xf70, RVA 0x2666d0; ev_f36e256d259c52aadb70e5b35f2c3c991951e347c0f12ad45785bb5fdcec0b42 */
void trampoline_002666d0(void) { REA_TAILCALL_RVA(0x600f40); }

/* file+0xf78, RVA 0x2666d8; ev_fe6c364e1dbfe14a8d2da6578824571634c20828e0c52592fb6ea11c1fc52c63 */
void trampoline_002666d8(void) { REA_TAILCALL_RVA(0xae64a0); }

/* file+0xf80, RVA 0x2666e0; ev_2cb0e1269df922329ddbf52995b2c193a64491d2b2f8e13710d81df301619fc5 */
void trampoline_002666e0(void) { REA_TAILCALL_RVA(0x62daa0); }

/* file+0xf88, RVA 0x2666e8; ev_be35578515bb7eac742cd9e0035c2ba71234bc1d6d7c03b70e67a8a1772c0aca */
void trampoline_002666e8(void) { REA_TAILCALL_RVA(0x6302d0); }

/* file+0xf90, RVA 0x2666f0; ev_3fa43938021d371b600960971eba1e4b74f3ee855a2a88f6f5ac8636a1353528 */
void trampoline_002666f0(void) { REA_TAILCALL_RVA(0x634f10); }

/* file+0xf98, RVA 0x2666f8; ev_61725172ce3a3b71fdf15035ca5f82ae5a0dc864dbb4502ef35cabcb9b82a8f0 */
void trampoline_002666f8(void) { REA_TAILCALL_RVA(0x63f520); }

/* file+0xfa0, RVA 0x266700; ev_bbc5354bad12fa280c5fa04713b475e194e2c49652b0dfc6a49a8536e95d7e8f */
void trampoline_00266700(void) { REA_TAILCALL_RVA(0x6579b0); }

/* file+0xfa8, RVA 0x266708; ev_5e41736513dfe69b25f14c42f50a2448440c79882a4bfacdc5c6be379555b1e6 */
void trampoline_00266708(void) { REA_TAILCALL_RVA(0xca7310); }

/* file+0xfb0, RVA 0x266710; ev_4e47c0f100e5651199007fa31cf68fffc4c18afcd709587fcf979ba3e2a068ac */
void trampoline_00266710(void) { REA_TAILCALL_RVA(0x662e70); }

/* file+0xfb8, RVA 0x266718; ev_02610441ba492ef0f06ffc9201d125589f7944ffc2bf9470c6767e40bd84ba26 */
void trampoline_00266718(void) { REA_TAILCALL_RVA(0x662e80); }

/* file+0xfc0, RVA 0x266720; ev_d735c205b1631f9982a50d6b3fbcc8161229f870f56b25afc11fa11773dc9ebf */
void trampoline_00266720(void) { REA_TAILCALL_RVA(0x678e10); }

/* file+0xfc8, RVA 0x266728; ev_67ba73450c68710572ab4dc3000e735d311c67e6c7c48da291828528cd261909 */
void trampoline_00266728(void) { REA_TAILCALL_RVA(0x678e60); }

/* file+0xfd0, RVA 0x266730; ev_c42aee078d3af653ceef9d5ba42dbd0580a0172676faaeba0d98c3630ced7c6f */
void trampoline_00266730(void) { REA_TAILCALL_RVA(0x678ec0); }

/* file+0xfd8, RVA 0x266738; ev_1c06028de82defe35d7465893ce4e09155e182b726cd9f5c302f5bd50c4d3d1b */
void trampoline_00266738(void) { REA_TAILCALL_RVA(0x678f60); }

/* file+0xfe0, RVA 0x266740; ev_ae1fec14813bea42fc2435ed6569d0e60e1565afbb3912f36ad156c4e3b77f47 */
void trampoline_00266740(void) { REA_TAILCALL_RVA(0x679190); }

/* file+0xfe8, RVA 0x266748; ev_94255a908116ee36481aaac6004eafebda085c4a77a34a53d6ddd345746895b1 */
void trampoline_00266748(void) { REA_TAILCALL_RVA(0x679360); }

/* file+0xff0, RVA 0x266750; ev_8d81e7078427f73982b18f19c300e22fe199fffc885fd4813e4f0e22d36b2bc8 */
void trampoline_00266750(void) { REA_TAILCALL_RVA(0x679680); }

/* file+0xff8, RVA 0x266758; ev_3120929bc86bc9c3ccc1ca4e5fe804edaef7dbe51b4d867f3b3ef8a7a04c34fa */
void trampoline_00266758(void) { REA_TAILCALL_RVA(0x33b90); }

