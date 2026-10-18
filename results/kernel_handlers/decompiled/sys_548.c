/* handler_548.bin — REA 6.7.0 / Ghidra 12.1.4 pseudocode.
 * Input SHA256: 48478b8dfcf5f00e7bcdb8dfa88fe79574f2660898d85f697ea2b0178a140fef
 * Original trampoline RVA: 0x265d60; selected implementation RVA: 0xabbe60.
 * The supplied 4096 bytes are trampoline slots, not the implementation.
 * Implementation and local helpers below use byte-matched kernel_text.bin context.
 * Pseudocode is not original source and is not intended to compile as a unit.
 * ABI fields and semantic names in Part 1 are analyst recovery from loads/stores;
 * Part 3 preserves REA decompiler text, including unknown external call types.
 * undefinedN, extraout_*, register intrinsics and invalidInstructionException are
 * decompiler artifacts, not verified C behavior. Address constants are kernel RVAs.
 */
#include <stdint.h>
#include <stddef.h>
struct proc_recovered;
struct cred_recovered;
/* Verified field offsets, not a complete ABI declaration. */
struct thread_recovered {
    uint8_t unknown_000[0x8];
    struct proc_recovered *process; /* +0x008 */
    uint8_t unknown_010[0x130];
    struct cred_recovered *credential; /* +0x140 */
    uint8_t unknown_148[0x2c0];
    uint64_t syscall_retval[2]; /* +0x408; only used where stores establish it */
};
_Static_assert(offsetof(struct thread_recovered, process)==0x8,"process offset");
_Static_assert(offsetof(struct thread_recovered, credential)==0x140,"credential offset");
_Static_assert(offsetof(struct thread_recovered, syscall_retval)==0x408,"retval offset");

/* PART 1 — ANALYST RECOVERED TYPES AND READABLE BOUNDARY */

struct batch_vm_operation_548 {
    uint64_t address; /* +0x00 */
    uint64_t offset_or_aux; /* +0x08, meaning depends on case */
    uint64_t length; /* +0x10 */
    uint8_t protection; /* +0x18 */
    uint8_t memory_type; /* +0x19 */
    uint16_t unknown_1a;
    uint32_t operation; /* +0x1c, range 0..4 */
};
struct sys_548_args {
    int32_t descriptor; uint32_t pad_04;
    uint32_t flags; uint32_t pad_0c;
    const struct batch_vm_operation_548 *user_operations; /* +0x10 */
    int32_t count; uint32_t pad_1c;
    uint32_t *user_processed; /* +0x20, optional */
};
struct deferred_vm_node_548 {
    struct deferred_vm_node_548 *next;
    struct batch_vm_operation_548 operation;
};
_Static_assert(sizeof(struct batch_vm_operation_548)==0x20,"descriptor size");
_Static_assert(offsetof(struct batch_vm_operation_548,operation)==0x1c,"selector offset");
_Static_assert(sizeof(struct deferred_vm_node_548)==0x28,"node size");
/* Partial credential view established by the recovered predicate helpers. */
struct cred_recovered {
    uint8_t unknown_00[0x58];
    uint64_t identity_58; /* compared with fixed 64-bit identities */
    uint8_t unknown_60[8];
    uint64_t capability_bits_68;
    uint8_t unknown_70[0x10];
    uint64_t policy_bits_80; /* byte +0x82 is bits 16..23 of this word */
};
_Static_assert(offsetof(struct cred_recovered,identity_58)==0x58,"credential identity");
_Static_assert(offsetof(struct cred_recovered,capability_bits_68)==0x68,"credential capability word");
_Static_assert(offsetof(struct cred_recovered,policy_bits_80)==0x80,"credential policy word");

/* Structured reconstruction of the unresolved table dispatch. This is analyst
 * pseudocode: the missing table lookup is intentionally an unknown function,
 * and destinations are code addresses, NOT recovered numeric selector IDs. */
int dispatch_548_case(uintptr_t destination, struct thread_recovered *td,
                      const struct sys_548_args *a, struct batch_vm_operation_548 *op,
                      struct deferred_vm_node_548 **pending, int32_t index,
                      int32_t *first_deferred) {
    switch (destination) {
    case 0xabbff3:
        /* Compatibility checks select specialized mapping at 0xabd540.
         * Otherwise require aligned address/length/aux, nonnegative aux and
         * !(protection & 8), then call 0xab8430 with flags|1 and a->descriptor. */
        return mapping_case_abbff3(td,a,op);
    case 0xabc088:
        if (*first_deferred < 0) *first_deferred=index;
        if (op->protection & 2) op->protection |= 1;
        append_zone_node_43b880(pending,op); return 0;
    case 0xabc0b0:
        if ((op->address|op->length)&0x3fff || op->protection&8 ||
            op->address+op->length<op->address) return 0x16;
        /* 0x2cbdb0 return 2 -> 0xd, 6 -> 0xc, other nonzero -> 0x16. */
        return protection_case_abc0b0(td,op);
    case 0xabc11e:
        if ((op->address|op->length)&0x3fff || op->protection&8) return 0x16;
        return map_0xab8430(td,op->address,op->length,op->protection,
                           a->flags|0x1000,0,-1,0);
    case 0xabc185:
        if ((op->address|op->length)&0x3fff) return 0x16;
        return unmap_0xab8bb0(td,op->address,op->length);
    default: return UNKNOWN_MISSING_JUMP_TABLE_DESTINATION;
    }
}
/* The operation loop uses destination = 0x18dbf54 +
 * sign_extend_32(MISSING_TABLE[op.operation]); it does not select a user pointer.
 * All paths that actually reach common cleanup free outstanding nodes, clear
 * thread batch state, perform required callback work and optionally store progress.
 * Raw REA's `return` immediately after its unresolved indirect-call expression
 * is an analysis artifact and must not replace that loop/common-cleanup flow. */
/* Structured operation loop: missing-table and external operations stay symbolic.
 * `progress` follows the machine's accounting, including queued operations; it
 * is not a guarantee that every counted operation already changed the VM map. */
int handler_548_loop_recovered(struct thread_recovered *td, const struct sys_548_args *a) {
    if (a->count < 0) { if(a->user_processed) (void)store32_259790(a->user_processed,0); return 0x16; }
    if (invalid_platform_flags(a->flags,td->process)) return 0x16;
    begin_thread_vm_batch(td);
    struct deferred_vm_node_548 *pending=0;
    int32_t first=-1, progress=0;
    int status=0;
    for(int32_t i=0;i<a->count;i++) {
        struct batch_vm_operation_548 op;
        status=copyin_259280(&a->user_operations[i],&op,0x20);
        if(status) break;
        if(op.operation!=4 && pending) {
            int32_t flushed; /* no visible initialization on this path */
            status=sub_00abc3b0(&pending,&flushed);
            if(status) { progress=first+flushed; break; }
            first=-1;
        }
        if(op.operation>4) { status=0x16; break; }
        uintptr_t destination=missing_relative_table_18dbf54(op.operation);
        status=dispatch_548_case(destination,td,a,&op,&pending,i,&first);
        if(status) break;
        progress=i+1;
    }
    if(!status && pending) {
        int32_t flushed=0; /* explicitly initialized in final-flush path */
        status=sub_00abc3b0(&pending,&flushed);
        progress=status ? first+flushed : a->count;
    }
    free_pending_vm_nodes(&pending);
    finish_thread_vm_batch_and_kernel_callback(td);
    if(a->user_processed) (void)store32_259790(a->user_processed,progress);
    return status;
}

/* Semantic reconstruction of the first REA-disassembled JMP; no return address is pushed. */
int handler_548_trampoline(struct thread_recovered *td, const void *uap) {
    return implementation_at_rva_00abbe60(td, uap); /* tail call */
}


/* PART 2 — ORIGINAL TRAMPOLINE: REA may emit halt_baddata because the target is outside the imported trampoline region. This is a decompiler artifact: the actual instruction is a direct tail jump to the Part 3 target, preserving incoming registers. Verbatim REA pseudocode; evidence ev_cdff235dcf9e98c0bd113f7f728aaafc131cb2d73c0589f6a45d7a252783adf7. */


/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_00abbe60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Every supplied slot is an independent direct tail jump; this is a lossless target inventory,
 * not an indexed dispatch instruction in sys_548. Unused CC bytes are listed in .asm. */
static const struct { uint32_t file_offset, trampoline_rva, target_rva; } original_slots[512] = {

    {0x000, 0x00265d60, 0x00abbe60},
    {0x008, 0x00265d68, 0x00c16020},
    {0x010, 0x00265d70, 0x00c16270},
    {0x018, 0x00265d78, 0x00c16720},
    {0x020, 0x00265d80, 0x00c16880},
    {0x028, 0x00265d88, 0x00c163d0},
    {0x030, 0x00265d90, 0x00c164f0},
    {0x038, 0x00265d98, 0x00c165d0},
    {0x040, 0x00265da0, 0x00c16660},
    {0x048, 0x00265da8, 0x00ac7240},
    {0x050, 0x00265db0, 0x00ac73c0},
    {0x058, 0x00265db8, 0x00abc510},
    {0x060, 0x00265dc0, 0x004f5e60},
    {0x068, 0x00265dc8, 0x00602fe0},
    {0x070, 0x00265dd0, 0x00603260},
    {0x078, 0x00265dd8, 0x006034e0},
    {0x080, 0x00265de0, 0x00603710},
    {0x088, 0x00265de8, 0x006039d0},
    {0x090, 0x00265df0, 0x00abac50},
    {0x098, 0x00265df8, 0x008fc610},
    {0x0a0, 0x00265e00, 0x004e1a70},
    {0x0a8, 0x00265e08, 0x00abc5f0},
    {0x0b0, 0x00265e10, 0x00a367e0},
    {0x0b8, 0x00265e18, 0x00ca0630},
    {0x0c0, 0x00265e20, 0x00a368e0},
    {0x0c8, 0x00265e28, 0x0072ecc0},
    {0x0d0, 0x00265e30, 0x004f7370},
    {0x0d8, 0x00265e38, 0x00a36b00},
    {0x0e0, 0x00265e40, 0x00a36b90},
    {0x0e8, 0x00265e48, 0x00abc710},
    {0x0f0, 0x00265e50, 0x005a7f60},
    {0x0f8, 0x00265e58, 0x00a36bc0},
    {0x100, 0x00265e60, 0x00abca10},
    {0x108, 0x00265e68, 0x00abcc00},
    {0x110, 0x00265e70, 0x00438c90},
    {0x118, 0x00265e78, 0x008d2570},
    {0x120, 0x00265e80, 0x00abd0f0},
    {0x128, 0x00265e88, 0x00a37650},
    {0x130, 0x00265e90, 0x00abd430},
    {0x138, 0x00265e98, 0x007dcd40},
    {0x140, 0x00265ea0, 0x008d25a0},
    {0x148, 0x00265ea8, 0x00abd4f0},
    {0x150, 0x00265eb0, 0x00603c90},
    {0x158, 0x00265eb8, 0x00604cf0},
    {0x160, 0x00265ec0, 0x004a2850},
    {0x168, 0x00265ec8, 0x00abd540},
    {0x170, 0x00265ed0, 0x0091c640},
    {0x178, 0x00265ed8, 0x0091cc70},
    {0x180, 0x00265ee0, 0x00438e30},
    {0x188, 0x00265ee8, 0x00439070},
    {0x190, 0x00265ef0, 0x00439150},
    {0x198, 0x00265ef8, 0x004393a0},
    {0x1a0, 0x00265f00, 0x006be4d0},
    {0x1a8, 0x00265f08, 0x00abd930},
    {0x1b0, 0x00265f10, 0x006be5c0},
    {0x1b8, 0x00265f18, 0x006be800},
    {0x1c0, 0x00265f20, 0x00a90e10},
    {0x1c8, 0x00265f28, 0x004a2de0},
    {0x1d0, 0x00265f30, 0x00abdad0},
    {0x1d8, 0x00265f38, 0x00a37660},
    {0x1e0, 0x00265f40, 0x00abe1c0},
    {0x1e8, 0x00265f48, 0x00abe7b0},
    {0x1f0, 0x00265f50, 0x009f81f0},
    {0x1f8, 0x00265f58, 0x00be9510},
    {0x200, 0x00265f60, 0x009a7d10},
    {0x208, 0x00265f68, 0x009a9560},
    {0x210, 0x00265f70, 0x009a9e10},
    {0x218, 0x00265f78, 0x009a9f40},
    {0x220, 0x00265f80, 0x008fb440},
    {0x228, 0x00265f88, 0x004a31a0},
    {0x230, 0x00265f90, 0x00abe8b0},
    {0x238, 0x00265f98, 0x009ab1f0},
    {0x240, 0x00265fa0, 0x00abb980},
    {0x248, 0x00265fa8, 0x006f92e0},
    {0x250, 0x00265fb0, 0x00434da0},
    {0x258, 0x00265fb8, 0x00434db0},
    {0x260, 0x00265fc0, 0x00434dc0},
    {0x268, 0x00265fc8, 0x00437d90},
    {0x270, 0x00265fd0, 0x00438280},
    {0x278, 0x00265fd8, 0x00ae6690},
    {0x280, 0x00265fe0, 0x00ae6580},
    {0x288, 0x00265fe8, 0x004490d0},
    {0x290, 0x00265ff0, 0x000a6dc0},
    {0x298, 0x00265ff8, 0x0044aa70},
    {0x2a0, 0x00266000, 0x009b6110},
    {0x2a8, 0x00266008, 0x000a7670},
    {0x2b0, 0x00266010, 0x000a7850},
    {0x2b8, 0x00266018, 0x000a7880},
    {0x2c0, 0x00266020, 0x00452040},
    {0x2c8, 0x00266028, 0x00454cc0},
    {0x2d0, 0x00266030, 0x00457820},
    {0x2d8, 0x00266038, 0x0046df70},
    {0x2e0, 0x00266040, 0x0046e080},
    {0x2e8, 0x00266048, 0x00472990},
    {0x2f0, 0x00266050, 0x004733b0},
    {0x2f8, 0x00266058, 0x004738b0},
    {0x300, 0x00266060, 0x00474250},
    {0x308, 0x00266068, 0x00474db0},
    {0x310, 0x00266070, 0x0047cff0},
    {0x318, 0x00266078, 0x0021dff0},
    {0x320, 0x00266080, 0x00490300},
    {0x328, 0x00266088, 0x00490db0},
    {0x330, 0x00266090, 0x00497fb0},
    {0x338, 0x00266098, 0x00497fe0},
    {0x340, 0x002660a0, 0x00498630},
    {0x348, 0x002660a8, 0x00498640},
    {0x350, 0x002660b0, 0x008f7bc0},
    {0x358, 0x002660b8, 0x008f6800},
    {0x360, 0x002660c0, 0x008f7420},
    {0x368, 0x002660c8, 0x008f9f80},
    {0x370, 0x002660d0, 0x005df350},
    {0x378, 0x002660d8, 0x005df820},
    {0x380, 0x002660e0, 0x00a34ce0},
    {0x388, 0x002660e8, 0x005e84a0},
    {0x390, 0x002660f0, 0x008f81f0},
    {0x398, 0x002660f8, 0x008f9410},
    {0x3a0, 0x00266100, 0x008fc3f0},
    {0x3a8, 0x00266108, 0x008f6c90},
    {0x3b0, 0x00266110, 0x00cb1a10},
    {0x3b8, 0x00266118, 0x00ab83a0},
    {0x3c0, 0x00266120, 0x00ab83b0},
    {0x3c8, 0x00266128, 0x008fa1c0},
    {0x3d0, 0x00266130, 0x008f7b40},
    {0x3d8, 0x00266138, 0x004a0960},
    {0x3e0, 0x00266140, 0x00729780},
    {0x3e8, 0x00266148, 0x00729790},
    {0x3f0, 0x00266150, 0x007297a0},
    {0x3f8, 0x00266158, 0x006bb590},
    {0x400, 0x00266160, 0x00ab8da0},
    {0x408, 0x00266168, 0x008fa170},
    {0x410, 0x00266170, 0x00b7f0c0},
    {0x418, 0x00266178, 0x00b7f100},
    {0x420, 0x00266180, 0x008f9cf0},
    {0x428, 0x00266188, 0x008fa740},
    {0x430, 0x00266190, 0x00552b70},
    {0x438, 0x00266198, 0x00552bf0},
    {0x440, 0x002661a0, 0x00552c50},
    {0x448, 0x002661a8, 0x00552c80},
    {0x450, 0x002661b0, 0x00552cb0},
    {0x458, 0x002661b8, 0x00552ce0},
    {0x460, 0x002661c0, 0x00b7e800},
    {0x468, 0x002661c8, 0x00b7ebe0},
    {0x470, 0x002661d0, 0x00b7ef70},
    {0x478, 0x002661d8, 0x00c06d30},
    {0x480, 0x002661e0, 0x00792690},
    {0x488, 0x002661e8, 0x005e8b20},
    {0x490, 0x002661f0, 0x00552d10},
    {0x498, 0x002661f8, 0x00b7f160},
    {0x4a0, 0x00266200, 0x005de250},
    {0x4a8, 0x00266208, 0x00a54a30},
    {0x4b0, 0x00266210, 0x00a54a40},
    {0x4b8, 0x00266218, 0x00a54a50},
    {0x4c0, 0x00266220, 0x00a54a60},
    {0x4c8, 0x00266228, 0x00a54a80},
    {0x4d0, 0x00266230, 0x00a54a90},
    {0x4d8, 0x00266238, 0x008f9720},
    {0x4e0, 0x00266240, 0x00a54ab0},
    {0x4e8, 0x00266248, 0x008f64e0},
    {0x4f0, 0x00266250, 0x008f5ef0},
    {0x4f8, 0x00266258, 0x00a54a20},
    {0x500, 0x00266260, 0x00a54a70},
    {0x508, 0x00266268, 0x00a54aa0},
    {0x510, 0x00266270, 0x006e54d0},
    {0x518, 0x00266278, 0x00b7f4b0},
    {0x520, 0x00266280, 0x0083d660},
    {0x528, 0x00266288, 0x0083d7c0},
    {0x530, 0x00266290, 0x0083dab0},
    {0x538, 0x00266298, 0x0083de80},
    {0x540, 0x002662a0, 0x008f9c80},
    {0x548, 0x002662a8, 0x008fa110},
    {0x550, 0x002662b0, 0x008f91b0},
    {0x558, 0x002662b8, 0x008fa4f0},
    {0x560, 0x002662c0, 0x008f8090},
    {0x568, 0x002662c8, 0x008fbb80},
    {0x570, 0x002662d0, 0x008f7b80},
    {0x578, 0x002662d8, 0x008f7890},
    {0x580, 0x002662e0, 0x008fb8a0},
    {0x588, 0x002662e8, 0x008f8510},
    {0x590, 0x002662f0, 0x008f8800},
    {0x598, 0x002662f8, 0x0049b080},
    {0x5a0, 0x00266300, 0x0049b090},
    {0x5a8, 0x00266308, 0x0055fa50},
    {0x5b0, 0x00266310, 0x00c34870},
    {0x5b8, 0x00266318, 0x007dccf0},
    {0x5c0, 0x00266320, 0x007dcd00},
    {0x5c8, 0x00266328, 0x007dcd10},
    {0x5d0, 0x00266330, 0x007dcd20},
    {0x5d8, 0x00266338, 0x007dcd30},
    {0x5e0, 0x00266340, 0x005a6c90},
    {0x5e8, 0x00266348, 0x005a7300},
    {0x5f0, 0x00266350, 0x005a7610},
    {0x5f8, 0x00266358, 0x005a7900},
    {0x600, 0x00266360, 0x00c9c830},
    {0x608, 0x00266368, 0x005a7f00},
    {0x610, 0x00266370, 0x005a8070},
    {0x618, 0x00266378, 0x00be8480},
    {0x620, 0x00266380, 0x0049b0a0},
    {0x628, 0x00266388, 0x0049b0c0},
    {0x630, 0x00266390, 0x0049b0d0},
    {0x638, 0x00266398, 0x0049b0e0},
    {0x640, 0x002663a0, 0x0049b0f0},
    {0x648, 0x002663a8, 0x00530720},
    {0x650, 0x002663b0, 0x00531670},
    {0x658, 0x002663b8, 0x008f96f0},
    {0x660, 0x002663c0, 0x00531230},
    {0x668, 0x002663c8, 0x00802df0},
    {0x670, 0x002663d0, 0x00b7f140},
    {0x678, 0x002663d8, 0x00ae35e0},
    {0x680, 0x002663e0, 0x004eee20},
    {0x688, 0x002663e8, 0x008fab10},
    {0x690, 0x002663f0, 0x008fae30},
    {0x698, 0x002663f8, 0x009c9220},
    {0x6a0, 0x00266400, 0x009c9100},
    {0x6a8, 0x00266408, 0x00642310},
    {0x6b0, 0x00266410, 0x00642820},
    {0x6b8, 0x00266418, 0x006436e0},
    {0x6c0, 0x00266420, 0x006438d0},
    {0x6c8, 0x00266428, 0x00643c60},
    {0x6d0, 0x00266430, 0x009f8290},
    {0x6d8, 0x00266438, 0x009fbb70},
    {0x6e0, 0x00266440, 0x00a45280},
    {0x6e8, 0x00266448, 0x00c87ca0},
    {0x6f0, 0x00266450, 0x009ff000},
    {0x6f8, 0x00266458, 0x00a00780},
    {0x700, 0x00266460, 0x00a007e0},
    {0x708, 0x00266468, 0x00abe830},
    {0x710, 0x00266470, 0x009fcf30},
    {0x718, 0x00266478, 0x005f0fc0},
    {0x720, 0x00266480, 0x008f73f0},
    {0x728, 0x00266488, 0x004f7250},
    {0x730, 0x00266490, 0x009fdad0},
    {0x738, 0x00266498, 0x009fddb0},
    {0x740, 0x002664a0, 0x009fdf10},
    {0x748, 0x002664a8, 0x006444d0},
    {0x750, 0x002664b0, 0x00650fd0},
    {0x758, 0x002664b8, 0x009fea30},
    {0x760, 0x002664c0, 0x004f7940},
    {0x768, 0x002664c8, 0x00ab8ae0},
    {0x770, 0x002664d0, 0x00abb660},
    {0x778, 0x002664d8, 0x009fe260},
    {0x780, 0x002664e0, 0x009fe4e0},
    {0x788, 0x002664e8, 0x009fe630},
    {0x790, 0x002664f0, 0x00798330},
    {0x798, 0x002664f8, 0x00abd000},
    {0x7a0, 0x00266500, 0x000fc890},
    {0x7a8, 0x00266508, 0x0049f090},
    {0x7b0, 0x00266510, 0x0049f200},
    {0x7b8, 0x00266518, 0x004c0590},
    {0x7c0, 0x00266520, 0x004c05b0},
    {0x7c8, 0x00266528, 0x000a9430},
    {0x7d0, 0x00266530, 0x004ca350},
    {0x7d8, 0x00266538, 0x004caa40},
    {0x7e0, 0x00266540, 0x000aa510},
    {0x7e8, 0x00266548, 0x004d51d0},
    {0x7f0, 0x00266550, 0x008111b0},
    {0x7f8, 0x00266558, 0x0001ae90},
    {0x800, 0x00266560, 0x004f0030},
    {0x808, 0x00266568, 0x004fbbd0},
    {0x810, 0x00266570, 0x0050ced0},
    {0x818, 0x00266578, 0x0050cee0},
    {0x820, 0x00266580, 0x0050cf30},
    {0x828, 0x00266588, 0x0050cf70},
    {0x830, 0x00266590, 0x0050cfb0},
    {0x838, 0x00266598, 0x0050cfe0},
    {0x840, 0x002665a0, 0x0051e4d0},
    {0x848, 0x002665a8, 0x0051ef60},
    {0x850, 0x002665b0, 0x0051f000},
    {0x858, 0x002665b8, 0x0051f0b0},
    {0x860, 0x002665c0, 0x0051f2e0},
    {0x868, 0x002665c8, 0x0051f670},
    {0x870, 0x002665d0, 0x0051fee0},
    {0x878, 0x002665d8, 0x00536400},
    {0x880, 0x002665e0, 0x00544ca0},
    {0x888, 0x002665e8, 0x005468f0},
    {0x890, 0x002665f0, 0x000b1630},
    {0x898, 0x002665f8, 0x000b1fb0},
    {0x8a0, 0x00266600, 0x0055bf40},
    {0x8a8, 0x00266608, 0x0055c030},
    {0x8b0, 0x00266610, 0x0055c050},
    {0x8b8, 0x00266618, 0x0056e200},
    {0x8c0, 0x00266620, 0x0057f4a0},
    {0x8c8, 0x00266628, 0x009945e0},
    {0x8d0, 0x00266630, 0x00585950},
    {0x8d8, 0x00266638, 0x00599820},
    {0x8e0, 0x00266640, 0x0059a3e0},
    {0x8e8, 0x00266648, 0x0059a530},
    {0x8f0, 0x00266650, 0x0059a700},
    {0x8f8, 0x00266658, 0x0059a7d0},
    {0x900, 0x00266660, 0x0059aa50},
    {0x908, 0x00266668, 0x0059ab60},
    {0x910, 0x00266670, 0x0059ac60},
    {0x918, 0x00266678, 0x005dbed0},
    {0x920, 0x00266680, 0x005eb720},
    {0x928, 0x00266688, 0x005ec030},
    {0x930, 0x00266690, 0x005ecad0},
    {0x938, 0x00266698, 0x005ed440},
    {0x940, 0x002666a0, 0x005edb30},
    {0x948, 0x002666a8, 0x0014e280},
    {0x950, 0x002666b0, 0x005f18b0},
    {0x958, 0x002666b8, 0x005f2b30},
    {0x960, 0x002666c0, 0x005fd0c0},
    {0x968, 0x002666c8, 0x00600680},
    {0x970, 0x002666d0, 0x00600f40},
    {0x978, 0x002666d8, 0x00ae64a0},
    {0x980, 0x002666e0, 0x0062daa0},
    {0x988, 0x002666e8, 0x006302d0},
    {0x990, 0x002666f0, 0x00634f10},
    {0x998, 0x002666f8, 0x0063f520},
    {0x9a0, 0x00266700, 0x006579b0},
    {0x9a8, 0x00266708, 0x00ca7310},
    {0x9b0, 0x00266710, 0x00662e70},
    {0x9b8, 0x00266718, 0x00662e80},
    {0x9c0, 0x00266720, 0x00678e10},
    {0x9c8, 0x00266728, 0x00678e60},
    {0x9d0, 0x00266730, 0x00678ec0},
    {0x9d8, 0x00266738, 0x00678f60},
    {0x9e0, 0x00266740, 0x00679190},
    {0x9e8, 0x00266748, 0x00679360},
    {0x9f0, 0x00266750, 0x00679680},
    {0x9f8, 0x00266758, 0x00033b90},
    {0xa00, 0x00266760, 0x00033ca0},
    {0xa08, 0x00266768, 0x00033d20},
    {0xa10, 0x00266770, 0x0003cf70},
    {0xa18, 0x00266778, 0x0003d0e0},
    {0xa20, 0x00266780, 0x0003d660},
    {0xa28, 0x00266788, 0x0003e100},
    {0xa30, 0x00266790, 0x0003e160},
    {0xa38, 0x00266798, 0x0003e1c0},
    {0xa40, 0x002667a0, 0x0003f070},
    {0xa48, 0x002667a8, 0x0003f0d0},
    {0xa50, 0x002667b0, 0x0003f4b0},
    {0xa58, 0x002667b8, 0x0003f510},
    {0xa60, 0x002667c0, 0x0003f570},
    {0xa68, 0x002667c8, 0x0003fbb0},
    {0xa70, 0x002667d0, 0x0003ffc0},
    {0xa78, 0x002667d8, 0x00040960},
    {0xa80, 0x002667e0, 0x00040b50},
    {0xa88, 0x002667e8, 0x00040c30},
    {0xa90, 0x002667f0, 0x00041630},
    {0xa98, 0x002667f8, 0x00041750},
    {0xaa0, 0x00266800, 0x00041830},
    {0xaa8, 0x00266808, 0x000418c0},
    {0xab0, 0x00266810, 0x00042060},
    {0xab8, 0x00266818, 0x000424d0},
    {0xac0, 0x00266820, 0x000425a0},
    {0xac8, 0x00266828, 0x00042600},
    {0xad0, 0x00266830, 0x00690030},
    {0xad8, 0x00266838, 0x00696cc0},
    {0xae0, 0x00266840, 0x006985d0},
    {0xae8, 0x00266848, 0x006a2050},
    {0xaf0, 0x00266850, 0x006a22b0},
    {0xaf8, 0x00266858, 0x006ae640},
    {0xb00, 0x00266860, 0x006ae7f0},
    {0xb08, 0x00266868, 0x001813b0},
    {0xb10, 0x00266870, 0x006befa0},
    {0xb18, 0x00266878, 0x00188040},
    {0xb20, 0x00266880, 0x006d0b00},
    {0xb28, 0x00266888, 0x006d1100},
    {0xb30, 0x00266890, 0x006d1260},
    {0xb38, 0x00266898, 0x006d13e0},
    {0xb40, 0x002668a0, 0x006d1520},
    {0xb48, 0x002668a8, 0x006d1640},
    {0xb50, 0x002668b0, 0x006d1720},
    {0xb58, 0x002668b8, 0x006dc660},
    {0xb60, 0x002668c0, 0x006dc690},
    {0xb68, 0x002668c8, 0x006dc6a0},
    {0xb70, 0x002668d0, 0x006e0920},
    {0xb78, 0x002668d8, 0x006e1440},
    {0xb80, 0x002668e0, 0x006e1450},
    {0xb88, 0x002668e8, 0x00189a70},
    {0xb90, 0x002668f0, 0x00190aa0},
    {0xb98, 0x002668f8, 0x00702970},
    {0xba0, 0x00266900, 0x00702d60},
    {0xba8, 0x00266908, 0x00706170},
    {0xbb0, 0x00266910, 0x007061f0},
    {0xbb8, 0x00266918, 0x0070ff00},
    {0xbc0, 0x00266920, 0x0070ffb0},
    {0xbc8, 0x00266928, 0x007101c0},
    {0xbd0, 0x00266930, 0x00710320},
    {0xbd8, 0x00266938, 0x00712bb0},
    {0xbe0, 0x00266940, 0x00716360},
    {0xbe8, 0x00266948, 0x0072f970},
    {0xbf0, 0x00266950, 0x0072f990},
    {0xbf8, 0x00266958, 0x0072fa20},
    {0xc00, 0x00266960, 0x00246e30},
    {0xc08, 0x00266968, 0x007647f0},
    {0xc10, 0x00266970, 0x00773710},
    {0xc18, 0x00266978, 0x00775950},
    {0xc20, 0x00266980, 0x00799e90},
    {0xc28, 0x00266988, 0x007b31f0},
    {0xc30, 0x00266990, 0x007e23a0},
    {0xc38, 0x00266998, 0x007e83e0},
    {0xc40, 0x002669a0, 0x007e8480},
    {0xc48, 0x002669a8, 0x00c3b1b0},
    {0xc50, 0x002669b0, 0x00c3c6e0},
    {0xc58, 0x002669b8, 0x00c3c690},
    {0xc60, 0x002669c0, 0x00c3c730},
    {0xc68, 0x002669c8, 0x00802220},
    {0xc70, 0x002669d0, 0x008024f0},
    {0xc78, 0x002669d8, 0x0080c570},
    {0xc80, 0x002669e0, 0x0082b300},
    {0xc88, 0x002669e8, 0x00920ee0},
    {0xc90, 0x002669f0, 0x00920b90},
    {0xc98, 0x002669f8, 0x00830810},
    {0xca0, 0x00266a00, 0x00830f00},
    {0xca8, 0x00266a08, 0x008352b0},
    {0xcb0, 0x00266a10, 0x008352c0},
    {0xcb8, 0x00266a18, 0x008352d0},
    {0xcc0, 0x00266a20, 0x008352f0},
    {0xcc8, 0x00266a28, 0x00835440},
    {0xcd0, 0x00266a30, 0x00835450},
    {0xcd8, 0x00266a38, 0x00835490},
    {0xce0, 0x00266a40, 0x00835ad0},
    {0xce8, 0x00266a48, 0x00850870},
    {0xcf0, 0x00266a50, 0x008702f0},
    {0xcf8, 0x00266a58, 0x008705d0},
    {0xd00, 0x00266a60, 0x00872af0},
    {0xd08, 0x00266a68, 0x00873800},
    {0xd10, 0x00266a70, 0x00063a40},
    {0xd18, 0x00266a78, 0x00066370},
    {0xd20, 0x00266a80, 0x000e6590},
    {0xd28, 0x00266a88, 0x000e65a0},
    {0xd30, 0x00266a90, 0x000e6760},
    {0xd38, 0x00266a98, 0x000e6870},
    {0xd40, 0x00266aa0, 0x000e7f90},
    {0xd48, 0x00266aa8, 0x000e9fa0},
    {0xd50, 0x00266ab0, 0x000ea670},
    {0xd58, 0x00266ab8, 0x000ea760},
    {0xd60, 0x00266ac0, 0x000eb0a0},
    {0xd68, 0x00266ac8, 0x000eb190},
    {0xd70, 0x00266ad0, 0x000ed000},
    {0xd78, 0x00266ad8, 0x000ed110},
    {0xd80, 0x00266ae0, 0x0088a8a0},
    {0xd88, 0x00266ae8, 0x0089cdf0},
    {0xd90, 0x00266af0, 0x000eeb50},
    {0xd98, 0x00266af8, 0x008cb250},
    {0xda0, 0x00266b00, 0x008cb390},
    {0xda8, 0x00266b08, 0x008d2f60},
    {0xdb0, 0x00266b10, 0x008d2f90},
    {0xdb8, 0x00266b18, 0x008d8230},
    {0xdc0, 0x00266b20, 0x008d8de0},
    {0xdc8, 0x00266b28, 0x008d97b0},
    {0xdd0, 0x00266b30, 0x008d9910},
    {0xdd8, 0x00266b38, 0x008da4c0},
    {0xde0, 0x00266b40, 0x008da570},
    {0xde8, 0x00266b48, 0x008da5b0},
    {0xdf0, 0x00266b50, 0x00904c80},
    {0xdf8, 0x00266b58, 0x00904e60},
    {0xe00, 0x00266b60, 0x0091d400},
    {0xe08, 0x00266b68, 0x0091d4a0},
    {0xe10, 0x00266b70, 0x00a821d0},
    {0xe18, 0x00266b78, 0x00b42120},
    {0xe20, 0x00266b80, 0x00964f30},
    {0xe28, 0x00266b88, 0x00975f50},
    {0xe30, 0x00266b90, 0x00976200},
    {0xe38, 0x00266b98, 0x0098c950},
    {0xe40, 0x00266ba0, 0x0098cc30},
    {0xe48, 0x00266ba8, 0x0098cf30},
    {0xe50, 0x00266bb0, 0x0098d6e0},
    {0xe58, 0x00266bb8, 0x0098e5d0},
    {0xe60, 0x00266bc0, 0x0098e700},
    {0xe68, 0x00266bc8, 0x00992170},
    {0xe70, 0x00266bd0, 0x00992240},
    {0xe78, 0x00266bd8, 0x000f5400},
    {0xe80, 0x00266be0, 0x009a2320},
    {0xe88, 0x00266be8, 0x009a5720},
    {0xe90, 0x00266bf0, 0x009ac9a0},
    {0xe98, 0x00266bf8, 0x009aca20},
    {0xea0, 0x00266c00, 0x001be640},
    {0xea8, 0x00266c08, 0x009bed20},
    {0xeb0, 0x00266c10, 0x009c6050},
    {0xeb8, 0x00266c18, 0x009c60d0},
    {0xec0, 0x00266c20, 0x009c6280},
    {0xec8, 0x00266c28, 0x009c6310},
    {0xed0, 0x00266c30, 0x009c6490},
    {0xed8, 0x00266c38, 0x009c65b0},
    {0xee0, 0x00266c40, 0x009c6890},
    {0xee8, 0x00266c48, 0x009c9340},
    {0xef0, 0x00266c50, 0x009c9360},
    {0xef8, 0x00266c58, 0x009c9370},
    {0xf00, 0x00266c60, 0x009c9380},
    {0xf08, 0x00266c68, 0x009dadb0},
    {0xf10, 0x00266c70, 0x009dafa0},
    {0xf18, 0x00266c78, 0x009dc860},
    {0xf20, 0x00266c80, 0x009dcc40},
    {0xf28, 0x00266c88, 0x009dce80},
    {0xf30, 0x00266c90, 0x009dd500},
    {0xf38, 0x00266c98, 0x00caacd0},
    {0xf40, 0x00266ca0, 0x009dd7d0},
    {0xf48, 0x00266ca8, 0x009dd990},
    {0xf50, 0x00266cb0, 0x009ddba0},
    {0xf58, 0x00266cb8, 0x009ddc00},
    {0xf60, 0x00266cc0, 0x009dde50},
    {0xf68, 0x00266cc8, 0x009ddeb0},
    {0xf70, 0x00266cd0, 0x009ddff0},
    {0xf78, 0x00266cd8, 0x009de070},
    {0xf80, 0x00266ce0, 0x009de0f0},
    {0xf88, 0x00266ce8, 0x009e0b90},
    {0xf90, 0x00266cf0, 0x009e0cd0},
    {0xf98, 0x00266cf8, 0x009e0d70},
    {0xfa0, 0x00266d00, 0x009e0ef0},
    {0xfa8, 0x00266d08, 0x009e1050},
    {0xfb0, 0x00266d10, 0x009e1490},
    {0xfb8, 0x00266d18, 0x00a065e0},
    {0xfc0, 0x00266d20, 0x00101340},
    {0xfc8, 0x00266d28, 0x00a32f30},
    {0xfd0, 0x00266d30, 0x00a336c0},
    {0xfd8, 0x00266d38, 0x00a38c90},
    {0xfe0, 0x00266d40, 0x00a6ab00},
    {0xfe8, 0x00266d48, 0x00a6abb0},
    {0xff0, 0x00266d50, 0x00a8ec10},
    {0xff8, 0x00266d58, 0x00a8ee00},
};

/* PART 3 — VERBATIM REA/GHIDRA DECOMPILATION OF IMPLEMENTATION AND LOCAL CALLEES */


/* BEGIN sys_548, RVA 0xabbe60; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabbe60", "end": "0xabbf19"}, {"start": "0xabbf68", "end": "0xabbff2"}, {"start": "0xabc24d", "end": "0xabc256"}, {"start": "0xabc29e", "end": "0xabc2ab"}, {"start": "0xabc2b8", "end": "0xabc3a3"}], "total_bytes": 585, "span_bytes": 1348, "non_contiguous": true, "contains_entry": true}
 * REA Evidence: ev_b826bb78fb8a0f832f866a8153aa4c33d2ab65c5bb1b608391a20dd207c8cf36, ev_02bee09c316f6f7fafb93db4957e243ecb2e97280302e7a1523c7f0ee7c1f090, ev_92c1e6e99db5011a906a957c1f49da4dd1b65e7b1a8ed89223a1f0a860001b44
 */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sys_548(long param_1,long param_2)

{
  undefined8 uVar1;
  long *plVar2;
  code *pcVar3;
  ulong uVar4;
  int iVar5;
  ulong uVar6;
  long *plVar7;
  undefined8 *in_GS_OFFSET;
  undefined1 local_a0 [28];
  uint local_84;
  long *local_80;
  long **local_78;
  int local_70 [14];
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar5 = *(int *)(param_2 + 0x18);
  if (iVar5 < 0) {
    uVar4 = 0x16;
    if (*(long *)(param_2 + 0x20) != 0) {
      func_0x00259790(*(long *)(param_2 + 0x20),0);
      uVar4 = 0x16;
    }
    goto LAB_00abc371;
  }
  uVar4 = 0x16;
  if ((*(uint *)(param_2 + 8) &
      (uint)(*(char *)(*(long *)(param_1 + 8) + 0xc81) != '\0') * 0x20000000 + 0xe0bffb6f) != 0)
  goto LAB_00abc371;
  local_78 = &local_80;
  *(undefined2 *)(param_1 + 0x116) = 1;
  *(undefined1 *)(param_1 + 0x5f0) = 0;
  local_80 = (long *)0x0;
  if (iVar5 == 0) {
    uVar4 = 0;
    iVar5 = 0;
  }
  else {
    uVar1 = *(undefined8 *)(param_2 + 0x10);
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    uVar4 = func_0x00259280(uVar1,local_a0,0x20);
    iVar5 = 0;
    if ((int)uVar4 == 0) {
      uVar6 = (ulong)local_84;
      if ((local_84 != 4) && (local_80 != (long *)0x0)) {
        uVar4 = sub_00abc3b0(&local_80,local_70);
        if ((int)uVar4 != 0) {
          iVar5 = local_70[0] + -1;
          goto LAB_00abc2b8;
        }
        uVar6 = (ulong)local_84;
      }
      uVar4 = 0x16;
      iVar5 = 0;
      if ((uint)uVar6 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00abbfea */
                    /* WARNING: Treating indirect jump as call */
        uVar4 = (*(code *)((long)*(int *)(uVar6 * 4 + 0x18dbf54) + 0x18dbf54))();
        return uVar4;
      }
    }
LAB_00abc2b8:
    if (local_80 != (long *)0x0) {
      uVar4 = uVar4 & 0xffffffff;
      plVar7 = local_80;
      do {
        plVar2 = (long *)*plVar7;
        func_0x0043c0c0(_DAT_03bf6e18,plVar7,0);
        plVar7 = plVar2;
      } while (plVar2 != (long *)0x0);
    }
  }
  *(undefined1 *)(param_1 + 0x116) = 0;
  if (*(char *)(param_1 + 0x117) != '\0') {
    uVar4 = uVar4 & 0xffffffff;
    pcVar3 = *(code **)(_DAT_01a962e8 + 0x40);
    if (0x6ff < (-(long)pcVar3 + 0x260ce8U >> 3 | -(long)pcVar3 << 0x3d)) {
      func_0x0044f8c0(0x2888cf0,pcVar3);
    }
    (*pcVar3)(*(undefined8 *)(*(long *)(param_1 + 8) + 0x200));
    if (*(char *)(param_1 + 0x5f0) != '\0') {
      LOCK();
      _DAT_02d616c0 = _DAT_02d616c0 + -1;
      UNLOCK();
    }
  }
  if (*(long *)(param_2 + 0x20) != 0) {
    uVar4 = uVar4 & 0xffffffff;
    func_0x00259790(*(long *)(param_2 + 0x20),iVar5);
  }
LAB_00abc371:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return uVar4;
}


/* END sys_548 */


/* BEGIN sub_00259280, RVA 0x259280; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x259280", "end": "0x259330"}, {"start": "0x259340", "end": "0x25935f"}], "total_bytes": 209, "span_bytes": 224, "non_contiguous": true, "contains_entry": true}
 * REA Evidence: ev_debd8d50b7962cd1afa8647e0ca453db15b7560ec44b6a3675c7a02558304169, ev_73da546979483f9bbd6d30c4abec1f69be544aac39b799063b0171e43b398ec9, ev_12a161297d1dd9710fceb3df06a161b8b46208acffb462f50019d243f6b946af
 */


undefined8 sub_00259280(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  ulong uVar1;
  undefined8 *extraout_RDX;
  undefined8 *puVar2;
  long *in_GS_OFFSET;
  
  if (!CARRY8((ulong)param_2,(ulong)param_3)) {
    if (((undefined1 *)((long)param_2 + (long)param_3) <= &stack0xfffffffffffffff8) ||
       ((long)&stack0x00000008 <= (long)param_2)) goto LAB_002592aa;
    param_1 = param_2;
    func_0x00258fd0();
    param_2 = param_3;
  }
  func_0x00258fe0();
  param_3 = extraout_RDX;
LAB_002592aa:
  *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0x259340;
  if (param_3 != (undefined8 *)0x0) {
    if (((CARRY8((ulong)param_1,(ulong)param_3)) ||
        ((undefined1 *)0x800000000000 < (undefined1 *)((long)param_1 + (long)param_3))) ||
       (*(char *)(*(long *)(*in_GS_OFFSET + 8) + 0x591) != '\0')) {
      *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0;
      return 0xe;
    }
    puVar2 = (undefined8 *)((ulong)param_1 & 0x7fffffffffff);
    for (uVar1 = (ulong)param_3 >> 3; uVar1 != 0; uVar1 = uVar1 - 1) {
      *param_2 = *puVar2;
      puVar2 = puVar2 + 1;
      param_2 = param_2 + 1;
    }
    for (uVar1 = (ulong)param_3 & 7; uVar1 != 0; uVar1 = uVar1 - 1) {
      *(undefined1 *)param_2 = *(undefined1 *)puVar2;
      puVar2 = (undefined8 *)((long)puVar2 + 1);
      param_2 = (undefined8 *)((long)param_2 + 1);
    }
  }
  *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0;
  return 0;
}


/* END sub_00259280 */


/* BEGIN sub_00259790, RVA 0x259790; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x259790", "end": "0x259800"}], "total_bytes": 113, "span_bytes": 113, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_bb3b0bcd632dc2b81c16497e0db1d8800900d35d2e053558a645b676ff74415d, ev_e4bee306c2053bfb85142e24a9ddb7bf6922a87e834cada59ab949ca09310c28, ev_131bb3eb63071c246a55da83bfddf87c69bb4f3bd3b300ab649d36c41f1e2965
 */


undefined8 sub_00259790(ulong param_1,undefined4 param_2)

{
  long *in_GS_OFFSET;
  
  *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0x259700;
  if ((param_1 < 0x7ffffffffffd) && (*(char *)(*(long *)(*in_GS_OFFSET + 8) + 0x591) == '\0')) {
    *(undefined4 *)(param_1 & 0x7fffffffffff) = param_2;
    *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0;
    return 0;
  }
  *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0;
  return 0xffffffffffffffff;
}


/* END sub_00259790 */


/* BEGIN sub_00609560, RVA 0x609560; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x609560", "end": "0x60957b"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_ab24de8a18f38c184b0fdf3793f385870fcaaa95e0db07a30e3f22c631fafdb0, ev_2b5413c8ce707e4eb022cc66f9e45abcfbc33b1f00b7329a5b29c49efbac04b9, ev_08fe2c93270e50828988bb228f89c51d04acce655069cdad7d7fc651ed3e360e
 */


undefined8 sub_00609560(long param_1)

{
  undefined8 uVar1;
  
  if (((*(byte *)(param_1 + 0x6f) & 0x40) == 0) ||
     (uVar1 = 1, (*(byte *)(param_1 + 0x82) & 0x80) == 0)) {
    uVar1 = 0;
  }
  return uVar1;
}


/* END sub_00609560 */


/* BEGIN sub_006095a0, RVA 0x6095a0; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x6095a0", "end": "0x6095bb"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_78331d1ccab6a8fda949573ab98f18a36d9e656ee621185e90923fa6b1e5f8d6, ev_d3bc324f1fa759f19e17da6ff32bb7126f41955684a3a500b7478de1348111e2, ev_05eeced9d86280eeac04b9f22d16ce1677b9464e4cb4b7014cc7a5591e1750cc
 */


undefined8 sub_006095a0(long param_1)

{
  undefined8 uVar1;
  
  if (((*(byte *)(param_1 + 0x6f) & 0x40) == 0) ||
     (uVar1 = 1, (*(byte *)(param_1 + 0x82) & 0x40) == 0)) {
    uVar1 = 0;
  }
  return uVar1;
}


/* END sub_006095a0 */


/* BEGIN sub_00609940, RVA 0x609940; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x609940", "end": "0x609954"}], "total_bytes": 21, "span_bytes": 21, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_685a433cbf20575e8bdde91ed2b353e21c71da9208c2985001002a72634e68c6, ev_b20537780310e3c8ced7415109b744b41baba469fc0dc1918d08b8635aed1e73, ev_afa176b34baacfb362d432e9d47a4f9e963312aad89192d86435d9391719b636
 */


bool sub_00609940(void)

{
  int iVar1;
  
  iVar1 = func_0x005a4e50();
  return iVar1 == 1;
}


/* END sub_00609940 */


/* BEGIN FUN_00abbf1a, RVA 0xabbf1a; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabbf1a", "end": "0xabbff2"}], "total_bytes": 217, "span_bytes": 217, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_b87828ffff496302a271dc82ac80a402d8199118a181b87b498639ff18f1cf4e, ev_ef4ff29d1327598bc90b8a17257b58ee1ec96c76c10b96eb1f7d18885d2e0070, ev_32a27c74cb83978f275046ec8ffdba62dfbc10045177195b6e73754261f0b992
 */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong FUN_00abbf1a(void)

{
  long lVar1;
  long *plVar2;
  code *pcVar3;
  undefined8 *puVar4;
  ulong uVar5;
  uint uVar6;
  ulong uVar7;
  long unaff_RBX;
  long unaff_RBP;
  long *plVar8;
  ulong unaff_R13;
  long unaff_R14;
  long unaff_R15;
  ulong uVar9;
  undefined8 *in_GS_OFFSET;
  
  puVar4 = (undefined8 *)func_0x0043b880(_DAT_03bf6e18,0,2);
  func_0x00259be0(unaff_RBP + -0x98,puVar4 + 1,0x20);
  *puVar4 = 0;
  **(undefined8 **)(unaff_RBP + -0x70) = puVar4;
  *(undefined8 **)(unaff_RBP + -0x70) = puVar4;
  uVar9 = unaff_R15 + 1;
  if (unaff_R13 == uVar9) {
    if (*(long *)(unaff_RBP + -0x78) == 0) {
      uVar5 = 0;
      uVar9 = unaff_R13 & 0xffffffff;
    }
    else {
      *(undefined4 *)(unaff_RBP + -0x68) = 0;
      uVar5 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
      uVar6 = *(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68);
      if ((int)uVar5 == 0) {
        uVar6 = (uint)unaff_R13;
      }
      uVar9 = (ulong)uVar6;
    }
    goto LAB_00abc2ec;
  }
  lVar1 = *(long *)(unaff_RBX + 0x10);
  func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
  uVar5 = sub_00259280(lVar1 + unaff_R14 + 0x20,unaff_RBP + -0x98,0x20);
  if ((int)uVar5 == 0) {
    uVar7 = (ulong)*(uint *)(unaff_RBP + -0x7c);
    if ((*(uint *)(unaff_RBP + -0x7c) != 4) && (*(long *)(unaff_RBP + -0x78) != 0)) {
      uVar5 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
      if ((int)uVar5 != 0) {
        uVar9 = (ulong)(uint)(*(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68));
        goto LAB_00abc2b8;
      }
      uVar7 = (ulong)*(uint *)(unaff_RBP + -0x7c);
      *(undefined4 *)(unaff_RBP + -0x9c) = 0xffffffff;
    }
    uVar5 = 0x16;
    if ((uint)uVar7 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00abbfea */
                    /* WARNING: Treating indirect jump as call */
      uVar9 = (*(code *)((long)*(int *)(uVar7 * 4 + 0x18dbf54) + 0x18dbf54))();
      return uVar9;
    }
  }
LAB_00abc2b8:
  if (*(long **)(unaff_RBP + -0x78) != (long *)0x0) {
    uVar5 = uVar5 & 0xffffffff;
    plVar8 = *(long **)(unaff_RBP + -0x78);
    do {
      plVar2 = (long *)*plVar8;
      func_0x0043c0c0(_DAT_03bf6e18,plVar8,0);
      plVar8 = plVar2;
    } while (plVar2 != (long *)0x0);
  }
LAB_00abc2ec:
  lVar1 = *(long *)(unaff_RBP + -0xa8);
  *(undefined1 *)(lVar1 + 0x116) = 0;
  if (*(char *)(lVar1 + 0x117) != '\0') {
    uVar5 = uVar5 & 0xffffffff;
    pcVar3 = *(code **)(_DAT_01a962e8 + 0x40);
    if (0x6ff < (-(long)pcVar3 + 0x260ce8U >> 3 | -(long)pcVar3 << 0x3d)) {
      func_0x0044f8c0(0x2888cf0,pcVar3);
    }
    lVar1 = *(long *)(unaff_RBP + -0xa8);
    (*pcVar3)(*(undefined8 *)(*(long *)(lVar1 + 8) + 0x200));
    if (*(char *)(lVar1 + 0x5f0) != '\0') {
      LOCK();
      _DAT_02d616c0 = _DAT_02d616c0 + -1;
      UNLOCK();
    }
  }
  if (*(long *)(unaff_RBX + 0x20) != 0) {
    uVar5 = uVar5 & 0xffffffff;
    sub_00259790(*(long *)(unaff_RBX + 0x20),uVar9 & 0xffffffff);
  }
  if (_DAT_0391c310 != *(long *)(unaff_RBP + -0x30)) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return uVar5;
}


/* END FUN_00abbf1a */


/* BEGIN fragment_548_00abbff3, RVA 0xabbff3; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabbff3", "end": "0xabc087"}, {"start": "0xabc1c5", "end": "0xabc232"}], "total_bytes": 259, "span_bytes": 576, "non_contiguous": true, "contains_entry": true}
 * REA Evidence: ev_cb60f49b08947a4fcb96da6a185fcdb8eaff0b5fd3e4c9d904c56adcb0e97023, ev_0667cc2905a188067e0ab035946284c73cdd25f72c1f3bcdf1261521dd4ae157, ev_13a4f69bbb405c66eeac53f21b80844495325b7e7599dac7482d49b8e4b94979
 */

/* Synthetic fragment: original entry registers/stack are live-ins; interpret with the structured reconstruction. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void fragment_548_00abbff3(void)

{
  byte bVar1;
  undefined4 uVar2;
  long lVar3;
  undefined8 *puVar4;
  code *pcVar5;
  undefined8 *puVar6;
  int iVar7;
  uint uVar8;
  ulong uVar9;
  undefined4 *unaff_RBX;
  long unaff_RBP;
  ulong unaff_R13;
  long unaff_R14;
  ulong unaff_R15;
  undefined8 *in_GS_OFFSET;
  
  uVar2 = *unaff_RBX;
  uVar8 = unaff_RBX[2];
  bVar1 = *(byte *)(unaff_RBP + -0x80);
  lVar3 = *(long *)(*(long *)(unaff_RBP + -0xa8) + 8);
  if ((((*(byte *)(*(long *)(lVar3 + 0x200) + 0x1c9) < 2) || ((*(byte *)(lVar3 + 0x464) & 2) != 0))
      || ((uVar8 & 0x400) != 0)) || (*(uint *)(lVar3 + 0x5d4) < 0x2500000)) {
    if ((((*(ulong *)(unaff_RBP + -0x98) & 0x3fff) == 0) &&
        ((*(ulong *)(unaff_RBP + -0x88) & 0x3fff) == 0)) &&
       (((*(ulong *)(unaff_RBP + -0x90) & 0x8000000000003fff) == 0 && ((bVar1 & 8) == 0)))) {
      *(ulong *)(unaff_RBP + -0x68) = *(ulong *)(unaff_RBP + -0x98);
      *(ulong *)(unaff_RBP + -0x60) = *(ulong *)(unaff_RBP + -0x88);
      *(uint *)(unaff_RBP + -0x58) = (uint)bVar1;
      *(uint *)(unaff_RBP + -0x50) = uVar8 | 1;
      *(undefined8 *)(unaff_RBP + -0x48) = 0;
      *(undefined4 *)(unaff_RBP + -0x40) = uVar2;
      *(ulong *)(unaff_RBP + -0x38) = *(ulong *)(unaff_RBP + -0x90);
      iVar7 = func_0x00ab8430(*(undefined8 *)(unaff_RBP + -0xa8),unaff_RBP + -0x68);
      goto LAB_00abc243;
    }
  }
  else {
    *(undefined8 *)(unaff_RBP + -0x68) = *(undefined8 *)(unaff_RBP + -0x98);
    *(undefined8 *)(unaff_RBP + -0x60) = *(undefined8 *)(unaff_RBP + -0x88);
    *(undefined4 *)(unaff_RBP + -0x58) = 0xffffffff;
    *(uint *)(unaff_RBP + -0x50) = (uint)bVar1;
    *(uint *)(unaff_RBP + -0x48) = uVar8;
    *(undefined8 *)(unaff_RBP + -0x40) = *(undefined8 *)(unaff_RBP + -0x90);
    iVar7 = func_0x00abd540(*(undefined8 *)(unaff_RBP + -0xa8),unaff_RBP + -0x68);
LAB_00abc243:
    if (iVar7 == 0) {
      unaff_R15 = unaff_R15 + 1;
      if (unaff_R13 == unaff_R15) {
        if (*(long *)(unaff_RBP + -0x78) == 0) {
          unaff_R15 = unaff_R13 & 0xffffffff;
        }
        else {
          *(undefined4 *)(unaff_RBP + -0x68) = 0;
          iVar7 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
          uVar8 = *(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68);
          if (iVar7 == 0) {
            uVar8 = (uint)unaff_R13;
          }
          unaff_R15 = (ulong)uVar8;
        }
        goto LAB_00abc2ec;
      }
      lVar3 = *(long *)(unaff_RBX + 4);
      func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
      iVar7 = sub_00259280(lVar3 + unaff_R14 + 0x20,unaff_RBP + -0x98,0x20);
      if (iVar7 == 0) {
        uVar9 = (ulong)*(uint *)(unaff_RBP + -0x7c);
        if ((*(uint *)(unaff_RBP + -0x7c) != 4) && (*(long *)(unaff_RBP + -0x78) != 0)) {
          iVar7 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
          if (iVar7 != 0) {
            unaff_R15 = (ulong)(uint)(*(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68));
            goto LAB_00abc2b8;
          }
          uVar9 = (ulong)*(uint *)(unaff_RBP + -0x7c);
          *(undefined4 *)(unaff_RBP + -0x9c) = 0xffffffff;
        }
        if ((uint)uVar9 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00abbfea */
                    /* WARNING: Treating indirect jump as call */
          (*(code *)((long)*(int *)(uVar9 * 4 + 0x18dbf54) + 0x18dbf54))();
          return;
        }
      }
    }
  }
LAB_00abc2b8:
  puVar6 = *(undefined8 **)(unaff_RBP + -0x78);
  while (puVar6 != (undefined8 *)0x0) {
    puVar4 = (undefined8 *)*puVar6;
    func_0x0043c0c0(_DAT_03bf6e18,puVar6,0);
    puVar6 = puVar4;
  }
LAB_00abc2ec:
  lVar3 = *(long *)(unaff_RBP + -0xa8);
  *(undefined1 *)(lVar3 + 0x116) = 0;
  if (*(char *)(lVar3 + 0x117) != '\0') {
    pcVar5 = *(code **)(_DAT_01a962e8 + 0x40);
    if (0x6ff < (-(long)pcVar5 + 0x260ce8U >> 3 | -(long)pcVar5 << 0x3d)) {
      func_0x0044f8c0(0x2888cf0,pcVar5);
    }
    lVar3 = *(long *)(unaff_RBP + -0xa8);
    (*pcVar5)(*(undefined8 *)(*(long *)(lVar3 + 8) + 0x200));
    if (*(char *)(lVar3 + 0x5f0) != '\0') {
      LOCK();
      _DAT_02d616c0 = _DAT_02d616c0 + -1;
      UNLOCK();
    }
  }
  if (*(long *)(unaff_RBX + 8) != 0) {
    sub_00259790(*(long *)(unaff_RBX + 8),unaff_R15 & 0xffffffff);
  }
  if (_DAT_0391c310 == *(long *)(unaff_RBP + -0x30)) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}


/* END fragment_548_00abbff3 */


/* BEGIN fragment_548_00abc088, RVA 0xabc088; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabc088", "end": "0xabc0af"}], "total_bytes": 40, "span_bytes": 40, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_598039e134b0bd8b516f022999335838ab582e6f28788315334bffb239e4b180, ev_244948839dd4af6366e1ab59ed2f310829c64e7c2566e293cea25333eff731b2, ev_d1041e0b41ab83606c95eab0cc8a3b7b02b7b5eff06e75e3b3cdd6ae154f420f
 */

/* Synthetic fragment: original entry registers/stack are live-ins; interpret with the structured reconstruction. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong fragment_548_00abc088(void)

{
  long lVar1;
  long *plVar2;
  code *pcVar3;
  int iVar4;
  undefined8 *puVar5;
  ulong uVar6;
  ulong uVar7;
  uint uVar8;
  ulong uVar9;
  long unaff_RBX;
  long unaff_RBP;
  long *plVar10;
  ulong unaff_R13;
  long unaff_R14;
  long unaff_R15;
  undefined8 *in_GS_OFFSET;
  
  iVar4 = *(int *)(unaff_RBP + -0x9c);
  if (iVar4 < 0) {
    iVar4 = (int)unaff_R15;
  }
  *(int *)(unaff_RBP + -0x9c) = iVar4;
  if ((*(byte *)(unaff_RBP + -0x80) & 2) != 0) {
    *(byte *)(unaff_RBP + -0x80) = *(byte *)(unaff_RBP + -0x80) | 1;
    uVar7 = FUN_00abbf1a();
    return uVar7;
  }
  puVar5 = (undefined8 *)func_0x0043b880(_DAT_03bf6e18,0,2);
  func_0x00259be0(unaff_RBP + -0x98,puVar5 + 1,0x20);
  *puVar5 = 0;
  **(undefined8 **)(unaff_RBP + -0x70) = puVar5;
  *(undefined8 **)(unaff_RBP + -0x70) = puVar5;
  uVar7 = unaff_R15 + 1;
  if (unaff_R13 == uVar7) {
    if (*(long *)(unaff_RBP + -0x78) == 0) {
      uVar6 = 0;
      uVar7 = unaff_R13 & 0xffffffff;
    }
    else {
      *(undefined4 *)(unaff_RBP + -0x68) = 0;
      uVar6 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
      uVar8 = *(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68);
      if ((int)uVar6 == 0) {
        uVar8 = (uint)unaff_R13;
      }
      uVar7 = (ulong)uVar8;
    }
    goto LAB_00abc2ec;
  }
  lVar1 = *(long *)(unaff_RBX + 0x10);
  func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
  uVar6 = sub_00259280(lVar1 + unaff_R14 + 0x20,unaff_RBP + -0x98,0x20);
  if ((int)uVar6 == 0) {
    uVar9 = (ulong)*(uint *)(unaff_RBP + -0x7c);
    if ((*(uint *)(unaff_RBP + -0x7c) != 4) && (*(long *)(unaff_RBP + -0x78) != 0)) {
      uVar6 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
      if ((int)uVar6 != 0) {
        uVar7 = (ulong)(uint)(*(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68));
        goto LAB_00abc2b8;
      }
      uVar9 = (ulong)*(uint *)(unaff_RBP + -0x7c);
      *(undefined4 *)(unaff_RBP + -0x9c) = 0xffffffff;
    }
    uVar6 = 0x16;
    if ((uint)uVar9 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00abbfea */
                    /* WARNING: Treating indirect jump as call */
      uVar7 = (*(code *)((long)*(int *)(uVar9 * 4 + 0x18dbf54) + 0x18dbf54))();
      return uVar7;
    }
  }
LAB_00abc2b8:
  if (*(long **)(unaff_RBP + -0x78) != (long *)0x0) {
    uVar6 = uVar6 & 0xffffffff;
    plVar10 = *(long **)(unaff_RBP + -0x78);
    do {
      plVar2 = (long *)*plVar10;
      func_0x0043c0c0(_DAT_03bf6e18,plVar10,0);
      plVar10 = plVar2;
    } while (plVar2 != (long *)0x0);
  }
LAB_00abc2ec:
  lVar1 = *(long *)(unaff_RBP + -0xa8);
  *(undefined1 *)(lVar1 + 0x116) = 0;
  if (*(char *)(lVar1 + 0x117) != '\0') {
    uVar6 = uVar6 & 0xffffffff;
    pcVar3 = *(code **)(_DAT_01a962e8 + 0x40);
    if (0x6ff < (-(long)pcVar3 + 0x260ce8U >> 3 | -(long)pcVar3 << 0x3d)) {
      func_0x0044f8c0(0x2888cf0,pcVar3);
    }
    lVar1 = *(long *)(unaff_RBP + -0xa8);
    (*pcVar3)(*(undefined8 *)(*(long *)(lVar1 + 8) + 0x200));
    if (*(char *)(lVar1 + 0x5f0) != '\0') {
      LOCK();
      _DAT_02d616c0 = _DAT_02d616c0 + -1;
      UNLOCK();
    }
  }
  if (*(long *)(unaff_RBX + 0x20) != 0) {
    uVar6 = uVar6 & 0xffffffff;
    sub_00259790(*(long *)(unaff_RBX + 0x20),uVar7 & 0xffffffff);
  }
  if (_DAT_0391c310 != *(long *)(unaff_RBP + -0x30)) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return uVar6;
}


/* END fragment_548_00abc088 */


/* BEGIN fragment_548_00abc0b0, RVA 0xabc0b0; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabc0b0", "end": "0xabc11d"}], "total_bytes": 110, "span_bytes": 110, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_31c59e445ba3df11ca68c00b1494805a9479d148db2dc3998ef4892977af90ec, ev_2562d619d8a3efd1b7e2acc504f6128e6fc82763dcb6ba1312216164cbc33ee5, ev_6fe8765d80801b8485c8c9d584dd882143127f86f43b00143ee27ee9364c7893
 */

/* Synthetic fragment: original entry registers/stack are live-ins; interpret with the structured reconstruction. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void fragment_548_00abc0b0(void)

{
  byte bVar1;
  long lVar2;
  ulong uVar3;
  undefined8 *puVar4;
  code *pcVar5;
  undefined8 *puVar6;
  int iVar7;
  uint uVar8;
  ulong uVar9;
  long unaff_RBX;
  long unaff_RBP;
  ulong unaff_R13;
  long unaff_R14;
  ulong unaff_R15;
  undefined8 *in_GS_OFFSET;
  
  uVar9 = *(ulong *)(unaff_RBP + -0x98);
  if (((((uVar9 & 0x3fff) == 0) && (uVar3 = *(ulong *)(unaff_RBP + -0x88), (uVar3 & 0x3fff) == 0))
      && (bVar1 = *(byte *)(unaff_RBP + -0x80), (bVar1 & 8) == 0)) && (!CARRY8(uVar3,uVar9))) {
    iVar7 = func_0x002cbdb0(*(undefined8 *)(*(long *)(*(long *)(unaff_RBP + -0xa8) + 8) + 0x200),
                            uVar9,uVar3 + uVar9,bVar1 >> 1 & 0xc1 | bVar1,0);
    if (iVar7 != 0) {
      FUN_00abc286();
      return;
    }
    unaff_R15 = unaff_R15 + 1;
    if (unaff_R13 == unaff_R15) {
      if (*(long *)(unaff_RBP + -0x78) == 0) {
        unaff_R15 = unaff_R13 & 0xffffffff;
      }
      else {
        *(undefined4 *)(unaff_RBP + -0x68) = 0;
        iVar7 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
        uVar8 = *(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68);
        if (iVar7 == 0) {
          uVar8 = (uint)unaff_R13;
        }
        unaff_R15 = (ulong)uVar8;
      }
      goto LAB_00abc2ec;
    }
    lVar2 = *(long *)(unaff_RBX + 0x10);
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    iVar7 = sub_00259280(lVar2 + unaff_R14 + 0x20,unaff_RBP + -0x98,0x20);
    if (iVar7 == 0) {
      uVar9 = (ulong)*(uint *)(unaff_RBP + -0x7c);
      if ((*(uint *)(unaff_RBP + -0x7c) != 4) && (*(long *)(unaff_RBP + -0x78) != 0)) {
        iVar7 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
        if (iVar7 != 0) {
          unaff_R15 = (ulong)(uint)(*(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68));
          goto LAB_00abc2b8;
        }
        uVar9 = (ulong)*(uint *)(unaff_RBP + -0x7c);
        *(undefined4 *)(unaff_RBP + -0x9c) = 0xffffffff;
      }
      if ((uint)uVar9 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00abbfea */
                    /* WARNING: Treating indirect jump as call */
        (*(code *)((long)*(int *)(uVar9 * 4 + 0x18dbf54) + 0x18dbf54))();
        return;
      }
    }
  }
LAB_00abc2b8:
  puVar6 = *(undefined8 **)(unaff_RBP + -0x78);
  while (puVar6 != (undefined8 *)0x0) {
    puVar4 = (undefined8 *)*puVar6;
    func_0x0043c0c0(_DAT_03bf6e18,puVar6,0);
    puVar6 = puVar4;
  }
LAB_00abc2ec:
  lVar2 = *(long *)(unaff_RBP + -0xa8);
  *(undefined1 *)(lVar2 + 0x116) = 0;
  if (*(char *)(lVar2 + 0x117) != '\0') {
    pcVar5 = *(code **)(_DAT_01a962e8 + 0x40);
    if (0x6ff < (-(long)pcVar5 + 0x260ce8U >> 3 | -(long)pcVar5 << 0x3d)) {
      func_0x0044f8c0(0x2888cf0,pcVar5);
    }
    lVar2 = *(long *)(unaff_RBP + -0xa8);
    (*pcVar5)(*(undefined8 *)(*(long *)(lVar2 + 8) + 0x200));
    if (*(char *)(lVar2 + 0x5f0) != '\0') {
      LOCK();
      _DAT_02d616c0 = _DAT_02d616c0 + -1;
      UNLOCK();
    }
  }
  if (*(long *)(unaff_RBX + 0x20) != 0) {
    sub_00259790(*(long *)(unaff_RBX + 0x20),unaff_R15 & 0xffffffff);
  }
  if (_DAT_0391c310 == *(long *)(unaff_RBP + -0x30)) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}


/* END fragment_548_00abc0b0 */


/* BEGIN fragment_548_00abc11e, RVA 0xabc11e; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabc11e", "end": "0xabc184"}, {"start": "0xabc233", "end": "0xabc242"}], "total_bytes": 119, "span_bytes": 293, "non_contiguous": true, "contains_entry": true}
 * REA Evidence: ev_433999a868ad765d74d30285717f063be9ae483f80d3af81c1b8222378b0f44f, ev_5c881ba1aefaaf111e488bfb5294c90d6ebe4f5ecc45acf2e6aab43c684b82fb, ev_54651862d1d0807cf9ea4e5b7eee815c224e27e6ecbe4e983c97862aef91dd5a
 */

/* Synthetic fragment: original entry registers/stack are live-ins; interpret with the structured reconstruction. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void fragment_548_00abc11e(void)

{
  undefined8 *puVar1;
  long lVar2;
  code *pcVar3;
  undefined8 *puVar4;
  int iVar5;
  uint uVar6;
  ulong uVar7;
  long unaff_RBX;
  long unaff_RBP;
  ulong unaff_R13;
  long unaff_R14;
  ulong unaff_R15;
  undefined8 *in_GS_OFFSET;
  
  if ((((*(ulong *)(unaff_RBP + -0x98) & 0x3fff) == 0) &&
      ((*(ulong *)(unaff_RBP + -0x88) & 0x3fff) == 0)) && ((*(byte *)(unaff_RBP + -0x80) & 8) == 0))
  {
    uVar6 = *(uint *)(unaff_RBX + 8);
    *(ulong *)(unaff_RBP + -0x68) = *(ulong *)(unaff_RBP + -0x98);
    *(ulong *)(unaff_RBP + -0x60) = *(ulong *)(unaff_RBP + -0x88);
    *(uint *)(unaff_RBP + -0x58) = (uint)*(byte *)(unaff_RBP + -0x80);
    *(uint *)(unaff_RBP + -0x50) = uVar6 | 0x1000;
    *(undefined8 *)(unaff_RBP + -0x48) = 0;
    *(undefined4 *)(unaff_RBP + -0x40) = 0xffffffff;
    *(undefined8 *)(unaff_RBP + -0x38) = 0;
    iVar5 = func_0x00ab8430(*(undefined8 *)(unaff_RBP + -0xa8),unaff_RBP + -0x68);
    if (iVar5 == 0) {
      unaff_R15 = unaff_R15 + 1;
      if (unaff_R13 == unaff_R15) {
        if (*(long *)(unaff_RBP + -0x78) == 0) {
          unaff_R15 = unaff_R13 & 0xffffffff;
        }
        else {
          *(undefined4 *)(unaff_RBP + -0x68) = 0;
          iVar5 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
          uVar6 = *(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68);
          if (iVar5 == 0) {
            uVar6 = (uint)unaff_R13;
          }
          unaff_R15 = (ulong)uVar6;
        }
        goto LAB_00abc2ec;
      }
      lVar2 = *(long *)(unaff_RBX + 0x10);
      func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
      iVar5 = sub_00259280(lVar2 + unaff_R14 + 0x20,unaff_RBP + -0x98,0x20);
      if (iVar5 == 0) {
        uVar7 = (ulong)*(uint *)(unaff_RBP + -0x7c);
        if ((*(uint *)(unaff_RBP + -0x7c) != 4) && (*(long *)(unaff_RBP + -0x78) != 0)) {
          iVar5 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
          if (iVar5 != 0) {
            unaff_R15 = (ulong)(uint)(*(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68));
            goto LAB_00abc2b8;
          }
          uVar7 = (ulong)*(uint *)(unaff_RBP + -0x7c);
          *(undefined4 *)(unaff_RBP + -0x9c) = 0xffffffff;
        }
        if ((uint)uVar7 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00abbfea */
                    /* WARNING: Treating indirect jump as call */
          (*(code *)((long)*(int *)(uVar7 * 4 + 0x18dbf54) + 0x18dbf54))();
          return;
        }
      }
    }
  }
LAB_00abc2b8:
  puVar4 = *(undefined8 **)(unaff_RBP + -0x78);
  while (puVar4 != (undefined8 *)0x0) {
    puVar1 = (undefined8 *)*puVar4;
    func_0x0043c0c0(_DAT_03bf6e18,puVar4,0);
    puVar4 = puVar1;
  }
LAB_00abc2ec:
  lVar2 = *(long *)(unaff_RBP + -0xa8);
  *(undefined1 *)(lVar2 + 0x116) = 0;
  if (*(char *)(lVar2 + 0x117) != '\0') {
    pcVar3 = *(code **)(_DAT_01a962e8 + 0x40);
    if (0x6ff < (-(long)pcVar3 + 0x260ce8U >> 3 | -(long)pcVar3 << 0x3d)) {
      func_0x0044f8c0(0x2888cf0,pcVar3);
    }
    lVar2 = *(long *)(unaff_RBP + -0xa8);
    (*pcVar3)(*(undefined8 *)(*(long *)(lVar2 + 8) + 0x200));
    if (*(char *)(lVar2 + 0x5f0) != '\0') {
      LOCK();
      _DAT_02d616c0 = _DAT_02d616c0 + -1;
      UNLOCK();
    }
  }
  if (*(long *)(unaff_RBX + 0x20) != 0) {
    sub_00259790(*(long *)(unaff_RBX + 0x20),unaff_R15 & 0xffffffff);
  }
  if (_DAT_0391c310 == *(long *)(unaff_RBP + -0x30)) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}


/* END fragment_548_00abc11e */


/* BEGIN fragment_548_00abc185, RVA 0xabc185; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabc185", "end": "0xabc1c4"}, {"start": "0xabc243", "end": "0xabc24c"}, {"start": "0xabc257", "end": "0xabc285"}], "total_bytes": 121, "span_bytes": 257, "non_contiguous": true, "contains_entry": true}
 * REA Evidence: ev_db9177c5cd23047ee16fded55106c38800b616ae5ff19d340389d30262bfda17, ev_23af40b35666fb148f1e846fa46c37516a674c2d6091ef05b9addd41d79a94c6, ev_08a71951e60fd6c6c56afe91f7d765f4613dc7cceb798929e2ac0afd5bb95140
 */

/* Synthetic fragment: original entry registers/stack are live-ins; interpret with the structured reconstruction. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void fragment_548_00abc185(void)

{
  undefined8 *puVar1;
  long lVar2;
  code *pcVar3;
  undefined8 *puVar4;
  int iVar5;
  uint uVar6;
  ulong uVar7;
  long unaff_RBX;
  long unaff_RBP;
  ulong unaff_R13;
  long unaff_R14;
  ulong unaff_R15;
  undefined8 *in_GS_OFFSET;
  
  if (((*(ulong *)(unaff_RBP + -0x98) & 0x3fff) == 0) &&
     ((*(ulong *)(unaff_RBP + -0x88) & 0x3fff) == 0)) {
    *(ulong *)(unaff_RBP + -0x68) = *(ulong *)(unaff_RBP + -0x98);
    *(ulong *)(unaff_RBP + -0x60) = *(ulong *)(unaff_RBP + -0x88);
    iVar5 = func_0x00ab8bb0(*(undefined8 *)(unaff_RBP + -0xa8),unaff_RBP + -0x68);
    if (iVar5 == 0) {
      unaff_R15 = unaff_R15 + 1;
      if (unaff_R13 == unaff_R15) {
        if (*(long *)(unaff_RBP + -0x78) == 0) {
          unaff_R15 = unaff_R13 & 0xffffffff;
        }
        else {
          *(undefined4 *)(unaff_RBP + -0x68) = 0;
          iVar5 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
          uVar6 = *(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68);
          if (iVar5 == 0) {
            uVar6 = (uint)unaff_R13;
          }
          unaff_R15 = (ulong)uVar6;
        }
        goto LAB_00abc2ec;
      }
      lVar2 = *(long *)(unaff_RBX + 0x10);
      func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
      iVar5 = sub_00259280(lVar2 + unaff_R14 + 0x20,unaff_RBP + -0x98,0x20);
      if (iVar5 == 0) {
        uVar7 = (ulong)*(uint *)(unaff_RBP + -0x7c);
        if ((*(uint *)(unaff_RBP + -0x7c) != 4) && (*(long *)(unaff_RBP + -0x78) != 0)) {
          iVar5 = func_0x00abc3b0(unaff_RBP + -0x78,unaff_RBP + -0x68);
          if (iVar5 != 0) {
            unaff_R15 = (ulong)(uint)(*(int *)(unaff_RBP + -0x9c) + *(int *)(unaff_RBP + -0x68));
            goto LAB_00abc2b8;
          }
          uVar7 = (ulong)*(uint *)(unaff_RBP + -0x7c);
          *(undefined4 *)(unaff_RBP + -0x9c) = 0xffffffff;
        }
        if ((uint)uVar7 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00abbfea */
                    /* WARNING: Treating indirect jump as call */
          (*(code *)((long)*(int *)(uVar7 * 4 + 0x18dbf54) + 0x18dbf54))();
          return;
        }
      }
    }
  }
LAB_00abc2b8:
  puVar4 = *(undefined8 **)(unaff_RBP + -0x78);
  while (puVar4 != (undefined8 *)0x0) {
    puVar1 = (undefined8 *)*puVar4;
    func_0x0043c0c0(_DAT_03bf6e18,puVar4,0);
    puVar4 = puVar1;
  }
LAB_00abc2ec:
  lVar2 = *(long *)(unaff_RBP + -0xa8);
  *(undefined1 *)(lVar2 + 0x116) = 0;
  if (*(char *)(lVar2 + 0x117) != '\0') {
    pcVar3 = *(code **)(_DAT_01a962e8 + 0x40);
    if (0x6ff < (-(long)pcVar3 + 0x260ce8U >> 3 | -(long)pcVar3 << 0x3d)) {
      func_0x0044f8c0(0x2888cf0,pcVar3);
    }
    lVar2 = *(long *)(unaff_RBP + -0xa8);
    (*pcVar3)(*(undefined8 *)(*(long *)(lVar2 + 8) + 0x200));
    if (*(char *)(lVar2 + 0x5f0) != '\0') {
      LOCK();
      _DAT_02d616c0 = _DAT_02d616c0 + -1;
      UNLOCK();
    }
  }
  if (*(long *)(unaff_RBX + 0x20) != 0) {
    sub_00259790(*(long *)(unaff_RBX + 0x20),unaff_R15 & 0xffffffff);
  }
  if (_DAT_0391c310 == *(long *)(unaff_RBP + -0x30)) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}


/* END fragment_548_00abc185 */


/* BEGIN FUN_00abc286, RVA 0xabc286; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabc286", "end": "0xabc29d"}, {"start": "0xabc2b3", "end": "0xabc3a3"}], "total_bytes": 265, "span_bytes": 286, "non_contiguous": true, "contains_entry": true}
 * REA Evidence: ev_f450a5a5a48b7365d1c35c17e1b4c76849e6885e78f09d8cff46b25c8e902106, ev_ce2f423f2c52604e6d741b4c9245ea6c629154346424379a7b07a787e59bec75, ev_891197d1acf792ca390df3b8930ba84a1118dc4219516e53a5cd5d10b9b5df07
 */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 FUN_00abc286(void)

{
  undefined8 *puVar1;
  long lVar2;
  code *pcVar3;
  undefined8 *puVar4;
  int in_EAX;
  undefined8 uVar5;
  long unaff_RBX;
  long unaff_RBP;
  undefined4 unaff_R15D;
  
  if (in_EAX == 2) {
    uVar5 = 0xd;
  }
  else {
    uVar5 = 0xc;
    if (in_EAX != 6) {
      uVar5 = 0x16;
    }
  }
  puVar4 = *(undefined8 **)(unaff_RBP + -0x78);
  while (puVar4 != (undefined8 *)0x0) {
    puVar1 = (undefined8 *)*puVar4;
    func_0x0043c0c0(_DAT_03bf6e18,puVar4,0);
    puVar4 = puVar1;
  }
  lVar2 = *(long *)(unaff_RBP + -0xa8);
  *(undefined1 *)(lVar2 + 0x116) = 0;
  if (*(char *)(lVar2 + 0x117) != '\0') {
    pcVar3 = *(code **)(_DAT_01a962e8 + 0x40);
    if (0x6ff < (-(long)pcVar3 + 0x260ce8U >> 3 | -(long)pcVar3 << 0x3d)) {
      func_0x0044f8c0(0x2888cf0,pcVar3);
    }
    lVar2 = *(long *)(unaff_RBP + -0xa8);
    (*pcVar3)(*(undefined8 *)(*(long *)(lVar2 + 8) + 0x200));
    if (*(char *)(lVar2 + 0x5f0) != '\0') {
      LOCK();
      _DAT_02d616c0 = _DAT_02d616c0 + -1;
      UNLOCK();
    }
  }
  if (*(long *)(unaff_RBX + 0x20) != 0) {
    sub_00259790(*(long *)(unaff_RBX + 0x20),unaff_R15D);
  }
  if (_DAT_0391c310 == *(long *)(unaff_RBP + -0x30)) {
    return uVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}


/* END FUN_00abc286 */


/* BEGIN fragment_548_00abc2ac, RVA 0xabc2ac; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabc2ac", "end": "0xabc2b2"}], "total_bytes": 7, "span_bytes": 7, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_bd73d41090dd1bb55eb42366a81bff30285e28cb7819c1013f00db19c2472ff6, ev_11e0cf80f59a4d0a34357a5d10c293506ea1d88aa27e254c2fd56727668efb9d, ev_c0af36f50ce15abb98191bda2dbd39138aa22e4259f5239b505753215c79c43b
 */

/* Synthetic fragment: original entry registers/stack are live-ins; interpret with the structured reconstruction. */

/* WARNING: Control flow encountered bad instruction data */

void fragment_548_00abc2ac(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


/* END fragment_548_00abc2ac */


/* BEGIN sub_00abc3b0, RVA 0xabc3b0; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabc3b0", "end": "0xabc505"}], "total_bytes": 342, "span_bytes": 342, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_abdccfc5079cfb29661d93a66bc8be1ccf267e9d7818152c7d02cb3a24b5e7bf, ev_dd92e7bcaffde26359852ded4e168e76a422de7d8f2f66467e230f6a76b09773, ev_18ebf34c435f9398216aa2306bb85cb648b97acfa3d22c9cc736743e9cb1f9ef
 */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 sub_00abc3b0(long *param_1,int *param_2)

{
  long lVar1;
  undefined8 *puVar2;
  code *pcVar3;
  undefined8 *puVar4;
  int iVar5;
  uint uVar6;
  ulong uVar7;
  long *plVar8;
  int iVar9;
  undefined4 uVar10;
  long *in_GS_OFFSET;
  int local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar1 = *in_GS_OFFSET;
  iVar5 = func_0x00609560(*(undefined8 *)(lVar1 + 0x140));
  uVar10 = 1;
  if ((iVar5 == 0) && (iVar5 = func_0x006095a0(*(undefined8 *)(lVar1 + 0x140)), iVar5 == 0)) {
    local_3c = 0;
    plVar8 = (long *)*param_1;
    if (plVar8 != (long *)0x0) {
      uVar10 = 0x16;
      iVar5 = 1;
      do {
        iVar9 = iVar5;
        uVar7 = plVar8[3] + plVar8[1];
        if ((((CARRY8(plVar8[3],plVar8[1])) || ((uVar7 + 0x3fff & 0xffffffffffffc000) < uVar7)) ||
            (iVar5 = func_0x003c33e0((int)*(char *)((long)plVar8 + 0x21),*(undefined8 *)(lVar1 + 8))
            , iVar5 == 0)) || ((*(byte *)(plVar8 + 4) & 8) != 0)) goto LAB_00abc4a2;
        plVar8 = (long *)*plVar8;
        iVar5 = iVar9 + 1;
        local_3c = iVar9;
      } while (plVar8 != (long *)0x0);
    }
    uVar6 = func_0x002cdc10(*(undefined8 *)(*(long *)(lVar1 + 8) + 0x200),param_1,&local_3c);
    uVar10 = 0x16;
    if (uVar6 < 10) {
      uVar10 = *(undefined4 *)((ulong)uVar6 * 4 + 0x18dbfb4);
    }
LAB_00abc4a2:
    puVar4 = (undefined8 *)*param_1;
    while (puVar4 != (undefined8 *)0x0) {
      puVar2 = (undefined8 *)*puVar4;
      func_0x0043c0c0(_DAT_03bf6e18,puVar4,0);
      puVar4 = puVar2;
    }
    *param_1 = 0;
    param_1[1] = (long)param_1;
    *param_2 = local_3c;
  }
  if (_DAT_0391c310 == local_38) {
    return uVar10;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}


/* END sub_00abc3b0 */


/* BEGIN sub_00c1a3e0, RVA 0xc1a3e0; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xc1a3e0", "end": "0xc1a4a5"}], "total_bytes": 198, "span_bytes": 198, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_5b02a6d434dfd1e956b092a96af2cd2f6f9cf6a6ef6acf53496fe909d1dd92a8, ev_15dbed26acd85854f16d37e7805d3abe74971ba5fb861115d8fa4beec0eb8aff, ev_7d48a995ced64e599c2e597f3b73b74ff3938d9e071932d12911fad54c239f73
 */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00c1a3e0(long param_1,undefined8 param_2,int param_3)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  ulong *in_GS_OFFSET;
  
  if (*(int *)(param_1 + 0x138) != 0) {
    func_0x007f1950();
    func_0x007f18a0(0xc1a477,param_2);
    func_0x00c9aa10(0x17,0x13434da,param_2);
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  if ((*(uint *)(param_1 + 0xec) & 0x4000) != 0) {
    return;
  }
  if ((*(uint *)(param_1 + 0xec) & 0x100) == 0) {
    if (*(short *)(param_1 + 0x10a) < 1) {
      return;
    }
    if (param_3 != 0) {
      return;
    }
    if ((_DAT_03538910 & 0xfffffffffffffff8) == *in_GS_OFFSET) {
      return;
    }
    uVar3 = 0x127e998;
  }
  else {
    uVar3 = 0x13434f2;
  }
  func_0x0025d410(uVar3,param_2,param_1 + 0x294);
  iVar2 = func_0x00b07920();
  if ((iVar2 != 0) && (iVar2 = func_0x00609940(), iVar2 != 0)) {
    func_0x00046c60();
  }
  *(byte *)(param_1 + 0xed) = *(byte *)(param_1 + 0xed) | 0x40;
  return;
}


/* END sub_00c1a3e0 */
