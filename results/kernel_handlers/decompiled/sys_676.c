/* Handler 676: REA6.7.0 / Ghidra12.1.4 recovered pseudocode, not original or buildable C.
 * Original4096-byte input SHA256 c939ff1fe660c65241cbd3bff95bf55fcc29969913e358b6bbc4749c71a13fc3
 * Raw entry RVA 0x265fa8 -> actual target 0x6f92e0. narg=0.
 * Kernel RVAs; runtime VA=0xffffffff8a9c0000+RVA. Opaque externals/data remain unknown.
 * Analyst types below are inferred from accesses. Recovered pseudocode is retained verbatim afterward.
 * Original entry is an assembly-verified tail JMP to the target above. An engine halt_baddata
 * at that unmapped edge is a decompiler boundary artifact, not a recovered halt operation.
 */
#include <stdint.h>

/* ===== Analyst recovered interface/types ===== */
extern int impl_6f8910(uint32_t internal_mode);
extern uint8_t analyst_current_process_byte_c81(void); /* symbolic accessor: *(GS:0 -> +8 -> +0xc81) */
extern uint8_t analyst_global_byte_391c1c0; /* symbolic location, kernel RVA0x391c1c0 */
int analyst_handler_676(void) {
    if (analyst_current_process_byte_c81() != 0) return 78;
    if (analyst_global_byte_391c1c0 == 0) analyst_global_byte_391c1c0 = 1;
    return impl_6f8910(2) == 0 ? 0 : 22;
}
/* Accessor/global identifiers above are analyst explanatory declarations, not recovered linker symbols. */


/* ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_EXT_FUN_006f92e0 RVA 0x265fa8 | Evidence ev_c4a74c9ce2fc789cd5d1065d49c1604835bebc3f85fa69c049bfb3c59a201be9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x265fa8", "end": "0x265fac"}], "total_bytes": 5, "span_bytes": 5, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_006f92e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): impl_cpumode_6f8910 RVA 0x6f8910 | Evidence ev_eb1b8bb4bf8e3e79e659da66b51aecdfc958f4bdc4c03446588963c83280fcbe | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.bin SHA256 52a840747e97096877d643ade1dd1cdc6e6e5b3d3dd7e8a19333d7e1031d853f =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x6f8910", "end": "0x6f90c6"}, {"start": "0x6f90d0", "end": "0x6f92c6"}], "total_bytes": 2478, "span_bytes": 2487, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int impl_cpumode_6f8910(int param_1)

{
  long *plVar1;
  code *pcVar2;
  bool bVar3;
  bool bVar4;
  int iVar5;
  ulong uVar6;
  undefined8 uVar7;
  ulong uVar8;
  uint uVar9;
  ulong uVar10;
  undefined8 *in_GS_OFFSET;
  bool bVar11;
  undefined8 local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  plVar1 = (long *)*in_GS_OFFSET;
  if ((_DAT_021fb408 != 0) && (param_1 == 1)) {
    func_0x00a90d70(0x13b25df,0);
    func_0x00a90d70(0x13b25df,0xf);
    func_0x00a90d70(0x13b25df,0);
  }
  if ((_DAT_021fb3c4 == 1) && (_DAT_021fb3d0 == 0)) {
    if (_DAT_021fb3c0 != 1) {
      iVar5 = -1;
      if (param_1 == 1) {
        func_0x008c4180();
      }
      goto LAB_006f91b1;
    }
    if (DAT_0391c178 == '\x01') {
      if (param_1 == 1) {
        iVar5 = 0;
        func_0x004c78b0(plVar1,0,0x1279d12,0x471);
        if (_DAT_0391c240 != 0) {
          func_0x004ea9b0(_DAT_0391c238,0x21fb4b0);
        }
        func_0x004c7520(*plVar1 + 0x18,0,0,0);
        func_0x008c4180();
      }
      else {
        iVar5 = -(uint)(*(int *)((long)in_GS_OFFSET + 0x34) != 3);
      }
      goto LAB_006f91b1;
    }
  }
  uVar8 = 0;
  func_0x004c7190(0x391c198,0,0,0);
  func_0x004c78b0(plVar1,0,0x1279d12);
  if (param_1 == 2) {
    if (((DAT_0391c230 != '\x01') || (_DAT_021fb3c8 == 0)) ||
       (*(int *)((long)in_GS_OFFSET + 0x34) != 3)) {
      func_0x004c7520(*plVar1 + 0x18,0,0,0);
      func_0x004c7520(0x391c198,0,0,0);
      iVar5 = -1;
      goto LAB_006f91b1;
    }
    bVar11 = false;
LAB_006f8c52:
    uVar8 = 0;
    bVar4 = false;
  }
  else {
    bVar11 = param_1 == 1;
    if (!bVar11) goto LAB_006f8c52;
    bVar4 = false;
    if (_DAT_021fb3d0 != 0) {
      if (_DAT_021fb3d4 == 1) {
        func_0x0025d410(0x12c0eac);
        _DAT_021fb3d4 = 0;
        func_0x006b7e80(0);
        func_0x004c7190(0x391c1b8,0,0,0);
        func_0x00ac7630(0x391c1e8);
        _DAT_021fb3f0 = 0;
        func_0x00258ff0(&DAT_021fb3f8,0x10);
        func_0x004c7520(0x391c1b8,0,0,0);
        if (_DAT_021fb408 != 0) {
          func_0x006f9960(_DAT_021fb3d4,1);
        }
      }
      func_0x004c7190(0x391c1b8,0,0,0);
      _DAT_021fb3f0 = 1;
      func_0x004c7520(0x391c1b8,0,0,0);
      if (_DAT_021fb408 != 0) {
        func_0x006f9960(1,0);
      }
      iVar5 = func_0x006b7e80(1);
      _DAT_021fb3d4 = 1;
      if (iVar5 == 0) {
        local_48 = 0;
        local_40 = 0x116ebd4cfd0842;
        func_0x004c7190(0x391c1b8,0,0,0);
        func_0x00acf200(&DAT_021fb3f8);
        _DAT_021fb3f8 = _DAT_021fb3f8 + (ulong)(0xffee9142b302f7bd < _DAT_021fb400);
        _DAT_021fb400 = _DAT_021fb400 + 0x116ebd4cfd0842;
        func_0x00ac7630(0x391c1e8);
        _DAT_0391c228 = 1;
        _DAT_0391c218 = 0x2677d8;
        func_0x00ac7470(0x391c1e8,&local_48);
        if (_DAT_021fb408 != 0) {
          func_0x006f8830();
        }
        func_0x004c7520(0x391c1b8,0,0,0);
      }
      if ((_DAT_021fb3c4 == 1) && (_DAT_021fb3c0 != 1)) {
        if (*(int *)((long)in_GS_OFFSET + 0x34) == 0) {
          func_0x006b6cf0(plVar1);
        }
        else {
          func_0x006b6c00(0);
        }
        func_0x004c7520(*plVar1 + 0x18,0,0,0);
        func_0x004c7520(0x391c198,0,0,0);
        func_0x008c4180();
        iVar5 = -1;
        goto LAB_006f91b1;
      }
      bVar4 = true;
      bVar11 = true;
      uVar8 = 1;
      DAT_0391c234 = 1;
    }
  }
  if ((_DAT_021fb3c4 == 0) || (_DAT_021fb3c0 == 1)) {
    if (_DAT_021fb3c8 == 0) {
      if (param_1 == 0) {
        _DAT_021fb3c8 = 1;
        func_0x00ac7630(0x391c280);
        if (_DAT_021fb3c4 == 1) {
          local_40 = (long)_DAT_021fb3e8 * 0x10c6f7a0b5ed;
        }
        else {
          local_40 = 0x22ee41919ac671;
        }
        local_48 = 0;
        _DAT_0391c2c0 = 1;
        _DAT_0391c2b0 = 0x2677d0;
        func_0x00ac7470(0x391c280,&local_48);
        iVar5 = func_0x00b078d0();
        pcVar2 = _DAT_03bf68e8;
        if ((iVar5 != 0) && (_DAT_02cb0000 != 0)) {
          if (8 < (-(long)_DAT_03bf68e8 + 0x26b750U >> 3 | -(long)_DAT_03bf68e8 << 0x3d)) {
            func_0x0044f8c0(0x21fb410,_DAT_03bf68e8);
          }
          (*pcVar2)(1);
        }
      }
      else {
        func_0x00ac7630(0x391c280);
        if (_DAT_021fb3c4 == 1) {
          local_40 = (long)_DAT_021fb3ec * 0x10c6f7a0b5ed;
        }
        else {
          local_40 = 0x13a92a305531bc0;
        }
        local_48 = 0;
        _DAT_0391c2c0 = 1;
        _DAT_0391c2b0 = 0x2677d0;
        func_0x00ac7470(0x391c280,&local_48);
        DAT_0391c234 = 1;
        bVar4 = true;
      }
      goto LAB_006f905a;
    }
    if (DAT_0391c230 != '\0') {
      _DAT_021fb3c8 = 0;
      func_0x00ac7630(0x391c280);
      if (_DAT_021fb3c4 == 1) {
        local_40 = (long)_DAT_021fb3ec * 0x10c6f7a0b5ed;
      }
      else {
        local_40 = 0x13a92a305531bc0;
      }
      local_48 = 0;
      _DAT_0391c2c0 = 1;
      _DAT_0391c2b0 = 0x2677d0;
      func_0x00ac7470(0x391c280,&local_48);
      iVar5 = func_0x00b078d0();
      pcVar2 = _DAT_03bf68e8;
      if (param_1 == 2) {
        if (_DAT_02cb0000 != 0 && iVar5 != 0) {
          if (8 < (-(long)_DAT_03bf68e8 + 0x26b750U >> 3 | -(long)_DAT_03bf68e8 << 0x3d)) {
            func_0x0044f8c0(0x21fb450,_DAT_03bf68e8);
          }
          uVar7 = 3;
LAB_006f8ee9:
          (*pcVar2)(uVar7);
        }
      }
      else if (_DAT_02cb0000 != 0 && iVar5 != 0) {
        if (8 < (-(long)_DAT_03bf68e8 + 0x26b750U >> 3 | -(long)_DAT_03bf68e8 << 0x3d)) {
          func_0x0044f8c0(0x21fb470,_DAT_03bf68e8);
        }
        uVar7 = 0;
        goto LAB_006f8ee9;
      }
      DAT_0391c230 = '\0';
      bVar4 = true;
      if (bVar11 != false) {
        DAT_0391c234 = 1;
      }
      goto LAB_006f905a;
    }
    func_0x00ac7630(0x391c280);
    iVar5 = func_0x00b078d0();
    pcVar2 = _DAT_03bf68e8;
    if (((iVar5 != 0) && (_DAT_02cb0000 != 0)) && ((DAT_0391c1c0 & 1) != 0)) {
      if (8 < (-(long)_DAT_03bf68e8 + 0x26b750U >> 3 | -(long)_DAT_03bf68e8 << 0x3d)) {
        func_0x0044f8c0(0x21fb430,_DAT_03bf68e8);
      }
      (*pcVar2)(2);
    }
    _DAT_0391c2c0 = 1;
    local_48 = 0;
    _DAT_0391c2b0 = 0x2677d0;
    local_40 = 0x68db8bac71094;
    func_0x00ac7470(0x391c280,&local_48);
    DAT_0391c230 = '\x01';
    bVar3 = false;
    DAT_0391c234 = bVar11;
    func_0x004c7520(*plVar1 + 0x18,0,0,0);
    uVar6 = 0;
  }
  else {
LAB_006f905a:
    func_0x004c7520(*plVar1 + 0x18,0,0,0);
    bVar3 = true;
    uVar6 = (ulong)(_DAT_021fb3c0 == 1) << 3;
    if (_DAT_021fb3c4 == 0) {
      uVar6 = uVar6 | 1L << ((ulong)*(byte *)((long)_DAT_021fb3cc * 8 + 0x13b9e10) & 0x3f) |
                      1L << ((ulong)*(byte *)((long)_DAT_021fb3cc * 8 + 0x13b9e14) & 0x3f);
    }
  }
  uVar10 = 0;
  do {
    if (((uVar6 | uVar8) >> (uVar10 & 0x3f) & 1) != 0) {
      if ((int)uVar10 == *(int *)((long)in_GS_OFFSET + 0x34)) {
        plVar1 = (long *)*in_GS_OFFSET;
        func_0x004c78b0(plVar1,0,0x1279d12,0x2b4);
        func_0x006b6cf0(plVar1);
        func_0x004c7520(*plVar1 + 0x18,0,0,0);
      }
      else {
        func_0x006b6c00(uVar10);
      }
    }
    uVar9 = (int)uVar10 + 1;
    uVar10 = (ulong)uVar9;
  } while (uVar9 <= _DAT_03d0e8b8);
  iVar5 = 0;
  func_0x004c7520(0x391c198,0,0,0);
  if (((!bVar3) && (_DAT_021fb3c0 == 1)) && (_DAT_0391c240 != 0)) {
    func_0x004ea9b0(_DAT_0391c238,0x21fb4b0);
  }
  if ((bVar4) && ((DAT_0391c234 & 1) != 0)) {
    if (param_1 - 1U < 2) {
      func_0x008c4180();
    }
    else {
      func_0x004ea9b0(_DAT_0391c238,0x21fb490);
    }
    DAT_0391c234 = 0;
  }
LAB_006f91b1:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return iVar5;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_006f92d0 RVA 0x6f92d0 | Evidence ev_8f143a0594eab42e88c821757be8fe1f7c4e1be535b33f6c8ef50ee6903e0f6a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.bin SHA256 52a840747e97096877d643ade1dd1cdc6e6e5b3d3dd7e8a19333d7e1031d853f =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x6f92d0", "end": "0x6f92de"}], "total_bytes": 15, "span_bytes": 15, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x6f92da to 0x6f8910 impl_cpumode_6f8910 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void FUN_006f92d0(void)

{
  impl_cpumode_6f8910(1);
  return;
}




/* ===== TARGET: handler_676_body RVA 0x6f92e0 | Evidence ev_d1b588fe78e706c3825cc0049d254e141a90f2fd6f058f6aaa4872bb9c9a3b0f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.bin SHA256 52a840747e97096877d643ade1dd1cdc6e6e5b3d3dd7e8a19333d7e1031d853f =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x6f92e0", "end": "0x6f930b"}], "total_bytes": 44, "span_bytes": 44, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 handler_676_body(void)

{
  int iVar1;
  undefined8 uVar2;
  long *in_GS_OFFSET;
  
  if (*(char *)(*(long *)(*in_GS_OFFSET + 8) + 0xc81) != '\0') {
    return 0x4e;
  }
  if (DAT_0391c1c0 == '\0') {
    DAT_0391c1c0 = '\x01';
  }
  iVar1 = impl_cpumode_6f8910(2);
  uVar2 = 0x16;
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  return uVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): handler_676_continuation RVA 0x6f930c | Evidence ev_4a6161f1939b938ebfffa78d3fd9344a0c694ecd60ef7f99bd6b0e639bcca554 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_676.helper.bin SHA256 52a840747e97096877d643ade1dd1cdc6e6e5b3d3dd7e8a19333d7e1031d853f =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x6f930c", "end": "0x6f9327"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 handler_676_continuation(void)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = impl_cpumode_6f8910(2);
  uVar2 = 0x16;
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  return uVar2;
}


