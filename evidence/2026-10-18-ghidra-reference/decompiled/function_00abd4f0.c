/* 13.60-labeled; acquisition authenticity unresolved; Ghidra pseudocode, not original source. */

undefined8 ref_body_00abd4f0(long param_1)

{
  long lVar1;

  lVar1 = *(long *)(*(long *)(param_1 + 8) + 0x200);
  func_0x002c6820(lVar1,0,0);
  *(ulong *)(param_1 + 0x408) = (ulong)*(uint *)(lVar1 + 0x1c4);
  func_0x002c6870(lVar1,0,0);
  return 0;
}
