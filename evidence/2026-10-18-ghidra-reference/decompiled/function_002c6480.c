/* 13.60-labeled; acquisition authenticity unresolved; Ghidra pseudocode, not original source. */

void ref_body_002c6480(long param_1,undefined8 param_2,undefined4 param_3)

{
  long *in_GS_OFFSET;

  if ((*(byte *)(param_1 + 0x244) & 0x10) == 0) {
    if ((*(byte *)(param_1 + 0x244) & 8) != 0) {
      LOCK();
      *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
      UNLOCK();
    }
    func_0x00c4bb20(param_1 + 0x170,0);
  }
  else {
    func_0x004c6a00(param_1 + 0x1a8,0,param_2,param_3);
  }
  *(int *)(param_1 + 0x1c0) = *(int *)(param_1 + 0x1c0) + 1;
  LOCK();
  *(int *)(param_1 + 0x1c4) = *(int *)(param_1 + 0x1c4) + 1;
  UNLOCK();
  return;
}
