# [SUPERSEDED] Draft issue for pastawithpesto — answered by cobrajet302gt (issue #10 in their fork)

This draft is obsolete. The questions it asked were answered on 2026-11-06 by
cobrajet302gt (verification bench, 14.10 device rows + WK-1400 drop) in
cobrajet302gt/PS5-14.10-Jailbreak-Research issue #10:

- +112/+120/+124 is device-canonical on 14.10 (both generations); sizeof(State)=448;
  inline State[0] +128, lineWidth +176; m_unrealizedSaveCount +592.
- The all-words arm is dead by construction (cap/size are 4-byte Vector cells).
- Zero-survivor crashes are unattributable (destructor nulls m_stateStack.m_buffer;
  our build publishes no fault module+offset).
- The swept regions came from the loader-process map, not the WebProcess.
- They never ran V650-V655; no public first-HIT region exists anywhere.
- Pre-registered instrument: two-arm differential (size=1 vs size=64/cap=64),
  implemented here as probes/phase13_webkit/v911_differential_scan.html.

Remaining open items for a future post: the 14.22 deltas we measured (ctx chunk
zeroed/nulled at free, AB-first slot behavior, FontFace p640 outcome on 14.22).
