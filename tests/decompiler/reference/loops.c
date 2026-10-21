
int loops(int param_1)

{
  int iVar1;
  int iVar2;
  
                    /* 0x1025  4  loops */
  if (param_1 < 1) {
    iVar2 = 0;
  }
  else {
    iVar1 = 0;
    iVar2 = 0;
    do {
      iVar2 = iVar2 + iVar1 * iVar1;
      iVar1 = iVar1 + 1;
    } while (param_1 != iVar1);
  }
  return iVar2;
}

