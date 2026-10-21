
int switches(undefined4 param_1,int param_2)

{
  int iVar1;
  
                    /* 0x105b  7  switches */
  switch(param_1) {
  case 0:
    iVar1 = arithmetic(param_2,0xd);
    break;
  case 1:
    iVar1 = branches(param_2);
    break;
  case 2:
    iVar1 = loops(param_2);
    break;
  case 3:
    iVar1 = arithmetic(param_2,0x1b);
    break;
  case 4:
    iVar1 = arithmetic(param_2,0x5b);
    break;
  case 5:
    iVar1 = branches(param_2 + 0xc);
    break;
  case 6:
    iVar1 = loops(param_2 + 2);
    break;
  default:
    iVar1 = -1;
  }
  return iVar1;
}

