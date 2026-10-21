
uint stack_variables(uint param_1)

{
  uint local_18 [6];
  
                    /* 0x10ca  6  stack_variables */
  local_18[0] = param_1;
  local_18[1] = param_1 + 9;
  return local_18[param_1 & 1];
}

