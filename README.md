# Overview

This project explores compiler-based code hardening techniques that aim to raise the cost of unauthorized tampering and patching and study how modern decompilers recover control flow. The intended applications include IP protection for proprietary software and client side integrity checks in anti-cheat and anti-tamper systems. Originally developed in 2023, published in 2025 for portfolio.

# Bogus Control Flow

The bogus control flow pass adds false execution paths to functions through if-then instructions evaluating opaque predicates. These execution paths are unreachable and contain random dead instructions that do not affect the output of the program. Each path will split itself a random number of times, creating a tree-like structure which diverge from the true execution paths. Then, this false execution path connects back to a random block of the true execution path, resembling a legitimate execution path.

# Integrity Guard and CFG Obfuscator

The integrity guard and CFG obfuscator pass inserts user-provided integrity validators and response to failed integrity validation functions, inserts dead instructions on a global guard variable that will eventually set itself back to a known state/value, and injects raw assembly into the prologue of functions which causes confusion to the pseudo-code generation of decompilers. 

The integrity validator function is randomly inserted throughout the `.text` segment and is meant to be user-implemented, and can validate integrity by checking for tampering, debugger flags, or checksums of `.text` segments. Then, the integrity validator can modify the guard variable (set it to any value that it is not currently equal to) to indicate the validation has failed.

The integrity validator response function is a reaction to modifications of the guard variable (if it is not equal to an expected value, react accordingly, i.e. through killing process). Note that the implementation of the integrity validator is up to the user, and therefore it can be written to react immediately on its own.

If the guard variable was only used by the validator and the validation response, it would be simple for a reverse engineer to bypass these security mechanisms through finding all xrefs to the variable, and NOP changes from the validator. Therefore, I insert random instructions that modify the guard variable, and restore it back to a known value after a random number of instructions. This is not foolproof, but should make it more confusing and improve security.

Finally, the following assembly is injected into the prologue of every function:

```
push {r0-r2}
add r0, pc, #20
mov r2, 0
orr r1, r0, r2
and r0, r0, r2
mul r0, r1, r0
eor r0, r1, r0
mov pc, r0
pop {r0-r2}
```

All this is doing is, after the push instruction, jumping to the pop instruction. However, decompilers (such as IDA) are unable to determine that this is a branch within the function. A smart decompiler may be able to realize this, so dynamic measures of figuring out offset (i.e. through volatile variables) may be a more fool proof of defending against static analysis so the branch can no longer be resolved.


# Examples

To understand the effectiveness of these security measures, we will look at a simple function that traverses an array, counts the number of positive and negative numbers, and returns the difference:

```
int balance_signs(const int *a, size_t n) {
  int positives = 0;
  int negatives = 0;
  for(size_t i = 0; i < n; i++) {
    if(a[i] > 0) {
      positives++;
    } else if(a[i] < 0) {
      negatives++;
    }
  }
  return positives - negatives;
}
```

Initially, a decompiler determines the pseudocode for this function is as followed:

```
int __fastcall balance_signs(int a1, unsigned int a2)
{
  v5 = 0;
  v4 = 0;
  for ( i = 0; i < a2; ++i )
  {
    if ( *(int *)(a1 + 4 * i) < 1 )
    {
      if ( *(int *)(a1 + 4 * i) <= -1 )
        ++v4;
    }
    else
    {
      ++v5;
    }
  }
  return v5 - v4;
}
```

And the CFG is produced as followed:

<img width="281" height="668" alt="image" src="https://github.com/user-attachments/assets/a28bb25e-b255-43a0-9b31-d2c443e02150" />

Observe that the pseudocode is easy to follow, and the CFG is fairly simple.

## Running Bogus Pass on Example

After running the bogus control flow pass on the example function, the following pseudocode output is produced:

```
int __fastcall balance_signs(int a1, unsigned int a2)
{
  v9 = 0;
  v8 = 0;
  v7 = 0;
  v6 = -218304109;
  while ( 1 )
  {
    v11 = v6;
    savedregs = 123;
    if ( v6 < -921493436 )
      break;
    if ( v6 < -218304109 )
    {
      if ( v6 < -754984990 )
      {
        ++v8;
        v6 = -754984990;
        savedregsc = 8;
        goto LABEL_32;
      }
      v6 = -1407412650;
      savedregsb = 89;
      _unnamed_6 = 0;
      savedregsi = 105;
      _unnamed_3 = 6;
      if ( _unnamed_9 >= 2147483543 )
      {
LABEL_5:
        if ( v11 < 1723713735 )
        {
          if ( v11 == 927710821 )
          {
            ++v9;
            v6 = -1407412650;
            savedregsh = 114;
            _unnamed_5 = 114;
          }
        }
        else
        {
          ++v7;
          v6 = -218304109;
          savedregsa = 59;
        }
        goto LABEL_32;
      }
      savedregsj = 101;
      _unnamed_4 = 202;
      goto LABEL_15;
    }
    if ( v6 >= 927710821 )
      goto LABEL_5;
    v3 = -2088870396;
    if ( v7 < a2 )
      v3 = -1549834610;
    v6 = v3;
    savedregse = 80;
LABEL_32:
    savedregsk = 122;
  }
  if ( v6 >= -1407412650 )
  {
    while ( v11 >= -1140993914 )
    {
      v2 = -754984990;
      if ( *(int *)(a1 + 4 * v7) < 0 )
        v2 = -921493436;
      v6 = v2;
      savedregsd = 26;
      _unnamed_8 = 26;
      _unnamed_7 = 1;
    }
LABEL_15:
    if ( v11 == -1407412650 )
    {
      v6 = 1723713735;
      savedregsf = 75;
    }
    goto LABEL_32;
  }
  if ( v6 >= -1549834610 )
  {
    v5 = -1140993914;
    if ( *(int *)(a1 + 4 * v7) > 0 )
      v5 = 927710821;
    v6 = v5;
    savedregsg = 84;
    _unnamed_3 = 252;
    goto LABEL_32;
  }
  return v9 - v8;
}
```

And the CFG is as followed:

<img width="195" height="666" alt="image" src="https://github.com/user-attachments/assets/9f3e2131-ff9a-4f2e-ac25-dd778ed0246b" />

Observe that the pseudocode and CFG output are now much harder to follow.

## Running Integrity Guard and CFG Obfuscation Pass Example

After running the integrity guard and CFG obfuscation pass on the example function, the following assembly output is produced:

<img width="682" height="580" alt="image" src="https://github.com/user-attachments/assets/d895f04e-3efd-4fbe-af6c-16c76b90c56a" />

The decompiler now believes balance_signs is a function that calls sub_684(). sub_684()'s pseudocode output is as followed:

```
// positive sp value has been detected, the output may be wrong!
int sub_684()
{
  v2 = *(_DWORD *)(v1 - 52);
  v3 = *(_DWORD *)(v1 - 48);
  *(_DWORD *)(v1 - 20) = v3;
  *(_DWORD *)(v1 - 24) = v2;
  *(_DWORD *)(v1 - 28) = v3;
  *(_DWORD *)(v1 - 32) = v2;
  *(_DWORD *)(v1 - 36) = 0;
  *(_DWORD *)(v1 - 40) = 0;
  for ( *(_DWORD *)(v1 - 44) = 0; ; ++*(_DWORD *)(v1 - 44) )
  {
    v4 = *(_DWORD *)(v1 - 44);
    v5 = globalCheck0x1000;
    v12 = *globalCheck0x1000;
    *globalCheck0x1000 = 130494065
                       * ((271668663 * ((*globalCheck0x1000 + 1498150722) ^ 0x7583F851) - 388293341) ^ 0x5803830 | 0x300CC4C1);
    *v5 = v12;
    v6 = *(_DWORD *)(v1 - 32);
    v11 = *v5;
    *(_DWORD *)(v11 - 8) = -2014483590;
    *v5 = *(_DWORD *)(v11 - 8);
    *v5 = v11;
    if ( v4 >= v6 )
      break;
    if ( *(int *)(*(_DWORD *)(v1 - 28) + 4 * *(_DWORD *)(v1 - 44)) < 1 )
    {
      if ( *(int *)(*(_DWORD *)(v1 - 28) + 4 * *(_DWORD *)(v1 - 44)) <= -1 )
        ++*(_DWORD *)(v1 - 40);
    }
    else
    {
      v7 = *(_DWORD *)(v1 - 36) + 1;
      v8 = globalCheck0x1000;
      v10 = *globalCheck0x1000;
      *globalCheck0x1000 = 341483021 * ((*globalCheck0x1000 - 1464654246) ^ 0x335B5385) + 1996414341;
      *v8 = v10;
      *(_DWORD *)(v1 - 36) = v7;
    }
  }
  *(_DWORD *)(v1 - 56) = *(_DWORD *)(v1 - 36) - *(_DWORD *)(v1 - 40);
  if ( (int *)*globalCheck0x1000 != (int *)((char *)globalCheck0x1000_expected + 714889139 * zeroVar) )
  {
    *(_DWORD *)(v1 - 12) = linux_eabi_syscall(__NR_mmap2, 0, &loc_8, (char *)&loc_4 + 3, (char *)&loc_20 + 2, 0, 0, v0);
    *(_DWORD *)(v1 - 16) = *(_DWORD *)(v1 - 12);
    **(_DWORD **)(v1 - 16) = -475996160;
    *(_DWORD *)(*(_DWORD *)(v1 - 16) + 4) = -475992064;
    (*(void (**)(void))(v1 - 16))();
  }
  return *(_DWORD *)(v1 - 56);
}
```

Note that with debug symbols stripped, it becomes even harder to determine what is going on. Also note that our integrity validation response function was inserted at the end, where it mmaps an executable region of space, fills it with instructions that will set LR to 0 and jump PC to 0 (so location of crash is not immediately known on backtrace).



## Combining Our Passes

Combining our passes, below is the pseudocode output of balance_signs:
```
int __fastcall sub_2E7C(int a1, int a2, int a3, int a4, int a5)
{
  v7 = *(_DWORD *)(v6 - 100);
  *(_DWORD *)(v6 - 28) = *(_DWORD *)(v6 - 92);
  *(_DWORD *)(v6 - 96) = &globalCheck0x1000;
  v8 = globalCheck0x1000;
  *(_DWORD *)(v6 - 36) = globalCheck0x1000;
  *(_DWORD *)(v6 - 40) = v8 & 0x49FB92DB;
  globalCheck0x1000 = *(_DWORD *)(v6 - 40);
  globalCheck0x1000 = *(_DWORD *)(v6 - 36);
  *(_DWORD *)(v6 - 32) = v7;
  v9 = globalCheck0x1000;
  *(_DWORD *)(v6 - 52) = globalCheck0x1000;
  *(_DWORD *)(v6 - 56) = (((36702145
                          * ((1900062447
                            * ((((522716139 * ((v9 + 193317914) & 0x177EC3) + 1467864203) & 0x12963BD) - 1974441862) & 0x1000016 | 0x7CD4A889)
                            + 704219647) ^ 0x3AA168B3)
                          + 728863705) ^ 0x60000801) & 0x7C061879)
                       - 385763583;
  globalCheck0x1000 = *(_DWORD *)(v6 - 56);
  globalCheck0x1000 = *(_DWORD *)(v6 - 52);
  printf("Global value %d\n", globalCheck0x1000);
  v10 = *(_DWORD *)(v6 - 100);
  v11 = *(int **)(v6 - 96);
  *(_DWORD *)(v6 - 44) = *(_DWORD *)(v6 - 92);
  *(_DWORD *)(v6 - 48) = v10;
  *(_DWORD *)(v6 - 60) = 0;
  v12 = *v11;
  *(_DWORD *)(v6 - 76) = *v11;
  *(_DWORD *)(v6 - 80) = 53957169
                       * (((((((661172401 * ((607285565 * (v12 & 0x5002A488 | 0x2ABD4837)) ^ 0x3C5C89EF) - 943633683) | 0xB21F)
                            + 375229821) ^ 0x80000 | 0x3809123) & 0x3A89123)
                         - 369171679) & 0x4586044)
                       - 914770108;
  *v11 = *(_DWORD *)(v6 - 80);
  *v11 = *(_DWORD *)(v6 - 76);
  *(_DWORD *)(v6 - 64) = 0;
  v13 = *v11;
  *(_DWORD *)(v6 - 84) = *v11;
  *(_DWORD *)(v6 - 88) = ((((374513679 * (((v13 ^ 0x1923916F) - 26493841) | 0x1D747E7F)) & 0x25644800) - 1214928801) ^ 0x28B8615F)
                       + 1316135543;
  *v11 = *(_DWORD *)(v6 - 88);
  *v11 = *(_DWORD *)(v6 - 84);
  *(_DWORD *)(v6 - 68) = 0;
  *(_DWORD *)(v6 - 72) = 0;
  while ( 1 )
  {
    v14 = *(_DWORD *)(v6 - 72);
    v15 = *(_DWORD *)(v6 - 48);
    globalCheck0x1000 = 1894289677 * ((globalCheck0x1000 - 887318331) | 0x4624FAB7) - 1806297848;
    if ( v14 >= v15 )
      break;
    v16 = *(_DWORD *)(*(_DWORD *)(v6 - 44) + 4 * *(_DWORD *)(v6 - 72));
    globalCheck0x1000 = ((435003511
                        * ((717979839
                          * ((1810604013
                            * ((1107107979 * ((1811694569 * globalCheck0x1000) | 0x25DF3AD5) + 1772080405) | 0x3A8B66B)
                            + 756494023) & 0x2000000 | 0xCCFB8F7)) & 0xC528041)) ^ 0x5FC28F71)
                      - 308872557;
    if ( v16 < 1 )
    {
      if ( *(int *)(*(_DWORD *)(v6 - 44) + 4 * *(_DWORD *)(v6 - 72)) <= -1 )
      {
LABEL_6:
        v17 = *(_DWORD *)(v6 - 64);
        globalCheck0x1000 = (globalCheck0x1000 - 1287175881) ^ 0xDC3E1F5;
        *(_DWORD *)(v6 - 64) = v17 + 1;
LABEL_12:
        a5 = ((((2075923009
               * (((788846485
                  * (((1614747667 * ((globalCheck0x1000 | 0x20008800) & 0x62008810 | 0x1DE6632B) + 1288325812) | 0x7FA9A9) ^ 0x145475)) ^ 0x134005) & 0x5B4F77)
               - 1651110239) & 0x6BD7C9)
             + 1768141340) | 0x7E9B274D) & 0x7F9B375D;
        goto LABEL_16;
      }
      while ( 1 )
      {
        ++*(_DWORD *)(v6 - 68);
        a5 = 1817021403 * ((((520821011 - 477328005 * globalCheck0x1000) & 0x15C7563D) - 717309721) ^ 0x9D26457);
        _unnamed_3 = 16380;
LABEL_16:
        *(_DWORD *)(v6 - 332) = &globalCheck0x1000;
        a5 = ((((661368491
               * (((((931389768 - 1000733581 * ((141755279 * globalCheck0x1000 + 1290266421) | 0x3E7D5)) & 0x422C0028 | 0x28D2CCC7) ^ 0x7F4F50CD)
                 - 1075125285) ^ 0x35F4877)) ^ 0x35DB905)
             - 1470914695) & 0x2048900 | 0x2D2156CD) ^ 0x4BF6B77F;
        *(_DWORD *)(v6 - 348) = &a5;
        v34 = globalCheck0x1000;
        *(_DWORD *)(v6 - 336) = "Global value %d\n";
        printf("Global value %d\n", v34);
        v35 = *(int **)(v6 - 332);
        v36 = *(const char **)(v6 - 336);
        *(_DWORD *)(*(_DWORD *)(v6 - 348) - 8) = 55;
        v69 = *v35;
        a5 = 1166470995 * ((((*v35 + 696287976) & 0x11507B45) - 2041871399) & 0x1641D619) - 1028096772;
        *v35 = a5;
        *v35 = v69;
        v37 = v69;
        *(_DWORD *)(v6 - 328) = v69;
        v70 = 694930361 * *v35 - 827619683;
        *v35 = v70;
        *v35 = v70;
        *(_DWORD *)(v6 - 344) = (v37 + 3) ^ v37;
        printf(v36, *v35);
        v38 = *(_DWORD **)(v6 - 332);
        v39 = *(const char **)(v6 - 336);
        *(_DWORD *)(v6 - 340) = *(_DWORD *)(v6 - 344) - *(_DWORD *)(v6 - 328);
        printf(v39, *v38);
        v40 = *(_DWORD **)(v6 - 332);
        v41 = *(const char **)(v6 - 336);
        _unnamed_6 = *(_DWORD *)(v6 - 340);
        printf(v41, *v40);
        v42 = *(int **)(v6 - 332);
        v43 = *(_DWORD *)(v6 - 328) + 7;
        a5 = *v42;
        v71 = ((((674411043 * a5) & 0x64F1EF85) - 1829541299) | 0x113A8AE7) - 809567991;
        *v42 = v71;
        *v42 = v71;
        if ( v43 > 0 )
          goto LABEL_30;
        *(_DWORD *)(v6 - 360) = &globalCheck0x1000;
        v72 = globalCheck0x1000;
        v5 = 565418493;
        a5 = (1678529455
            * ((324214511
              * ((834697833
                * ((2012373979 * ((1670015503 * (globalCheck0x1000 & 0x6DDF51F5) - 410933587) ^ 0x5394A017)) ^ 0x6AF965FD)
                - 177790123) ^ 0x661BD80B)
              + 1163682132) | 0x4457095F)
            + 565418493) | 0x2F02A3AF;
        *(_DWORD *)(v6 - 356) = globalCheck0x1000;
        globalCheck0x1000 = ((((-1575271647
                              - 623755595
                              * (((((1662635759 * ((globalCheck0x1000 - 961727560) | 0x2045EE09) - 941689407) | 0x44083919) & 0x6F0A7B19)
                                - 1674780807) | 0x1228695B)) | 0x1E1EDB45)
                            - 866817105) & 0x2D040464)
                          - 732291609;
        *(_DWORD *)(v6 - 352) = 68 * v72;
        printf("Global value %d\n", globalCheck0x1000);
        if ( (*(_DWORD *)(v6 - 352) - *(_DWORD *)(v6 - 356)) * *(_DWORD *)(v6 - 356) != 1635846530 )
          break;
        *(_DWORD *)(v6 - 364) = 84;
        *(_DWORD *)(v6 - 368) = 84;
        if ( ((2 * *(_DWORD *)(v6 - 368)) | *(_DWORD *)(v6 - 364)) != *(_DWORD *)(v6 - 364) )
        {
          _unnamed_4 = 36;
          *(_DWORD *)(v6 - 416) = &globalCheck0x1000;
          a5 = (993814409 * ((((1956799899 * globalCheck0x1000) ^ 0x455D35C9) - 1448920245) ^ 0x25A07ABB) - 2024280507) | 0xCE0B425;
          *(_DWORD *)(v6 - 412) = 15;
          *(_DWORD *)(v6 - 424) = 15;
          *(_DWORD *)(v6 - 428) = 30;
          v62 = globalCheck0x1000;
          *(_DWORD *)(v6 - 420) = "Global value %d\n";
          printf("Global value %d\n", v62);
          v63 = *(int **)(v6 - 416);
          v64 = *(const char **)(v6 - 420);
          _unnamed_2 = ((((*(_DWORD *)(v6 - 428) | *(_DWORD *)(v6 - 412)) ^ *(_DWORD *)(v6 - 424))
                       * *(_DWORD *)(v6 - 424)) | *(_DWORD *)(v6 - 424))
                     % 126;
          v76 = *v63;
          a5 = (1985648811 * ((*v63 - 325356920) & 0x7B06F09 ^ 0x5ED4FE29) + 1017460222) | 0x3B4C2953;
          *v63 = a5;
          *v63 = v76;
          v77 = 1062223153
              * ((189677201
                * (((992482847 * ((((*v63 - 2057317866) | 0x5EDE9893) + 1436807476) ^ 0xAF95B89) + 1473274557) ^ 0x26088308) & 0x2758A31A)) | 0x7322C8AD)
              - 1756166926;
          *v63 = v77;
          *v63 = v77;
          printf(v64, *v63);
          v65 = *(int **)(v6 - 416);
          v66 = *(_DWORD *)(v6 - 412);
          a5 = *v65;
          a5 = 1547809435 * ((((635889385 * a5) ^ 0x22C146F) - 134654981) & 0x2223244 | 0x7CD94D9B) + 1275097755;
          *v65 = a5;
          *v65 = v77;
          v78 = *v65 | 0x322C4285;
          *v65 = v78;
          *v65 = v78;
          if ( ((v66 + 7) & 0x7FFFFFFF) == 786350288 )
            goto LABEL_13;
        }
        else
        {
          do
          {
            *(_DWORD *)(v6 - 408) = &globalCheck0x1000;
            *(_DWORD *)(v6 - 404) = 58;
            *(_DWORD *)(v6 - 400) = 58;
            a5 = globalCheck0x1000;
            v5 = 779142823;
            globalCheck0x1000 = (779142823 - 1083288141 * globalCheck0x1000) ^ 0x331E1DF7;
            _unnamed_3 = 6728;
            v61 = *(_DWORD **)(v6 - 408);
            _unnamed_6 = (*(_DWORD *)(v6 - 400) + 464) % 9;
            printf("Global value %d\n", *v61);
          }
          while ( 799063683
                * ((unsigned int)((*(_DWORD *)(v6 - 404) + 1) / *(_DWORD *)(v6 - 400)) ^ *(_DWORD *)(v6 - 400))
                + 49941480 > 0x5F417D0 );
        }
      }
      while ( 1 )
      {
        _unnamed_1 = 93;
        *(_DWORD *)(v6 - 372) = &globalCheck0x1000;
        v44 = globalCheck0x1000;
        *(_DWORD *)(v6 - 384) = globalCheck0x1000;
        v45 = globalCheck0x1000;
        *(_DWORD *)(v6 - 380) = globalCheck0x1000;
        a5 = globalCheck0x1000;
        globalCheck0x1000 = (1833858873
                           * ((((((1024735095
                                 * ((2134022949 * ((1092680687 * globalCheck0x1000) ^ 0x1561231D) + 821388554) & 0x3299F239)
                                 + 772192389) ^ 0x320F0100 | 0x4DE072DD)
                               - 1465747835) | 0x200BA3ED)
                             - 1720624929) ^ 0x4FC3C9)) ^ 0x35BBDD43;
        v46 = ((((2 * v45 + 7) * v44) | v45) ^ v44) / v44;
        v47 = *(_DWORD *)(v6 - 384);
        v48 = *(_DWORD *)(v6 - 380);
        v49 = v46;
        v50 = *(_DWORD **)(v6 - 372);
        _unnamed_4 = v49;
        *(_DWORD *)(v6 - 376) = ((v49 ^ v48) * v48 - v47) % 15 + v48;
        printf("Global value %d\n", *v50);
        v51 = *(_DWORD *)(v6 - 376) / *(_DWORD *)(v6 - 380);
        v52 = *(int **)(v6 - 372);
        v73 = 1518750299 * (*v52 & 0x30639003);
        *v52 = v73;
        *v52 = v73;
        if ( v51 > _unnamed_2 )
          break;
        *(_DWORD *)(v6 - 396) = &globalCheck0x1000;
        printf("Global value %d\n", globalCheck0x1000);
        v53 = *(_DWORD **)(v6 - 396);
        *v53 = 1050636155;
        *v53 = 1050636155;
        *(_DWORD *)(v6 - 388) = 124;
        *(_DWORD *)(v6 - 392) = 124;
        v54 = *(int **)(v6 - 396);
        v55 = *(_DWORD *)(v6 - 392);
        v56 = *(_DWORD *)(v6 - 388);
        a5 = *v54;
        v74 = 155392533 * ((1541668597 * a5) ^ 0x3EE1E8C5) + 744396424;
        *v54 = v74;
        *v54 = v74;
        v57 = ((v56 | 1) + v55) / v56;
        v58 = *(int **)(v6 - 396);
        v59 = *(_DWORD *)(v6 - 392);
        v60 = *(_DWORD *)(v6 - 388);
        a5 = *v58;
        v5 = 1698108123;
        v75 = (((((1698108123 - 681409787 * a5) | 0x6DB381E5) - 1940895066) | 0x574E2417) ^ 0x14CCC0B3) + 1352654099;
        *v58 = v75;
        *v58 = v75;
        if ( ((((((v57 * v60 % 102) | v59) * v59) | v59) % 3) ^ v60) != 1072892355 )
          goto LABEL_6;
      }
      a5 = globalCheck0x1000;
      globalCheck0x1000 = (1147745985 * ((89754403 * globalCheck0x1000) & 0x3A61D07B)) | 0xF36888B;
      if ( globalCheck0x1000 == 1271208439 )
        goto LABEL_12;
LABEL_13:
      while ( 1 )
      {
        *(_DWORD *)(v6 - 204) = &globalCheck0x1000;
        v67 = globalCheck0x1000;
        *(_DWORD *)(v6 - 196) = globalCheck0x1000;
        *(_DWORD *)(v6 - 192) = v67;
        _unnamed_6 = 2 * (v67 | 3);
        a5 = (834637295
            * ((2015322787
              * ((1084754337 * (((globalCheck0x1000 - 1303691160) | 0x74040010) & 0x76043010 | 0x8FA48E3) + 695136115) | 0xD4E4AD5)) ^ 0x396668AD)
            - 1367087765) & 0x244F582B;
        globalCheck0x1000 = ((~globalCheck0x1000 | 0x282C0E11) & 0x282C8E19) - 846251493;
        *(_DWORD *)(v6 - 200) = ((v67 + 1) % 53 % 98) | v67;
        printf("Global value %d\n", globalCheck0x1000);
        if ( ((*(_DWORD *)(v6 - 200) / *(_DWORD *)(v6 - 196)) ^ *(_DWORD *)(v6 - 196) | *(_DWORD *)(v6 - 192)) <= _unnamed_2 )
          break;
        *(_DWORD *)(v6 - 240) = &a5;
        *(_DWORD *)(v6 - 236) = 14;
        *(_DWORD *)(v6 - 228) = 14;
        *(_DWORD *)(v6 - 224) = &globalCheck0x1000;
        v19 = globalCheck0x1000;
        *(_DWORD *)(v6 - 220) = "Global value %d\n";
        printf("Global value %d\n", v19);
        v20 = *(_DWORD *)(v6 - 236);
        v21 = *(_DWORD **)(v6 - 224);
        v22 = *(const char **)(v6 - 220);
        *(_DWORD *)(v6 - 216) = *(_DWORD *)(*(_DWORD *)(v6 - 240) - 8);
        *(_DWORD *)(v6 - 232) = &_unnamed_1;
        _unnamed_1 = v20;
        printf(v22, *v21);
        v23 = *(_DWORD **)(v6 - 232);
        v24 = *(_DWORD *)(v6 - 228);
        v25 = *(_DWORD *)(v6 - 216);
        v26 = (v24 + 2) * v25;
        _unnamed_6 = v26 - v25;
        *v23 = v26 - v25;
        v27 = v26 / v24;
        v28 = *(_DWORD *)(v6 - 228);
        v29 = *(int **)(v6 - 224);
        v30 = v27;
        v31 = *(const char **)(v6 - 220);
        v32 = ((((2 * v30) | v28) * v28) | *(_DWORD *)(v6 - 216)) + *(_DWORD *)(v6 - 216);
        v68 = 1281721571 * *v29;
        *v29 = v68;
        *v29 = v68;
        v33 = v32 | v28;
        *(_DWORD *)(v6 - 212) = v33;
        _unnamed_2 = v33;
        printf(v31, *v29);
        _unnamed_5 = (*(_DWORD *)(v6 - 212) ^ *(_DWORD *)(v6 - 216)) + *(_DWORD *)(v6 - 216);
      }
      *(_DWORD *)(v6 - 208) = &globalCheck0x1000;
      a5 = globalCheck0x1000;
      globalCheck0x1000 = ((((2005796373 * (((-1716727801 * globalCheck0x1000) | 0x600009C0) & 0x66945DC0 | 0x1929A23F)
                            + 1834878374) | 0xEB1EC7D) ^ 0x10CE2D0F)
                         - 1535059161) & 0x12DA9809;
      _unnamed_5 = 87;
    }
    ++*(_DWORD *)(v6 - 60);
    a5 = (((((((((((globalCheck0x1000 + 984387398) ^ 0x11BBBF7) - 747827047) & 0x2B389681 ^ 0x754D139) + 614316497) | 0x34831) & 0x210B4CB9)
           - 1174368569) ^ 0x2E70FCF1)
         - 1009825595) & 0x2000042C)
       - 701746715;
    _unnamed_4 = 86;
LABEL_30:
    a5 = ((((1442858416 - 1210741663 * ((1335935215 * globalCheck0x1000) | 0xD8B0A53)) & 0x9800081) - 1998918737) | 0x779CF363)
       - 1895114912;
    ++*(_DWORD *)(v6 - 72);
    *(_DWORD *)(v6 - 432) = &globalCheck0x1000;
    a5 = 1718969045 * ((749491895 * (globalCheck0x1000 & 0x57DCFA1)) & 0x1C420101) - 1260291903;
    globalCheck0x1000 = 1402511217 - 214646035 * ((1252386095 * (globalCheck0x1000 | 0x78B8241D)) ^ 0x54CE65CF);
  }
  *(_DWORD *)(v6 - 104) = *(_DWORD *)(v6 - 60) - *(_DWORD *)(v6 - 64);
  if ( globalCheck0x1000 != globalCheck0x1000_expected + 1238950975 * zeroVar )
  {
    *(_DWORD *)(v6 - 20) = linux_eabi_syscall(__NR_mmap2, 0, &byte_8, &byte_7, (char *)&dword_20 + 2, 0, 0, (void *)v5);
    *(_DWORD *)(v6 - 24) = *(_DWORD *)(v6 - 20);
    **(_DWORD **)(v6 - 24) = -475996160;
    *(_DWORD *)(*(_DWORD *)(v6 - 24) + 4) = -475992064;
    (*(void (**)(void))(v6 - 24))();
  }
  return v79(*(_DWORD *)(v6 - 104));
}
```

Note that the `printf("Global value %d\n", globalCheck0x1000);` is from the user-defined integrity validator function (I left it unimplemented, so all it does now is check what the guard variable is).

Also note that a decompiler would have much more difficulty on functions that aren't as simple as balance_signs, so these techniques should be even more successful on real software.

Alone, these methods won't stop a strong reverse engineer. However, when combined with other security techniques (see [ARM Segment Encryption Decryption](https://github.com/ksl02/Runtime-ARM-Segment-Encryption-Decryption), [Control Flow Flattener](https://github.com/ksl02/LLVM-Compiler-Pass-Control-Flow-Flattening), [.rodata Encrypt/Decrypt](https://github.com/ksl02/rodata-segment-encrypt-decrypt)), they can meaningfully increase reverse-engineering effort and reduce the reliability of static analysis.
